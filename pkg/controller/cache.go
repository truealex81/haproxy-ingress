/*
Copyright 2019 The HAProxy Ingress Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	api "k8s.io/api/core/v1"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/acme"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/file"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/controller"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/net/ssl"
	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
)

type cache struct {
	listers    *ingress.StoreLister
	controller *controller.GenericController
	//
	acmeSecretKeyName      string
	acmeTokenConfigmapName string
}

func newCache(listers *ingress.StoreLister, controller *controller.GenericController) *cache {
	return &cache{
		listers:    listers,
		controller: controller,
		// TODO parameterize object names and namespace
		acmeSecretKeyName:      "ingress-controller/acme-private-key",
		acmeTokenConfigmapName: "ingress-controller/acme-validation-tokens",
	}
}

func (c *cache) GetService(serviceName string) (*api.Service, error) {
	return c.listers.Service.GetByName(serviceName)
}

func (c *cache) GetEndpoints(service *api.Service) (*api.Endpoints, error) {
	ep, err := c.listers.Endpoint.GetServiceEndpoints(service)
	return &ep, err
}

func (c *cache) GetTerminatingPods(service *api.Service) ([]*api.Pod, error) {
	pods, err := c.listers.Pod.GetTerminatingServicePods(service)
	if err != nil {
		return []*api.Pod{}, err
	}
	podRef := make([]*api.Pod, len(pods))
	for i := range pods {
		podRef[i] = &pods[i]
	}
	return podRef, err
}

func (c *cache) GetPod(podName string) (*api.Pod, error) {
	sname := strings.Split(podName, "/")
	if len(sname) != 2 {
		return nil, fmt.Errorf("invalid pod name: '%s'", podName)
	}
	return c.listers.Pod.GetPod(sname[0], sname[1])
}

func (c *cache) GetTLSSecretPath(secretName string) (convtypes.File, error) {
	sslCert, err := c.controller.GetCertificate(secretName)
	if err != nil {
		return convtypes.File{}, err
	}
	if sslCert.PemFileName == "" {
		return convtypes.File{}, fmt.Errorf("secret '%s' does not have keys 'tls.crt' and 'tls.key'", secretName)
	}
	return convtypes.File{
		Filename: sslCert.PemFileName,
		SHA1Hash: sslCert.PemSHA,
	}, nil
}

func (c *cache) GetCASecretPath(secretName string) (convtypes.File, error) {
	sslCert, err := c.controller.GetCertificate(secretName)
	if err != nil {
		return convtypes.File{}, err
	}
	if sslCert.CAFileName == "" {
		return convtypes.File{}, fmt.Errorf("secret '%s' does not have key 'ca.crt'", secretName)
	}
	return convtypes.File{
		Filename: sslCert.CAFileName,
		SHA1Hash: sslCert.PemSHA,
	}, nil
}

func (c *cache) GetDHSecretPath(secretName string) (convtypes.File, error) {
	secret, err := c.listers.Secret.GetByName(secretName)
	if err != nil {
		return convtypes.File{}, err
	}
	dh, found := secret.Data[dhparamFilename]
	if !found {
		return convtypes.File{}, fmt.Errorf("secret '%s' does not have key '%s'", secretName, dhparamFilename)
	}
	pem := strings.Replace(secretName, "/", "_", -1)
	pemFileName, err := ssl.AddOrUpdateDHParam(pem, dh)
	if err != nil {
		return convtypes.File{}, fmt.Errorf("error creating dh-param file '%s': %v", pem, err)
	}
	return convtypes.File{
		Filename: pemFileName,
		SHA1Hash: file.SHA1(pemFileName),
	}, nil
}

func (c *cache) GetSecretContent(secretName, keyName string) ([]byte, error) {
	secret, err := c.listers.Secret.GetByName(secretName)
	if err != nil {
		return nil, err
	}
	data, found := secret.Data[keyName]
	if !found {
		return nil, fmt.Errorf("secret '%s' does not have key '%s'", secretName, keyName)
	}
	return data, nil
}

// Implements acme.ClientResolver
func (c *cache) GetKey() (crypto.Signer, error) {
	secret, err := c.listers.Secret.GetByName(c.acmeSecretKeyName)
	var key *rsa.PrivateKey
	if err == nil {
		pemKey, found := secret.Data[api.TLSPrivateKeyKey]
		if !found {
			return nil, fmt.Errorf("secret '%s' does not have a key", c.acmeSecretKeyName)
		}
		derBlock, _ := pem.Decode(pemKey)
		if derBlock == nil {
			return nil, fmt.Errorf("secret '%s' has not a valid pem encoded private key", c.acmeSecretKeyName)
		}
		key, err = x509.ParsePKCS1PrivateKey(derBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing acme client private key: %v", err)
		}
	}
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		pemEncode := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		secretName := strings.Split(c.acmeSecretKeyName, "/")
		newSecret := &api.Secret{}
		newSecret.Namespace = secretName[0]
		newSecret.Name = secretName[1]
		newSecret.Data = map[string][]byte{api.TLSPrivateKeyKey: pemEncode}
		if err := c.listers.Secret.CreateOrUpdate(newSecret); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// Implements acme.SignerResolver
func (c *cache) GetTLSSecretContent(secretName string) *acme.TLSSecret {
	secret, err := c.listers.Secret.GetByName(secretName)
	if err != nil {
		return nil
	}
	pemCrt, foundCrt := secret.Data[api.TLSCertKey]
	pemKey, foundKey := secret.Data[api.TLSPrivateKeyKey]
	if !foundCrt || !foundKey {
		return nil
	}
	derCrt, _ := pem.Decode(pemCrt)
	derKey, _ := pem.Decode(pemKey)
	if derCrt == nil || derKey == nil {
		return nil
	}
	crt, errCrt := x509.ParseCertificate(derCrt.Bytes)
	key, errKey := x509.ParsePKCS1PrivateKey(derKey.Bytes)
	if errCrt != nil || errKey != nil {
		return nil
	}
	return &acme.TLSSecret{
		Crt: crt,
		Key: key,
	}
}

// Implements acme.SignerResolver
func (c *cache) SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error {
	name := strings.Split(secretName, "/")
	secret := &api.Secret{}
	secret.Namespace = name[0]
	secret.Name = name[1]
	secret.Type = api.SecretTypeTLS
	secret.Data = map[string][]byte{
		api.TLSCertKey:       pemCrt,
		api.TLSPrivateKeyKey: pemKey,
	}
	return c.listers.Secret.CreateOrUpdate(secret)
}

// Implements acme.ServerResolver
func (c *cache) GetToken(domain, uri string) string {
	config, err := c.listers.ConfigMap.GetByName(c.acmeTokenConfigmapName)
	if err != nil {
		return ""
	}
	data, found := config.Data[domain]
	if !found {
		return ""
	}
	prefix := uri + "="
	if !strings.HasPrefix(data, prefix) {
		return ""
	}
	return strings.TrimPrefix(data, prefix)
}

// Implements acme.ClientResolver
func (c *cache) SetToken(domain string, uri, token string) error {
	config, err := c.listers.ConfigMap.GetByName(c.acmeTokenConfigmapName)
	if err != nil {
		configName := strings.Split(c.acmeTokenConfigmapName, "/")
		config = &api.ConfigMap{}
		config.Namespace = configName[0]
		config.Name = configName[1]
	}
	if config.Data == nil {
		config.Data = make(map[string]string, 1)
	}
	config.Data[domain] = uri + "=" + token
	return c.listers.ConfigMap.CreateOrUpdate(config)
}
