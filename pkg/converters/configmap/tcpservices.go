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

package configmap

import (
	"fmt"
	"strconv"
	"strings"

	convtypes "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/types"
	convutils "github.com/jcmoraisjr/haproxy-ingress/pkg/converters/utils"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/haproxy"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// TCPServicesConverter ...
type TCPServicesConverter interface {
	Sync(tcpservices map[string]string)
}

// NewTCPServicesConverter ...
func NewTCPServicesConverter(logger types.Logger, haproxy haproxy.Config, cache convtypes.Cache) TCPServicesConverter {
	return &tcpSvcConverter{
		logger:  logger,
		cache:   cache,
		haproxy: haproxy,
	}
}

type tcpSvcConverter struct {
	logger  types.Logger
	cache   convtypes.Cache
	haproxy haproxy.Config
}

func (c *tcpSvcConverter) Sync(tcpservices map[string]string) {
	// map[key]value is:
	// - key   => port to expose
	// - value => <service-name>:<port>:[<PROXY>]:[<PROXY[-<V1|V2>]]:<secret-name>
	//   - 0: namespace/name of the target service
	//   - 1: target port number
	//   - 2: "PROXY" means accept proxy protocol
	//   - 3: "PROXY[-V1|V2]" means send proxy protocol, defaults to V2
	//   - 4: namespace/name of crt/key secret if should ssl-offload
	for k, v := range tcpservices {
		publicport, err := strconv.Atoi(k)
		if err != nil {
			c.logger.Warn("skipping invalid public listening port of TCP service: %s", k)
			continue
		}
		svc := c.parseService(v)
		if svc.name == "" {
			c.logger.Warn("skipping empty TCP service name on public port %d", publicport)
			continue
		}
		service, err := c.cache.GetService(svc.name)
		if err != nil {
			c.logger.Warn("skipping TCP service on public port %d: %v", publicport, err)
			continue
		}
		svcport := convutils.FindServicePort(service, svc.port)
		if svcport == nil {
			c.logger.Warn("skipping TCP service on public port %d: port not found: %s:%s", publicport, svc.name, svc.port)
			continue
		}
		addrs, _, err := convutils.CreateEndpoints(c.cache, service, svcport)
		if err != nil {
			c.logger.Warn("skipping TCP service on public port %d: %v", svc.port, err)
			continue
		}
		var crtfile convtypes.File
		if svc.secret != "" {
			crtfile, err = c.cache.GetTLSSecretPath(svc.secret)
			if err != nil {
				c.logger.Warn("skipping TCP service on public port %d: %v", publicport, err)
				continue
			}
		}
		servicename := fmt.Sprintf("%s_%s", service.Namespace, service.Name)
		backend := c.haproxy.AcquireTCPBackend(servicename, publicport)
		for _, addr := range addrs {
			backend.AddEndpoint(addr.IP, addr.Port)
		}
		backend.ProxyProt.Decode = strings.ToLower(svc.inProxy) == "proxy"
		switch strings.ToLower(svc.outProxy) {
		case "proxy", "proxy-v2":
			backend.ProxyProt.EncodeVersion = "v2"
		case "proxy-v1":
			backend.ProxyProt.EncodeVersion = "v1"
		}
		backend.SSL.Filename = crtfile.Filename
	}
}

type tcpSvc struct {
	name     string
	port     string
	inProxy  string
	outProxy string
	secret   string
}

func (c *tcpSvcConverter) parseService(service string) *tcpSvc {
	svc := make([]string, 5)
	for i, v := range strings.Split(service, ":") {
		if i < 5 {
			svc[i] = v
		}
	}
	return &tcpSvc{
		name:     svc[0],
		port:     svc[1],
		inProxy:  svc[2],
		outProxy: svc[3],
		secret:   svc[4],
	}
}
