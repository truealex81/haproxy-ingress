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

package acme

import (
	"crypto/rsa"
	"crypto/x509"
	"sort"
	"strings"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/utils"
)

// NewSigner ...
func NewSigner(
	logger types.Logger,
	socket string,
	cache Cache,
) Signer {
	return &signer{
		logger:       logger,
		cache:        cache,
		currentHosts: map[string]*hostnames{},
		newHosts:     map[string]*hostnames{},
		socket:       socket,
	}
}

// Signer ...
type Signer interface {
	AcmeAccount(endpoint, emails string)
	AddHosts(hosts []string, secret string)
	ClearHosts()
	HasAccount() bool
	Verify(interval time.Duration)
}

// Cache ...
type Cache interface {
	ClientResolver
	ServerResolver
	SignerResolver
}

// SignerResolver ...
type SignerResolver interface {
	GetTLSSecretContent(secretName string) *TLSSecret
	SetTLSSecretContent(secretName string, pemCrt, pemKey []byte) error
}

// TLSSecret ...
type TLSSecret struct {
	Crt *x509.Certificate
	Key *rsa.PrivateKey
}

type signer struct {
	logger       types.Logger
	cache        Cache
	lastCheck    time.Time
	account      Account
	currentHosts map[string]*hostnames
	newHosts     map[string]*hostnames
	running      bool
	socket       string
	verifyCount  int
}

type hostnames struct {
	hosts map[string]struct{}
}

func (s *signer) AcmeAccount(endpoint, emails string) {
	switch endpoint {
	case "v2", "v02":
		endpoint = "https://acme-v02.api.letsencrypt.org"
	case "v2-staging", "v02-staging":
		endpoint = "https://acme-staging-v02.api.letsencrypt.org"
	}
	s.account = Account{
		Endpoint: endpoint,
		Emails:   emails,
	}
}

func (s *signer) AddHosts(hosts []string, secret string) {
	h, found := s.newHosts[secret]
	if !found {
		h = newHostnames()
		s.newHosts[secret] = h
	}
	h.addHosts(hosts)
}

func (s *signer) ClearHosts() {
	s.newHosts = map[string]*hostnames{}
}

func (s *signer) HasAccount() bool {
	return s.account.Endpoint != "" && s.account.Emails != ""
}

func (s *signer) Verify(interval time.Duration) {
	if s.running {
		// a verification is still running on another goroutine
		// TODO make a queue
		return
	}
	now := time.Now()
	// if verified less than <interval> ago and does not have any new domains...
	if s.lastCheck.Add(interval).After(now) && !s.hasNewDomain() {
		// ... then, too early and no new domains, skipping
		return
	}
	s.lastCheck = now
	s.shiftHosts()
	// TODO parameterize days-before-expiration
	duedate := now.Add(30 * 24 * time.Hour)
	// TODO sign only new domains if <lastcheck> + <interval> > <now>
	timer := utils.NewTimer()
	go s.doVerify(duedate, timer)
}

func (s *signer) hasNewDomain() bool {
	for secret, n := range s.newHosts {
		curr, found := s.currentHosts[secret]
		if !found {
			return true
		}
		for host := range n.hosts {
			if _, found := curr.hosts[host]; !found {
				return true
			}
		}
	}
	return false
}

func (s *signer) shiftHosts() {
	s.currentHosts = s.newHosts
	s.ClearHosts()
}

func (s *signer) doVerify(duedate time.Time, timer *utils.Timer) {
	s.start()
	defer s.done()
	client, err := NewClient(s.logger, s.cache, &s.account)
	if err != nil {
		s.logger.Warn("error creating the acme client: %v", err)
		return
	}
	timer.Tick("checkAccount")
	server := NewServer(s.logger, s.socket, s.cache)
	defer server.Close()
	if err := server.Listen(); err != nil {
		s.logger.Warn("error creating the acme server listener: %v", err)
		return
	}
	timer.Tick("createServer")
	s.verifyCount++
	s.logger.Info("starting certificate sign verification id=%d", s.verifyCount)
	var success, count int
	for secret, hosts := range s.currentHosts {
		dnsnames := hosts.dnsnames()
		tls := s.cache.GetTLSSecretContent(secret)
		if tls == nil || tls.Crt.NotAfter.Before(duedate) || !hosts.match(tls.Crt.DNSNames) {
			s.logger.InfoV(2, "authorizing domain(s): %s", strings.Join(dnsnames, ", "))
			crt, key, err := client.Sign(dnsnames)
			if err == nil {
				if errTLS := s.cache.SetTLSSecretContent(secret, crt, key); errTLS == nil {
					s.logger.InfoV(2, "new certificate issued for: %s", strings.Join(dnsnames, ", "))
					success++
				} else {
					s.logger.Warn("error storing: %v", errTLS)
				}
			} else {
				s.logger.Warn("error signing: %v", err)
			}
			count++
		}
	}
	acmeCerts := len(s.currentHosts)
	timer.Tick("sign")
	s.logger.Info("finish certificate sign verification id=%d: acmeCerts=%d needToSign=%d signed=%d failed=%d skipped=%d %s",
		s.verifyCount, acmeCerts, count, success, count-success, acmeCerts-count, timer.AsString("total"))
}

func (s *signer) start() {
	s.running = true
}

func (s *signer) done() {
	s.running = false
}

func newHostnames() *hostnames {
	return &hostnames{hosts: map[string]struct{}{}}
}

func (h *hostnames) addHosts(hosts []string) {
	for _, host := range hosts {
		h.hosts[host] = struct{}{}
	}
}

func (h *hostnames) dnsnames() []string {
	names := make([]string, len(h.hosts))
	var i int
	for host := range h.hosts {
		names[i] = host
		i++
	}
	sort.Slice(names, func(i, j int) bool {
		return names[i] < names[j]
	})
	return names
}

// match return true if all hosts in hostnames (desired configuration)
// are already in dnsnames (current certificate).
func (h *hostnames) match(dnsnames []string) bool {
	for host := range h.hosts {
		found := false
		for _, dns := range dnsnames {
			if host == dns {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
