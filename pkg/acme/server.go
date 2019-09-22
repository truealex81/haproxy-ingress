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
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// NewServer ...
func NewServer(logger types.Logger, socket string, resolver ServerResolver) Server {
	return &server{
		logger:   logger,
		socket:   socket,
		resolver: resolver,
	}
}

// ServerResolver ...
type ServerResolver interface {
	GetToken(domain, uri string) string
}

// Server ...
type Server interface {
	Listen() error
	Close() error
}

type server struct {
	logger   types.Logger
	resolver ServerResolver
	server   *http.Server
	socket   string
}

func (s *server) Listen() error {
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		uri := r.URL.Path
		token := s.resolver.GetToken(host, uri)
		if token == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "404 not found\n")
			s.logger.Warn("url token not found: http://%s%s", host, uri)
			return
		}
		fmt.Fprintf(w, token)
	})
	s.server = &http.Server{Addr: s.socket, Handler: handler}
	l, err := net.Listen("unix", s.server.Addr)
	if err != nil {
		return err
	}
	s.logger.Info("listening on acme unix socket")
	go s.server.Serve(l)
	// TODO properly wait s.server ready to avoid socket leak on s.Close()
	time.Sleep(time.Second)
	return nil
}

func (s *server) Close() error {
	if s.server == nil {
		s.logger.Warn("cannot close, server is nil")
		return nil
	}
	s.logger.Info("closing acme unix socket")
	return s.server.Close()
}
