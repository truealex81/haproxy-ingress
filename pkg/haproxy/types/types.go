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

package types

// Global ...
type Global struct {
	Procs                  ProcsConfig
	Syslog                 SyslogConfig
	MaxConn                int
	Timeout                TimeoutConfig
	SSL                    SSLConfig
	ModSecurity            ModSecurityConfig
	DrainSupport           bool
	DrainSupportRedispatch bool
	LoadServerState        bool
	StatsSocket            string
	CustomConfig           []string
	CustomDefaults         []string
}

// ProcsConfig ...
type ProcsConfig struct {
	Nbproc          int
	Nbthread        int
	NbprocBalance   int
	NbprocSSL       int
	BindprocBalance string
	BindprocSSL     string
	CPUMap          string
}

// SyslogConfig ...
type SyslogConfig struct {
	Endpoint string
	Format   string
	Tag      string
}

// TimeoutConfig ...
type TimeoutConfig struct {
	HostTimeoutConfig
	BackendTimeoutConfig
	Stop string
}

// SSLConfig ...
type SSLConfig struct {
	DHParam       DHParamConfig
	Ciphers       string
	Options       string
	Engine        string
	ModeAsync     bool
	HeadersPrefix string
}

// DHParamConfig ...
type DHParamConfig struct {
	Filename       string
	DefaultMaxSize int
}

// ModSecurityConfig ...
type ModSecurityConfig struct {
	Endpoints []string
	Timeout   ModSecurityTimeoutConfig
}

// ModSecurityTimeoutConfig ...
type ModSecurityTimeoutConfig struct {
	Hello      string
	Idle       string
	Processing string
}

// HostsMapEntry ...
type HostsMapEntry struct {
	Key   string
	Value string
}

// HostsMap ...
type HostsMap struct {
	Match     []*HostsMapEntry
	MatchFile string
	Regex     []*HostsMapEntry
	RegexFile string
}

// HostsMaps ...
type HostsMaps struct {
	Items []*HostsMap
}

// FrontendGroup ...
type FrontendGroup struct {
	Frontends []*Frontend
	//
	HasSSLPassthrough bool
	//
	Maps              *HostsMaps
	HTTPFrontsMap     *HostsMap
	HTTPRootRedirMap  *HostsMap
	HTTPSRedirMap     *HostsMap
	SSLPassthroughMap *HostsMap
}

// Frontend ...
type Frontend struct {
	Name  string
	Binds []*BindConfig
	Hosts []*Host
	//
	Timeout HostTimeoutConfig
	//
	Maps                       *HostsMaps
	HostBackendsMap            *HostsMap
	RootRedirMap               *HostsMap
	SNIBackendsMap             *HostsMap
	TLSInvalidCrtErrorList     *HostsMap
	TLSInvalidCrtErrorPagesMap *HostsMap
	TLSNoCrtErrorList          *HostsMap
	TLSNoCrtErrorPagesMap      *HostsMap
	VarNamespaceMap            *HostsMap
}

// BindConfig ...
type BindConfig struct {
	Name   string
	Socket string
	Hosts  []*Host
	//
	AcceptProxy bool
	TLS         BindTLSConfig
	//
	Maps          *HostsMaps
	UseServerList *HostsMap
}

// BindTLSConfig ...
type BindTLSConfig struct {
	CAFilename string
	CAHash     string
	TLSCert    string
	TLSCertDir string
}

// Host ...
//
// Wildcard `*` hostname is a catch all and will be used if no other hostname,
// alias or regex matches the request. If wildcard hostname is not declared,
// the default backend will be used. If the default backend is empty,
// a default 404 page generated by HAProxy will be used.
type Host struct {
	Hostname string
	Paths    []*HostPath
	//
	Alias                  HostAliasConfig
	HTTPPassthroughBackend *Backend
	RootRedirect           string
	SSLPassthrough         bool
	Timeout                HostTimeoutConfig
	TLS                    HostTLSConfig
	VarNamespace           bool
}

// HostPath ...
//
// Root context `/` path is a catch all and will be used if no other path
// matches the request on this host. If a root context path is not
// declared, the default backend will be used. If the default backend is
// empty, a default 404 page generated by HAProxy will be used.
type HostPath struct {
	Path      string
	Backend   *Backend
	BackendID string
}

// HostAliasConfig ...
type HostAliasConfig struct {
	AliasName  string
	AliasRegex string
}

// HostTimeoutConfig ...
type HostTimeoutConfig struct {
	Client    string
	ClientFin string
}

// HostTLSConfig ...
type HostTLSConfig struct {
	CAErrorPage      string
	CAFilename       string
	CAHash           string
	CAVerifyOptional bool
	TLSFilename      string
	TLSHash          string
}

// Backend ...
type Backend struct {
	ID        string
	Namespace string
	Name      string
	Port      int
	Endpoints []*Endpoint
	//
	AgentCheck        AgentCheck
	BalanceAlgorithm  string
	Cookie            Cookie
	CustomConfig      []string
	HealthCheck       HealthCheck
	HTTPRequests      []*HTTPRequest
	MaxConnServer     int
	MaxQueueServer    int
	ModeTCP           bool
	ProxyBodySize     string
	SendProxyProtocol string
	SSL               SSLBackendConfig
	SSLRedirect       bool
	Timeout           BackendTimeoutConfig
}

// Endpoint ...
type Endpoint struct {
	Disabled  bool
	IP        string
	Name      string
	Port      int
	TargetRef string
	Weight    int
}

// AgentCheck ...
type AgentCheck struct {
	Addr     string
	Interval string
	Port     string
	Send     string
}

// HealthCheck ...
type HealthCheck struct {
	Addr      string
	FallCount string
	Interval  string
	Port      string
	RiseCount string
}

// SSLBackendConfig ...
type SSLBackendConfig struct {
	HasTLSAuth    bool
	AddCertHeader bool
	IsSecure      bool
	CertFilename  string
	CertHash      string
	CAFilename    string
	CAHash        string
}

// BackendTimeoutConfig ...
type BackendTimeoutConfig struct {
	Connect     string
	HTTPRequest string
	KeepAlive   string
	Queue       string
	Server      string
	ServerFin   string
	Tunnel      string
}

// Cookie ...
type Cookie struct {
	Name     string
	Strategy string
	Key      string
}

// HTTPRequest ...
type HTTPRequest struct {
}

// Userlist ...
type Userlist struct {
	Name  string
	Users []User
}

// User ...
type User struct {
	Name      string
	Passwd    string
	Encrypted bool
}
