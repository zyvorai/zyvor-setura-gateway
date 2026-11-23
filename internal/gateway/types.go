// Package gateway is Setura's built-in Gateway API data plane: an HTTP/HTTPS
// reverse proxy that serves Gateway and HTTPRoute specs using only the Go
// standard library. It never imports the rest of Setura; the CLI injects the
// linter and passes in the pieces it needs.
package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Identifiers shared with the Setura snapshot format.
const (
	SnapshotSchema = "setura.route-specs/v1"
	ControllerName = "zyvor.dev/setura-gateway"
	APIGroup       = "gateway.networking.k8s.io"
	gatewayKey     = "gateways." + APIGroup
	routeKey       = "httproutes." + APIGroup
	// BackendHeader carries the backend identity (Service name) on responses.
	BackendHeader = "X-Setura-Backend"
)

// Gateway is the subset of a Gateway the data plane honours.
type Gateway struct {
	NS, Name   string
	Generation int64
	ClassName  string
	Listeners  []Listener
	// Addresses is spec.addresses; AllowedListeners is spec.allowedListeners.namespaces;
	// BackendClientCert is spec.tls.backend.clientCertificateRef.
	Addresses         []GatewayAddress
	AllowedListeners  *RouteNamespaces
	BackendClientCert *ObjRef
	// TLS is spec.tls (Gateway API 1.5 frontend TLS validation).
	TLS *GatewayTLS
	// Annotations are the Gateway's setura.zyvor.dev/* annotations (a snapshot
	// carries them under setura.zyvor.dev/annotations).
	Annotations map[string]string
}

// Key is namespace/name.
func (g *Gateway) Key() string { return g.NS + "/" + g.Name }

// Listener mirrors a Gateway listener.
type Listener struct {
	Name          string         `json:"name"`
	Hostname      string         `json:"hostname,omitempty"`
	Port          int            `json:"port"`
	Protocol      string         `json:"protocol"`
	TLS           *ListenerTLS   `json:"tls,omitempty"`
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty"`
	// Limits is a Setura extension of the listener (snapshot files).
	Limits *ListenerLimits `json:"setura.zyvor.dev/limits,omitempty"`
}

// ListenerTLS is a listener's TLS block.
type ListenerTLS struct {
	Mode            string   `json:"mode,omitempty"`
	CertificateRefs []ObjRef `json:"certificateRefs,omitempty"`
	// Options are implementation specific; Setura reads TLSMinVersionOption and TLSMaxVersionOption.
	Options map[string]string `json:"options,omitempty"`
}

// ObjRef references another object.
type ObjRef struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// AllowedRoutes limits which routes may attach to a listener.
type AllowedRoutes struct {
	Namespaces *RouteNamespaces `json:"namespaces,omitempty"`
	Kinds      []struct {
		Group string `json:"group,omitempty"`
		Kind  string `json:"kind"`
	} `json:"kinds,omitempty"`
}

// RouteNamespaces is allowedRoutes.namespaces.
type RouteNamespaces struct {
	From     string `json:"from,omitempty"`
	Selector *struct {
		MatchLabels      map[string]string     `json:"matchLabels,omitempty"`
		MatchExpressions []SelectorRequirement `json:"matchExpressions,omitempty"`
	} `json:"selector,omitempty"`
}

// ParentRef attaches a route to a Gateway (and optionally one listener).
type ParentRef struct {
	Group       string `json:"group,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace,omitempty"`
	SectionName string `json:"sectionName,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// Route is an HTTPRoute.
type Route struct {
	Kind       string // "" for HTTPRoute; "GRPCRoute" or "TLSRoute" for stand-ins of those kinds
	NS, Name   string
	Generation int64
	Created    time.Time
	Parents    []ParentRef
	Hostnames  []string
	Rules      []Rule
}

// Key is namespace/name.
func (r *Route) Key() string { return r.NS + "/" + r.Name }

// StatusKey is the key in the status document: namespace/name for HTTPRoute,
// Kind/namespace/name for the other kinds (names may repeat across kinds).
func (r *Route) StatusKey() string {
	if r.Kind == "" {
		return r.Key()
	}
	return r.Kind + "/" + r.Key()
}

// Rule is one HTTPRoute rule.
type Rule struct {
	Name string `json:"name,omitempty"`
	// SessionPersistence pins a client to one backend endpoint (affinity.go).
	SessionPersistence *SessionPersistence `json:"sessionPersistence,omitempty"`
	Matches            []Match             `json:"matches,omitempty"`
	Filters            []Filter            `json:"filters,omitempty"`
	BackendRefs        []BackendRef        `json:"backendRefs,omitempty"`
	Retry              *RetryRule          `json:"retry,omitempty"`
	Timeouts           *struct {
		Request        string `json:"request,omitempty"`
		BackendRequest string `json:"backendRequest,omitempty"`
	} `json:"timeouts,omitempty"`
	// Auth is the traffic-security policy of the rule (setura.zyvor.dev/auth).
	Auth *AuthPolicy `json:"setura.zyvor.dev/auth,omitempty"`
	// DirectResponse answers without a backend, RateLimit adds a per-rule token
	// bucket and Limits overrides the gateway-wide body and idle limits (ruleext.go).
	DirectResponse *DirectResponse `json:"setura.zyvor.dev/direct-response,omitempty"`
	RateLimit      *RouteRateLimit `json:"setura.zyvor.dev/rate-limit,omitempty"`
	Limits         *RuleLimits     `json:"setura.zyvor.dev/limits,omitempty"`
	extErr         error           // an annotation of the rule could not be decoded
	// Fault injects latency, errors and other failures for game days. It must
	// carry a ttl or an expiry (setura.zyvor.dev/fault, chaos.go).
	Fault *Fault `json:"setura.zyvor.dev/fault,omitempty"`
}

// Match is one HTTPRouteMatch.
type Match struct {
	Path        *PathMatch   `json:"path,omitempty"`
	Headers     []ValueMatch `json:"headers,omitempty"`
	QueryParams []ValueMatch `json:"queryParams,omitempty"`
	Method      string       `json:"method,omitempty"`
}

// PathMatch is a path matcher.
type PathMatch struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// ValueMatch matches a header or query parameter.
type ValueMatch struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Filter is an HTTPRoute filter.
type Filter struct {
	Type                   string        `json:"type"`
	RequestHeaderModifier  *HeaderMod    `json:"requestHeaderModifier,omitempty"`
	ResponseHeaderModifier *HeaderMod    `json:"responseHeaderModifier,omitempty"`
	RequestRedirect        *Redirect     `json:"requestRedirect,omitempty"`
	URLRewrite             *Rewrite      `json:"urlRewrite,omitempty"`
	RequestMirror          *Mirror       `json:"requestMirror,omitempty"`
	CORS                   *CORS         `json:"cors,omitempty"`
	ExternalAuth           *ExternalAuth `json:"externalAuth,omitempty"`
}

// NameValue is a header name and value.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HeaderMod edits headers.
type HeaderMod struct {
	Set    []NameValue `json:"set,omitempty"`
	Add    []NameValue `json:"add,omitempty"`
	Remove []string    `json:"remove,omitempty"`
}

// PathMod rewrites or redirects a path.
type PathMod struct {
	Type               string `json:"type"`
	ReplaceFullPath    string `json:"replaceFullPath,omitempty"`
	ReplacePrefixMatch string `json:"replacePrefixMatch,omitempty"`
}

// Redirect is the RequestRedirect filter.
type Redirect struct {
	Scheme     string   `json:"scheme,omitempty"`
	Hostname   string   `json:"hostname,omitempty"`
	Path       *PathMod `json:"path,omitempty"`
	Port       int      `json:"port,omitempty"`
	StatusCode int      `json:"statusCode,omitempty"`
}

// Rewrite is the URLRewrite filter.
type Rewrite struct {
	Hostname string   `json:"hostname,omitempty"`
	Path     *PathMod `json:"path,omitempty"`
}

// Mirror is the RequestMirror filter.
type Mirror struct {
	BackendRef BackendRef `json:"backendRef"`
	Percent    *int       `json:"percent,omitempty"`
	// ShadowDiff turns the mirror into a comparison (setura.zyvor.dev/shadow-diff).
	ShadowDiff *ShadowDiff `json:"setura.zyvor.dev/shadow-diff,omitempty"`
}

// BackendRef references a Service.
type BackendRef struct {
	Group     string   `json:"group,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Port      int      `json:"port,omitempty"`
	Weight    *int     `json:"weight,omitempty"`
	Filters   []Filter `json:"filters,omitempty"`
	// SessionPersistence is a Setura extension: persistence scoped to this backendRef.
	SessionPersistence *SessionPersistence `json:"setura.zyvor.dev/sessionPersistence,omitempty"`
}

// BackendDef maps a Service port to upstream endpoints.
type BackendDef struct {
	Endpoints          []string     `json:"endpoints"`
	Timeout            string       `json:"timeout,omitempty"`
	HealthCheck        *HealthCheck `json:"healthCheck,omitempty"`
	InsecureSkipVerify bool         `json:"insecureSkipVerify,omitempty"`
	// PortName is the Service port name (BackendTLSPolicy targetRefs may name a section).
	PortName string `json:"portName,omitempty"`
	// CircuitBreaker overrides the gateway-wide circuit breaking defaults for
	// this backend (negative numbers lift a default limit).
	CircuitBreaker *CircuitConfig `json:"circuitBreaker,omitempty"`
	// Protocol "h2c" speaks HTTP/2 with prior knowledge to plain http:// endpoints.
	Protocol string `json:"protocol,omitempty"`
	// ProxyProtocol "v1" or "v2" sends a PROXY protocol header on every upstream connection.
	ProxyProtocol string `json:"proxyProtocol,omitempty"`
}

// HealthCheck is an active HTTP health check.
type HealthCheck struct {
	Path     string `json:"path"`
	Interval string `json:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	// UnhealthyThreshold consecutive failed probes mark an endpoint down and
	// HealthyThreshold consecutive passes bring it back (both default 1).
	UnhealthyThreshold int `json:"unhealthyThreshold,omitempty"`
	HealthyThreshold   int `json:"healthyThreshold,omitempty"`
	// Protocol is "http" (default) or "grpc": a grpc check calls
	// grpc.health.v1.Health/Check (Path is ignored) and Service names the
	// service to ask about ("" asks about the whole server).
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
}

// UnmarshalJSON accepts "host:port", ["host:port", ...] or an object.
func (b *BackendDef) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		b.Endpoints = []string{one}
		return nil
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		b.Endpoints = many
		return nil
	}
	type alias BackendDef
	var a struct {
		alias
		URL  string   `json:"url"`
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	*b = BackendDef(a.alias)
	if a.URL != "" {
		b.Endpoints = append(b.Endpoints, a.URL)
	}
	b.Endpoints = append(b.Endpoints, a.URLs...)
	return nil
}

// SecretDef supplies a TLS key pair, as files or inline PEM. File paths in a
// config file are resolved relative to that file.
type SecretDef struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	Cert     string `json:"cert,omitempty"`
	Key      string `json:"key,omitempty"`
}

func (s SecretDef) load() (tls.Certificate, error) {
	cert, key := []byte(s.Cert), []byte(s.Key)
	var err error
	if s.CertFile != "" {
		if cert, err = os.ReadFile(s.CertFile); err != nil {
			return tls.Certificate{}, err
		}
	}
	if s.KeyFile != "" {
		if key, err = os.ReadFile(s.KeyFile); err != nil {
			return tls.Certificate{}, err
		}
	}
	if len(cert) == 0 || len(key) == 0 {
		return tls.Certificate{}, fmt.Errorf("secret has no certificate or key")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return pair, err
	}
	if len(pair.Certificate) > 0 {
		pair.Leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	}
	return pair, nil
}

// Grant is a ReferenceGrant.
type Grant struct {
	Namespace string
	From      []struct{ Group, Kind, Namespace string }
	To        []struct{ Group, Kind, Name string }
}

// permits reports whether fromKind in fromNS may reference toKind/name in the
// grant's namespace.
func (g Grant) permits(fromKind, fromNS, toGroup, toKind, toNS, name string) bool {
	if g.Namespace != toNS {
		return false
	}
	okFrom := false
	for _, f := range g.From {
		okFrom = okFrom || (f.Kind == fromKind && f.Namespace == fromNS && f.Group == APIGroup)
	}
	for _, t := range g.To {
		if okFrom && t.Kind == toKind && t.Group == toGroup && (t.Name == "" || t.Name == name) {
			return true
		}
	}
	return false
}

// Config is everything the data plane needs, whatever its source.
type Config struct {
	// ACME and ACMEDNS are set by the server: listeners without certificateRefs
	// get ACME certificates, wildcards only when a DNS-01 hook exists.
	ACME, ACMEDNS bool
	Namespace     string
	Gateways      []*Gateway
	Routes        []*Route
	Backends      map[string]*BackendDef // namespace/name:port
	Secrets       map[string]SecretDef   // namespace/name
	Grants        []Grant
	Namespaces    map[string]map[string]string // namespace -> labels
	// Resilience is the optional "resilience" block of a config file.
	Resilience *ResilienceConfig
	// GrantsCaptured records that ReferenceGrants were read from the source
	// (even if there are none), so lint can treat a missing grant as an error.
	GrantsCaptured bool
	// ClassStatus lets a source learn about GatewayClass handling.
	Classes []string
	// GRPCRoutes and TLSRoutes are the additional route kinds.
	GRPCRoutes []*GRPCRoute
	TLSRoutes  []*TLSRoute
	// BackendTLS are the BackendTLSPolicies, CACerts the CA bundles (ConfigMaps
	// and Secrets, "ns/name") their caCertificateRefs name.
	BackendTLS []*BackendTLSPolicy
	CACerts    map[string]CADef
	// ListenerSets, TCPRoutes and UDPRoutes are further resource kinds
	// (listenerset.go, l4route.go).
	ListenerSets []*ListenerSet
	TCPRoutes    []*L4Route
	UDPRoutes    []*L4Route

	skipCerts bool // offline replay: do not load listener certificates
}

type fileConfig struct {
	Schema          string                     `json:"schema"`
	Namespace       string                     `json:"namespace"`
	Resources       map[string]json.RawMessage `json:"resources"`
	Backends        map[string]BackendDef      `json:"backends"`
	Secrets         map[string]SecretDef       `json:"secrets"`
	CACertificates  map[string]CADef           `json:"caCertificates"`
	ReferenceGrants []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			From []struct{ Group, Kind, Namespace string } `json:"from"`
			To   []struct{ Group, Kind, Name string }      `json:"to"`
		} `json:"spec"`
	} `json:"referenceGrants"`
	Namespaces map[string]struct {
		Labels map[string]string `json:"labels"`
	} `json:"namespaces"`
	Resilience *ResilienceConfig `json:"resilience"`
}

type gatewaySpec struct {
	GatewayClassName string     `json:"gatewayClassName"`
	Listeners        []Listener `json:"listeners"`
	// TLS is spec.tls: frontend client certificate validation and the backend client certificate.
	TLS *GatewayTLS `json:"tls,omitempty"`
	// Annotations carries the Gateway annotations of the object this spec was taken from.
	Annotations map[string]string `json:"setura.zyvor.dev/annotations,omitempty"`
	// Addresses are the static addresses the Gateway asks for (reported in status).
	Addresses []GatewayAddress `json:"addresses,omitempty"`
	// AllowedListeners says which ListenerSets may attach (default: none).
	AllowedListeners *struct {
		Namespaces *RouteNamespaces `json:"namespaces,omitempty"`
	} `json:"allowedListeners,omitempty"`
}

// gateway builds the Gateway a gatewaySpec describes.
func (s gatewaySpec) gateway(ns, name string, generation int64) *Gateway {
	g := &Gateway{NS: ns, Name: name, Generation: generation, ClassName: s.GatewayClassName, Listeners: s.Listeners, TLS: s.TLS, Addresses: s.Addresses, Annotations: s.Annotations}
	if s.AllowedListeners != nil {
		g.AllowedListeners = s.AllowedListeners.Namespaces
	}
	if s.TLS != nil && s.TLS.Backend != nil {
		g.BackendClientCert = s.TLS.Backend.ClientCertificateRef
	}
	return g
}

type routeSpec struct {
	creationMeta
	ParentRefs []ParentRef `json:"parentRefs"`
	Hostnames  []string    `json:"hostnames"`
	Rules      []Rule      `json:"rules"`
	// Annotations carries the shadow-diff annotations of the object this spec
	// was taken from (see SeturaAnnotationsKey).
	Annotations map[string]string `json:"setura.zyvor.dev/annotations,omitempty"`
}

// ParseConfig reads a Setura snapshot (setura.route-specs/v1) extended with
// backends and secrets sections. Relative secret paths resolve against dir.
func ParseConfig(raw []byte, dir string) (*Config, error) {
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return nil, fmt.Errorf("config is not valid JSON: %w", err)
	}
	if fc.Schema != SnapshotSchema || fc.Resources == nil {
		return nil, fmt.Errorf("config must be a %s snapshot with a resources object", SnapshotSchema)
	}
	ns := fc.Namespace
	if ns == "" {
		ns = "default"
	}
	cfg := &Config{Namespace: ns, Backends: map[string]*BackendDef{}, Secrets: map[string]SecretDef{}, Namespaces: map[string]map[string]string{}}
	for _, key := range sortedKeys(fc.Resources) {
		kind, rest, _ := strings.Cut(key, "/")
		rns, name := ns, rest
		if a, b, ok := strings.Cut(rest, "/"); ok {
			rns, name = a, b
		}
		switch kind {
		case gatewayKey:
			var spec gatewaySpec
			if err := json.Unmarshal(fc.Resources[key], &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			cfg.Gateways = append(cfg.Gateways, spec.gateway(rns, name, 0))
		case routeKey:
			var spec routeSpec
			if err := json.Unmarshal(fc.Resources[key], &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			created, err := spec.created()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			annotateHTTP(spec.Rules, spec.Annotations)
			annotateAuth(spec.Rules, spec.Annotations)
			annotateExt(spec.Rules, spec.Annotations)
			annotateFault(spec.Rules, spec.Annotations)
			cfg.Routes = append(cfg.Routes, &Route{NS: rns, Name: name, Created: created, Parents: spec.ParentRefs, Hostnames: spec.Hostnames, Rules: spec.Rules})
		case grantKey:
			var spec struct {
				From []struct{ Group, Kind, Namespace string } `json:"from"`
				To   []struct{ Group, Kind, Name string }      `json:"to"`
			}
			if err := json.Unmarshal(fc.Resources[key], &spec); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			cfg.Grants = append(cfg.Grants, Grant{Namespace: rns, From: spec.From, To: spec.To})
			cfg.GrantsCaptured = true
		case grpcRouteKey, tlsRouteKey, tcpRouteKey, udpRouteKey, listenerSetKey, backendTLSPolicyKey:
			if err := cfg.parseExtraRoute(kind, rns, name, fc.Resources[key]); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	for k, v := range fc.Backends {
		v := v
		key := k
		if !strings.Contains(key, "/") {
			key = ns + "/" + key
		}
		cfg.Backends[key] = &v
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) || dir == "" {
			return p
		}
		return filepath.Join(dir, p)
	}
	for k, v := range fc.Secrets {
		key := k
		if !strings.Contains(key, "/") {
			key = ns + "/" + key
		}
		v.CertFile, v.KeyFile = abs(v.CertFile), abs(v.KeyFile)
		cfg.Secrets[key] = v
	}
	cfg.CACerts = map[string]CADef{}
	for k, v := range fc.CACertificates {
		if !strings.Contains(k, "/") {
			k = ns + "/" + k
		}
		cfg.CACerts[k] = v.abs(dir)
	}
	for _, g := range fc.ReferenceGrants {
		gr := Grant{Namespace: g.Metadata.Namespace}
		if gr.Namespace == "" {
			gr.Namespace = ns
		}
		gr.From, gr.To = g.Spec.From, g.Spec.To
		cfg.Grants = append(cfg.Grants, gr)
	}
	for k, v := range fc.Namespaces {
		cfg.Namespaces[k] = v.Labels
	}
	cfg.GrantsCaptured = cfg.GrantsCaptured || fc.ReferenceGrants != nil
	if fc.Resilience != nil {
		if err := fc.Resilience.validate(); err != nil {
			return nil, fmt.Errorf("resilience: %w", err)
		}
		cfg.Resilience = fc.Resilience
	}
	return cfg, nil
}

// backendKey is the lookup key for a Service port.
func backendKey(ns, name string, port int) string {
	return fmt.Sprintf("%s/%s:%d", ns, name, port)
}

// parseEndpoint accepts host:port or an http(s) URL.
func parseEndpoint(e string) (*url.URL, error) {
	if !strings.Contains(e, "://") {
		if _, _, err := net.SplitHostPort(e); err != nil {
			return nil, fmt.Errorf("endpoint %q: want host:port or http(s) URL", e)
		}
		e = "http://" + e
	}
	u, err := url.Parse(e)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("endpoint %q: want host:port or http(s) URL", e)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func parseDur(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
