package gateway

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fact is one condition's outcome.
type fact struct {
	OK      bool
	Reason  string
	Message string
}

// Table is an immutable, fully resolved routing table. The data plane swaps
// whole tables atomically; a Table is never modified after BuildTable.
type Table struct {
	Cfg       *Config
	Ports     map[int]*PortGroup
	Listeners []*RTListener
	Backends  map[string]*Backend
	routes    []*routeResult
}

// PortGroup holds the listeners sharing one port.
type PortGroup struct {
	Port        int
	TLS         bool
	Passthrough bool // raw TCP listener for TLS passthrough (TLSRoute)
	Listeners   []*RTListener
}

// RTListener is a resolved listener.
type RTListener struct {
	GW         *Gateway
	L          Listener
	Key        string
	Host       string
	Certs      []tls.Certificate
	Entries    []*Entry
	TLSEntries []*TLSEntry // TLSRoute entries (passthrough listeners)
	Attached   int
	Serving    bool
	Accepted   fact
	Resolved   fact
	Conflicted fact
}

// Entry is one (route, rule, match) on one listener.
type Entry struct {
	Route *Route
	Rule  *CRule
	Match *CMatch
	Hosts []string
	GRPC  bool // entry comes from a GRPCRoute
}

// CRule is a compiled rule.
type CRule struct {
	RouteKey string
	Index    int
	Rule     *Rule
	Refs     []*CRef
	Total    int
	Timeout  time.Duration
	Redirect *Redirect
	Mirrors  []*CMirror
	Retry    *CRetry
}

// CRef is a backendRef with its resolved backend (nil when unresolved).
type CRef struct {
	Name    string
	B       *Backend
	Weight  int
	Filters []Filter
}

// CMirror is a resolved RequestMirror target.
type CMirror struct {
	B       *Backend
	Percent int
	Shadow  *CShadow // never nil
}

// CMatch is a compiled HTTPRouteMatch.
type CMatch struct {
	PathType  string
	PathValue string
	PathRe    *regexp.Regexp
	Method    string
	Headers   []cvm
	Query     []cvm
}

type cvm struct {
	Name, Value string
	Re          *regexp.Regexp
}

type parentResult struct {
	Ref      ParentRef
	Accepted fact
}

type routeResult struct {
	Route   *Route
	Parents []*parentResult
	Refs    fact
}

// Endpoint is one upstream address.
type Endpoint struct {
	URL     *url.URL
	healthy atomic.Bool
	st      epState // guarded by Backend.hmu
}

// Backend is a Service port's upstream pool.
type Backend struct {
	Key, Name string
	Eps       []*Endpoint
	Timeout   time.Duration
	Health    *HealthCheck
	Insecure  bool
	rr        atomic.Uint64
	hmu       sync.Mutex // guards Endpoint.st and ejection decisions
}

// pick returns the next healthy endpoint, or any endpoint when none is.
func (b *Backend) pick() *Endpoint {
	n := uint64(len(b.Eps))
	if n == 0 {
		return nil
	}
	start := b.rr.Add(1) - 1
	for i := uint64(0); i < n; i++ {
		if e := b.Eps[(start+i)%n]; e.healthy.Load() {
			return e
		}
	}
	return b.Eps[start%n]
}

func newBackend(key, name string, def *BackendDef) (*Backend, error) {
	b := &Backend{Key: key, Name: name, Health: def.HealthCheck, Insecure: def.InsecureSkipVerify}
	var err error
	if b.Timeout, err = parseDur(def.Timeout); err != nil {
		return nil, fmt.Errorf("backend %s: timeout: %w", key, err)
	}
	for _, e := range def.Endpoints {
		u, err := parseEndpoint(e)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", key, err)
		}
		ep := &Endpoint{URL: u}
		ep.healthy.Store(true)
		b.Eps = append(b.Eps, ep)
	}
	if len(b.Eps) == 0 {
		return nil, fmt.Errorf("backend %s: no endpoints", key)
	}
	return b, nil
}

// hostRank orders hostname specificity: exact beats wildcard (longer first)
// beats no hostname.
func hostRank(pattern string) int {
	switch {
	case pattern == "":
		return 0
	case strings.HasPrefix(pattern, "*."):
		return len(pattern)
	}
	return 1 << 20
}

// hostMatches reports whether a Gateway API hostname pattern matches host.
// "*.example.com" matches any name with at least one extra label.
func hostMatches(pattern, host string) bool {
	switch {
	case pattern == "":
		return true
	case strings.HasPrefix(pattern, "*."):
		suffix := pattern[1:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return pattern == host
}

// intersect returns the hostname both a route and a listener accept.
func intersect(routeHost, listenerHost string) (string, bool) {
	routeHost, listenerHost = strings.ToLower(routeHost), strings.ToLower(listenerHost)
	switch {
	case listenerHost == "":
		return routeHost, true
	case routeHost == "" || routeHost == listenerHost:
		return listenerHost, true
	case strings.HasPrefix(listenerHost, "*.") && strings.HasPrefix(routeHost, "*."):
		if strings.HasSuffix(routeHost, listenerHost[1:]) {
			return routeHost, true // route is the narrower wildcard
		}
		if strings.HasSuffix(listenerHost, routeHost[1:]) {
			return listenerHost, true
		}
	case strings.HasPrefix(listenerHost, "*."):
		if hostMatches(listenerHost, routeHost) {
			return routeHost, true
		}
	case strings.HasPrefix(routeHost, "*."):
		if hostMatches(routeHost, listenerHost) {
			return listenerHost, true
		}
	}
	return "", false
}

func (c *Config) allowedNamespace(kind string, l *RTListener, routeNS string) bool {
	return c.allowedWhy(kind, l, routeNS) == ""
}

func (c *Config) granted(fromKind, fromNS, toGroup, toKind, toNS, name string) bool {
	if fromNS == toNS {
		return true
	}
	for _, g := range c.Grants {
		if g.permits(fromKind, fromNS, toGroup, toKind, toNS, name) {
			return true
		}
	}
	return false
}

// BuildTable resolves a Config into a routing table. Problems with single
// resources become condition facts rather than errors, so one bad route never
// stops the rest from serving.
func BuildTable(cfg *Config) *Table {
	t := &Table{Cfg: cfg, Ports: map[int]*PortGroup{}, Backends: map[string]*Backend{}}
	gws := append([]*Gateway(nil), cfg.Gateways...)
	sort.Slice(gws, func(i, j int) bool { return gws[i].Key() < gws[j].Key() })

	portProto := map[int]string{}
	hostSeen := map[string]string{}
	for _, gw := range gws {
		names := map[string]bool{}
		for _, spec := range gw.Listeners {
			l := &RTListener{GW: gw, L: spec, Key: gw.Key() + "/" + spec.Name, Host: strings.ToLower(spec.Hostname),
				Accepted: fact{true, "Accepted", ""}, Resolved: fact{true, "ResolvedRefs", ""}, Conflicted: fact{false, "NoConflicts", ""}}
			l.L.Protocol = strings.ToUpper(spec.Protocol)
			t.Listeners = append(t.Listeners, l)
			proto := l.L.Protocol
			switch {
			case names[spec.Name]:
				l.Accepted = fact{false, "Invalid", "listener name is declared more than once"}
				continue
			case proto != "HTTP" && proto != "HTTPS" && proto != "TLS":
				l.Accepted = fact{false, "UnsupportedProtocol", "built-in gateway serves HTTP, HTTPS and TLS (passthrough) listeners only"}
				continue
			case proto == "TLS" && (spec.TLS == nil || spec.TLS.Mode != "Passthrough"):
				l.Accepted = fact{false, "UnsupportedProtocol", "TLS listeners need tls.mode Passthrough; Terminate is not supported for TLS listeners"}
				continue
			case spec.Port < 1 || spec.Port > 65535:
				l.Accepted = fact{false, "Invalid", "port out of range"}
				continue
			}
			names[spec.Name] = true
			if bad := l.invalidKinds(); len(bad) > 0 {
				l.Resolved = fact{false, "InvalidRouteKinds", "allowedRoutes.kinds names kinds this listener cannot carry: " + strings.Join(bad, ", ")}
			}
			if prev, ok := portProto[spec.Port]; ok && prev != proto {
				l.Conflicted = fact{true, "ProtocolConflict", fmt.Sprintf("port %d already serves %s", spec.Port, prev)}
				continue
			}
			shape := fmt.Sprintf("%d/%s/%s", spec.Port, proto, l.Host)
			if prev, ok := hostSeen[shape]; ok && prev != l.Key {
				l.Conflicted = fact{true, "HostnameConflict", "listener " + prev + " already serves this port, protocol and hostname"}
				continue
			}
			hostSeen[shape] = l.Key
			portProto[spec.Port] = proto
			if proto == "HTTPS" {
				cfg.resolveCerts(l)
				if l.L.TLS != nil && l.L.TLS.Mode == "Passthrough" {
					l.Accepted = fact{false, "UnsupportedProtocol", "HTTPS listeners cannot use TLS mode Passthrough; use protocol TLS with a TLSRoute"}
					continue
				}
			}
			l.Serving = l.Accepted.OK && l.Resolved.OK
			if !l.Serving {
				continue
			}
			pg := t.Ports[spec.Port]
			if pg == nil {
				pg = &PortGroup{Port: spec.Port, TLS: proto == "HTTPS", Passthrough: proto == "TLS"}
				t.Ports[spec.Port] = pg
			}
			pg.Listeners = append(pg.Listeners, l)
		}
	}

	rs := append([]*Route(nil), cfg.Routes...)
	sort.SliceStable(rs, func(i, j int) bool {
		if !rs[i].Created.Equal(rs[j].Created) {
			return rs[i].Created.Before(rs[j].Created)
		}
		return rs[i].Key() < rs[j].Key()
	})
	for _, r := range rs {
		t.attach(r)
	}
	t.attachExtra()
	return t
}

func (c *Config) resolveCerts(l *RTListener) {
	if c.skipCerts {
		return
	}
	if l.L.TLS == nil || len(l.L.TLS.CertificateRefs) == 0 {
		l.Resolved = fact{false, "InvalidCertificateRef", "HTTPS listener has no certificateRefs"}
		return
	}
	for _, ref := range l.L.TLS.CertificateRefs {
		if (ref.Kind != "" && ref.Kind != "Secret") || (ref.Group != "" && ref.Group != "core") {
			l.Resolved = fact{false, "InvalidCertificateRef", "certificateRef kind must be a core Secret"}
			return
		}
		ns := ref.Namespace
		if ns == "" {
			ns = l.GW.NS
		}
		if !c.granted("Gateway", l.GW.NS, "", "Secret", ns, ref.Name) {
			l.Resolved = fact{false, "RefNotPermitted", fmt.Sprintf("Secret %s/%s needs a ReferenceGrant", ns, ref.Name)}
			return
		}
		def, ok := c.Secrets[ns+"/"+ref.Name]
		if !ok {
			l.Resolved = fact{false, "InvalidCertificateRef", fmt.Sprintf("Secret %s/%s is not available", ns, ref.Name)}
			return
		}
		pair, err := def.load()
		if err != nil {
			l.Resolved = fact{false, "InvalidCertificateRef", fmt.Sprintf("Secret %s/%s: %v", ns, ref.Name, err)}
			return
		}
		l.Certs = append(l.Certs, pair)
	}
	if l.Resolved.OK {
		l.Resolved.Reason = "ResolvedRefs"
	}
}

func (t *Table) backend(r *Route, ref BackendRef) (*Backend, fact) {
	return t.backendFor("HTTPRoute", r.NS, ref)
}

// backendFor resolves a backendRef for a route of the given kind and namespace.
func (t *Table) backendFor(kind, routeNS string, ref BackendRef) (*Backend, fact) {
	if (ref.Kind != "" && ref.Kind != "Service") || (ref.Group != "" && ref.Group != "core") {
		return nil, fact{false, "InvalidKind", fmt.Sprintf("backendRef %q must be a Service", ref.Name)}
	}
	ns := ref.Namespace
	if ns == "" {
		ns = routeNS
	}
	if !t.Cfg.granted(kind, routeNS, "", "Service", ns, ref.Name) {
		return nil, fact{false, "RefNotPermitted", fmt.Sprintf("Service %s/%s needs a ReferenceGrant", ns, ref.Name)}
	}
	key := backendKey(ns, ref.Name, ref.Port)
	if b, ok := t.Backends[key]; ok {
		return b, fact{true, "ResolvedRefs", ""}
	}
	def := t.Cfg.Backends[key]
	if def == nil {
		def = t.Cfg.Backends[ns+"/"+ref.Name]
	}
	if def == nil {
		return nil, fact{false, "BackendNotFound", fmt.Sprintf("no upstream configured for %s", key)}
	}
	b, err := newBackend(key, ref.Name, def)
	if err != nil {
		return nil, fact{false, "BackendNotFound", err.Error()}
	}
	t.Backends[key] = b
	return b, fact{true, "ResolvedRefs", ""}
}

func compileMatch(m Match) (*CMatch, error) {
	c := &CMatch{Method: strings.ToUpper(m.Method), PathType: "PathPrefix", PathValue: "/"}
	if m.Path != nil {
		if m.Path.Type != "" {
			c.PathType = m.Path.Type
		}
		if m.Path.Value != "" {
			c.PathValue = m.Path.Value
		}
		if !strings.HasPrefix(c.PathValue, "/") {
			return nil, fmt.Errorf("path value %q must start with /", c.PathValue)
		}
	}
	switch c.PathType {
	case "Exact":
	case "PathPrefix":
		if c.PathValue != "/" {
			c.PathValue = strings.TrimRight(c.PathValue, "/")
		}
	case "RegularExpression":
		re, err := regexp.Compile(`^(?:` + c.PathValue + `)$`)
		if err != nil {
			return nil, fmt.Errorf("path regex: %w", err)
		}
		c.PathRe = re
	default:
		return nil, fmt.Errorf("unsupported path match type %q", c.PathType)
	}
	conv := func(in []ValueMatch, header bool) ([]cvm, error) {
		var out []cvm
		for _, v := range in {
			cv := cvm{Name: v.Name, Value: v.Value}
			if header {
				cv.Name = strings.ToLower(v.Name)
			}
			switch v.Type {
			case "", "Exact":
			case "RegularExpression":
				re, err := regexp.Compile(`^(?:` + v.Value + `)$`)
				if err != nil {
					return nil, fmt.Errorf("regex for %q: %w", v.Name, err)
				}
				cv.Re = re
			default:
				return nil, fmt.Errorf("unsupported match type %q", v.Type)
			}
			out = append(out, cv)
		}
		return out, nil
	}
	var err error
	if c.Headers, err = conv(m.Headers, true); err != nil {
		return nil, err
	}
	if c.Query, err = conv(m.QueryParams, false); err != nil {
		return nil, err
	}
	return c, nil
}

func validFilters(fs []Filter) error {
	for _, f := range fs {
		switch f.Type {
		case "RequestHeaderModifier", "ResponseHeaderModifier", "RequestRedirect", "URLRewrite", "RequestMirror":
		default:
			return fmt.Errorf("unsupported filter type %q", f.Type)
		}
		if f.Type == "RequestRedirect" && f.RequestRedirect != nil {
			if sc := f.RequestRedirect.StatusCode; sc != 0 && sc != 301 && sc != 302 && sc != 303 && sc != 307 && sc != 308 {
				return fmt.Errorf("redirect statusCode %d is not allowed", sc)
			}
		}
	}
	return nil
}

// compileRule validates one rule. refs is the aggregate ResolvedRefs fact.
func (t *Table) compileRule(r *Route, idx int, rule *Rule, refs *fact) (*CRule, []*CMatch, error) {
	cr := &CRule{RouteKey: r.Key(), Index: idx, Rule: rule}
	if err := validFilters(rule.Filters); err != nil {
		return nil, nil, err
	}
	if rule.Timeouts != nil {
		var err error
		if cr.Timeout, err = parseDur(rule.Timeouts.Request); err != nil {
			return nil, nil, fmt.Errorf("timeouts.request: %w", err)
		}
	}
	if rule.Retry != nil {
		var err error
		if cr.Retry, err = compileRetry(rule.Retry); err != nil {
			return nil, nil, err
		}
	}
	note := func(f fact) {
		if !f.OK && refs.OK {
			*refs = f
		}
	}
	for _, f := range rule.Filters {
		switch f.Type {
		case "RequestRedirect":
			if cr.Redirect == nil && f.RequestRedirect != nil {
				cr.Redirect = f.RequestRedirect
			}
		case "RequestMirror":
			if f.RequestMirror != nil {
				b, fc := t.backend(r, f.RequestMirror.BackendRef)
				note(fc)
				pct := 100
				if f.RequestMirror.Percent != nil {
					pct = *f.RequestMirror.Percent
				}
				if b != nil {
					cs, err := compileShadow(f.RequestMirror.ShadowDiff)
					if err != nil {
						return nil, nil, err
					}
					cr.Mirrors = append(cr.Mirrors, &CMirror{B: b, Percent: pct, Shadow: cs})
				}
			}
		}
	}
	for _, ref := range rule.BackendRefs {
		if err := validFilters(ref.Filters); err != nil {
			return nil, nil, err
		}
		w := 1
		if ref.Weight != nil {
			w = *ref.Weight
		}
		if w < 0 {
			w = 0
		}
		b, fc := t.backend(r, ref)
		note(fc)
		cr.Refs = append(cr.Refs, &CRef{Name: ref.Name, B: b, Weight: w, Filters: ref.Filters})
		cr.Total += w
	}
	matches := rule.Matches
	if len(matches) == 0 {
		matches = []Match{{}}
	}
	var cms []*CMatch
	for _, m := range matches {
		cm, err := compileMatch(m)
		if err != nil {
			return nil, nil, err
		}
		cms = append(cms, cm)
	}
	return cr, cms, nil
}

func (t *Table) attach(r *Route) {
	res := &routeResult{Route: r, Refs: fact{true, "ResolvedRefs", "all references resolved"}}
	t.routes = append(t.routes, res)
	crs := make([]*CRule, len(r.Rules))
	cms := make([][]*CMatch, len(r.Rules))
	var invalid error
	for i := range r.Rules {
		var err error
		if crs[i], cms[i], err = t.compileRule(r, i, &r.Rules[i], &res.Refs); err != nil {
			invalid = fmt.Errorf("rule %d: %w", i+1, err)
			break
		}
	}
	res.Parents = t.attachParents("HTTPRoute", r.NS, r.Parents, r.Hostnames, invalid, func(l *RTListener, hosts []string) {
		for i := range r.Rules {
			for _, cm := range cms[i] {
				l.Entries = append(l.Entries, &Entry{Route: r, Rule: crs[i], Match: cm, Hosts: hosts})
			}
		}
	})
}

// attachParents resolves parentRefs for a route of any kind. add is called for
// every listener the route attaches to, with the effective hostnames.
func (t *Table) attachParents(kind, routeNS string, parents []ParentRef, hostnames []string, invalid error, add func(l *RTListener, hosts []string)) []*parentResult {
	var out []*parentResult
	gateways := map[string]*Gateway{}
	for _, g := range t.Cfg.Gateways {
		gateways[g.Key()] = g
	}
	for _, p := range parents {
		pr := &parentResult{Ref: p}
		out = append(out, pr)
		if invalid != nil {
			pr.Accepted = fact{false, "UnsupportedValue", invalid.Error()}
			continue
		}
		if (p.Group != "" && p.Group != APIGroup) || (p.Kind != "" && p.Kind != "Gateway") {
			pr.Accepted = fact{false, "NoMatchingParent", "parentRef is not a Gateway"}
			continue
		}
		ns := p.Namespace
		if ns == "" {
			ns = routeNS
		}
		gw := gateways[ns+"/"+p.Name]
		if gw == nil {
			pr.Accepted = fact{false, "NoMatchingParent", fmt.Sprintf("Gateway %s/%s not found", ns, p.Name)}
			continue
		}
		candidates, notAllowed, noHost := 0, 0, 0
		attached := false
		for _, l := range t.Listeners {
			hosts, fit, _ := t.parentFit(kind, routeNS, p, gw, hostnames, l)
			if fit == fitSkip {
				continue
			}
			candidates++
			switch fit {
			case fitNotAllowed:
				notAllowed++
			case fitNoHost:
				noHost++
			default:
				attached = true
				l.Attached++
				add(l, hosts)
			}
		}
		switch {
		case attached:
			pr.Accepted = fact{true, "Accepted", "route attached"}
		case candidates == 0:
			pr.Accepted = fact{false, "NoMatchingParent", "no listener matches sectionName/port"}
		case noHost > 0 && notAllowed == 0:
			pr.Accepted = fact{false, "NoMatchingListenerHostname", "route hostnames do not intersect the listener hostname"}
		default:
			pr.Accepted = fact{false, "NotAllowedByListeners", "listener does not allow this route"}
		}
	}
	return out
}

func effectiveHosts(routeHosts []string, listenerHost string) []string {
	if len(routeHosts) == 0 {
		return []string{listenerHost}
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range routeHosts {
		if v, ok := intersect(h, listenerHost); ok && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
