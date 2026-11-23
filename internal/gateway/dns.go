package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// External backends: endpoints that are a name resolved by the gateway, a plain
// address, or a unix socket.
//
// A backend is declared in the snapshot "backends" section or, without a
// Service, in the setura.zyvor.dev/backends annotation of a route, and a
// backendRef names it with group setura.zyvor.dev and kind Backend:
//
//	backendRef: {group: setura.zyvor.dev, kind: Backend, name: payments}
//
// Names are re-resolved on a TTL; a failed lookup keeps serving the last answer.
const (
	BackendGroup = "setura.zyvor.dev"
	BackendKind  = "Backend"
	// BackendsKey is the route annotation holding Service-less backends as a
	// JSON object of name to backend.
	BackendsKey = "setura.zyvor.dev/backends"

	defaultDNSMin     = 5 * time.Second
	defaultDNSMax     = 5 * time.Minute
	unknownDNSTTL     = 30 * time.Second
	maxDNSAddresses   = 64
	dnsLookupTimeout  = 3 * time.Second
	unixEndpointHost  = "unix-"
	unixEndpointLocal = "localhost"
)

// DNSResolver resolves a host name. ttl is the record TTL, or a negative value
// when the resolver cannot tell (the system resolver cannot).
type DNSResolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, ttl time.Duration, err error)
}

// DNSOptions tunes name resolution of external backends.
type DNSOptions struct {
	Resolver DNSResolver // default: the system resolver
	// TTLMin and TTLMax clamp the time an answer is trusted (defaults 5s and 5m).
	TTLMin, TTLMax time.Duration
}

type systemResolver struct{}

func (systemResolver) LookupHost(ctx context.Context, host string) ([]string, time.Duration, error) {
	a, err := net.DefaultResolver.LookupHost(ctx, host)
	return a, -1, err
}

// DNSDef turns on resolution of the host names in a backend's endpoints.
// It is written true, false or an object.
type DNSDef struct {
	Enabled bool
	TTLMin  string `json:"ttlMin,omitempty"`
	TTLMax  string `json:"ttlMax,omitempty"`
	min     time.Duration
	max     time.Duration
}

func (d *DNSDef) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	var on bool
	if json.Unmarshal(raw, &on) == nil {
		d.Enabled = on
		return nil
	}
	var o struct {
		TTLMin string `json:"ttlMin"`
		TTLMax string `json:"ttlMax"`
	}
	if err := strictDecode("dns", raw, &o); err != nil {
		return err
	}
	d.Enabled, d.TTLMin, d.TTLMax = true, o.TTLMin, o.TTLMax
	return nil
}

func (d DNSDef) MarshalJSON() ([]byte, error) {
	if d.TTLMin == "" && d.TTLMax == "" {
		return json.Marshal(d.Enabled)
	}
	return json.Marshal(map[string]string{"ttlMin": d.TTLMin, "ttlMax": d.TTLMax})
}

func (d *DNSDef) validate() error {
	var err error
	if d.min, err = parseDur(d.TTLMin); err != nil || d.min < 0 {
		return fmt.Errorf("dns.ttlMin %q is not a duration", d.TTLMin)
	}
	if d.max, err = parseDur(d.TTLMax); err != nil || d.max < 0 {
		return fmt.Errorf("dns.ttlMax %q is not a duration", d.TTLMax)
	}
	if d.max > 0 && d.min > d.max {
		return fmt.Errorf("dns.ttlMin %s is above ttlMax %s", d.TTLMin, d.TTLMax)
	}
	return nil
}

// EndpointDef is the object form of a backend endpoint.
type EndpointDef struct {
	Address  string `json:"address"`
	Weight   int    `json:"weight,omitempty"`
	Zone     string `json:"zone,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

func (e EndpointDef) validate() error {
	if e.Address == "" {
		return fmt.Errorf("endpoint has no address")
	}
	if e.Weight < 0 || e.Weight > 1000 {
		return fmt.Errorf("endpoint %s: weight %d is outside 1-1000", e.Address, e.Weight)
	}
	if e.Priority < 0 || e.Priority > 100 {
		return fmt.Errorf("endpoint %s: priority %d is outside 0-100", e.Address, e.Priority)
	}
	return nil
}

// ---- resolution cache ----

type dnsEnt struct {
	addrs   []string
	expires time.Time
	stale   bool // the last lookup failed; addrs is the last good answer
	err     string
	lastOK  time.Time
	lookups int
	errors  int
	min     time.Duration // per backend overrides, 0 = gateway wide
	max     time.Duration
}

// dnsCache holds the answers of every resolved host.
type dnsCache struct {
	mu   sync.Mutex
	opts DNSOptions
	now  func() time.Time
	ents map[string]*dnsEnt
}

func newDNSCache(o DNSOptions, now func() time.Time) *dnsCache {
	if o.Resolver == nil {
		o.Resolver = systemResolver{}
	}
	if o.TTLMin <= 0 {
		o.TTLMin = defaultDNSMin
	}
	if o.TTLMax <= 0 {
		o.TTLMax = defaultDNSMax
	}
	if o.TTLMax < o.TTLMin {
		o.TTLMax = o.TTLMin
	}
	return &dnsCache{opts: o, now: now, ents: map[string]*dnsEnt{}}
}

func (c *dnsCache) clamp(ttl, lo, hi time.Duration) time.Duration {
	if lo <= 0 {
		lo = c.opts.TTLMin
	}
	if hi <= 0 {
		hi = c.opts.TTLMax
	}
	if hi < lo {
		hi = lo
	}
	if ttl < 0 {
		ttl = unknownDNSTTL
	}
	return min(max(ttl, lo), hi)
}

// resolve looks host up now and records the outcome. Caller holds no lock.
func (c *dnsCache) resolve(ctx context.Context, host string, lo, hi time.Duration) (changed bool) {
	ctx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	addrs, ttl, err := c.opts.Resolver.LookupHost(ctx, host)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.ents[host]
	if e == nil {
		e = &dnsEnt{}
		c.ents[host] = e
	}
	e.lookups++
	e.min, e.max = lo, hi
	if err == nil && len(addrs) == 0 {
		err = fmt.Errorf("no addresses")
	}
	if err != nil {
		e.errors++
		e.err = err.Error()
		e.stale = len(e.addrs) > 0
		e.expires = now.Add(c.clamp(0, lo, hi)) // retry soon, keep serving the last answer
		return false
	}
	addrs = normalizeAddrs(addrs)
	changed = !equalStrings(e.addrs, addrs)
	e.addrs, e.stale, e.err, e.lastOK = addrs, false, "", now
	e.expires = now.Add(c.clamp(ttl, lo, hi))
	return changed
}

func normalizeAddrs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range in {
		if p, err := netip.ParseAddr(strings.Trim(a, "[]")); err == nil {
			a = p.Unmap().String()
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	if len(out) > maxDNSAddresses {
		out = out[:maxDNSAddresses]
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lookup returns the cached answer for host, resolving it when there is none yet.
func (c *dnsCache) lookup(host string, lo, hi time.Duration) ([]string, error) {
	c.mu.Lock()
	e := c.ents[host]
	have := e != nil && len(e.addrs) > 0
	c.mu.Unlock()
	if !have {
		c.resolve(context.Background(), host, lo, hi)
		c.mu.Lock()
		e = c.ents[host]
		have = e != nil && len(e.addrs) > 0
		c.mu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !have {
		msg := "no answer"
		if e != nil && e.err != "" {
			msg = e.err
		}
		return nil, fmt.Errorf("cannot resolve %s: %s", host, msg)
	}
	return append([]string(nil), e.addrs...), nil
}

// refreshDue re-resolves every host whose answer has expired and reports
// whether any answer changed.
func (c *dnsCache) refreshDue(ctx context.Context, hosts []string) bool {
	now := c.now()
	changed := false
	for _, h := range hosts {
		c.mu.Lock()
		e := c.ents[h]
		due := e == nil || !now.Before(e.expires)
		var lo, hi time.Duration
		if e != nil {
			lo, hi = e.min, e.max
		}
		c.mu.Unlock()
		if due && c.resolve(ctx, h, lo, hi) {
			changed = true
		}
	}
	return changed
}

// nextDue is when the earliest tracked answer expires.
func (c *dnsCache) nextDue(hosts []string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var next time.Time
	ok := false
	for _, h := range hosts {
		if e := c.ents[h]; e != nil && (!ok || e.expires.Before(next)) {
			next, ok = e.expires, true
		}
	}
	return next, ok
}

// DNSStatus is one resolved host in /status.
type DNSStatus struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
	Expires   string   `json:"expires,omitempty"`
	Stale     bool     `json:"stale,omitempty"`
	Error     string   `json:"error,omitempty"`
	Lookups   int      `json:"lookups"`
	Errors    int      `json:"errors,omitempty"`
}

func (c *dnsCache) status() []DNSStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []DNSStatus
	for h, e := range c.ents {
		out = append(out, DNSStatus{Host: h, Addresses: append([]string(nil), e.addrs...), Expires: e.expires.UTC().Format(time.RFC3339), Stale: e.stale, Error: e.err, Lookups: e.lookups, Errors: e.errors})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// dnsHosts lists the names the config's DNS backends resolve.
func (c *Config) dnsHosts() []string {
	seen := map[string]bool{}
	for _, def := range c.Backends {
		if def.DNS == nil || !def.DNS.Enabled {
			continue
		}
		for _, e := range def.Endpoints {
			if host, ok := dnsHostOf(e); ok {
				seen[host] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// RefreshDNS re-resolves expired names and, when an answer changed, rebuilds the
// routing table from the same configuration so new endpoints take traffic. It
// reports whether the table was rebuilt. The Run loop calls it on a timer.
func (s *Server) RefreshDNS(ctx context.Context) (bool, error) {
	t := s.Table()
	if t == nil || s.dns == nil {
		return false, nil
	}
	if !s.dns.refreshDue(ctx, t.Cfg.dnsHosts()) {
		return false, nil
	}
	s.mu.Lock()
	hash := s.hash
	s.mu.Unlock()
	return true, s.Apply(&Loaded{Config: t.Cfg, Hash: hash})
}

// dnsLoop refreshes names until ctx ends.
func (s *Server) dnsLoop(ctx context.Context) {
	for {
		wait := 5 * time.Second
		if t := s.Table(); t != nil {
			if next, ok := s.dns.nextDue(t.Cfg.dnsHosts()); ok {
				wait = min(max(next.Sub(s.res.now()), time.Second), s.dns.opts.TTLMax)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if _, err := s.RefreshDNS(ctx); err != nil && ctx.Err() == nil {
			s.diag("dns refresh: %v", err)
		}
	}
}

// ---- endpoint parsing ----

// dnsHostOf is the host of an endpoint when it is a name (not an IP address or a unix socket).
func dnsHostOf(e string) (string, bool) {
	if isUnixEndpoint(e) {
		return "", false
	}
	u, err := parseEndpoint(e)
	if err != nil {
		return "", false
	}
	h := u.Hostname()
	if _, err := netip.ParseAddr(h); err == nil || h == "" {
		return "", false
	}
	return h, true
}

func isUnixEndpoint(e string) bool {
	return strings.HasPrefix(e, "unix:") || strings.HasPrefix(e, "/")
}

// unixPath extracts the socket path of unix:///run/app.sock, unix:/run/app.sock or /run/app.sock.
func unixPath(e string) (string, error) {
	p := strings.TrimPrefix(e, "unix:")
	p = strings.TrimPrefix(p, "//")
	if !strings.HasPrefix(p, "/") || filepath.Clean(p) == "/" {
		return "", fmt.Errorf("endpoint %q: a unix socket needs an absolute path, for example unix:///run/app.sock", e)
	}
	return filepath.Clean(p), nil
}

// expand turns one declared endpoint into endpoints: a unix socket, a name that
// resolves to several addresses, or the address itself.
func (c *Config) expandEndpoint(b *Backend, def *BackendDef, decl string) ([]*Endpoint, error) {
	if isUnixEndpoint(decl) {
		p, err := unixPath(decl)
		if err != nil {
			return nil, err
		}
		host := unixEndpointHost + strconv.FormatUint(hash64(p)>>40, 16)
		if b.unix == nil {
			b.unix = map[string]string{}
		}
		b.unix[host] = p
		return []*Endpoint{{URL: &url.URL{Scheme: "http", Host: host}, Authority: unixEndpointLocal, Unix: p}}, nil
	}
	u, err := parseEndpoint(decl)
	if err != nil {
		return nil, err
	}
	host, isName := dnsHostOf(decl)
	if !isName || def.DNS == nil || !def.DNS.Enabled || c.dns == nil {
		return []*Endpoint{{URL: u}}, nil
	}
	addrs, err := c.dns.lookup(host, def.DNS.min, def.DNS.max)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	var out []*Endpoint
	for _, a := range addrs {
		hp := a
		if port != "" {
			hp = net.JoinHostPort(a, port)
		} else if strings.Contains(a, ":") {
			hp = "[" + a + "]"
		}
		out = append(out, &Endpoint{URL: &url.URL{Scheme: u.Scheme, Host: hp}, Authority: u.Host})
	}
	if u.Scheme == "https" && (b.sni == "" || b.sni == host) {
		b.sni = host
	}
	b.dnsHosts = append(b.dnsHosts, host)
	return out, nil
}

// externalBackend resolves a backendRef of kind Backend (group setura.zyvor.dev),
// declared in the snapshot "backends" section or a route annotation. Host names
// in its endpoints are resolved by the gateway unless it says "dns": false.
func (t *Table) externalBackend(kind, routeNS string, ref BackendRef) (*Backend, fact) {
	ns := ref.Namespace
	if ns == "" {
		ns = routeNS
	}
	if !t.Cfg.granted(kind, routeNS, BackendGroup, BackendKind, ns, ref.Name) {
		return nil, fact{false, "RefNotPermitted", fmt.Sprintf("Backend %s/%s needs a ReferenceGrant", ns, ref.Name)}
	}
	key := ns + "/" + ref.Name
	if b, ok := t.Backends[key]; ok {
		t.noteUse(b)
		return b, fact{true, "ResolvedRefs", ""}
	}
	def := t.Cfg.Backends[key]
	if def == nil && ref.Port != 0 {
		def = t.Cfg.Backends[backendKey(ns, ref.Name, ref.Port)]
	}
	if def == nil {
		return nil, fact{false, "BackendNotFound", fmt.Sprintf("no Backend %s is declared (snapshot backends section or the %s route annotation)", key, BackendsKey)}
	}
	if def.DNS == nil {
		def.DNS = &DNSDef{Enabled: true}
	}
	b, err := newBackend(t.Cfg, key, ref.Name, def)
	if err != nil {
		return nil, fact{false, "BackendNotFound", err.Error()}
	}
	b.Kind = BackendKind
	t.Backends[key] = b
	t.noteUse(b)
	return b, fact{true, "ResolvedRefs", ""}
}

// annotateBackends reads the setura.zyvor.dev/backends annotation of a route:
// a JSON object of name to backend, the same shape as the snapshot "backends"
// section, for backends that have no Service. A value that cannot be decoded is
// remembered on every rule of the route, so the route turns invalid.
func (c *Config) annotateBackends(ns string, rules []Rule, ann map[string]string) {
	v, ok := ann[BackendsKey]
	if !ok {
		return
	}
	fail := func(err error) {
		for i := range rules {
			if rules[i].extErr == nil {
				rules[i].extErr = fmt.Errorf("annotation %s: %w", BackendsKey, err)
			}
		}
	}
	var defs map[string]BackendDef
	if err := json.Unmarshal([]byte(v), &defs); err != nil {
		fail(err)
		return
	}
	for name, d := range defs {
		d := d
		if d.DNS == nil {
			d.DNS = &DNSDef{Enabled: true}
		}
		key := ns + "/" + name
		if _, exists := c.Backends[key]; !exists {
			c.Backends[key] = &d
		}
	}
}

// CheckBackendDef reports why the gateway would refuse a backend declaration
// (snapshot "backends" entry or a value of the setura.zyvor.dev/backends
// annotation): an endpoint that is neither an address, a name nor a unix
// socket, a bad weight, zone or priority, or an invalid dns or loadBalancer
// block. Lint rule SET052 calls it.
func CheckBackendDef(raw []byte) error {
	var def BackendDef
	if err := json.Unmarshal(raw, &def); err != nil {
		return fmt.Errorf("backend does not parse: %w", err)
	}
	if len(def.Endpoints) == 0 {
		return fmt.Errorf("backend has no endpoints")
	}
	for _, e := range def.Endpoints {
		if isUnixEndpoint(e) {
			if _, err := unixPath(e); err != nil {
				return err
			}
			continue
		}
		if _, err := parseEndpoint(e); err != nil {
			return err
		}
	}
	if def.DNS != nil {
		if err := def.DNS.validate(); err != nil {
			return err
		}
	}
	if def.LoadBalancer != nil {
		if _, err := def.LoadBalancer.Compile(); err != nil {
			return fmt.Errorf("loadBalancer: %w", err)
		}
	}
	if _, err := parseDur(def.Timeout); err != nil {
		return fmt.Errorf("timeout: %w", err)
	}
	return nil
}

// OrphanBackendRefs is a helper for lint: it reports whether a backendRef names a Setura Backend.
func IsBackendRef(group, kind string) bool { return group == BackendGroup && kind == BackendKind }
