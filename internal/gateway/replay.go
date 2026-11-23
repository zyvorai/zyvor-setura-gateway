package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Outcome classes of a resolved request.
const (
	OutcomeRouted     = "routed"
	OutcomeRedirect   = "redirect"
	OutcomeDirect     = "direct-response" // the rule answers with a fixed status
	OutcomeNoListener = "no-listener"     // 404: no listener serves the host
	OutcomeNoRoute    = "no-route"        // 404: listener found, no route matched
	OutcomeNoBackend  = "no-backend"      // 500: route matched, no valid backend
	NoBackendKey      = "(no backend)"    // pseudo backend for the unresolvable share
)

// ReqSpec is the part of a request an access log records. Headers are unknown.
type ReqSpec struct {
	Port   int    // listener port; 0 tries every port in ascending order
	Host   string // Host header, port allowed
	Method string
	Path   string // request target: path with optional query string
	GRPC   bool   // a gRPC call (HTTP/2, application/grpc): only GRPCRoutes match
	SNI    string // a TLS passthrough connection: only TLSRoutes match, Path and Method are unused
}

// WeightedBackend is one backend and its share of a rule's traffic.
type WeightedBackend struct {
	Key     string  `json:"backend"`
	Weight  int     `json:"weight"`
	Percent float64 `json:"percent"`
}

// Decision is the pure routing verdict for one request.
type Decision struct {
	Outcome  string            `json:"outcome"`
	Status   int               `json:"status"`
	Listener string            `json:"listener,omitempty"`
	Route    string            `json:"route,omitempty"`
	Rule     int               `json:"rule"`
	Backends []WeightedBackend `json:"backends,omitempty"` // sorted by key, weight > 0
	Location string            `json:"location,omitempty"` // redirect target
	Kind     string            `json:"kind,omitempty"`     // "grpc" or "tls" when not plain HTTP
	// Rule policy that is not routing: what the data path does besides picking
	// a backend. Retry, Timeout and Mirrors are empty for gRPC and TLS, which
	// the data path neither retries nor mirrors.
	Retry   string   `json:"retry,omitempty"`
	Timeout string   `json:"timeout,omitempty"`
	Mirrors []string `json:"mirrors,omitempty"`
	// HeaderDependent is set when a rule that needs request headers could
	// also match (and beat the reported winner). The log has no headers, so
	// the true outcome is unknown; the fields above describe the no-header case.
	HeaderDependent bool     `json:"header_dependent,omitempty"`
	HeaderRoutes    []string `json:"header_routes,omitempty"`
}

// ParseReplayConfig parses a snapshot for offline replay and builds its
// routing table. Certificates are not loaded, so HTTPS listeners serve.
func ParseReplayConfig(raw []byte, dir string) (*Table, error) {
	cfg, err := ParseConfig(raw, dir)
	if err != nil {
		return nil, err
	}
	cfg.skipCerts = true
	return BuildTable(cfg), nil
}

// ListenerPort returns the port of the serving listener with this key, or 0.
func (t *Table) ListenerPort(key string) int {
	for _, l := range t.Listeners {
		if l.Key == key && l.Serving {
			return l.L.Port
		}
	}
	return 0
}

// Resolve decides, without sockets or live backends, what the data plane
// would do with the request. Match code is shared with the proxy. Endpoint
// health is not known to an offline table and is not modelled here.
func (t *Table) Resolve(spec ReqSpec) Decision {
	if spec.SNI != "" {
		return t.resolveTLS(spec)
	}
	d := Decision{Outcome: OutcomeNoListener, Status: http.StatusNotFound}
	r := &http.Request{Method: strings.ToUpper(spec.Method), Header: http.Header{}, ProtoMajor: 1, ProtoMinor: 1}
	if spec.GRPC {
		d.Kind = "grpc"
		r.Method, r.ProtoMajor, r.ProtoMinor = http.MethodPost, 2, 0
		r.Header.Set("Content-Type", "application/grpc")
	}
	target := spec.Path
	if target == "" {
		target = "/"
	}
	u, err := url.ParseRequestURI(target)
	if err != nil {
		u = &url.URL{Path: strings.SplitN(target, "?", 2)[0]}
	}
	r.URL, r.Host, r.RequestURI = u, spec.Host, target
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	host := hostOnly(spec.Host)

	var ports []int
	if spec.Port != 0 {
		ports = []int{spec.Port}
	} else {
		for p := range t.Ports {
			ports = append(ports, p)
		}
		sort.Ints(ports)
	}
	var pg *PortGroup
	var l *RTListener
	for _, p := range ports {
		if g := t.Ports[p]; g != nil && !g.Passthrough && g.L4 == "" {
			if l = g.pickListener(host); l != nil {
				pg = g
				break
			}
		}
	}
	if l == nil {
		return d
	}
	d.Listener = l.Key
	d.Outcome = OutcomeNoRoute
	e, hdr := l.selectReplay(r, host)
	if len(hdr) > 0 {
		d.HeaderDependent = true
		seen := map[string]bool{}
		for _, h := range hdr {
			if k := h.Route.Key(); !seen[k] {
				seen[k] = true
				d.HeaderRoutes = append(d.HeaderRoutes, k)
			}
		}
		sort.Strings(d.HeaderRoutes)
	}
	if e == nil {
		return d
	}
	rule := e.Rule
	d.Route, d.Rule = rule.RouteKey, rule.Index
	if !e.GRPC {
		d.Retry, d.Timeout, d.Mirrors = rulePolicy(rule)
	}
	if rule.Redirect != nil {
		d.Outcome = OutcomeRedirect
		d.Status = rule.Redirect.StatusCode
		if d.Status == 0 {
			d.Status = http.StatusFound
		}
		d.Location = redirectURL(r, rule.Redirect, e.Match, pg.TLS)
		return d
	}
	if rule.Direct != nil {
		d.Outcome, d.Status = OutcomeDirect, rule.Direct.Status
		return d
	}
	d.Status = http.StatusInternalServerError
	d.Outcome = OutcomeNoBackend
	total, valid := 0, 0
	for _, c := range rule.Refs {
		total += c.Weight
		if c.B != nil {
			valid += c.Weight
		}
	}
	if total <= 0 {
		return d
	}
	agg := map[string]int{}
	for _, c := range rule.Refs {
		if c.Weight <= 0 {
			continue
		}
		k := NoBackendKey
		if c.B != nil {
			k = c.B.Key
		}
		agg[k] += c.Weight
	}
	for _, k := range sortedKeys(agg) {
		d.Backends = append(d.Backends, WeightedBackend{Key: k, Weight: agg[k], Percent: float64(agg[k]) * 100 / float64(total)})
	}
	if valid > 0 {
		d.Outcome, d.Status = OutcomeRouted, http.StatusOK
	}
	return d
}

// selectReplay is selectEntry for requests with unknown headers. It returns
// the winner among entries needing no headers, plus the header-requiring
// entries that match in every other respect and would beat that winner.
func (l *RTListener) selectReplay(r *http.Request, host string) (*Entry, []*Entry) {
	var best *Entry
	var bestScore score
	grpc := isGRPC(r)
	type cand struct {
		e *Entry
		s score
	}
	var hdr []cand
	for _, e := range l.Entries {
		if e.GRPC != grpc {
			continue
		}
		rank, ok := -1, false
		for _, h := range e.Hosts {
			if hostMatches(h, host) && hostRank(h) > rank {
				rank, ok = hostRank(h), true
			}
		}
		if !ok {
			continue
		}
		m := e.Match
		if len(m.Headers) > 0 {
			relaxed := *m
			relaxed.Headers = nil
			s, ok := relaxed.matches(r)
			if !ok {
				continue
			}
			s.host, s.headers = rank, len(m.Headers)
			hdr = append(hdr, cand{e, s})
			continue
		}
		s, ok := m.matches(r)
		if !ok {
			continue
		}
		s.host = rank
		if best == nil || s.better(bestScore) {
			best, bestScore = e, s
		}
	}
	var out []*Entry
	for _, c := range hdr {
		if best == nil || c.s.better(bestScore) {
			out = append(out, c.e)
		}
	}
	return best, out
}

// String renders a decision on one line for reports.
func (d Decision) String() string {
	s := d.base()
	if d.HeaderDependent {
		s += " [unknown, depends on headers: " + strings.Join(d.HeaderRoutes, ", ") + "]"
	}
	return s
}

func (d Decision) base() string {
	switch d.Outcome {
	case OutcomeRouted, OutcomeNoBackend:
		var parts []string
		for _, b := range d.Backends {
			parts = append(parts, fmt.Sprintf("%s %.0f%%", b.Key, b.Percent))
		}
		return fmt.Sprintf("%s rule %d -> %s", d.Route, d.Rule+1, strings.Join(parts, ", "))
	case OutcomeRedirect:
		return fmt.Sprintf("%s rule %d redirect %d %s", d.Route, d.Rule+1, d.Status, d.Location)
	case OutcomeDirect:
		return fmt.Sprintf("%s rule %d direct response %d", d.Route, d.Rule+1, d.Status)
	}
	return d.Outcome
}
