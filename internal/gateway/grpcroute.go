package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync"
	"time"
)

// GRPCRoute is a Gateway API GRPCRoute.
type GRPCRoute struct {
	NS, Name   string
	Generation int64
	Created    time.Time
	Parents    []ParentRef
	Hostnames  []string
	Rules      []GRPCRule
}

// GRPCRule is one GRPCRoute rule.
type GRPCRule struct {
	Matches     []GRPCMatch  `json:"matches,omitempty"`
	Filters     []Filter     `json:"filters,omitempty"`
	BackendRefs []BackendRef `json:"backendRefs,omitempty"`
}

// GRPCMatch is one GRPCRouteMatch.
type GRPCMatch struct {
	Method  *GRPCMethodMatch `json:"method,omitempty"`
	Headers []ValueMatch     `json:"headers,omitempty"`
}

// GRPCMethodMatch matches the gRPC service and method of /service/method.
type GRPCMethodMatch struct {
	Type    string `json:"type,omitempty"`
	Service string `json:"service,omitempty"`
	Method  string `json:"method,omitempty"`
}

type grpcRouteSpec struct {
	ParentRefs []ParentRef `json:"parentRefs"`
	Hostnames  []string    `json:"hostnames"`
	Rules      []GRPCRule  `json:"rules"`

	Annotations map[string]string `json:"setura.zyvor.dev/annotations,omitempty"`
}

func (r *GRPCRoute) stub() *Route {
	return &Route{Kind: "GRPCRoute", NS: r.NS, Name: r.Name, Generation: r.Generation, Created: r.Created, Parents: r.Parents, Hostnames: r.Hostnames}
}

// parseExtraRoute decodes a GRPCRoute or TLSRoute snapshot resource.
func (c *Config) parseExtraRoute(kind, ns, name string, raw json.RawMessage) error {
	switch kind {
	case grpcRouteKey:
		var spec grpcRouteSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return err
		}
		annotateGRPC(spec.Rules, spec.Annotations)
		c.GRPCRoutes = append(c.GRPCRoutes, &GRPCRoute{NS: ns, Name: name, Parents: spec.ParentRefs, Hostnames: spec.Hostnames, Rules: spec.Rules})
	case tlsRouteKey:
		var spec tlsRouteSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return err
		}
		c.TLSRoutes = append(c.TLSRoutes, &TLSRoute{NS: ns, Name: name, Parents: spec.ParentRefs, Hostnames: spec.Hostnames, Rules: spec.Rules})
	}
	return nil
}

// grpcMatchPath turns a GRPCRoute method match into the equivalent HTTP/2 path
// match on /service/method (nil matches every path).
func grpcMatchPath(m *GRPCMethodMatch) (*PathMatch, error) {
	if m == nil || (m.Service == "" && m.Method == "") {
		return nil, nil
	}
	switch m.Type {
	case "", "Exact":
		switch {
		case m.Service != "" && m.Method != "":
			return &PathMatch{Type: "Exact", Value: "/" + m.Service + "/" + m.Method}, nil
		case m.Service != "":
			return &PathMatch{Type: "PathPrefix", Value: "/" + m.Service}, nil
		}
		return &PathMatch{Type: "RegularExpression", Value: "/[^/]+/" + regexp.QuoteMeta(m.Method)}, nil
	case "RegularExpression":
		svc, meth := m.Service, m.Method
		if svc == "" {
			svc = "[^/]+"
		}
		if meth == "" {
			meth = "[^/]+"
		}
		return &PathMatch{Type: "RegularExpression", Value: "/(?:" + svc + ")/(?:" + meth + ")"}, nil
	}
	return nil, fmt.Errorf("unsupported gRPC method match type %q", m.Type)
}

// validGRPCFilters accepts the header modifiers; everything else is rejected so
// a silently ignored filter never changes what a route means.
func validGRPCFilters(fs []Filter, ruleLevel bool) error {
	for _, f := range fs {
		if f.Type == "RequestMirror" && ruleLevel {
			continue
		}
		if f.Type != "RequestHeaderModifier" && f.Type != "ResponseHeaderModifier" {
			return fmt.Errorf("unsupported GRPCRoute filter type %q", f.Type)
		}
	}
	return nil
}

func refWeight(ref BackendRef) int {
	w := 1
	if ref.Weight != nil {
		w = *ref.Weight
	}
	if w < 0 {
		w = 0
	}
	return w
}

func (t *Table) attachGRPC(r *GRPCRoute) {
	stub := r.stub()
	res := &routeResult{Route: stub, Refs: fact{true, "ResolvedRefs", "all references resolved"}}
	t.routes = append(t.routes, res)
	crs := make([]*CRule, len(r.Rules))
	cms := make([][]*CMatch, len(r.Rules))
	var invalid error
	note := func(f fact) {
		if !f.OK && res.Refs.OK {
			res.Refs = f
		}
	}
rules:
	for i := range r.Rules {
		rule := &r.Rules[i]
		fail := func(err error) { invalid = fmt.Errorf("rule %d: %w", i+1, err) }
		if err := validGRPCFilters(rule.Filters, true); err != nil {
			fail(err)
			break
		}
		cr := &CRule{RouteKey: stub.StatusKey(), Index: i, Rule: &Rule{Filters: rule.Filters}}
		mirrors, err := t.grpcMirrors(r, rule, note)
		if err != nil {
			fail(err)
			break
		}
		cr.Mirrors = mirrors
		for _, ref := range rule.BackendRefs {
			if err := validGRPCFilters(ref.Filters, false); err != nil {
				fail(err)
				break rules
			}
			w := refWeight(ref)
			b, fc := t.backendFor("GRPCRoute", r.NS, ref)
			note(fc)
			cr.Refs = append(cr.Refs, &CRef{Name: ref.Name, B: b, Weight: w, Filters: ref.Filters})
			cr.Total += w
		}
		matches := rule.Matches
		if len(matches) == 0 {
			matches = []GRPCMatch{{}}
		}
		for _, m := range matches {
			pm, err := grpcMatchPath(m.Method)
			if err != nil {
				fail(err)
				break rules
			}
			cm, err := compileMatch(Match{Path: pm, Headers: m.Headers})
			if err != nil {
				fail(err)
				break rules
			}
			cms[i] = append(cms[i], cm)
		}
		crs[i] = cr
	}
	res.Parents = t.attachParents("GRPCRoute", r.NS, r.Parents, r.Hostnames, invalid, func(l *RTListener, hosts []string) {
		for i := range r.Rules {
			for _, cm := range cms[i] {
				l.Entries = append(l.Entries, &Entry{Route: stub, Rule: crs[i], Match: cm, Hosts: hosts, GRPC: true})
			}
		}
	})
}

// isGRPC reports whether r is a gRPC call: HTTP/2 with an application/grpc
// content type.
func isGRPC(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+") || strings.HasPrefix(ct, "application/grpc;")
}

// gRPC status codes the gateway itself produces.
const (
	grpcDeadlineExceeded = 4
	grpcUnimplemented    = 12
	grpcUnavailable      = 14
)

// grpcFail answers with a Trailers-Only gRPC error: HTTP 200 and grpc-status
// in the headers. statsStatus is the HTTP-equivalent code used for logs and
// counters.
func grpcFail(rec *recorder, code int, msg string, statsStatus int) {
	h := rec.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", fmt.Sprint(code))
	h.Set("Grpc-Message", msg)
	rec.WriteHeader(http.StatusOK)
	rec.status = statsStatus
}

// grpcTransports are the HTTP/2 transports used towards gRPC backends.
type grpcTransports struct {
	once                sync.Once
	h2c, tls, tlsUnsafe *http.Transport
}

func (g *grpcTransports) get(scheme string, insecure bool) *http.Transport {
	g.once.Do(func() {
		g.h2c = newH2CTransport()
		mk := func(skip bool) *http.Transport {
			return newTLSH2Transport(skip)
		}
		g.tls, g.tlsUnsafe = mk(false), mk(true)
	})
	switch {
	case scheme != "https":
		return g.h2c
	case insecure:
		return g.tlsUnsafe
	}
	return g.tls
}

func (g *grpcTransports) closeIdle() {
	for _, t := range []*http.Transport{g.h2c, g.tls, g.tlsUnsafe} {
		if t != nil {
			t.CloseIdleConnections()
		}
	}
}

// pickWeighted chooses a backendRef by weight; nil when nothing can take traffic.
func (s *Server) pickWeighted(refs []*CRef, total int) *CRef {
	if total <= 0 {
		return nil
	}
	n := s.intn(total)
	for _, c := range refs {
		if n < c.Weight {
			return c
		}
		n -= c.Weight
	}
	return nil
}

// serveGRPC is the data-plane handler for gRPC calls (HTTP/2, application/grpc).
func (s *Server) serveGRPC(w http.ResponseWriter, r *http.Request, port int) {
	start := time.Now()
	rec := &recorder{ResponseWriter: w}
	st := &reqState{}
	defer func() { s.logRequest(rec, r, st, start) }()
	fail := func(code int, msg string, stats int) {
		st.errMsg = msg
		grpcFail(rec, code, msg, stats)
	}
	t := s.table.Load()
	var pg *PortGroup
	if t != nil {
		pg = t.Ports[port]
	}
	if pg == nil {
		fail(grpcUnavailable, "gateway not ready", http.StatusServiceUnavailable)
		return
	}
	host := hostOnly(r.Host)
	l := pg.pickListener(host)
	if l == nil {
		fail(grpcUnimplemented, "no listener serves this host", http.StatusNotFound)
		return
	}
	st.listener = l.Key
	e := l.selectEntry(r, host)
	if e == nil {
		fail(grpcUnimplemented, "no route matched", http.StatusNotFound)
		return
	}
	rule := e.Rule
	st.route = rule.RouteKey
	idx := rule.Index
	st.rule = &idx
	ref := s.pickWeighted(rule.Refs, rule.Total)
	if ref == nil || ref.B == nil {
		fail(grpcUnavailable, "no valid backend for this route", http.StatusInternalServerError)
		return
	}
	ep := ref.B.pick()
	st.backend = ref.B.Key
	tr := s.grpcTr.get(ep.URL.Scheme, ref.B.Insecure)
	if tr == nil {
		fail(grpcUnavailable, "cleartext HTTP/2 backends need Go 1.24 or newer", http.StatusBadGateway)
		return
	}
	if bt := ref.B.Timeout; bt > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), bt)
		defer cancel()
		r = r.WithContext(ctx)
	}
	filters := append(append([]Filter(nil), rule.Rule.Filters...), ref.Filters...)
	proxy := &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(ep.URL)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			if pg.TLS {
				pr.Out.Header.Set("X-Forwarded-Proto", "https")
			}
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			pr.Out.URL.Path, pr.Out.URL.RawPath = pr.In.URL.Path, pr.In.URL.RawPath
			for _, f := range filters {
				if f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil {
					applyHeaderMod(pr.Out.Header, f.RequestHeaderModifier)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set(BackendHeader, ref.Name)
			for _, f := range filters {
				if f.Type == "ResponseHeaderModifier" && f.ResponseHeaderModifier != nil {
					applyHeaderMod(resp.Header, f.ResponseHeaderModifier)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			st.errMsg = err.Error()
			w.Header().Set(BackendHeader, ref.Name)
			if errors.Is(err, context.DeadlineExceeded) {
				grpcFail(rec, grpcDeadlineExceeded, "upstream timeout", http.StatusGatewayTimeout)
				return
			}
			grpcFail(rec, grpcUnavailable, "upstream error", http.StatusBadGateway)
		},
	}
	sc, sp := s.grpcShadow(r, rule, ref.B.Key)
	defer sc.finish()
	if sp != nil {
		defer sp.release()
		r.Body = sp
	}
	proxy.ServeHTTP(sc.wrap(rec), r)
}
