package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
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
	// Retry retries replayable (unary) calls on UNAVAILABLE and similar.
	Retry *GRPCRetry `json:"retry,omitempty"`
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
	creationMeta
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
		created, err := spec.created()
		if err != nil {
			return err
		}
		annotateGRPC(spec.Rules, spec.Annotations)
		c.GRPCRoutes = append(c.GRPCRoutes, &GRPCRoute{NS: ns, Name: name, Created: created, Parents: spec.ParentRefs, Hostnames: spec.Hostnames, Rules: spec.Rules})
	case tlsRouteKey:
		var spec tlsRouteSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return err
		}
		created, err := spec.created()
		if err != nil {
			return err
		}
		c.TLSRoutes = append(c.TLSRoutes, &TLSRoute{NS: ns, Name: name, Created: created, Parents: spec.ParentRefs, Hostnames: spec.Hostnames, Rules: spec.Rules})
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

// validGRPCFilters accepts the header modifiers, and RequestMirror at rule
// level; everything else is rejected so a silently ignored filter never
// changes what a route means.
func validGRPCFilters(fs []Filter, ruleLevel bool) error {
	for _, f := range fs {
		switch {
		case f.Type == "RequestMirror" && ruleLevel:
		case f.Type == "RequestHeaderModifier", f.Type == "ResponseHeaderModifier":
		case f.Type == "ExtensionRef":
			return fmt.Errorf("ExtensionRef filters are not supported by the built-in gateway: it has no extension mechanism, and ignoring the reference would change what the route does")
		default:
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
		if rule.Retry != nil {
			var err error
			if cr.GRPCRetry, err = compileGRPCRetry(rule.Retry); err != nil {
				fail(err)
				break
			}
		}
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
			for j, cm := range cms[i] {
				l.Entries = append(l.Entries, &Entry{Route: stub, Rule: crs[i], Match: cm, Hosts: hosts, GRPC: true, MatchIdx: j})
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
	st.countBody(r)
	st.grpcSvc, st.grpcMethod = splitGRPCPath(r.URL.Path)
	defer func() { s.logRequest(rec, r, st, start) }()
	defer s.trackOpen(rec, r, st, "grpc")()
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
	st.match, st.matched = e.MatchIdx, true
	st.markRoute()
	ref := s.pickRef(rule)
	if ref == nil || ref.B == nil {
		fail(grpcUnavailable, "no valid backend for this route", http.StatusInternalServerError)
		return
	}
	ep := ref.B.choose(s.res.now(), nil)
	st.backend, st.weight = ref.B.Key, ref.Weight
	st.markRoute()
	if s.grpcTr.get(ep.URL.Scheme, ref.B.Insecure) == nil {
		fail(grpcUnavailable, "cleartext HTTP/2 backends need Go 1.24 or newer", http.StatusBadGateway)
		return
	}
	// Deadline: the shorter of the backend timeout and the client's grpc-timeout.
	timeout := ref.B.Timeout
	hdrTimeout, hdrOK := time.Duration(0), false
	hasHdr := r.Header.Get("Grpc-Timeout") != ""
	if hasHdr {
		if hdrTimeout, hdrOK = parseGRPCTimeout(r.Header.Get("Grpc-Timeout")); hdrOK && (timeout == 0 || hdrTimeout < timeout) {
			timeout = hdrTimeout
		}
	}
	var deadline time.Time
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		deadline, _ = ctx.Deadline()
	}
	// Retries work on a unary call held in memory.
	var replay []byte
	canReplay := false
	if rule.GRPCRetry != nil {
		replay, canReplay = bufferUnary(r, s.res.opt().RetryBodyLimit)
	}
	rt := &grpcTransport{s: s, b: ref.B, first: ep, retry: rule.GRPCRetry, replay: replay, canReplay: canReplay, tried: map[*Endpoint]bool{}, st: st}
	filters := requestFilters(rule, ref)
	proxy := &httputil.ReverseProxy{
		Transport:     rt,
		FlushInterval: -1,
		BufferPool:    proxyBufPool,
		ErrorLog:      discardLog,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(ep.URL)
			shapeUpstream(pr.Out, pr.In, remoteIP(pr.In), pg.TLS, filters, e.Match, true)
			s.chainForwardedFor(pr.In, pr.Out)
			if hasHdr {
				// Forward what is left of the deadline; drop an unparsable value.
				pr.Out.Header.Del("Grpc-Timeout")
				if hdrOK {
					left := hdrTimeout
					if !deadline.IsZero() {
						left = time.Until(deadline)
					}
					pr.Out.Header.Set("Grpc-Timeout", formatGRPCTimeout(left))
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set(BackendHeader, ref.Name)
			w.Header().Del(RequestIDHeader) // see serveHTTP: the proxy Adds upstream headers on top of the pre-set id
			resp.Header.Set(RequestIDHeader, st.reqID)
			if rt.retries > 0 && s.res.opt().RetryHeader {
				resp.Header.Set(RetryHeaderName, strconv.Itoa(rt.retries))
			}
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

// splitGRPCPath splits /package.Service/Method.
func splitGRPCPath(p string) (service, method string) {
	service, method, _ = strings.Cut(strings.TrimPrefix(p, "/"), "/")
	return service, method
}
