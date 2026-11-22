package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxMirrorBody = 1 << 20

// recorder captures status and size for logs and stats.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	open   *openConn // set for streams listed in the open connection table
}

// bytesOut is the number of body bytes written to the client so far.
func (r *recorder) bytesOut() int64 { return atomic.LoadInt64(&r.bytes) }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	n, err := r.ResponseWriter.Write(p)
	atomic.AddInt64(&r.bytes, int64(n))
	if r.open != nil {
		r.open.out.Add(int64(n))
	}
	return n, err
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach Hijack for upgrades.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Counter counts requests by status class.
type Counter struct {
	Requests int64            `json:"requests"`
	Status   map[string]int64 `json:"status"`
}

// Stats holds per-route and per-backend counters across reloads.
type Stats struct {
	mu        sync.Mutex
	total     int64
	unmatched int64
	routes    map[string]*Counter
	backends  map[string]*Counter
}

func newStats() *Stats {
	return &Stats{routes: map[string]*Counter{}, backends: map[string]*Counter{}}
}

func bump(m map[string]*Counter, key string, status int) {
	c := m[key]
	if c == nil {
		c = &Counter{Status: map[string]int64{}}
		m[key] = c
	}
	c.Requests++
	c.Status[fmt.Sprintf("%dxx", status/100)]++
}

func (s *Stats) record(route, backend string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	if route == "" {
		s.unmatched++
	} else {
		bump(s.routes, route, status)
	}
	if backend != "" {
		bump(s.backends, backend, status)
	}
}

// Snapshot returns a JSON-ready copy.
func (s *Stats) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := func(in map[string]*Counter) map[string]Counter {
		out := map[string]Counter{}
		for k, v := range in {
			c := Counter{Requests: v.Requests, Status: map[string]int64{}}
			for sk, sv := range v.Status {
				c.Status[sk] = sv
			}
			out[k] = c
		}
		return out
	}
	return map[string]any{"requests": s.total, "unmatched": s.unmatched, "routes": cp(s.routes), "backends": cp(s.backends)}
}

type reqState struct {
	listener, route, backend, errMsg string
	rule                             *int
	reqID                            string
	trace                            traceInfo

	match       int // index of the matching match within the rule
	matched     bool
	weight      int // weight of the chosen backendRef
	rateLimited bool
	grpcSvc     string
	grpcMethod  string
	in          *countReader
	open        *openConn
	up          upInfo
}

// countBody makes the request body count the bytes it delivers.
func (st *reqState) countBody(r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	st.in = &countReader{rc: r.Body}
	r.Body = st.in
}

// noteUpstream mirrors the chosen upstream into the open connection entry.
func (st *reqState) noteUpstream() {
	if st.open != nil {
		addr := st.up.addr
		st.open.set(func(v *OpenView) { v.UpstreamAddr = addr })
	}
}

// trackOpen lists a WebSocket or gRPC stream until the handler returns.
func (s *Server) trackOpen(rec *recorder, r *http.Request, st *reqState, kind string) func() {
	ip, port := splitRemote(r.RemoteAddr)
	o, done := s.conns.register(OpenView{Kind: kind, ClientIP: ip, ClientPort: port, ListenerPort: localPort(r),
		Protocol: protocolOf(r), Host: r.Host, Path: s.logPath(r)})
	if o != nil {
		rec.open, st.open = o, o
		if st.in != nil {
			st.in.mirror = &o.in
		}
	}
	return done
}

// markRoute fills the open entry once routing is known.
func (st *reqState) markRoute() {
	if st.open != nil {
		l, rt, b := st.listener, st.route, st.backend
		st.open.set(func(v *OpenView) { v.Listener, v.Route, v.Backend = l, rt, b })
	}
}

func (s *Server) logRequest(rec *recorder, r *http.Request, st *reqState, start time.Time) {
	status := rec.status
	if status == 0 {
		status = 200
	}
	s.stats.record(st.route, st.backend, status)
	s.hist.observe(st.route, status, time.Since(start))
	s.latency.observe(st.route, st.backend, time.Since(start))
	s.observe(rec, r, st, start, status)
}

func (s *Server) intn(n int) int {
	if s.opts.Rand != nil {
		return s.opts.Rand(n)
	}
	return randIntn(n)
}

func plain(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	io.WriteString(w, msg+"\n")
}

// serveHTTP is the data-plane handler for one port.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, port int) {
	if isGRPC(r) {
		s.serveGRPC(w, r, port)
		return
	}
	start := time.Now()
	rec := &recorder{ResponseWriter: w}
	st := &reqState{}
	s.beginTrace(rec, r, st)
	st.countBody(r)
	defer func() { s.logRequest(rec, r, st, start) }()
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		defer s.trackOpen(rec, r, st, "websocket")()
	}
	t := s.table.Load()
	var pg *PortGroup
	if t != nil {
		pg = t.Ports[port]
	}
	if pg == nil {
		plain(rec, http.StatusServiceUnavailable, "gateway not ready")
		return
	}
	host := hostOnly(r.Host)
	l := pg.pickListener(host)
	if l == nil {
		plain(rec, http.StatusNotFound, "no listener serves this host")
		return
	}
	st.listener = l.Key
	if pe, c := l.preflightTarget(r, host); pe != nil {
		st.route, st.matched, st.match = pe.Rule.RouteKey, true, pe.MatchIdx
		idx := pe.Rule.Index
		st.rule = &idx
		st.markRoute()
		for k, v := range c.preflightHeaders(r) {
			rec.Header()[k] = v
		}
		rec.WriteHeader(http.StatusOK)
		return
	}
	e := l.selectEntry(r, host)
	if e == nil {
		plain(rec, http.StatusNotFound, "no route matched")
		return
	}
	rule := e.Rule
	st.route = rule.RouteKey
	idx := rule.Index
	st.rule = &idx
	st.match, st.matched = e.MatchIdx, true
	st.markRoute()
	if s.rateLimited(rec, r, st) {
		return
	}

	if rule.Redirect != nil {
		shapeResponse(rec.Header(), r, rule.Rule.Filters)
		rec.Header().Set("Location", redirectURL(r, rule.Redirect, e.Match, pg.TLS))
		code := rule.Redirect.StatusCode
		if code == 0 {
			code = http.StatusFound
		}
		rec.WriteHeader(code)
		return
	}

	ref := s.pickRef(rule)
	var ep *Endpoint
	if len(rule.sessionPolicies()) > 0 {
		if pr, pe := s.sessionPin(rule, r, s.res.now()); pr != nil {
			ref, ep = pr, pe
		}
	}
	if ref == nil || ref.B == nil {
		st.errMsg = "no valid backend"
		plain(rec, http.StatusInternalServerError, "no valid backend for this route")
		return
	}
	if ep == nil {
		ep = ref.B.choose(s.res.now(), nil)
	}
	st.backend, st.weight = ref.B.Key, ref.Weight

	if hasExternalAuth(requestFilters(rule, ref)) {
		ar, v := s.runAuthFilters(r, rule, requestFilters(rule, ref), pg.TLS)
		if v != nil {
			st.errMsg = v.why
			shapeResponse(rec.Header(), r, requestFilters(rule, ref))
			writeAuthDenied(rec, v)
			return
		}
		r = ar
	}
	st.markRoute()

	timeout := rule.Timeout
	if bt := ref.B.Timeout; bt > 0 && (timeout == 0 || bt < timeout) {
		timeout = bt
	}
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	var replay []byte
	canReplay := false
	if rule.Retry != nil {
		replay, canReplay = bufferBody(r, s.res.opt().RetryBodyLimit)
	}
	rt := s.newTransport(rule, ref, ep, rule.Retry, replay, canReplay)
	rt.st = st
	var pristine, inbound *http.Request

	var body []byte
	var sp *bodySpool
	mirrors := rule.Mirrors
	if len(mirrors) > 0 {
		var err error
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxMirrorBody+1)); err != nil {
			st.errMsg = "reading request body: " + err.Error()
			plain(rec, http.StatusBadRequest, "cannot read request body")
			return
		}
		if len(body) > maxMirrorBody {
			mirrors, sp = s.bigBody(r, body, mirrors)
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	sc := s.shadowStart(r, rule.RouteKey, ref.B.Key, mirrors)
	defer sc.finish()
	if sp != nil {
		defer sp.release()
		sp.onOver = func() {
			if sc != nil {
				s.shadow.skip(rule.RouteKey)
			}
		}
	}

	proxy := &httputil.ReverseProxy{
		Transport:     rt,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(ep.URL)
			pristine, inbound = pr.Out.Clone(pr.Out.Context()), pr.In // before filters, for retries on another backendRef
			shapeUpstream(pr.Out, pr.In, remoteIP(pr.In), pg.TLS, requestFilters(rule, ref), e.Match, false)
			s.chainForwardedFor(pr.In, pr.Out)
			injectTrace(pr.Out, st)
			s.fireMirrorsOrSpool(pr.Out, body, mirrors, sc, sp)
		},
		ModifyResponse: func(resp *http.Response) error {
			ref := rt.ref // a retry may have moved to another backendRef
			st.backend = ref.B.Key
			resp.Header.Set(BackendHeader, ref.Name)
			// beginTrace pre-sets the id on the writer so gateway-made errors carry it; the
			// proxy then Adds the upstream headers on top, so drop ours or an upstream that
			// echoes X-Request-Id would produce two.
			w.Header().Del(RequestIDHeader)
			resp.Header.Set(RequestIDHeader, st.reqID)
			rt.annotate(resp.Header)
			shapeResponse(resp.Header, r, requestFilters(rule, ref))
			if len(rule.sessionPolicies()) > 0 && resp.Request != nil {
				var served *Endpoint
				for _, e := range ref.B.Eps {
					if e.URL.Host == resp.Request.URL.Host {
						served = e
					}
				}
				s.sessionAnnotate(resp.Header, rule, ref, r, served, pg.TLS, s.res.now())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			st.errMsg = err.Error()
			st.backend = rt.b.Key
			code := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}
			w.Header().Set(BackendHeader, rt.ref.Name)
			rt.annotate(w.Header())
			var shed *circuitReject
			if errors.As(err, &shed) {
				w.Header().Set(CircuitHeader, shed.Reason)
				w.Header().Set("Retry-After", "1")
				plain(w, http.StatusServiceUnavailable, "upstream shed load: circuit breaker "+shed.Reason)
				return
			}
			plain(w, code, "upstream error")
		},
	}
	rt.rebuild = func(ctx context.Context, nr *CRef) *http.Request {
		out := pristine.Clone(ctx)
		shapeUpstream(out, inbound, remoteIP(inbound), pg.TLS, requestFilters(rule, nr), e.Match, false)
		s.chainForwardedFor(inbound, out)
		injectTrace(out, st)
		return out
	}
	proxy.ServeHTTP(sc.wrap(rec), r)
}

// fireMirrors sends fire-and-forget copies of out to each mirror backend.
func (s *Server) fireMirrors(out *http.Request, body []byte, mirrors []*CMirror, sc *shadowReq) {
	for _, m := range mirrors {
		if m.Percent <= 0 || (m.Percent < 100 && s.intn(100) >= m.Percent) {
			continue
		}
		ep := m.B.pick()
		if ep == nil {
			continue
		}
		u := *out.URL
		u.Scheme, u.Host = ep.URL.Scheme, ep.URL.Host
		req, err := http.NewRequest(out.Method, u.String(), bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header = out.Header.Clone()
		req.Header.Set("X-Setura-Mirror", "1")
		req.Host = out.Host
		client := &http.Client{Transport: s.backendTransport(m.B), Timeout: 10 * time.Second}
		if sc.submit(m, req, client) {
			continue
		}
		s.mirrorWG.Add(1)
		go func() {
			defer s.mirrorWG.Done()
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
			}
		}()
	}
}

// applyHeaderMod applies set, add and remove in that order, as the spec does.
func applyHeaderMod(h http.Header, m *HeaderMod) {
	for _, nv := range m.Set {
		if !strings.EqualFold(nv.Name, "host") {
			h.Set(nv.Name, nv.Value)
		}
	}
	for _, nv := range m.Add {
		if strings.EqualFold(nv.Name, "host") {
			continue
		}
		if old := h.Get(nv.Name); old != "" {
			h.Set(nv.Name, old+","+nv.Value)
		} else {
			h.Set(nv.Name, nv.Value)
		}
	}
	for _, n := range m.Remove {
		h.Del(n)
	}
}

// rewritePath implements URLRewrite and RequestRedirect path edits.
func rewritePath(path string, pm *PathMod, m *CMatch) string {
	switch pm.Type {
	case "ReplaceFullPath":
		return pm.ReplaceFullPath
	case "ReplacePrefixMatch":
		if m.PathType != "PathPrefix" {
			return path
		}
		prefix := m.PathValue
		if prefix == "/" {
			prefix = ""
		}
		res := strings.TrimSuffix(pm.ReplacePrefixMatch, "/") + strings.TrimPrefix(path, prefix)
		if res == "" {
			res = "/"
		}
		return res
	}
	return path
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// redirectURL builds the Location for a RequestRedirect filter. Without an
// explicit scheme and port the port the client used is preserved.
func redirectURL(r *http.Request, rd *Redirect, m *CMatch, tlsPort bool) string {
	scheme := rd.Scheme
	if scheme == "" {
		scheme = "http"
		if tlsPort {
			scheme = "https"
		}
	}
	host := rd.Hostname
	reqPort := ""
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		reqPort = p
		if host == "" {
			host = h
		}
	} else if host == "" {
		host = strings.Trim(r.Host, "[]")
	}
	port := ""
	switch {
	case rd.Port != 0:
		port = strconv.Itoa(rd.Port)
	case rd.Scheme == "":
		port = reqPort
	}
	if port == defaultPort(scheme) {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if rd.Path != nil {
		path = (&url.URL{Path: rewritePath(r.URL.Path, rd.Path, m)}).EscapedPath()
	}
	u := scheme + "://" + host + path
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	return u
}
