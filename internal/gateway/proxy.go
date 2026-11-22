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
	"time"
)

const maxMirrorBody = 1 << 20

// recorder captures status and size for logs and stats.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

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
	r.bytes += int64(n)
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
}

func (s *Server) logRequest(rec *recorder, r *http.Request, st *reqState, start time.Time) {
	status := rec.status
	if status == 0 {
		status = 200
	}
	s.stats.record(st.route, st.backend, status)
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
	start := time.Now()
	rec := &recorder{ResponseWriter: w}
	st := &reqState{}
	s.beginTrace(rec, r, st)
	defer func() { s.logRequest(rec, r, st, start) }()
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
	e := l.selectEntry(r, host)
	if e == nil {
		plain(rec, http.StatusNotFound, "no route matched")
		return
	}
	rule := e.Rule
	st.route = rule.RouteKey
	idx := rule.Index
	st.rule = &idx
	if s.rateLimited(rec, r, st) {
		return
	}

	if rule.Redirect != nil {
		for _, f := range rule.Rule.Filters {
			if f.Type == "ResponseHeaderModifier" && f.ResponseHeaderModifier != nil {
				applyHeaderMod(rec.Header(), f.ResponseHeaderModifier)
			}
		}
		rec.Header().Set("Location", redirectURL(r, rule.Redirect, e.Match, pg.TLS))
		code := rule.Redirect.StatusCode
		if code == 0 {
			code = http.StatusFound
		}
		rec.WriteHeader(code)
		return
	}

	var ref *CRef
	if rule.Total > 0 {
		n := s.intn(rule.Total)
		for _, c := range rule.Refs {
			if n < c.Weight {
				ref = c
				break
			}
			n -= c.Weight
		}
	}
	if ref == nil || ref.B == nil {
		st.errMsg = "no valid backend"
		plain(rec, http.StatusInternalServerError, "no valid backend for this route")
		return
	}
	ep := ref.B.pick()
	st.backend = ref.B.Key

	timeout := rule.Timeout
	if bt := ref.B.Timeout; bt > 0 && (timeout == 0 || bt < timeout) {
		timeout = bt
	}
	if timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	var body []byte
	mirrors := rule.Mirrors
	if len(mirrors) > 0 {
		var err error
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxMirrorBody+1)); err != nil {
			st.errMsg = "reading request body: " + err.Error()
			plain(rec, http.StatusBadRequest, "cannot read request body")
			return
		}
		if len(body) > maxMirrorBody {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
			mirrors = nil
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	proxy := &httputil.ReverseProxy{
		Transport:     s.transport(ref.B.Insecure),
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
			filters := append(append([]Filter(nil), rule.Rule.Filters...), ref.Filters...)
			for _, f := range filters {
				switch {
				case f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil:
					applyHeaderMod(pr.Out.Header, f.RequestHeaderModifier)
				case f.Type == "URLRewrite" && f.URLRewrite != nil:
					if f.URLRewrite.Hostname != "" {
						pr.Out.Host = f.URLRewrite.Hostname
					}
					if p := f.URLRewrite.Path; p != nil {
						np := rewritePath(pr.Out.URL.Path, p, e.Match)
						pr.Out.URL.Path, pr.Out.URL.RawPath = np, ""
					}
				}
			}
			injectTrace(pr.Out, st)
			s.fireMirrors(pr.Out, body, mirrors)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set(BackendHeader, ref.Name)
			resp.Header.Set(RequestIDHeader, st.reqID)
			filters := append(append([]Filter(nil), rule.Rule.Filters...), ref.Filters...)
			for _, f := range filters {
				if f.Type == "ResponseHeaderModifier" && f.ResponseHeaderModifier != nil {
					applyHeaderMod(resp.Header, f.ResponseHeaderModifier)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			st.errMsg = err.Error()
			code := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}
			w.Header().Set(BackendHeader, ref.Name)
			plain(w, code, "upstream error")
		},
	}
	proxy.ServeHTTP(rec, r)
}

// fireMirrors sends fire-and-forget copies of out to each mirror backend.
func (s *Server) fireMirrors(out *http.Request, body []byte, mirrors []*CMirror) {
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
		client := &http.Client{Transport: s.transport(m.B.Insecure), Timeout: 10 * time.Second}
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
