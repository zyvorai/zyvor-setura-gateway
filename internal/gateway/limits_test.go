package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func annotated(r m, ann m) m {
	r["setura.zyvor.dev/annotations"] = ann
	return r
}

func TestDirectResponseRule(t *testing.T) {
	be, ups := upstreams(t, "a")
	deny := rule("/internal")
	deny["setura.zyvor.dev/direct-response"] = m{"status": 404, "body": "nothing here\n", "headers": m{"X-Blocked": "yes", "Cache-Control": "no-store"}}
	deny["filters"] = l{m{"type": "ResponseHeaderModifier", "responseHeaderModifier": hmod("X-Mod=1", "", "")}}
	delete(deny, "backendRefs")
	health := rule("/healthz")
	delete(health, "backendRefs")
	routes := map[string]m{"r": annotated(route("a.test", deny, health, rule("/", ref("a", 1))),
		m{"setura.zyvor.dev/direct-response.rule-2": `{"status":200,"body":"ok"}`})}
	var log bytes.Buffer
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.AccessLog = &log })

	r := get(t, s, "a.test", "/internal/x")
	if r.Status != 404 || r.Body != "nothing here\n" || r.Header.Get("X-Blocked") != "yes" || r.Header.Get("X-Mod") != "1" ||
		r.Header.Get("Content-Type") != "text/plain; charset=utf-8" || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("direct response: %d %q %v", r.Status, r.Body, r.Header)
	}
	if r.Header.Get(RequestIDHeader) == "" {
		t.Error("direct responses carry the request id")
	}
	if r := get(t, s, "a.test", "/healthz"); r.Status != 200 || r.Body != "ok" {
		t.Errorf("annotation rule-2: %d %q", r.Status, r.Body)
	}
	if r := req(t, client(s.Addr(8080), nil), "http", "HEAD", "a.test", "/internal", ""); r.Status != 404 || r.Body != "" {
		t.Errorf("HEAD: %d %q", r.Status, r.Body)
	}
	if r := get(t, s, "a.test", "/other"); r.Status != 200 || r.Echo.Name != "a" {
		t.Errorf("other path should still be proxied: %d %+v", r.Status, r.Echo)
	}
	if n := len(ups["a"].seen()); n != 1 {
		t.Errorf("backend saw %d requests, want 1 (only /other)", n)
	}
	s.FlushAccessLog()
	if !strings.Contains(log.String(), `"status":404`) {
		t.Errorf("access log lacks the 404:\n%s", log.String())
	}
}

func TestDirectResponseRouteWideAnnotationAndErrors(t *testing.T) {
	be, _ := upstreams(t, "a")
	only := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/"}}}}
	good := map[string]m{"r": annotated(route("a.test", only), m{"setura.zyvor.dev/direct-response": `{"status":403}`})}
	s := startServer(t, snap(httpGateway(""), good, be), nil)
	if r := get(t, s, "a.test", "/anything"); r.Status != 403 || r.Body != "" {
		t.Errorf("route wide: %d %q", r.Status, r.Body)
	}
	for name, ann := range map[string]string{
		"status":  `{"status":99}`,
		"unknown": `{"status":404,"nope":1}`,
		"nobody":  `{"status":204,"body":"x"}`,
		"header":  `{"status":404,"headers":{"Content-Length":"3"}}`,
		"json":    `{`,
	} {
		bad := map[string]m{"r": annotated(route("a.test", only), m{"setura.zyvor.dev/direct-response": ann})}
		cfg, err := ParseConfig(snap(httpGateway(""), bad, be), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		tb := BuildTable(cfg)
		if len(tb.routes) != 1 || tb.routes[0].Parents[0].Accepted.OK {
			t.Errorf("%s: an invalid block must make the route invalid", name)
		}
	}
	// a direct-response rule with backendRefs is a conflict, not a silent choice
	both := rule("/", ref("a", 1))
	both["setura.zyvor.dev/direct-response"] = m{"status": 404}
	cfg, _ := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("a.test", both)}, be), t.TempDir())
	if tb := BuildTable(cfg); tb.routes[0].Parents[0].Accepted.OK {
		t.Error("direct-response with backendRefs must be refused")
	}
}

func TestDirectResponseWhyAndReplay(t *testing.T) {
	be, _ := upstreams(t, "a")
	deny := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/internal"}}}, "setura.zyvor.dev/direct-response": m{"status": 403, "body": "no", "headers": m{"X-Why": "x"}}}
	raw := snap(httpGateway(""), map[string]m{"r": route("a.test", deny, rule("/", ref("a", 1)))}, be)
	tb, err := ParseReplayConfig(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseExplainRequest("GET", "http://a.test:8080/internal/x", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	tr := Explain(tb, q)
	if tr.Verdict != VerdictDirect || tr.Winner == nil || tr.Winner.Direct == nil || tr.Winner.Direct.Status != 403 || tr.Winner.Direct.Headers["X-Why"] != "x" || tr.Winner.Direct.Body != "no" {
		t.Fatalf("explain: %s %+v", tr.Verdict, tr.Winner)
	}
	d := tb.Resolve(ReqSpec{Host: "a.test", Method: "GET", Path: "/internal/x"})
	if d.Outcome != OutcomeDirect || d.Status != 403 || !strings.Contains(d.String(), "direct response 403") {
		t.Errorf("replay: %+v", d)
	}
	if d := tb.Resolve(ReqSpec{Host: "a.test", Method: "GET", Path: "/ok"}); d.Outcome != OutcomeRouted {
		t.Errorf("replay other path: %+v", d)
	}
}

func TestRouteRateLimit(t *testing.T) {
	be, _ := upstreams(t, "a")
	lim := rule("/limited", ref("a", 1))
	lim["setura.zyvor.dev/rate-limit"] = m{"rate": "1/s", "burst": 2, "key": "header:X-Tenant"}
	whole := rule("/shared", ref("a", 1))
	whole["setura.zyvor.dev/rate-limit"] = m{"rate": 1, "burst": 1, "key": "route"}
	routes := map[string]m{"r": route("a.test", lim, whole, rule("/", ref("a", 1)))}
	raw := snap(httpGateway(""), routes, be)
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	var log bytes.Buffer
	s := startServer(t, raw, func(o *Options) { o.Obs.Now = clk.now; o.AccessLog = &log })

	st := func(path, tenant string) reply { return get(t, s, "a.test", path, "X-Tenant", tenant) }
	for i := 0; i < 2; i++ {
		if r := st("/limited", "t1"); r.Status != 200 {
			t.Fatalf("request %d: %d", i, r.Status)
		}
	}
	r := st("/limited", "t1")
	if r.Status != 429 || r.Header.Get("Retry-After") != "1" {
		t.Errorf("third request: %d retry-after %q", r.Status, r.Header.Get("Retry-After"))
	}
	if r := st("/limited", "t2"); r.Status != 200 {
		t.Errorf("another tenant has its own bucket: %d", r.Status)
	}
	if r := st("/", "t1"); r.Status != 200 {
		t.Errorf("rules without a limit are unaffected: %d", r.Status)
	}
	// key route: one bucket for everyone
	if r := st("/shared", "a"); r.Status != 200 {
		t.Errorf("shared first: %d", r.Status)
	}
	if r := st("/shared", "b"); r.Status != 429 {
		t.Errorf("shared second: %d", r.Status)
	}
	// a reload with the same config keeps the buckets, the clock refills them
	cfg, _ := ParseConfig(raw, t.TempDir())
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h2"}); err != nil {
		t.Fatal(err)
	}
	if r := st("/limited", "t1"); r.Status != 429 {
		t.Errorf("reload must not refill the bucket: %d", r.Status)
	}
	clk.add(2 * time.Second)
	if r := st("/limited", "t1"); r.Status != 200 {
		t.Errorf("after refill: %d", r.Status)
	}
	var m bytes.Buffer
	s.writeObsMetrics(&m)
	for _, want := range []string{
		`setura_gateway_route_ratelimit_limited_total{route="t/r",rule="1"} 2`,
		`setura_gateway_route_ratelimit_limited_total{route="t/r",rule="2"} 1`,
		`setura_gateway_ratelimit_limited_total{route="t/r"} 3`,
	} {
		if !strings.Contains(m.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, m.String())
		}
	}
	s.FlushAccessLog()
	if !strings.Contains(log.String(), "rate limited (route)") {
		t.Errorf("access log should name the route limit:\n%s", log.String())
	}
}

func TestRouteAndGlobalRateLimitBothApply(t *testing.T) {
	be, _ := upstreams(t, "a")
	lim := rule("/", ref("a", 1))
	lim["setura.zyvor.dev/rate-limit"] = m{"rate": "100/s", "burst": 100}
	raw := snap(httpGateway(""), map[string]m{"r": route("a.test", lim)}, be)
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := startServer(t, raw, func(o *Options) {
		o.Obs.Now = clk.now
		o.Obs.RateLimit = RateLimitConfig{Rate: 1, Burst: 1, Key: "route"}
	})
	if r := get(t, s, "a.test", "/"); r.Status != 200 {
		t.Fatalf("first: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/"); r.Status != 429 {
		t.Errorf("the global limit must still apply: %d", r.Status)
	}
}

func TestRouteRateLimitWhy(t *testing.T) {
	be, _ := upstreams(t, "a")
	lim := rule("/", ref("a", 1))
	lim["setura.zyvor.dev/rate-limit"] = m{"rate": "5/s", "burst": 7, "key": "route"}
	tb, err := ParseReplayConfig(snap(httpGateway(""), map[string]m{"r": route("a.test", lim)}, be), "")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := ParseExplainRequest("GET", "http://a.test:8080/", nil, "", "")
	tr := Explain(tb, q)
	if tr.Winner == nil || tr.Winner.RouteLimit == nil || !strings.Contains(tr.Winner.RouteLimit.Policy, "burst 7, key route") {
		t.Fatalf("why lacks the rule limit: %+v", tr.Winner)
	}
	for name, bad := range map[string]m{"rate": {"rate": "x"}, "key": {"rate": "1/s", "key": "cookie"}, "burst": {"rate": "1/s", "burst": -1}, "norate": {"burst": 1}} {
		b := rule("/", ref("a", 1))
		b["setura.zyvor.dev/rate-limit"] = bad
		cfg, _ := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("a.test", b)}, be), t.TempDir())
		if BuildTable(cfg).routes[0].Parents[0].Accepted.OK {
			t.Errorf("%s: invalid rate limit accepted", name)
		}
	}
}

func TestMaxRequestBody(t *testing.T) {
	be, ups := upstreams(t, "a")
	big := rule("/big", ref("a", 1))
	big["setura.zyvor.dev/limits"] = m{"maxRequestBody": "1KB"}
	free := rule("/free", ref("a", 1))
	free["setura.zyvor.dev/limits"] = m{"maxRequestBody": "unlimited"}
	routes := map[string]m{"r": route("a.test", big, free, rule("/", ref("a", 1)))}
	var log bytes.Buffer
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Limits.MaxBodyBytes = 10; o.AccessLog = &log })
	c := client(s.Addr(8080), nil)
	body := strings.Repeat("x", 100)

	if r := req(t, c, "http", "POST", "a.test", "/small", "0123456789"); r.Status != 200 {
		t.Errorf("exactly at the limit: %d", r.Status)
	}
	before := len(ups["a"].seen())
	if r := req(t, c, "http", "POST", "a.test", "/small", body); r.Status != 413 {
		t.Errorf("content-length over the limit: %d", r.Status)
	}
	if len(ups["a"].seen()) != before {
		t.Error("a refused body must not reach the backend")
	}
	// chunked: the length is unknown, the body is cut while streaming
	rq, _ := http.NewRequest("POST", "http://a.test/small", io.NopCloser(strings.NewReader(body)))
	resp, err := c.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Errorf("chunked over the limit: %d", resp.StatusCode)
	}
	if r := req(t, c, "http", "POST", "a.test", "/big", body); r.Status != 200 {
		t.Errorf("rule limit 1KB must allow 100 bytes: %d", r.Status)
	}
	if r := req(t, c, "http", "POST", "a.test", "/free", strings.Repeat("y", 5000)); r.Status != 200 {
		t.Errorf("unlimited rule: %d", r.Status)
	}
	if r := req(t, c, "http", "POST", "a.test", "/big", strings.Repeat("z", 2000)); r.Status != 413 {
		t.Errorf("over the rule limit: %d", r.Status)
	}
	s.FlushAccessLog()
	if !strings.Contains(log.String(), `"status":413`) {
		t.Errorf("access log lacks 413:\n%s", log.String())
	}
}

func TestListenerBodyLimit(t *testing.T) {
	be, _ := upstreams(t, "a")
	gw := httpGateway("")
	gw["listeners"].([]any)[0].(m)["setura.zyvor.dev/limits"] = m{"maxRequestBody": 5}
	s := startServer(t, snap(gw, map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), nil)
	c := client(s.Addr(8080), nil)
	if r := req(t, c, "http", "POST", "a.test", "/", "123456"); r.Status != 413 {
		t.Errorf("listener limit: %d", r.Status)
	}
	if r := req(t, c, "http", "POST", "a.test", "/", "12345"); r.Status != 200 {
		t.Errorf("at the listener limit: %d", r.Status)
	}
}

func rawRequest(t *testing.T, addr, text string) (string, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, text)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line, c
}

func TestMaxHeaderBytes(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) { o.Limits.MaxHeaderBytes = 1024 })
	line, _ := rawRequest(t, s.Addr(8080), "GET / HTTP/1.1\r\nHost: a.test\r\nX-Big: "+strings.Repeat("a", 20000)+"\r\n\r\n")
	if !strings.Contains(line, "431") {
		t.Errorf("oversized headers: %q", line)
	}
	line, _ = rawRequest(t, s.Addr(8080), "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
	if !strings.Contains(line, "200") {
		t.Errorf("small headers: %q", line)
	}
}

func TestHeaderReadAndIdleTimeouts(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) {
		o.Limits.HeaderReadTimeout = 100 * time.Millisecond
		o.Limits.IdleTimeout = 100 * time.Millisecond
	})
	// a client that never finishes its headers is dropped
	_, c := rawRequest(t, "127.0.0.1"+s.Addr(8080)[strings.LastIndex(s.Addr(8080), ":"):], "GET / HTTP/1.1\r\nHost: a.test\r\n")
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Errorf("slow header client: %d %v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("the gateway did not close the slow connection before the test deadline")
	}
	// a keep-alive connection idle past the timeout is closed
	c2, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	br := bufio.NewReader(c2)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if _, err := br.ReadByte(); err == nil {
		t.Error("expected the idle connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("the gateway did not close the idle connection before the test deadline")
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	stalled := make(chan struct{})
	up := httpServerFunc(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		select { // stall until the gateway gives up on us
		case <-r.Context().Done():
			close(stalled)
		case <-time.After(10 * time.Second):
		}
	})
	be := map[string]any{"a": up}
	slow := rule("/", ref("a", 1))
	routes := map[string]m{"r": route("a.test", slow)}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Limits.StreamIdleTimeout = 150 * time.Millisecond })
	resp, err := client(s.Addr(8080), nil).Get("http://a.test/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil || string(b) != "first\n" {
		t.Errorf("the stalled response should be cut after its first chunk: %q err=%v", b, err)
	}
	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Error("the backend request was not cancelled")
	}
}

func TestStreamIdleRuleOverrideLifts(t *testing.T) {
	be, _ := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	r["setura.zyvor.dev/limits"] = m{"streamIdleTimeout": "0"}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), func(o *Options) { o.Limits.StreamIdleTimeout = time.Nanosecond })
	if got := get(t, s, "a.test", "/x"); got.Status != 200 || got.Echo.Name != "a" {
		t.Errorf("rule override 0 must lift the gateway idle timeout: %d %q", got.Status, got.Body)
	}
	for _, bad := range []string{`{"maxRequestBody":"lots"}`, `{"streamIdleTimeout":"soon"}`, `{"unknown":1}`} {
		if _, err := ParseLimitsBlock([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func httpServerFunc(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestPathNormalisation(t *testing.T) {
	be, ups := upstreams(t, "a")
	routes := map[string]m{"r": route("a.test", rule("/api", ref("a", 1)))}
	raw := snap(httpGateway(""), routes, be)

	off := startServer(t, raw, nil)
	for _, p := range []string{"/x/../api/v", "//api/v", "/api%2Fv"} {
		r := get(t, off, "a.test", p)
		if p == "/api%2Fv" {
			if r.Status != 200 {
				t.Errorf("default: %q should pass untouched, got %d", p, r.Status)
			}
			continue
		}
		if r.Status != 404 {
			t.Errorf("default: %q should not match /api, got %d", p, r.Status)
		}
	}

	var log bytes.Buffer
	on := startServer(t, raw, func(o *Options) {
		o.Path = PathOptions{Normalize: true, MergeSlashes: true, RejectEscapedSlashes: true}
		o.AccessLog = &log
	})
	for _, c := range []struct{ in, want string }{
		{"/x/../api/v", "/api/v"}, {"//api///v", "/api/v"}, {"/api/./v/", "/api/v/"}, {"/api/v/..", "/api/"}, {"/%2e%2e/api/v", "/api/v"},
	} {
		r := get(t, on, "a.test", c.in)
		if r.Status != 200 || r.Echo.Path != c.want {
			t.Errorf("%q: status %d, backend saw %q, want %q", c.in, r.Status, r.Echo.Path, c.want)
		}
	}
	for _, p := range []string{"/api%2Fv", "/api%2fv", "/api%5Cv"} {
		if r := get(t, on, "a.test", p); r.Status != 400 {
			t.Errorf("%q: %d, want 400", p, r.Status)
		}
	}
	s := len(ups["a"].seen())
	get(t, on, "a.test", "/api%2Fv")
	if len(ups["a"].seen()) != s {
		t.Error("a rejected path must not reach the backend")
	}
	on.FlushAccessLog()
	if !strings.Contains(log.String(), `"status":400`) {
		t.Errorf("access log lacks the 400:\n%s", log.String())
	}

	// why applies the same options
	tb, _ := ParseReplayConfig(raw, "")
	q, _ := ParseExplainRequest("GET", "http://a.test:8080/x/../api/v", nil, "", "")
	q.Server.Path = PathOptions{Normalize: true}
	if tr := Explain(tb, q); tr.Verdict != VerdictRouted || tr.NormalizedPath != "/api/v" {
		t.Errorf("why: %s %q", tr.Verdict, tr.NormalizedPath)
	}
	q, _ = ParseExplainRequest("GET", "http://a.test:8080/api%2Fv", nil, "", "")
	q.Server.Path = PathOptions{RejectEscapedSlashes: true}
	if tr := Explain(tb, q); tr.Verdict != VerdictBadRequest {
		t.Errorf("why reject: %s", tr.Verdict)
	}
}

func TestRemoveDotSegments(t *testing.T) {
	for in, want := range map[string]string{
		"/": "/", "/a/b": "/a/b", "/a/./b": "/a/b", "/a/../b": "/b", "/../a": "/a", "/a/b/..": "/a/", "/a/.": "/a/", "/a//../b": "/a/b", "/..": "/",
	} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("removeDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
	if got := mergeSlashes("///a//b/"); got != "/a/b/" {
		t.Errorf("mergeSlashes: %q", got)
	}
}

func tlsVersionServer(t *testing.T, mod func(*Options), listenerOpts m) (*Server, *pki) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	ln := tlsListener("a", "a.test", "a-cert")
	if listenerOpts != nil {
		ln["tls"].(m)["options"] = listenerOpts
	}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpsGateway(ln), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}}, "rules": l{rule("/", ref("a", 1))}}},
		"backends":  m{"t/a:80": be["a"]}, "secrets": m{"a-cert": p.files("a", "a.test")}})
	return startServer(t, raw, mod), p
}

func handshake(t *testing.T, s *Server, p *pki, min, max uint16) (uint16, error) {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{RootCAs: p.pool, ServerName: "a.test", MinVersion: min, MaxVersion: max}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", s.Addr(8443))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.(*tls.Conn).ConnectionState().Version, nil
}

func TestTLSVersionBounds(t *testing.T) {
	s, p := tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Min: tls.VersionTLS13} }, nil)
	if v, err := handshake(t, s, p, tls.VersionTLS12, tls.VersionTLS13); err != nil || v != tls.VersionTLS13 {
		t.Errorf("1.3 floor: %x %v", v, err)
	}
	if _, err := handshake(t, s, p, tls.VersionTLS12, tls.VersionTLS12); err == nil {
		t.Error("a TLS 1.2 only client must be refused by --tls-min-version 1.3")
	}
	s, p = tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Max: tls.VersionTLS12} }, nil)
	if v, err := handshake(t, s, p, tls.VersionTLS12, tls.VersionTLS13); err != nil || v != tls.VersionTLS12 {
		t.Errorf("1.2 ceiling: %x %v", v, err)
	}
	if _, err := handshake(t, s, p, tls.VersionTLS13, tls.VersionTLS13); err == nil {
		t.Error("a TLS 1.3 only client must be refused by --tls-max-version 1.2")
	}
}

func TestTLSVersionListenerOptions(t *testing.T) {
	// the listener's options win over the gateway-wide flag
	s, p := tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Min: tls.VersionTLS13} },
		m{TLSMinVersionOption: "1.2", TLSMaxVersionOption: "1.2"})
	if v, err := handshake(t, s, p, tls.VersionTLS12, tls.VersionTLS13); err != nil || v != tls.VersionTLS12 {
		t.Errorf("listener 1.2: %x %v", v, err)
	}
	// min above max, or an unknown version, makes the listener invalid
	for _, o := range []m{{TLSMinVersionOption: "1.3", TLSMaxVersionOption: "1.2"}, {TLSMinVersionOption: "1.1"}} {
		p := newPKI(t)
		be, _ := upstreams(t, "a")
		ln := tlsListener("a", "a.test", "a-cert")
		ln["tls"].(m)["options"] = o
		raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": httpsGateway(ln), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}}, "rules": l{rule("/", ref("a", 1))}}},
			"backends":  m{"t/a:80": be["a"]}, "secrets": m{"a-cert": p.files("a", "a.test")}})
		cfg, err := ParseConfig(raw, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if tb := BuildTable(cfg); tb.Listeners[0].Accepted.OK {
			t.Errorf("%v: listener must be invalid", o)
		}
	}
}

func TestParseTLSVersionAndFlags(t *testing.T) {
	for in, want := range map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13, "TLS1.3": tls.VersionTLS13} {
		if got, err := ParseTLSVersion(in); err != nil || got != want {
			t.Errorf("%s: %x %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1.0", "1.1", "2", "tls"} {
		if _, err := ParseTLSVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, f := range []limitFlags{{tlsMin: "1.3", tlsMax: "1.2"}, {maxBody: "lots"}, {maxHeader: "0"}, {headerRead: -time.Second}, {tlsMin: "9"}} {
		var o Options
		if err := f.apply(&o); err == nil {
			t.Errorf("flags %+v accepted", f)
		}
	}
	var o Options
	f := limitFlags{maxBody: "10MB", maxHeader: "16k", headerRead: time.Second, idle: time.Minute, streamIdle: 30 * time.Second, normalize: true, tlsMin: "1.3"}
	if err := f.apply(&o); err != nil || o.Limits.MaxBodyBytes != 10<<20 || o.Limits.MaxHeaderBytes != 16<<10 || !o.Path.Normalize || o.TLS.Min != tls.VersionTLS13 || o.Limits.StreamIdleTimeout != 30*time.Second {
		t.Errorf("flags: %+v %v", o, err)
	}
}
