package gateway

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func obsServer(t *testing.T, mod func(*Options)) (*Server, map[string]*upstream) {
	be, ups := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/ok", ref("a", 1)))}, be), mod)
	return s, ups
}

func logLines(t *testing.T, b *syncBuf) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if ln == "" {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(ln), &v); err != nil {
			t.Fatalf("not JSON: %q", ln)
		}
		out = append(out, v)
	}
	return out
}

var (
	reTrace = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
	reHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func TestAccessLogJSONFields(t *testing.T) {
	var buf syncBuf
	s, _ := obsServer(t, func(o *Options) { o.AccessLog = &buf })
	r := get(t, s, "x.test", "/ok?q=1")
	s.FlushAccessLog()
	ls := logLines(t, &buf)
	if len(ls) != 1 {
		t.Fatalf("lines %v", ls)
	}
	l := ls[0]
	for _, k := range []string{"time", "listener", "host", "method", "path", "route", "backend", "status", "bytes", "duration_ms", "request_id", "trace_id"} {
		if _, ok := l[k]; !ok {
			t.Errorf("missing %q in %v", k, l)
		}
	}
	if l["path"] != "/ok" || l["status"].(float64) != 200 || l["request_id"] != r.Header.Get("X-Request-Id") {
		t.Errorf("line %v", l)
	}
	if !reHex32.MatchString(l["trace_id"].(string)) {
		t.Errorf("trace id %v", l["trace_id"])
	}
}

func TestAccessLogText(t *testing.T) {
	var buf syncBuf
	s, _ := obsServer(t, func(o *Options) { o.AccessLog = &buf; o.Obs.AccessLogFormat = "text" })
	get(t, s, "x.test", "/ok")
	s.FlushAccessLog()
	out := strings.TrimSpace(buf.String())
	for _, want := range []string{`method="GET"`, `path="/ok"`, `status=200`, `route="t/r"`, `request_id="`, `trace_id="`} {
		if !strings.Contains(out, want) {
			t.Errorf("text log lacks %s: %s", want, out)
		}
	}
	if strings.Count(out, "\n") != 0 {
		t.Errorf("want one line: %q", out)
	}
}

// blockedWriter never returns until released, like a stuck disk.
type blockedWriter struct{ release chan struct{} }

func (w *blockedWriter) Write(p []byte) (int, error) { <-w.release; return len(p), nil }

func TestAccessLogNeverBlocksRequests(t *testing.T) {
	bw := &blockedWriter{release: make(chan struct{})}
	defer close(bw.release) // runs before the server cleanup, which drains the log
	s, _ := obsServer(t, func(o *Options) { o.AccessLog = bw; o.Obs.AccessLogBuffer = 2 })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			if r := get(t, s, "x.test", "/ok"); r.Status != 200 {
				t.Errorf("status %d", r.Status)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("requests stalled behind a blocked access log")
	}
	if d := s.obs.access.dropped.Load(); d < 10 {
		t.Errorf("dropped %d, want at least 10", d)
	}
	rec := httptest.NewRecorder()
	s.metrics(rec, nil)
	if !strings.Contains(rec.Body.String(), "setura_gateway_accesslog_dropped_total ") {
		t.Errorf("metrics lack drop counter:\n%s", rec.Body)
	}
}

func TestTracePropagation(t *testing.T) {
	s, ups := obsServer(t, nil)
	// no incoming context: one is generated and forwarded
	r := get(t, s, "x.test", "/ok")
	tp := r.Echo.Headers["traceparent"]
	if !reTrace.MatchString(tp) || !strings.HasSuffix(tp, "-01") {
		t.Fatalf("generated traceparent %q", tp)
	}
	if rid := r.Header.Get("X-Request-Id"); rid == "" || r.Echo.Headers["x-request-id"] != rid {
		t.Fatalf("request id: response %q backend %q", rid, r.Echo.Headers["x-request-id"])
	}
	// incoming context: same trace id, new span id, flags and tracestate kept
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
	r = get(t, s, "x.test", "/ok", "Traceparent", in, "Tracestate", "k=v", "X-Request-Id", "abc-123")
	out := r.Echo.Headers["traceparent"]
	if !reTrace.MatchString(out) || !strings.HasPrefix(out, "00-4bf92f3577b34da6a3ce929d0e0e4736-") || strings.Contains(out, "00f067aa0ba902b7") || !strings.HasSuffix(out, "-00") {
		t.Fatalf("continued traceparent %q", out)
	}
	if r.Echo.Headers["tracestate"] != "k=v" || r.Header.Get("X-Request-Id") != "abc-123" || r.Echo.Headers["x-request-id"] != "abc-123" {
		t.Fatalf("passthrough: %v / %v", r.Echo.Headers, r.Header)
	}
	// invalid context is replaced, not forwarded
	r = get(t, s, "x.test", "/ok", "Traceparent", "garbage", "Tracestate", "x=y")
	if tp := r.Echo.Headers["traceparent"]; !reTrace.MatchString(tp) || r.Echo.Headers["tracestate"] != "" {
		t.Fatalf("invalid input: %q %q", tp, r.Echo.Headers["tracestate"])
	}
	// the gateway's own errors carry a request id too
	if r = get(t, s, "x.test", "/nope"); r.Status != 404 || r.Header.Get("X-Request-Id") == "" {
		t.Fatalf("404 reply %d %v", r.Status, r.Header)
	}
	if n := len(ups["a"].seen()); n != 3 {
		t.Fatalf("backend saw %d", n)
	}
}

func TestParseTraceparent(t *testing.T) {
	good := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if _, _, _, ok := parseTraceparent(good); !ok {
		t.Fatal("good rejected")
	}
	for _, bad := range []string{"", "00-00000000000000000000000000000000-00f067aa0ba902b7-01", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", good + "-x"} {
		if _, _, _, ok := parseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestOTLPExport(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	got := make(chan struct{}, 8)
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("collector got %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		got <- struct{}{}
	}))
	defer col.Close()
	s, _ := obsServer(t, func(o *Options) { o.Obs.OTLPEndpoint = col.URL; o.Obs.OTLPInterval = 20 * time.Millisecond })
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	get(t, s, "x.test", "/ok", "Traceparent", in)
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no export")
	}
	mu.Lock()
	defer mu.Unlock()
	var doc struct {
		ResourceSpans []struct {
			Resource   struct{ Attributes []map[string]any }
			ScopeSpans []struct {
				Spans []map[string]any
			}
		}
	}
	if err := json.Unmarshal(bodies[0], &doc); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, bodies[0])
	}
	sp := doc.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if sp["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" || sp["parentSpanId"] != "00f067aa0ba902b7" || sp["name"] != "GET t/r" || sp["kind"].(float64) != 2 {
		t.Errorf("span %v", sp)
	}
	if len(sp["spanId"].(string)) != 16 || sp["startTimeUnixNano"] == "" || sp["endTimeUnixNano"] == "" {
		t.Errorf("span ids/times %v", sp)
	}
	if !strings.Contains(string(bodies[0]), `"stringValue":"setura-gateway"`) || !strings.Contains(string(bodies[0]), `"http.response.status_code","value":{"intValue":"200"}`) {
		t.Errorf("attributes missing: %s", bodies[0])
	}
}

func TestOTLPDownCollectorNeverBlocks(t *testing.T) {
	col := httptest.NewServer(http.NotFoundHandler())
	url := col.URL
	col.Close() // connection refused from now on
	s, _ := obsServer(t, func(o *Options) { o.Obs.OTLPEndpoint = url; o.Obs.OTLPInterval = 10 * time.Millisecond })
	for i := 0; i < 5; i++ {
		if r := get(t, s, "x.test", "/ok"); r.Status != 200 {
			t.Fatalf("status %d", r.Status)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.obs.otlp.dropped.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if d := s.obs.otlp.dropped.Load(); d != 5 {
		t.Errorf("dropped %d, want 5", d)
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func rlServer(t *testing.T, key string, burst int) (*Server, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := obsServer(t, func(o *Options) {
		o.Obs.RateLimit = RateLimitConfig{Rate: 1, Per: time.Second, Burst: burst, Key: key}
		o.Obs.Now = clk.now
	})
	return s, clk
}

func TestRateLimitBurstRefillAndRetryAfter(t *testing.T) {
	s, clk := rlServer(t, "ip", 2)
	for i := 0; i < 2; i++ {
		if r := get(t, s, "x.test", "/ok"); r.Status != 200 {
			t.Fatalf("request %d: %d", i, r.Status)
		}
	}
	r := get(t, s, "x.test", "/ok")
	if r.Status != 429 || r.Header.Get("Retry-After") != "1" || r.Header.Get("X-Request-Id") == "" {
		t.Fatalf("limited reply %d %v", r.Status, r.Header)
	}
	clk.add(500 * time.Millisecond)
	if r = get(t, s, "x.test", "/ok"); r.Status != 429 || r.Header.Get("Retry-After") != "1" {
		t.Fatalf("half refill %d %v", r.Status, r.Header)
	}
	clk.add(500 * time.Millisecond)
	if r = get(t, s, "x.test", "/ok"); r.Status != 200 {
		t.Fatalf("after refill %d", r.Status)
	}
	// unmatched requests are not limited (no route)
	for i := 0; i < 4; i++ {
		if r = get(t, s, "x.test", "/nope"); r.Status != 404 {
			t.Fatalf("unmatched %d", r.Status)
		}
	}
	rec := httptest.NewRecorder()
	s.metrics(rec, nil)
	body := rec.Body.String()
	for _, want := range []string{`setura_gateway_ratelimit_limited_total{route="t/r"} 2`, "setura_gateway_ratelimit_allowed_total 3",
		`setura_gateway_route_requests_total{route="t/r",code="4xx"} 2`, "# TYPE setura_gateway_requests_total counter"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
}

func TestRateLimitRetryAfterSlowRate(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, _ := obsServer(t, func(o *Options) {
		o.Obs.RateLimit = RateLimitConfig{Rate: 6, Per: time.Minute, Burst: 1, Key: "route"}
		o.Obs.Now = clk.now
	})
	get(t, s, "x.test", "/ok")
	if r := get(t, s, "x.test", "/ok"); r.Status != 429 || r.Header.Get("Retry-After") != "10" {
		t.Fatalf("%d %v", r.Status, r.Header)
	}
}

func TestRateLimitHeaderKey(t *testing.T) {
	s, _ := rlServer(t, "header:X-Api-Key", 1)
	for _, k := range []string{"alice", "bob"} {
		if r := get(t, s, "x.test", "/ok", "X-Api-Key", k); r.Status != 200 {
			t.Fatalf("%s first: %d", k, r.Status)
		}
	}
	if r := get(t, s, "x.test", "/ok", "X-Api-Key", "alice"); r.Status != 429 {
		t.Fatalf("alice second: %d", r.Status)
	}
	// without the header the client IP is the key, with its own bucket
	if r := get(t, s, "x.test", "/ok"); r.Status != 200 {
		t.Fatalf("anon first: %d", r.Status)
	}
	if r := get(t, s, "x.test", "/ok"); r.Status != 429 {
		t.Fatalf("anon second: %d", r.Status)
	}
}

func TestRateLimitPerRouteIsolation(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r1": route("", rule("/one", ref("a", 1))), "r2": route("", rule("/two", ref("b", 1)))}, be),
		func(o *Options) {
			o.Obs.RateLimit = RateLimitConfig{Rate: 1, Burst: 1, Key: "route"}
			o.Obs.Now = clk.now
		})
	if get(t, s, "x.test", "/one").Status != 200 || get(t, s, "x.test", "/one").Status != 429 {
		t.Fatal("route one should admit then limit")
	}
	if get(t, s, "x.test", "/two").Status != 200 {
		t.Fatal("route two must have its own bucket")
	}
}

func TestRateLimitConcurrentIsExact(t *testing.T) {
	s, _ := rlServer(t, "route", 5)
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := get(t, s, "x.test", "/ok")
			mu.Lock()
			counts[r.Status]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts[200] != 5 || counts[429] != 15 {
		t.Fatalf("counts %v", counts)
	}
}

func TestParseRateAndFlags(t *testing.T) {
	for in, want := range map[string]time.Duration{"100/s": time.Second, "30/m": time.Minute, "5/h": time.Hour, "7": time.Second} {
		if _, per, err := ParseRate(in); err != nil || per != want {
			t.Errorf("%s: %v %v", in, per, err)
		}
	}
	for _, bad := range []string{"0/s", "-1/s", "x/s", "5/d", ""} {
		if _, _, err := ParseRate(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	parse := func(args ...string) (Options, error) {
		var rf runFlags
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		addRunFlags(fs, &rf)
		if err := fs.Parse(args); err != nil {
			return rf.opts, err
		}
		_, err := rf.finish(io.Discard, io.Discard, nil)
		return rf.opts, err
	}
	o, err := parse("--rate-limit", "100/s", "--rate-burst", "200", "--rate-key", "header:X-Key", "--access-log-format", "text", "--otlp-endpoint", "127.0.0.1:4318")
	if err != nil {
		t.Fatal(err)
	}
	if rl := o.Obs.RateLimit; rl.Rate != 100 || rl.Burst != 200 || rl.Key != "header:X-Key" || o.Obs.AccessLogFormat != "text" || o.Obs.OTLPEndpoint != "127.0.0.1:4318" {
		t.Errorf("opts %+v", o.Obs)
	}
	for _, bad := range [][]string{{"--rate-limit", "5/s", "--rate-key", "cookie"}, {"--access-log-format", "xml"}, {"--rate-limit", "nope"}} {
		if _, err := parse(bad...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestOTLPURL(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1:4318": "http://127.0.0.1:4318/v1/traces", "http://c:4318": "http://c:4318/v1/traces", "https://c/x/y": "https://c/x/y"} {
		if got := otlpURL(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
}
