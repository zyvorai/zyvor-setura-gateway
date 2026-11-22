package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// flaky is a real backend whose status can be flipped at runtime.
type flaky struct {
	*httptest.Server
	status atomic.Int32
	hits   atomic.Int32
	mu     sync.Mutex
	bodies []string
}

func newFlaky(t *testing.T, status int) *flaky {
	f := &flaky{}
	f.status.Store(int32(status))
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(int(f.status.Load()))
			return
		}
		f.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		f.mu.Unlock()
		w.WriteHeader(int(f.status.Load()))
		io.WriteString(w, "ok")
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *flaky) addr() string { return strings.TrimPrefix(f.URL, "http://") }

// deadAddr returns an address nothing listens on.
func deadAddr(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	a := strings.TrimPrefix(s.URL, "http://")
	s.Close()
	return a
}

func retryRoute(codes []int, attempts int, backoff string) m {
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"codes": codes, "attempts": attempts, "backoff": backoff}
	return route("", rl)
}

func svcBackend(addrs ...string) map[string]any {
	eps := l{}
	for _, a := range addrs {
		eps = append(eps, a)
	}
	return map[string]any{"svc": m{"endpoints": eps}}
}

type sleepRec struct {
	mu sync.Mutex
	ds []time.Duration
}

func (s *sleepRec) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.ds = append(s.ds, d)
	s.mu.Unlock()
	return nil
}
func (s *sleepRec) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ds) }

func resOpts(c *fakeClock, sl *sleepRec, mod func(*ResilienceOptions)) func(*Options) {
	return func(o *Options) {
		o.Resilience.Now = c.Now
		o.Resilience.Sleep = sl.sleep
		o.Resilience.RetryHeader = true
		if mod != nil {
			mod(&o.Resilience)
		}
	}
}

func TestRetryStatusGoesToOtherEndpoint(t *testing.T) {
	bad, good := newFlaky(t, 503), newFlaky(t, 200)
	c, sl := newClock(), &sleepRec{}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute([]int{503}, 2, "10ms")}, svcBackend(bad.addr(), good.addr())), resOpts(c, sl, nil))
	r := get(t, s, "x.test", "/")
	if r.Status != 200 || r.Header.Get(RetryHeaderName) != "1" {
		t.Fatalf("status %d retries %q, want 200 and 1", r.Status, r.Header.Get(RetryHeaderName))
	}
	if bad.hits.Load() != 1 || good.hits.Load() != 1 {
		t.Errorf("hits bad=%d good=%d, want 1 and 1", bad.hits.Load(), good.hits.Load())
	}
	if sl.count() != 1 || sl.ds[0] != 10*time.Millisecond {
		t.Errorf("backoff sleeps = %v, want one of 10ms", sl.ds)
	}
	var out bytes.Buffer
	s.WriteMetrics(&out)
	if !strings.Contains(out.String(), `setura_gateway_retries_total{backend="t/svc:80"} 1`) {
		t.Errorf("metrics missing retry counter:\n%s", out.String())
	}
}

func TestRetryHeaderOffByDefault(t *testing.T) {
	bad, good := newFlaky(t, 503), newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute([]int{503}, 2, "0s")}, svcBackend(bad.addr(), good.addr())), nil)
	r := get(t, s, "x.test", "/")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	if _, ok := r.Header[RetryHeaderName]; ok {
		t.Error("X-Setura-Retries present without the option")
	}
}

func TestRetryConnectErrorReplaysPostBody(t *testing.T) {
	good := newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute(nil, 1, "0s")}, svcBackend(deadAddr(t), good.addr())), resOpts(newClock(), &sleepRec{}, nil))
	r := req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/", "payload")
	if r.Status != 200 || r.Header.Get(RetryHeaderName) != "1" {
		t.Fatalf("status %d retries %q", r.Status, r.Header.Get(RetryHeaderName))
	}
	if len(good.bodies) != 1 || good.bodies[0] != "payload" {
		t.Errorf("replayed body = %q, want payload", good.bodies)
	}
}

func TestRetryNonIdempotentNotRetriedOnStatus(t *testing.T) {
	bad, good := newFlaky(t, 503), newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute([]int{503}, 2, "0s")}, svcBackend(bad.addr(), good.addr())), resOpts(newClock(), &sleepRec{}, nil))
	r := req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/", "x")
	if r.Status != 503 || good.hits.Load() != 0 {
		t.Fatalf("POST status %d good hits %d, want 503 and 0", r.Status, good.hits.Load())
	}
}

func TestRetrySkippedWhenBodyTooLarge(t *testing.T) {
	good := newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute(nil, 1, "0s")}, svcBackend(deadAddr(t), good.addr())),
		resOpts(newClock(), &sleepRec{}, func(o *ResilienceOptions) { o.RetryBodyLimit = 8 }))
	r := req(t, client(s.Addr(8080), nil), "http", "PUT", "x.test", "/", strings.Repeat("a", 100))
	if r.Status != 502 || good.hits.Load() != 0 {
		t.Fatalf("status %d good hits %d, want 502 and 0 (body not replayable)", r.Status, good.hits.Load())
	}
}

func TestRetryBudgetCapsAmplification(t *testing.T) {
	bad := newFlaky(t, 503)
	c, sl := newClock(), &sleepRec{}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute([]int{503}, 5, "0s")}, svcBackend(bad.addr())),
		resOpts(c, sl, func(o *ResilienceOptions) { o.OutlierFailures = -1; o.RetryBudgetMin = 1 }))
	const n = 20
	for i := 0; i < n; i++ {
		if r := get(t, s, "x.test", "/"); r.Status != 503 {
			t.Fatalf("status %d", r.Status)
		}
	}
	retries := int(bad.hits.Load()) - n
	if limit := n * 20 / 100; retries > limit || retries < 1 {
		t.Errorf("retries = %d, want between 1 and %d (20%% of %d requests)", retries, limit, n)
	}
	var out bytes.Buffer
	s.WriteMetrics(&out)
	if !strings.Contains(out.String(), "setura_gateway_retries_denied_total{backend=\"t/svc:80\"}") {
		t.Errorf("denied counter missing:\n%s", out.String())
	}
}

func TestBudgetWindowSlides(t *testing.T) {
	c := newClock()
	b := &budget{width: time.Second}
	for i := 0; i < 10; i++ {
		b.request(c.Now())
	}
	if !b.tryRetry(c.Now(), 20, 0) || !b.tryRetry(c.Now(), 20, 0) || b.tryRetry(c.Now(), 20, 0) {
		t.Fatal("want exactly 2 retries for 10 requests at 20%")
	}
	c.Advance(11 * time.Second) // whole window has slid away
	if b.tryRetry(c.Now(), 20, 0) {
		t.Error("retry allowed with no recent requests and no floor")
	}
	if !b.tryRetry(c.Now(), 20, 1) {
		t.Error("floor of 1 should allow a retry")
	}
}

func TestRetryRespectsRequestTimeout(t *testing.T) {
	bad := newFlaky(t, 503)
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"codes": l{503}, "attempts": 3, "backoff": "1h"}
	rl["timeouts"] = m{"request": "5s"}
	sl := &sleepRec{}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend(bad.addr())), resOpts(newClock(), sl, nil))
	if r := get(t, s, "x.test", "/"); r.Status != 503 {
		t.Fatalf("status %d, want the 503 returned as is", r.Status)
	}
	if sl.count() != 0 || bad.hits.Load() != 1 {
		t.Errorf("slept %d times, hits %d; a backoff beyond the deadline must not be waited for", sl.count(), bad.hits.Load())
	}
}

func TestInvalidRetryRuleRejected(t *testing.T) {
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"codes": l{200}}
	cfg, err := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend("127.0.0.1:1")), "")
	if err != nil {
		t.Fatal(err)
	}
	tb := BuildTable(cfg)
	if got := tb.routes[0].Parents[0].Accepted; got.OK || got.Reason != "UnsupportedValue" {
		t.Errorf("route accepted with bad retry codes: %+v", got)
	}
}

func testBackend(t *testing.T, s *Server, n int) *Backend {
	t.Helper()
	b := s.Table().Backends["t/svc:80"]
	if b == nil || len(b.Eps) != n {
		t.Fatalf("backend not as expected: %+v", b)
	}
	return b
}

func TestOutlierEjectionBackoffAndLastHealthy(t *testing.T) {
	a, b := newFlaky(t, 200), newFlaky(t, 200)
	c := newClock()
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(a.addr(), b.addr())),
		resOpts(c, &sleepRec{}, func(o *ResilienceOptions) {
			o.OutlierFailures, o.OutlierBaseEject, o.OutlierMaxEject = 3, time.Minute, 3*time.Minute
		}))
	be := testBackend(t, s, 2)
	ea, eb := be.Eps[0], be.Eps[1]
	fail := func(e *Endpoint, n int) {
		for i := 0; i < n; i++ {
			s.res.observe(be, e, true, c.Now())
		}
	}
	fail(ea, 2)
	if !be.up(ea, c.Now()) {
		t.Fatal("ejected before reaching the threshold")
	}
	fail(ea, 1)
	if be.up(ea, c.Now()) {
		t.Fatal("not ejected after 3 consecutive failures")
	}
	for i := 0; i < 10; i++ {
		if be.choose(c.Now(), nil) != eb {
			t.Fatal("ejected endpoint was chosen")
		}
	}
	fail(eb, 10) // eb is the last healthy one
	if !be.up(eb, c.Now()) {
		t.Fatal("last healthy endpoint was ejected")
	}
	c.Advance(61 * time.Second)
	if !be.up(ea, c.Now()) {
		t.Fatal("endpoint not readmitted after the backoff")
	}
	fail(ea, 3) // second ejection doubles
	c.Advance(61 * time.Second)
	if be.up(ea, c.Now()) {
		t.Fatal("second ejection should last 2 minutes")
	}
	c.Advance(60 * time.Second)
	if !be.up(ea, c.Now()) {
		t.Fatal("second ejection should have ended after 2 minutes")
	}
	fail(ea, 3) // third: 4 min capped at 3
	c.Advance(179 * time.Second)
	if be.up(ea, c.Now()) {
		t.Fatal("third ejection ended before the 3 minute cap")
	}
	c.Advance(2 * time.Second)
	if !be.up(ea, c.Now()) {
		t.Fatal("third ejection exceeded the cap")
	}
	var out bytes.Buffer
	s.WriteMetrics(&out)
	if !strings.Contains(out.String(), `setura_gateway_ejections_total{backend="t/svc:80"} 3`) {
		t.Errorf("ejection counter wrong:\n%s", out.String())
	}
}

func TestPassiveEjectionEndToEnd(t *testing.T) {
	bad, good := newFlaky(t, 500), newFlaky(t, 200)
	c := newClock()
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(bad.addr(), good.addr())),
		resOpts(c, &sleepRec{}, func(o *ResilienceOptions) { o.OutlierFailures = 3 }))
	for i := 0; i < 6; i++ { // alternates: bad gets exactly 3 failures
		get(t, s, "x.test", "/")
	}
	if bad.hits.Load() != 3 {
		t.Fatalf("bad hits = %d, want 3", bad.hits.Load())
	}
	for i := 0; i < 20; i++ {
		if r := get(t, s, "x.test", "/"); r.Status != 200 {
			t.Fatalf("request %d got %d after ejection", i, r.Status)
		}
	}
	if bad.hits.Load() != 3 {
		t.Errorf("ejected endpoint still received traffic (%d hits)", bad.hits.Load())
	}
	// Recovery: backend heals, ejection expires, traffic returns.
	bad.status.Store(200)
	c.Advance(31 * time.Second)
	for i := 0; i < 4; i++ {
		get(t, s, "x.test", "/")
	}
	if bad.hits.Load() == 3 {
		t.Error("endpoint never readmitted after the ejection expired")
	}
}

func TestWeightsRenormaliseAroundUnavailableBackend(t *testing.T) {
	_, ups := upstreams(t, "a", "b")
	be := map[string]any{"a": ups["a"].addr(), "b": ups["b"].addr()}
	r := route("", rule("/", ref("a", 1), ref("b", 99)))
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": r}, be), nil)
	tb := s.Table()
	tb.Backends["t/b:80"].Eps[0].healthy.Store(false)
	for i := 0; i < 30; i++ {
		if got := get(t, s, "x.test", "/").Header.Get(BackendHeader); got != "a" {
			t.Fatalf("request %d went to %q; b is down so a must take the whole share", i, got)
		}
	}
	tb.Backends["t/b:80"].Eps[0].healthy.Store(true)
	tb.Backends["t/a:80"].Eps[0].healthy.Store(false)
	for i := 0; i < 30; i++ {
		if got := get(t, s, "x.test", "/").Header.Get(BackendHeader); got != "b" {
			t.Fatalf("request %d went to %q, want b", i, got)
		}
	}
	tb.Backends["t/b:80"].Eps[0].healthy.Store(false) // everything down: still attempt
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Errorf("all-down fallback status %d", r.Status)
	}
}

func TestActiveHealthThresholds(t *testing.T) {
	f := newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(f.addr())), nil)
	b := testBackend(t, s, 1)
	ep := b.Eps[0]
	hc := &healthConfig{path: "/health", timeout: time.Second, unhealthy: 2, healthy: 2}
	cl := &http.Client{Timeout: time.Second}
	probe := func() { s.checkEndpoint(context.Background(), cl, hc, b, ep) }

	f.status.Store(500)
	probe()
	if !ep.healthy.Load() {
		t.Fatal("marked down after 1 failure with threshold 2")
	}
	probe()
	if ep.healthy.Load() {
		t.Fatal("still up after 2 failures")
	}
	f.status.Store(200)
	probe()
	if ep.healthy.Load() {
		t.Fatal("marked up after 1 success with threshold 2")
	}
	probe()
	if !ep.healthy.Load() {
		t.Fatal("still down after 2 successes")
	}
	f.status.Store(500)
	probe()
	f.status.Store(200)
	probe() // a pass resets the failure streak
	f.status.Store(500)
	probe()
	if !ep.healthy.Load() {
		t.Error("non-consecutive failures must not mark the endpoint down")
	}
}

func TestDefaultHealthPathOptionRecovers(t *testing.T) {
	bad, good := newFlaky(t, 500), newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(bad.addr(), good.addr())),
		func(o *Options) {
			o.Resilience.HealthPath, o.Resilience.HealthInterval = "/health", 5*time.Millisecond
		})
	b := testBackend(t, s, 2)
	waitFor(t, "bad endpoint to be marked down", func() bool { return !b.Eps[0].healthy.Load() })
	bad.status.Store(200)
	waitFor(t, "bad endpoint to recover", func() bool { return b.Eps[0].healthy.Load() })
	var out bytes.Buffer
	s.WriteMetrics(&out)
	if !strings.Contains(out.String(), `setura_gateway_endpoint_healthy{backend="t/svc:80",endpoint="`+bad.addr()+`"} 1`) {
		t.Errorf("health gauge missing:\n%s", out.String())
	}
}

func TestMetricsEndpointOnAdmin(t *testing.T) {
	good := newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(good.addr())),
		func(o *Options) { o.Admin = "127.0.0.1:0" })
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + s.AdminAddr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"# TYPE setura_gateway_retries_total counter", "# TYPE setura_gateway_endpoint_healthy gauge", `setura_gateway_endpoint_ejected{backend="t/svc:80"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("/metrics missing %q:\n%s", want, b)
		}
	}
}
