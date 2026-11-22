package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func headerSet(name, value string) []any {
	return l{m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{"set": l{m{"name": name, "value": value}}}}}
}

func metricsOf(s *Server) string {
	var b bytes.Buffer
	s.WriteMetrics(&b)
	return b.String()
}

func crossRoute(cross bool) m {
	ra, rb := ref("bad", 1), ref("good", 1)
	ra["filters"], rb["filters"] = headerSet("X-Ref", "bad"), headerSet("X-Ref", "good")
	rl := rule("/", ra, rb)
	rl["retry"] = m{"codes": l{503}, "attempts": 1, "backoff": "0s", "crossBackend": cross}
	return route("", rl)
}

func TestRetryCrossBackendKeepsRefFilters(t *testing.T) {
	bad := newFlaky(t, 503)
	be, ups := upstreams(t, "good")
	be["bad"] = bad.addr()
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": crossRoute(true)}, be), resOpts(newClock(), &sleepRec{}, func(o *ResilienceOptions) { o.RetryBudgetMin = 1000 }))
	retried := 0
	for i := 0; i < 24; i++ {
		r := get(t, s, "x.test", "/")
		if r.Status != 200 || r.Header.Get(BackendHeader) != "good" {
			t.Fatalf("request %d: status %d backend %q, want 200 from good", i, r.Status, r.Header.Get(BackendHeader))
		}
		if got := r.Echo.Headers["x-ref"]; got != "good" {
			t.Fatalf("request %d: the retry carried filters of %q, want those of the ref that served it", i, got)
		}
		if r.Header.Get(RetryHeaderName) == "1" {
			retried++
		}
	}
	if retried == 0 || int(bad.hits.Load()) != retried {
		t.Errorf("retried %d times, bad backend hit %d times; every hit of the failing ref must be retried elsewhere", retried, bad.hits.Load())
	}
	if !strings.Contains(metricsOf(s), `setura_gateway_retries_cross_backend_total{backend="t/bad:80"}`) {
		t.Error("cross-backend retry counter missing")
	}
	_ = ups
}

func TestRetryStaysOnBackendUnlessCrossBackend(t *testing.T) {
	bad := newFlaky(t, 503)
	be, _ := upstreams(t, "good")
	be["bad"] = bad.addr()
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": crossRoute(false)}, be), resOpts(newClock(), &sleepRec{}, nil))
	seen503 := false
	for i := 0; i < 24; i++ {
		seen503 = seen503 || get(t, s, "x.test", "/").Status == 503
	}
	if !seen503 {
		t.Error("without crossBackend a failing single-endpoint ref must still answer 503")
	}
	// The gateway-wide default turns it on for rules that do not say.
	r := crossRoute(false)
	delete(r["rules"].([]m)[0]["retry"].(m), "crossBackend")
	s2 := startServer(t, snap(httpGateway(""), map[string]m{"r": r}, be), resOpts(newClock(), &sleepRec{}, func(o *ResilienceOptions) { o.RetryCrossBackend = true; o.RetryBudgetMin = 1000 }))
	for i := 0; i < 24; i++ {
		if r := get(t, s2, "x.test", "/"); r.Status != 200 {
			t.Fatalf("flag default crossBackend: request %d status %d", i, r.Status)
		}
	}
}

func TestPerTryTimeoutRetriesElsewhere(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); slow.Close() })
	good := newFlaky(t, 200)
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"attempts": 1, "backoff": "0s", "perTryTimeout": "60ms"}
	rl["timeouts"] = m{"request": "5s"}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend(strings.TrimPrefix(slow.URL, "http://"), good.addr())),
		resOpts(newClock(), &sleepRec{}, nil))
	start := time.Now()
	r := get(t, s, "x.test", "/")
	if r.Status != 200 || r.Header.Get(RetryHeaderName) != "1" {
		t.Fatalf("status %d retries %q, want 200 after one retry", r.Status, r.Header.Get(RetryHeaderName))
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v: the per-try timeout did not cut the slow attempt short", time.Since(start))
	}
	if !strings.Contains(metricsOf(s), `setura_gateway_retry_per_try_timeouts_total{backend="t/svc:80"} 1`) {
		t.Errorf("per-try timeout counter missing:\n%s", metricsOf(s))
	}
}

func TestPerTryTimeoutNotRetriedForPOST(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release); slow.Close() })
	good := newFlaky(t, 200)
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"attempts": 2, "backoff": "0s", "perTryTimeout": "60ms"}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend(strings.TrimPrefix(slow.URL, "http://"), good.addr())),
		resOpts(newClock(), &sleepRec{}, nil))
	r := req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/", "body")
	if r.Status != http.StatusGatewayTimeout || good.hits.Load() != 0 {
		t.Fatalf("POST status %d good hits %d, want 504 and no retry (non-idempotent safety)", r.Status, good.hits.Load())
	}
}

func TestRetryBackoffJitter(t *testing.T) {
	bad, good := newFlaky(t, 503), newFlaky(t, 200)
	rl := rule("/", ref("svc", 1))
	rl["retry"] = m{"codes": l{503}, "attempts": 1, "backoff": "100ms", "jitter": 0.5}
	sl := &sleepRec{}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend(bad.addr(), good.addr())), resOpts(newClock(), sl, func(o *ResilienceOptions) { o.RetryBudgetMin = 100 }))
	for i := 0; i < 40; i++ {
		get(t, s, "x.test", "/")
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if len(sl.ds) < 5 {
		t.Fatalf("only %d backoff waits recorded", len(sl.ds))
	}
	distinct := map[time.Duration]bool{}
	for _, d := range sl.ds {
		if d < 50*time.Millisecond || d > 150*time.Millisecond {
			t.Errorf("backoff %v outside 100ms +/- 50%%", d)
		}
		distinct[d] = true
	}
	if len(distinct) < 3 {
		t.Errorf("backoff not jittered: %d distinct values in %d waits", len(distinct), len(sl.ds))
	}
}

func TestRetryRuleRejectsBadNewFields(t *testing.T) {
	for _, bad := range []m{{"perTryTimeout": "soon"}, {"perTryTimeout": "0s"}, {"jitter": 1.5}} {
		rl := rule("/", ref("svc", 1))
		rl["retry"] = bad
		s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, svcBackend("127.0.0.1:1")), nil)
		st := s.Status().Routes["t/r"]
		if st == nil || cond(st.Parents[0].Conditions, "Accepted").Status != "False" {
			t.Errorf("retry %v was accepted", bad)
		}
	}
}

// ---- circuit breaking ----

func cbBackend(addr string, cb m) map[string]any {
	return map[string]any{"svc": m{"endpoints": l{addr}, "circuitBreaker": cb}}
}

func waitMetric(t *testing.T, s *Server, line string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if strings.Contains(metricsOf(s), line) {
			return
		}
	}
	t.Fatalf("metric line %q never appeared:\n%s", line, metricsOf(s))
}

func TestCircuitMaxRequestsAndPending(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-gate
	}))
	t.Cleanup(srv.Close)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))},
		cbBackend(strings.TrimPrefix(srv.URL, "http://"), m{"maxRequests": 1, "maxPending": 1})), nil)
	type res struct{ status int }
	out := make(chan res, 2)
	fire := func() { go func() { out <- res{get(t, s, "x.test", "/").Status} }() }
	fire()
	<-entered
	fire()
	waitMetric(t, s, `setura_gateway_circuit_pending_requests{backend="t/svc:80"} 1`)
	r := get(t, s, "x.test", "/")
	if r.Status != 503 || r.Header.Get(CircuitHeader) != CircuitMaxPending {
		t.Fatalf("third request: status %d circuit %q, want 503 %s", r.Status, r.Header.Get(CircuitHeader), CircuitMaxPending)
	}
	if !strings.Contains(r.Body, "circuit breaker") {
		t.Errorf("body %q does not name the circuit breaker", r.Body)
	}
	close(gate)
	for i := 0; i < 2; i++ {
		if got := <-out; got.status != 200 {
			t.Errorf("queued/in-flight request finished with %d", got.status)
		}
	}
	if !strings.Contains(metricsOf(s), `setura_gateway_circuit_rejected_total{backend="t/svc:80",reason="max_pending"} 1`) {
		t.Errorf("rejected counter missing:\n%s", metricsOf(s))
	}
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Errorf("after the burst the backend is reachable again, got %d", r.Status)
	}
}

func TestCircuitMaxRequestsWithoutQueueRejectsImmediately(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-gate }))
	t.Cleanup(srv.Close)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))},
		cbBackend(strings.TrimPrefix(srv.URL, "http://"), m{"maxRequests": 1})), nil)
	t.Cleanup(func() { close(gate) }) // runs before the server's Close, which would wait for the blocked call
	go get(t, s, "x.test", "/")
	<-entered
	r := get(t, s, "x.test", "/")
	if r.Status != 503 || r.Header.Get(CircuitHeader) != CircuitMaxRequests {
		t.Fatalf("status %d circuit %q, want 503 %s", r.Status, r.Header.Get(CircuitHeader), CircuitMaxRequests)
	}
}

func TestCircuitOpensProbesAndCloses(t *testing.T) {
	f := newFlaky(t, 500)
	c := newClock()
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(f.addr())),
		resOpts(c, &sleepRec{}, func(o *ResilienceOptions) {
			o.OutlierFailures = -1
			o.Circuit = CircuitOptions{FailureThreshold: 3, OpenFor: 10 * time.Second}
		}))
	for i := 0; i < 3; i++ {
		if r := get(t, s, "x.test", "/"); r.Status != 500 {
			t.Fatalf("request %d status %d, want the backend's 500", i, r.Status)
		}
	}
	r := get(t, s, "x.test", "/")
	if r.Status != 503 || r.Header.Get(CircuitHeader) != CircuitOpen || f.hits.Load() != 3 {
		t.Fatalf("status %d circuit %q hits %d, want 503/open and the backend untouched", r.Status, r.Header.Get(CircuitHeader), f.hits.Load())
	}
	if !strings.Contains(metricsOf(s), `setura_gateway_circuit_state{backend="t/svc:80"} 1`) {
		t.Errorf("state gauge should be open:\n%s", metricsOf(s))
	}
	// Half-open: after OpenFor one probe goes through. A failing probe re-opens it.
	c.Advance(11 * time.Second)
	if r := get(t, s, "x.test", "/"); r.Status != 500 || f.hits.Load() != 4 {
		t.Fatalf("probe: status %d hits %d, want the backend's 500 (4th hit)", r.Status, f.hits.Load())
	}
	if r := get(t, s, "x.test", "/"); r.Status != 503 {
		t.Fatalf("a failed probe must re-open the circuit, got %d", r.Status)
	}
	// A successful probe closes it.
	c.Advance(11 * time.Second)
	f.status.Store(200)
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Fatalf("successful probe: %d", r.Status)
	}
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Fatalf("closed circuit: %d", r.Status)
	}
	if got := metricsOf(s); !strings.Contains(got, `setura_gateway_circuit_state{backend="t/svc:80"} 0`) ||
		!strings.Contains(got, `setura_gateway_circuit_opened_total{backend="t/svc:80"} 2`) {
		t.Errorf("metrics after recovery:\n%s", got)
	}
}

func TestBreakerHalfOpenLimitsProbes(t *testing.T) {
	c := newClock()
	rs := newResilience(ResilienceOptions{Now: c.Now})
	bk := rs.breakerFor("k")
	lim := cbLimits{failures: 1, probes: 1, openFor: 5 * time.Second}
	ctx := context.Background()
	tk, err := rs.enter(ctx, bk, lim)
	if err != nil {
		t.Fatal(err)
	}
	tk.done(true, false)
	if _, err := rs.enter(ctx, bk, lim); err == nil {
		t.Fatal("open circuit admitted a request")
	}
	c.Advance(6 * time.Second)
	probe, err := rs.enter(ctx, bk, lim)
	if err != nil {
		t.Fatalf("half-open refused its probe: %v", err)
	}
	if _, err := rs.enter(ctx, bk, lim); err == nil {
		t.Fatal("half-open admitted a second concurrent probe")
	}
	probe.done(false, false)
	if tk, err := rs.enter(ctx, bk, lim); err != nil {
		t.Fatalf("closed after a good probe, got %v", err)
	} else {
		tk.done(false, false)
	}
}

func TestBreakerQueueCancelReleasesSlot(t *testing.T) {
	rs := newResilience(ResilienceOptions{})
	bk := rs.breakerFor("k")
	lim := cbLimits{maxReq: 1, maxPend: 1}
	first, _ := rs.enter(context.Background(), bk, lim)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := rs.enter(ctx, bk, lim); err == nil {
			t.Error("cancelled waiter was admitted")
		}
	}()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		bk.mu.Lock()
		n := len(bk.waiters)
		bk.mu.Unlock()
		if n == 1 {
			break
		}
	}
	cancel()
	wg.Wait()
	first.done(false, false)
	bk.mu.Lock()
	defer bk.mu.Unlock()
	if bk.active != 0 || len(bk.waiters) != 0 {
		t.Errorf("active %d waiters %d after cancel and release, want 0 and 0", bk.active, len(bk.waiters))
	}
}

func TestCircuitMaxConnectionsUsesDedicatedTransport(t *testing.T) {
	s := New(Options{Admin: "off"})
	t.Cleanup(s.Close)
	b := &Backend{Key: "k", Eps: []*Endpoint{{}, {}}}
	if s.transportFor(b, cbLimits{}) != s.transport(false) {
		t.Error("no maxConnections must use the shared transport")
	}
	tr, ok := s.transportFor(b, cbLimits{maxConn: 5}).(*http.Transport)
	if !ok || tr.MaxConnsPerHost != 3 { // 5 over 2 endpoints, rounded up
		t.Fatalf("dedicated transport = %+v", tr)
	}
	if s.transportFor(b, cbLimits{maxConn: 5}) != http.RoundTripper(tr) {
		t.Error("the dedicated transport must be cached")
	}
}

func TestCircuitPerBackendOverridesDefaults(t *testing.T) {
	s := New(Options{Admin: "off", Resilience: ResilienceOptions{Circuit: CircuitOptions{MaxRequests: 10, FailureThreshold: 4}}})
	t.Cleanup(s.Close)
	plain := &Backend{Key: "a"}
	over := &Backend{Key: "b", CB: &CircuitOptions{MaxRequests: 2, FailureThreshold: -1}}
	if l := s.limitsFor(plain); l.maxReq != 10 || l.failures != 4 || l.openFor != 30*time.Second || l.probes != 1 {
		t.Errorf("defaults = %+v", l)
	}
	if l := s.limitsFor(over); l.maxReq != 2 || l.failures != 0 {
		t.Errorf("override = %+v (negative lifts a default)", l)
	}
}

// ---- state across reloads ----

func TestEjectionSurvivesReload(t *testing.T) {
	bad, good := newFlaky(t, 500), newFlaky(t, 200)
	c := newClock()
	mk := func(path string, addrs ...string) *Config {
		cfg, err := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("", rule(path, ref("svc", 1)))}, svcBackend(addrs...)), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off", Rand: seededRand(1),
		Resilience: ResilienceOptions{Now: c.Now, Sleep: (&sleepRec{}).sleep, OutlierFailures: 2}})
	t.Cleanup(s.Close)
	if err := s.Apply(&Loaded{Config: mk("/", bad.addr(), good.addr()), Hash: "1"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		get(t, s, "x.test", "/")
	}
	eject := `setura_gateway_endpoint_ejected{backend="t/svc:80",endpoint="` + bad.addr() + `"} 1`
	if !strings.Contains(metricsOf(s), eject) {
		t.Fatalf("setup: bad endpoint not ejected:\n%s", metricsOf(s))
	}
	hits := bad.hits.Load()

	// A reload that only edits the route keeps the ejection.
	if err := s.Apply(&Loaded{Config: mk("/api", bad.addr(), good.addr()), Hash: "2"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(metricsOf(s), eject) {
		t.Errorf("ejection lost across a reload:\n%s", metricsOf(s))
	}
	for i := 0; i < 6; i++ {
		get(t, s, "x.test", "/api")
	}
	if bad.hits.Load() != hits {
		t.Errorf("the ejected endpoint got traffic after the reload (%d -> %d)", hits, bad.hits.Load())
	}

	// Reordering endpoints and adding a new one keeps the state by address.
	fresh := newFlaky(t, 200)
	if err := s.Apply(&Loaded{Config: mk("/api", good.addr(), fresh.addr(), bad.addr()), Hash: "3"}); err != nil {
		t.Fatal(err)
	}
	got := metricsOf(s)
	if !strings.Contains(got, eject) || !strings.Contains(got, `endpoint="`+fresh.addr()+`"} 0`) {
		t.Errorf("state not keyed by backend+address:\n%s", got)
	}

	// An endpoint that is removed and later comes back starts clean.
	if err := s.Apply(&Loaded{Config: mk("/api", good.addr(), fresh.addr()), Hash: "4"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: mk("/api", good.addr(), bad.addr()), Hash: "5"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(metricsOf(s), eject) {
		t.Errorf("a re-added endpoint must not inherit old ejection state:\n%s", metricsOf(s))
	}
}

func TestStaleDownStateClearedWhenHealthChecksRemoved(t *testing.T) {
	up := newFlaky(t, 503) // /health answers 503: down
	other := newFlaky(t, 200)
	hc := func(on bool) *Config {
		be := m{"endpoints": l{up.addr(), other.addr()}}
		if on {
			be["healthCheck"] = m{"path": "/health", "interval": "20ms"}
		}
		cfg, err := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, map[string]any{"svc": be}), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	t.Cleanup(s.Close)
	s.Apply(&Loaded{Config: hc(true), Hash: "1"})
	waitMetric(t, s, `setura_gateway_endpoint_healthy{backend="t/svc:80",endpoint="`+up.addr()+`"} 0`)
	s.Apply(&Loaded{Config: hc(false), Hash: "2"})
	if !strings.Contains(metricsOf(s), `setura_gateway_endpoint_healthy{backend="t/svc:80",endpoint="`+up.addr()+`"} 1`) {
		t.Errorf("an endpoint marked down by a check that no longer exists must come back:\n%s", metricsOf(s))
	}
}

// ---- resilience block in the config file ----

func resSnap(block m) []byte {
	var doc m
	mustUnmarshal(snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend("127.0.0.1:1")), &doc)
	doc["resilience"] = block
	return mustJSON(doc)
}

func TestResilienceBlockFillsUnsetOptionsAndFlagsWin(t *testing.T) {
	raw := resSnap(m{"retryBudget": 33, "retryJitter": 0.4, "retryCrossBackend": true, "retryHeader": true,
		"outlier": m{"failures": 0}, "health": m{"path": "/hz", "interval": "7s"},
		"circuitBreaker": m{"maxRequests": 9, "failureThreshold": 3, "openFor": "12s"}})
	s := startServer(t, raw, func(o *Options) {
		o.Resilience.RetryBudgetPercent = 50 // an explicit flag beats the file
		o.Resilience.Circuit.MaxRequests = 4
	})
	o := s.res.opt()
	if o.RetryBudgetPercent != 50 || o.RetryJitter != 0.4 || !o.RetryCrossBackend || !o.RetryHeader {
		t.Errorf("retry options = %+v", o)
	}
	if o.OutlierFailures != -1 || o.HealthPath != "/hz" || o.HealthInterval != 7*time.Second || o.HealthTimeout != 2*time.Second {
		t.Errorf("outlier/health options = %+v", o)
	}
	if c := o.Circuit; c.MaxRequests != 4 || c.FailureThreshold != 3 || c.OpenFor != 12*time.Second {
		t.Errorf("circuit options = %+v (flag value 4 wins, the rest from the file)", c)
	}
}

func TestResilienceBlockAppliesOnReloadAndIsValidated(t *testing.T) {
	s := startServer(t, resSnap(m{"retryBudget": 10}), nil)
	if s.res.opt().RetryBudgetPercent != 10 {
		t.Fatalf("initial block not applied: %+v", s.res.opt())
	}
	cfg, err := ParseConfig(resSnap(m{"retryBudget": 70}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: cfg, Hash: "2"}); err != nil {
		t.Fatal(err)
	}
	if s.res.opt().RetryBudgetPercent != 70 {
		t.Errorf("reload did not apply the changed block: %+v", s.res.opt())
	}
	cfg2, _ := ParseConfig(resSnap(nil), t.TempDir())
	s.Apply(&Loaded{Config: cfg2, Hash: "3"})
	if s.res.opt().RetryBudgetPercent != 20 {
		t.Errorf("removing the block must restore the defaults: %+v", s.res.opt())
	}
	for _, bad := range []m{{"retryBudget": 500}, {"retryJitter": 2}, {"circuitBreaker": m{"openFor": "x"}}, {"outlier": m{"baseEjection": "later"}}} {
		if _, err := ParseConfig(resSnap(bad), ""); err == nil || !strings.Contains(err.Error(), "resilience") {
			t.Errorf("block %v accepted (err %v)", bad, err)
		}
	}
}
