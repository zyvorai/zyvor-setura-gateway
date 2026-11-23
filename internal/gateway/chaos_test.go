package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func faultRoute(fault m) m {
	rl := rule("/", ref("svc", 1))
	rl[FaultKey] = fault
	return route("", rl)
}

func chaosServer(t *testing.T, fault m, c *resClock, sl *sleepRec, be map[string]any, mod func(*Options)) *Server {
	t.Helper()
	return startServer(t, snap(httpGateway(""), map[string]m{"r": faultRoute(fault)}, be), func(o *Options) {
		resOpts(c, sl, nil)(o)
		if mod != nil {
			mod(o)
		}
	})
}

func TestFaultCompileRules(t *testing.T) {
	good := `{"percent":10,"abort":{"status":503},"ttl":"5m"}`
	if _, err := ParseFaultBlock([]byte(good)); err != nil {
		t.Fatalf("valid fault refused: %v", err)
	}
	for name, tc := range map[string]struct{ in, want string }{
		"no ttl":         {`{"percent":10,"abort":{"status":503}}`, "no ttl or expires"},
		"ttl too long":   {`{"percent":10,"abort":{"status":503},"ttl":"48h"}`, "longer than"},
		"negative ttl":   {`{"percent":10,"abort":{"status":503},"ttl":"-1m"}`, "positive"},
		"no effect":      {`{"percent":10,"ttl":"1m"}`, "no effect"},
		"no selector":    {`{"abort":{"status":503},"ttl":"1m"}`, "percent or a header"},
		"bad percent":    {`{"percent":101,"abort":{"status":503},"ttl":"1m"}`, "1 to 100"},
		"bad status":     {`{"percent":1,"abort":{"status":200},"ttl":"1m"}`, "400-599"},
		"unknown field":  {`{"percent":1,"abort":{"status":500},"ttl":"1m","ttl2":1}`, "unknown field"},
		"bad expires":    {`{"percent":1,"abort":{"status":500},"expires":"tomorrow"}`, "RFC 3339"},
		"bad header":     {`{"header":":x","abort":{"status":500},"ttl":"1m"}`, "header"},
		"absurd latency": {`{"percent":1,"latency":{"delay":"1h"},"ttl":"1m"}`, "5m limit"},
	} {
		if _, err := ParseFaultBlock([]byte(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, tc.want)
		}
	}
	if _, err := ParseFaultBlock([]byte(`{"header":"X-Chaos: 1","abort":{"status":500},"ttl":"1m"}`)); err != nil {
		t.Errorf("header selector without percent must be accepted: %v", err)
	}
}

func TestFaultWithoutTTLRefusesTheRoute(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 100, "abort": m{"status": 503}}, c, sl, be, nil)
	if r := get(t, s, "x.test", "/"); r.Status != 404 {
		t.Fatalf("a route with a TTL-less fault must not serve, got %d", r.Status)
	}
}

func TestFaultAbortHeaderSelectorAndExpiry(t *testing.T) {
	be, ups := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"header": "X-Chaos: 1", "abort": m{"status": 503}, "ttl": "10m"}, c, sl, be, nil)
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Fatalf("request without the header: %d", r.Status)
	}
	r := get(t, s, "x.test", "/", "X-Chaos", "1")
	if r.Status != 503 || r.Header.Get(FaultHeader) != "abort" {
		t.Fatalf("selected request: %d %q", r.Status, r.Header.Get(FaultHeader))
	}
	if n := len(ups["svc"].seen()); n != 1 {
		t.Errorf("backend saw %d requests, want 1 (the aborted one never reached it)", n)
	}
	if r := get(t, s, "x.test", "/", "X-Chaos", "2"); r.Status != 200 {
		t.Errorf("wrong header value must not select: %d", r.Status)
	}
	c.Advance(10*time.Minute - time.Second)
	if r := get(t, s, "x.test", "/", "X-Chaos", "1"); r.Status != 503 {
		t.Errorf("one second before expiry the fault must still apply: %d", r.Status)
	}
	c.Advance(2 * time.Second)
	if r := get(t, s, "x.test", "/", "X-Chaos", "1"); r.Status != 200 || r.Header.Get(FaultHeader) != "" {
		t.Errorf("after the TTL the fault must be gone: %d", r.Status)
	}
	if st := s.ChaosStatus(); st.Active {
		t.Errorf("expired fault still listed: %+v", st)
	}
}

func TestFaultPercentUsesInjectedRand(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	for _, tc := range []struct {
		roll int
		want int
	}{{9, 503}, {10, 200}} {
		s := chaosServer(t, m{"percent": 10, "abort": m{"status": 503}, "ttl": "1m"}, c, sl, be, func(o *Options) {
			o.Rand = func(n int) int {
				if n == 100 {
					return tc.roll
				}
				return 0
			}
		})
		if r := get(t, s, "x.test", "/"); r.Status != tc.want {
			t.Errorf("roll %d: status %d, want %d", tc.roll, r.Status, tc.want)
		}
	}
}

func TestFaultLatencyFixedAndJitter(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 100, "latency": m{"delay": "200ms", "jitter": "50ms"}, "ttl": "1m"}, c, sl, be, func(o *Options) { o.Rand = func(n int) int { return n / 2 } })
	if r := get(t, s, "x.test", "/"); r.Status != 200 || r.Header.Get(FaultHeader) != "latency" {
		t.Fatalf("status %d", r.Status)
	}
	if len(sl.ds) != 1 || sl.ds[0] < 200*time.Millisecond || sl.ds[0] > 250*time.Millisecond || sl.ds[0] != 225*time.Millisecond {
		t.Errorf("injected delay = %v, want 225ms (200ms + half of 50ms jitter)", sl.ds)
	}
}

func TestFaultResetDropsTheConnection(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 100, "reset": m{}, "ttl": "1m"}, c, sl, be, nil)
	rq, _ := http.NewRequest("GET", "http://x.test/", nil)
	resp, err := client(s.Addr(8080), nil).Do(rq)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected a connection error, got status %d", resp.StatusCode)
	}
}

func bigUpstream(t *testing.T, size int) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, strings.Repeat("x", size))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestFaultTruncateCutsTheBody(t *testing.T) {
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 100, "truncate": m{"bytes": 100}, "ttl": "1m"}, c, sl, svcBackend(bigUpstream(t, 1000)), nil)
	rq, _ := http.NewRequest("GET", "http://x.test/", nil)
	resp, err := client(s.Addr(8080), nil).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, rerr := io.ReadAll(resp.Body)
	if rerr == nil || len(b) > 100 {
		t.Fatalf("read %d bytes, err %v; want an error after at most 100 bytes", len(b), rerr)
	}
}

func TestFaultThrottlePacesTheBody(t *testing.T) {
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 100, "throttle": m{"bytesPerSecond": 100}, "ttl": "1m"}, c, sl, svcBackend(bigUpstream(t, 1000)), nil)
	rq, _ := http.NewRequest("GET", "http://x.test/", nil)
	resp, err := client(s.Addr(8080), nil).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(b) < 900 && !strings.Contains(string(b), "x") {
		t.Fatalf("body %d bytes", len(b))
	}
	var total time.Duration
	sl.mu.Lock()
	for _, d := range sl.ds {
		total += d
	}
	sl.mu.Unlock()
	// 1000 bytes at 100 B/s is 10 s of pacing, in steps of at most 10 bytes (100ms).
	if total < 9*time.Second || total > 11*time.Second {
		t.Errorf("total injected pacing %v, want about 10s", total)
	}
}

func TestRuntimeFaultsKillSwitchAndStatus(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, be), resOpts(c, sl, nil))
	h := func(method, body string) (int, ChaosStatus, string) {
		rec := httptest.NewRecorder()
		s.chaosHandler(rec, httptest.NewRequest(method, "/chaos", strings.NewReader(body)))
		var st ChaosStatus
		json.Unmarshal(rec.Body.Bytes(), &st)
		return rec.Code, st, rec.Body.String()
	}
	if code, _, body := h("POST", `{"faults":[{"route":"t/nope","fault":{"percent":5,"abort":{"status":500},"ttl":"1m"}}]}`); code != 400 || !strings.Contains(body, "no route") {
		t.Errorf("unknown route: %d %s", code, body)
	}
	if code, _, body := h("POST", `{"faults":[{"route":"t/r","fault":{"percent":5,"abort":{"status":500}}}]}`); code != 400 || !strings.Contains(body, "no ttl") {
		t.Errorf("a runtime fault without ttl must be refused: %d %s", code, body)
	}
	code, st, body := h("POST", `{"faults":[{"route":"t/r","fault":{"percent":100,"abort":{"status":502},"ttl":"30s"}}]}`)
	if code != 200 || !st.Active || len(st.Faults) != 1 || st.Faults[0].RemainingSeconds != 30 || st.Faults[0].Source != "runtime" {
		t.Fatalf("install: %d %s", code, body)
	}
	if r := get(t, s, "x.test", "/"); r.Status != 502 {
		t.Fatalf("fault not applied: %d", r.Status)
	}
	if d := s.Status(); d == nil {
		t.Fatal("no status")
	}
	var buf bytes.Buffer
	rec := httptest.NewRecorder()
	s.chaosHandler(rec, httptest.NewRequest("GET", "/chaos", nil))
	buf.Write(rec.Body.Bytes())
	if !strings.Contains(buf.String(), `"injected": 1`) {
		t.Errorf("injection counter missing: %s", buf.String())
	}
	_, st, _ = h("DELETE", "")
	if st.Active || st.KilledAt == "" {
		t.Errorf("kill switch: %+v", st)
	}
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Errorf("after stop: %d", r.Status)
	}
	// a fault expires by itself, without the runner having to clean up
	h("POST", `{"faults":[{"route":"t/r","fault":{"percent":100,"abort":{"status":502},"ttl":"30s"}}]}`)
	c.Advance(31 * time.Second)
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Errorf("runtime fault outlived its ttl: %d", r.Status)
	}
	if s.ChaosStatus().Active {
		t.Error("expired runtime fault still active")
	}
}

func TestKillSwitchDisablesConfigFaultsUntilReload(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	raw := snap(httpGateway(""), map[string]m{"r": faultRoute(m{"percent": 100, "abort": m{"status": 503}, "ttl": "1h"})}, be)
	s := chaosServer(t, m{"percent": 100, "abort": m{"status": 503}, "ttl": "1h"}, c, sl, be, nil)
	if r := get(t, s, "x.test", "/"); r.Status != 503 {
		t.Fatalf("config fault not applied: %d", r.Status)
	}
	s.StopFaults()
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Fatalf("config fault survived the kill switch: %d", r.Status)
	}
	// a reload of an identical config does not re-arm, but a changed one is a new table
	c.Advance(time.Minute)
	cfg, _ := ParseConfig(raw, t.TempDir())
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h2"}); err != nil {
		t.Fatal(err)
	}
	if r := get(t, s, "x.test", "/"); r.Status != 503 {
		t.Errorf("new table brings the declared fault back: %d", r.Status)
	}
	if v := s.ChaosStatus().Faults; len(v) != 1 || v[0].RemainingSeconds != 3540 {
		t.Errorf("an unchanged fault must keep its original expiry across reloads (want 3540s left): %+v", v)
	}
}

func TestFaultsInWhyAndStatus(t *testing.T) {
	be, _ := upstreams(t, "svc")
	c, sl := newClock(), &sleepRec{}
	s := chaosServer(t, m{"percent": 20, "latency": m{"delay": "1s"}, "ttl": "15m"}, c, sl, be, func(o *Options) { o.Admin = "127.0.0.1:0" })
	req, err := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	req.Live, req.Now, req.Server = true, c.Now(), s.liveServerPolicy()
	tr := Explain(s.Table(), req)
	if tr.Winner == nil || len(tr.Winner.Faults) != 1 || !tr.Winner.Faults[0].Armed || tr.Winner.Faults[0].RemainingSeconds != 900 {
		t.Fatalf("why must list the armed fault: %+v", tr.Winner)
	}
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + s.AdminAddr() + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var doc StatusDoc
	json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc.Chaos == nil || !doc.Chaos.Active || doc.Chaos.Faults[0].Route != "t/r" {
		t.Fatalf("status JSON lacks the chaos block: %+v", doc.Chaos)
	}
	// offline (no running gateway): declared, not armed
	tab, err := ParseReplayConfig(snap(httpGateway(""), map[string]m{"r": faultRoute(m{"percent": 20, "latency": m{"delay": "1s"}, "ttl": "15m"})}, be), "")
	if err != nil {
		t.Fatal(err)
	}
	off := Explain(tab, req2(t))
	if off.Winner == nil || len(off.Winner.Faults) != 1 || off.Winner.Faults[0].Armed || !strings.Contains(off.Winner.Faults[0].Note, "arms for 15m0s") {
		t.Fatalf("offline why: %+v", off.Winner)
	}
}

func req2(t *testing.T) ExplainRequest {
	r, err := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFaultAnnotation(t *testing.T) {
	rules := []Rule{{}, {}}
	annotateFault(rules, map[string]string{
		FaultKey:               `{"percent":5,"abort":{"status":500},"ttl":"1m"}`,
		FaultRuleAnnotation(2): `{"percent":9,"abort":{"status":500}}`, // no ttl
	})
	if rules[0].Fault == nil || rules[0].Fault.Percent == nil || *rules[0].Fault.Percent != 5 {
		t.Errorf("route-wide annotation not applied: %+v", rules[0].Fault)
	}
	if rules[1].Fault == nil || rules[1].Fault.annErr == nil {
		t.Fatalf("rule-2 annotation without ttl must become a compile error: %+v", rules[1].Fault)
	}
	if _, err := CompileFault(rules[1].Fault); err == nil || !strings.Contains(err.Error(), "no ttl") {
		t.Errorf("got %v", err)
	}
	if got := OrphanFaultAnnotations(map[string]string{FaultRuleAnnotation(3): "{}", FaultKey: "{}"}, 2); len(got) != 1 {
		t.Errorf("orphans = %v", got)
	}
}
