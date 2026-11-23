package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// fakeChaosGW plays the gateway for the runner: virtual time, scripted
// traffic and the /chaos endpoint's bookkeeping.
type fakeChaosGW struct {
	clock    *fakeClock
	faults   []builtin.FaultView
	setCalls []builtin.ChaosRequest
	stops    int
	reqs     int64
	errs     int64
	slow     int64 // observations in the 1s bucket
	fast     int64 // observations in the 100ms bucket
	// perTick is called at every stats read with whether faults are on; it
	// returns the requests, 5xx and slow observations to add.
	perTick  func(active bool, step int) (req, errs, slow int64)
	reads    int
	failFrom int // stats reads fail from this read on (0 = never)
	pre      []builtin.FaultView
	onRead   func(n int)
}

func (g *fakeChaosGW) GatewayStats(ctx context.Context) (*gwSnap, error) {
	g.reads++
	if g.onRead != nil {
		g.onRead(g.reads)
	}
	if g.failFrom > 0 && g.reads >= g.failFrom {
		return nil, errors.New("connection refused")
	}
	req, errs, slow := g.perTick(len(g.faults) > 0, len(g.setCalls))
	g.reqs += req
	g.errs += errs
	g.slow += slow
	g.fast += req - slow
	key := "route:shop/orders"
	return &gwSnap{counts: map[string]gwCount{key: {g.reqs, g.errs}, "route:shop/other": {g.reqs * 10, 0}},
		hist: map[string][]gwBucket{key: {{0.1, g.fast}, {1, g.fast + g.slow}, {1e18, g.reqs}}}}, nil
}

func (g *fakeChaosGW) st() *builtin.ChaosStatus {
	return &builtin.ChaosStatus{Active: len(g.faults) > 0, Faults: append([]builtin.FaultView{}, g.faults...)}
}

func (g *fakeChaosGW) ChaosStatus(context.Context) (*builtin.ChaosStatus, error) {
	if g.pre != nil {
		return &builtin.ChaosStatus{Active: true, Faults: g.pre}, nil
	}
	return g.st(), nil
}

func (g *fakeChaosGW) ChaosSet(_ context.Context, r builtin.ChaosRequest) (*builtin.ChaosStatus, error) {
	g.setCalls = append(g.setCalls, r)
	g.pre = nil
	g.faults = nil
	for _, f := range r.Faults {
		g.faults = append(g.faults, builtin.FaultView{Route: f.Route, Rule: f.Rule, Effect: "abort 503", Selector: "5% of requests", Source: "runtime", Injected: 7})
	}
	return g.st(), nil
}

func (g *fakeChaosGW) ChaosStop(context.Context) (*builtin.ChaosStatus, error) {
	g.stops++
	g.faults, g.pre = nil, nil
	return g.st(), nil
}

const goodPlan = `{
 "name": "orders gameday", "maxBlastPercent": 10,
 "guard": {"maxErrorRate": 5, "window": "20s", "interval": "5s", "minRequests": 50},
 "baseline": "10s",
 "steps": [
  {"name": "abort 5%", "duration": "30s", "faults": [{"route": "shop/orders", "fault": {"percent": 5, "abort": {"status": 503}}}]},
  {"name": "cool down", "duration": "10s"}
 ]}`

func chaosRun(t *testing.T, planJSON string, gw *fakeChaosGW, mod func(*chaosRunner)) (*ChaosReport, int) {
	t.Helper()
	p, err := ParseChaosPlan([]byte(planJSON))
	if err != nil {
		t.Fatal(err)
	}
	gw.clock = &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	r := &chaosRunner{plan: p, admin: gw, clock: gw.clock, logf: func(string, ...any) {}}
	if mod != nil {
		mod(r)
	}
	return r.run(context.Background())
}

func TestChaosRunCompletes(t *testing.T) {
	gw := &fakeChaosGW{perTick: func(active bool, _ int) (int64, int64, int64) {
		if active {
			return 100, 2, 0 // 2% 5xx while the fault is on
		}
		return 100, 0, 0
	}}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 0 || rep.Outcome != "completed" || rep.GuardFired != nil {
		t.Fatalf("code %d outcome %s fired %+v notes %v", code, rep.Outcome, rep.GuardFired, rep.Notes)
	}
	if len(gw.setCalls) != 1 || gw.setCalls[0].Faults[0].Fault.TTL != "45s" {
		t.Fatalf("the fault TTL must be the step length plus the 15s grace: %+v", gw.setCalls)
	}
	if gw.stops != 1 || !rep.Cleanup.Stopped || !rep.Cleanup.Verified {
		t.Errorf("cleanup: stops %d %+v", gw.stops, rep.Cleanup)
	}
	if len(rep.Steps) != 2 || !rep.Steps[0].Completed || !rep.Steps[1].Completed {
		t.Fatalf("steps %+v", rep.Steps)
	}
	s := rep.Steps[0]
	if s.Observed.Requests != 600 || s.Observed.Errors != 12 || s.Observed.ErrorRate != 2 || s.Observed.Burn != 20 {
		t.Errorf("step observation %+v (30s at 5s ticks = 6 ticks of 100 requests, 2 errors)", s.Observed)
	}
	if len(s.Faults) != 1 || s.Faults[0].Injected != 7 || s.Faults[0].TTL != "45s" {
		t.Errorf("applied faults %+v", s.Faults)
	}
	if rep.Baseline == nil || rep.Baseline.Errors != 0 || rep.Baseline.Requests != 200 {
		t.Errorf("baseline %+v", rep.Baseline)
	}
	if rep.Peak.ErrorRate != 2 {
		t.Errorf("peak %+v", rep.Peak)
	}
	if rep.DurationSeconds != 50 {
		t.Errorf("virtual duration %v, want 10s baseline + 30s + 10s", rep.DurationSeconds)
	}
}

func TestChaosGuardAbortsOnErrorRate(t *testing.T) {
	gw := &fakeChaosGW{perTick: func(active bool, _ int) (int64, int64, int64) {
		if active {
			return 100, 30, 0
		}
		return 100, 0, 0
	}}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 1 || rep.Outcome != "guard-aborted" {
		t.Fatalf("code %d outcome %s", code, rep.Outcome)
	}
	g := rep.GuardFired
	if g == nil || g.Metric != "error-rate" || g.Step != "abort 5%" || g.Threshold != 5 || g.Observed <= 5 || !strings.Contains(g.Reason, "5xx rate") {
		t.Fatalf("guard fire %+v", g)
	}
	if g.ElapsedSeconds >= 50 || g.ElapsedSeconds < 15 {
		t.Errorf("must abort promptly inside the step, fired after %vs", g.ElapsedSeconds)
	}
	if gw.stops != 1 || !rep.Cleanup.Verified || len(gw.faults) != 0 {
		t.Errorf("faults must be removed: stops %d %+v", gw.stops, rep.Cleanup)
	}
	if len(rep.Steps) != 1 || rep.Steps[0].Completed || rep.Steps[0].Observed.Errors == 0 {
		t.Errorf("the aborted step is reported as incomplete with what was seen: %+v", rep.Steps)
	}
}

func TestChaosGuardAbortsOnP99AndBurn(t *testing.T) {
	slow := func(active bool, _ int) (int64, int64, int64) {
		if active {
			return 100, 0, 100 // every request lands in the 500ms-1s bucket
		}
		return 100, 0, 0
	}
	plan := strings.Replace(goodPlan, `"maxErrorRate": 5`, `"maxP99Ms": 400`, 1)
	rep, code := chaosRun(t, plan, &fakeChaosGW{perTick: slow}, nil)
	if code != 1 || rep.GuardFired == nil || rep.GuardFired.Metric != "p99" || rep.GuardFired.Observed < 400 {
		t.Fatalf("p99: code %d %+v", code, rep.GuardFired)
	}
	burn := func(active bool, _ int) (int64, int64, int64) {
		if active {
			return 100, 1, 0 // 1% errors against a 99.9% SLO is a 10x burn
		}
		return 100, 0, 0
	}
	plan = strings.Replace(goodPlan, `"maxErrorRate": 5`, `"maxBurn": 6`, 1)
	rep, code = chaosRun(t, plan, &fakeChaosGW{perTick: burn}, nil)
	if code != 1 || rep.GuardFired == nil || rep.GuardFired.Metric != "burn" || rep.GuardFired.Observed < 6 {
		t.Fatalf("burn: code %d %+v", code, rep.GuardFired)
	}
}

func TestChaosGuardIgnoresThinTraffic(t *testing.T) {
	gw := &fakeChaosGW{perTick: func(active bool, _ int) (int64, int64, int64) {
		if active {
			return 5, 5, 0 // 100% errors but only 5 requests per tick: window holds 20 < 50
		}
		return 5, 0, 0
	}}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 0 || rep.GuardFired != nil {
		t.Fatalf("a thin window must not trip the guard: %d %+v", code, rep.GuardFired)
	}
}

func TestChaosScopeTargetsIgnoresOtherRoutes(t *testing.T) {
	// the other route's counters grow 10x faster and never fail; scope "all"
	// dilutes the 20% errors on the target below the limit, "targets" does not
	gw := func() *fakeChaosGW {
		return &fakeChaosGW{perTick: func(active bool, _ int) (int64, int64, int64) {
			if active {
				return 100, 20, 0
			}
			return 100, 0, 0
		}}
	}
	if _, code := chaosRun(t, goodPlan, gw(), nil); code != 1 {
		t.Errorf("targets scope must see the 20%%: %d", code)
	}
	all := strings.Replace(goodPlan, `"minRequests": 50`, `"minRequests": 50, "scope": "all"`, 1)
	if rep, code := chaosRun(t, all, gw(), nil); code != 0 || rep.GuardFired != nil {
		t.Errorf("scope all dilutes the target's 20%% into 1.8%% of all traffic: %d", code)
	}
}

func TestChaosBaselineBreachRefusesToStart(t *testing.T) {
	gw := &fakeChaosGW{perTick: func(bool, int) (int64, int64, int64) { return 100, 50, 0 }}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 1 || rep.Outcome != "refused" || len(gw.setCalls) != 0 {
		t.Fatalf("an unhealthy baseline must not start the experiment: %d %s sets %d", code, rep.Outcome, len(gw.setCalls))
	}
	if rep.GuardFired == nil || rep.GuardFired.Step != "baseline" {
		t.Errorf("%+v", rep.GuardFired)
	}
}

func TestChaosRefusesWhenFaultsAlreadyActive(t *testing.T) {
	ok := func(bool, int) (int64, int64, int64) { return 100, 0, 0 }
	gw := &fakeChaosGW{perTick: ok, pre: []builtin.FaultView{{Route: "shop/orders", Effect: "latency"}}}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 1 || rep.Outcome != "refused" || len(gw.setCalls) != 0 || !strings.Contains(strings.Join(rep.Notes, " "), "already active") {
		t.Fatalf("%d %s %v", code, rep.Outcome, rep.Notes)
	}
	gw = &fakeChaosGW{perTick: ok, pre: []builtin.FaultView{{Route: "shop/orders", Effect: "latency"}}}
	rep, code = chaosRun(t, goodPlan, gw, func(r *chaosRunner) { r.takeover = true })
	if code != 0 {
		t.Errorf("--takeover: %d %s", code, rep.Outcome)
	}
}

func TestChaosLostVisibilityFailsSafe(t *testing.T) {
	gw := &fakeChaosGW{perTick: func(bool, int) (int64, int64, int64) { return 100, 0, 0 }, failFrom: 6}
	rep, code := chaosRun(t, goodPlan, gw, nil)
	if code != 1 || rep.GuardFired == nil || rep.GuardFired.Metric != "visibility" || gw.stops != 1 || !rep.Cleanup.Verified {
		t.Fatalf("code %d fired %+v stops %d", code, rep.GuardFired, gw.stops)
	}
}

func TestChaosInterruptRemovesFaults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gw := &fakeChaosGW{perTick: func(bool, int) (int64, int64, int64) { return 100, 0, 0 }}
	gw.onRead = func(n int) {
		if n == 6 { // inside the first step
			cancel()
		}
	}
	p, _ := ParseChaosPlan([]byte(goodPlan))
	gw.clock = &fakeClock{t: time.Unix(1e9, 0)}
	r := &chaosRunner{plan: p, admin: gw, clock: gw.clock, logf: func(string, ...any) {}}
	rep, code := r.run(ctx)
	if code != 1 || rep.Outcome != "interrupted" || gw.stops != 1 || len(gw.faults) != 0 || !rep.Cleanup.Verified {
		t.Fatalf("code %d %s stops %d faults %d", code, rep.Outcome, gw.stops, len(gw.faults))
	}
}

func TestChaosStepOffsetsObserveWithoutFaults(t *testing.T) {
	plan := `{"guard":{"maxErrorRate":5,"interval":"5s","window":"20s"},"baseline":"0s","steps":[
	  {"name":"a","duration":"10s","faults":[{"route":"shop/orders","fault":{"percent":5,"abort":{"status":500}}}]},
	  {"name":"b","at":"30s","duration":"10s","faults":[{"route":"shop/orders","fault":{"percent":5,"abort":{"status":500}}}]}]}`
	var sawIdle []bool
	gw := &fakeChaosGW{}
	gw.perTick = func(active bool, sets int) (int64, int64, int64) {
		sawIdle = append(sawIdle, active)
		return 100, 0, 0
	}
	rep, code := chaosRun(t, plan, gw, nil)
	if code != 0 || len(gw.setCalls) != 2 || rep.DurationSeconds != 40 {
		t.Fatalf("code %d sets %d duration %v", code, len(gw.setCalls), rep.DurationSeconds)
	}
	if rep.Steps[1].Start == rep.Steps[0].End {
		t.Errorf("step b must wait for its offset: %+v", rep.Steps)
	}
}

func TestParseChaosPlanRejects(t *testing.T) {
	fault := `{"route":"shop/orders","fault":{"percent":5,"abort":{"status":503}}}`
	mk := func(guard, extra, steps string) string {
		return `{"guard":` + guard + extra + `,"steps":` + steps + `}`
	}
	g := `{"maxErrorRate":5}`
	st := `[{"duration":"10s","faults":[` + fault + `]}]`
	for name, tc := range map[string]struct{ plan, want string }{
		"no guard":       {mk(`{"window":"10s"}`, "", st), "safety guard"},
		"no steps":       {mk(g, "", `[]`), "no steps"},
		"over blast cap": {mk(g, `,"maxBlastPercent":4`, st), "blast-radius cap"},
		"sum over cap":   {mk(g, `,"maxBlastPercent":8`, `[{"duration":"10s","faults":[`+fault+`,`+fault+`]}]`), "together select 10%"},
		"plan sets ttl":  {mk(g, "", `[{"duration":"10s","faults":[{"route":"a/b","fault":{"percent":1,"abort":{"status":500},"ttl":"1h"}}]}]`), "do not set ttl"},
		"bad fault":      {mk(g, "", `[{"duration":"10s","faults":[{"route":"a/b","fault":{"percent":1}}]}]`), "no effect"},
		"no route":       {mk(g, "", `[{"duration":"10s","faults":[{"fault":{"percent":1,"abort":{"status":500}}}]}]`), "route is required"},
		"no duration":    {mk(g, "", `[{"faults":[`+fault+`]}]`), "duration is required"},
		"overlap":        {mk(g, "", `[{"duration":"30s"},{"at":"10s","duration":"5s"}]`), "before the previous step ends"},
		"unknown field":  {mk(g, `,"oops":1`, st), "unknown field"},
		"bad objective":  {mk(`{"maxBurn":3,"objective":100}`, "", st), "objective"},
		"too long":       {mk(g, "", `[{"duration":"30h"}]`), "fault limit"},
		"bad scope":      {mk(`{"maxErrorRate":5,"scope":"some"}`, "", st), "scope"},
	} {
		if _, err := ParseChaosPlan([]byte(tc.plan)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	// a header-selected fault without a percent is opt-in traffic and passes any cap
	opt := mk(g, `,"maxBlastPercent":1`, `[{"duration":"10s","faults":[{"route":"a/b","fault":{"header":"X-Chaos: 1","abort":{"status":500}}}]}]`)
	if _, err := ParseChaosPlan([]byte(opt)); err != nil {
		t.Errorf("header opt-in fault: %v", err)
	}
}

func TestChaosDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	os.WriteFile(path, []byte(goodPlan), 0o644)
	var out, errb bytes.Buffer
	code := Main([]string{"chaos", "run", "--plan", path, "--dry-run", "--ascii"}, &out, &errb)
	for _, want := range []string{"orders gameday", "blast-radius cap 10%", "5xx over 5%", "shop/orders", "abort 503", "5% of requests", "observe only"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
	if code != 0 {
		t.Errorf("code %d %s", code, errb.String())
	}
	for _, args := range [][]string{{"chaos"}, {"chaos", "launch"}, {"chaos", "run"}, {"chaos", "run", "--plan", "/nonexistent"}} {
		if code := Main(args, io.Discard, io.Discard); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
}

// ---- against a real gateway ----

func chaosGet(t *testing.T, e *e2eEnv) (int, string) {
	t.Helper()
	return e.serve(t)
}

func TestChaosRealGatewayInstallStatusStopWhy(t *testing.T) {
	e := newE2E(t, "v1")
	ad := newHTTPAdmin(e.admin)
	ctx := context.Background()
	if code, _ := chaosGet(t, e); code != 200 {
		t.Fatalf("baseline %d", code)
	}
	st, err := ad.ChaosSet(ctx, builtin.ChaosRequest{Faults: []builtin.RuntimeFault{{Route: "demo/orders",
		Fault: builtin.Fault{Abort: &builtin.FaultAbort{Status: 503}, Header: "X-Chaos: 1", TTL: "5m"}}}})
	if err != nil || !st.Active || len(st.Faults) != 1 {
		t.Fatalf("set: %+v %v", st, err)
	}
	if code, _ := chaosGet(t, e); code != 200 {
		t.Errorf("a request without the header must not be hit: %d", code)
	}
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+e.port+"/checkout", nil)
	req.Host = "orders.mactra.test"
	req.Header.Set("X-Chaos", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get(builtin.FaultHeader) != "abort" {
		t.Errorf("selected request: %d %q", resp.StatusCode, resp.Header.Get(builtin.FaultHeader))
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"chaos", "status", "--admin", e.admin, "--format", "pretty", "--ascii"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "1 fault(s) active") || !strings.Contains(out.String(), "demo/orders") {
		t.Errorf("status: %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := Main([]string{"why", "GET", "http://orders.mactra.test:8080/checkout", "--admin", e.admin, "--ascii"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "FAULT INJECTION") {
		t.Errorf("why must show the active fault: %d\n%s", code, out.String())
	}
	if ui, ok := e.gw.UIState().(map[string]any); !ok || ui["chaos"] == nil {
		t.Errorf("the dashboard state must carry the chaos block for its banner: %v", ui)
	}
	// /status carries the chaos block for dashboards
	raw, _ := ad.get(ctx, "/status")
	var doc builtin.StatusDoc
	if json.Unmarshal(raw, &doc) != nil || doc.Chaos == nil || !doc.Chaos.Active {
		t.Errorf("status JSON lacks chaos: %s", raw)
	}
	out.Reset()
	if code := Main([]string{"chaos", "stop", "--admin", e.admin, "--format", "pretty", "--ascii"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "all faults removed (1 were active)") {
		t.Errorf("stop: %d\n%s", code, out.String())
	}
	if st, _ := ad.ChaosStatus(ctx); st.Active {
		t.Errorf("still active after stop: %+v", st)
	}
	// an invalid fault is refused by the gateway itself: no TTL, no fault
	if _, err := ad.ChaosSet(ctx, builtin.ChaosRequest{Faults: []builtin.RuntimeFault{{Route: "demo/orders", Fault: builtin.Fault{Abort: &builtin.FaultAbort{Status: 503}, Header: "X-Chaos"}}}}); err == nil || !strings.Contains(err.Error(), "no ttl") {
		t.Errorf("a fault without ttl must be refused: %v", err)
	}
}

func TestChaosRealGatewayGuardAbortsRun(t *testing.T) {
	e := newE2E(t, "v1")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // steady traffic for the guard to watch
		defer wg.Done()
		c := &http.Client{Timeout: 2 * time.Second}
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, _ := http.NewRequest("GET", "http://127.0.0.1:"+e.port+"/checkout", nil)
			req.Host = "orders.mactra.test"
			if resp, err := c.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	plan := `{"name":"e2e","maxBlastPercent":100,"baseline":"0s",
	  "guard":{"maxErrorRate":20,"window":"1s","interval":"50ms","minRequests":5},
	  "steps":[{"name":"all errors","duration":"20s","faults":[{"route":"demo/orders","fault":{"percent":100,"abort":{"status":503}}}]}]}`
	path := filepath.Join(t.TempDir(), "plan.json")
	os.WriteFile(path, []byte(plan), 0o644)
	rpt := filepath.Join(t.TempDir(), "report.json")
	var out, errb bytes.Buffer
	code := Main([]string{"chaos", "run", "--plan", path, "--admin", e.admin, "--report", rpt, "--format", "json"}, &out, &errb)
	if code != 1 {
		t.Fatalf("code %d\n%s\n%s", code, out.String(), errb.String())
	}
	var rep ChaosReport
	raw, err := os.ReadFile(rpt)
	if err != nil || json.Unmarshal(raw, &rep) != nil {
		t.Fatalf("report file: %v %s", err, raw)
	}
	if rep.Schema != chaosReportSchema || rep.Outcome != "guard-aborted" || rep.GuardFired == nil || rep.GuardFired.Metric != "error-rate" || !rep.Cleanup.Verified {
		t.Fatalf("report: %s", raw)
	}
	if rep.Steps[0].Faults[0].Injected == 0 {
		t.Errorf("injection counter missing from the report: %s", raw)
	}
	if rep.DurationSeconds >= 20 {
		t.Errorf("the guard must end the run long before the 20s step: %vs", rep.DurationSeconds)
	}
	if code, _ := chaosGet(t, e); code != 200 {
		t.Errorf("faults must be gone after the abort: %d", code)
	}
}
