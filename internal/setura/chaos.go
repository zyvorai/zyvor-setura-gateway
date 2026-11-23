package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// setura chaos: game-day fault injection with a safety guard.
//
// "chaos run" executes a timed plan against a running built-in gateway through
// its admin API (POST /chaos, DELETE /chaos). While faults are on, a guard
// reads the gateway's own request counters and latency histograms (the same
// /stats and /metrics a rollout and "setura top" use) and, the moment the
// error rate, the error-budget burn or the p99 crosses a threshold, removes
// every fault and writes down what happened. The runner is only half of the
// safety: every fault it installs carries a TTL of the step length plus a
// short grace, so a runner that dies or loses the network cannot leave a fault
// on.

// Report and plan schemas.
const (
	chaosPlanSchema   = "setura.chaos-plan/v1"
	chaosReportSchema = "setura.chaos-report/v1"
)

// ChaosGuard is the plan's safety guard. At least one threshold is required.
type ChaosGuard struct {
	// MaxErrorRate is the 5xx percent (0-100) over Window that aborts the run.
	MaxErrorRate float64 `json:"maxErrorRate,omitempty"`
	// MaxBurn is the error-budget burn rate (observed error ratio divided by
	// 1 - Objective/100) that aborts the run, as in setura slo.
	MaxBurn float64 `json:"maxBurn,omitempty"`
	// Objective is the availability SLO the burn rate refers to, percent (default 99.9).
	Objective float64 `json:"objective,omitempty"`
	// MaxP99Ms aborts when the p99 latency of any watched route exceeds it.
	MaxP99Ms float64 `json:"maxP99Ms,omitempty"`
	// Window is how much traffic each check looks at (default 30s); Interval
	// how often the gateway is read (default 2s).
	Window   string `json:"window,omitempty"`
	Interval string `json:"interval,omitempty"`
	// MinRequests is the least traffic in the window for a threshold to count
	// (default 20): a handful of requests proves nothing.
	MinRequests int64 `json:"minRequests,omitempty"`
	// Scope is "targets" (default, the routes the plan injects into) or "all".
	Scope string `json:"scope,omitempty"`
}

// ChaosPlanFault is one fault of a step. The TTL is set by the runner.
type ChaosPlanFault struct {
	Route string        `json:"route"`
	Rule  int           `json:"rule,omitempty"`
	Fault builtin.Fault `json:"fault"`
}

// ChaosStep is one phase of the experiment.
type ChaosStep struct {
	Name string `json:"name,omitempty"`
	// At is the start offset from the end of the baseline; default: right
	// after the previous step. Gaps are observed with no fault on.
	At       string           `json:"at,omitempty"`
	Duration string           `json:"duration"`
	Faults   []ChaosPlanFault `json:"faults,omitempty"`

	at, dur time.Duration
}

// ChaosPlan is the experiment plan file.
type ChaosPlan struct {
	Schema string `json:"schema,omitempty"`
	Name   string `json:"name,omitempty"`
	// MaxBlastPercent caps how much of a targeted route's traffic faults may
	// hit: no fault, and no sum of faults on one route in one step, may select
	// more (default 10). Faults selected by a header only count their percent
	// when they have one: the caller opts in.
	MaxBlastPercent int        `json:"maxBlastPercent,omitempty"`
	Guard           ChaosGuard `json:"guard"`
	// Baseline is observed with no fault before the first step (default 2
	// intervals); a guard breach there means the system is not healthy enough
	// to experiment on and the run does not start.
	Baseline string `json:"baseline,omitempty"`
	// TTLGrace is added to every step's length to form the fault TTL (default 15s).
	TTLGrace string      `json:"ttlGrace,omitempty"`
	Steps    []ChaosStep `json:"steps"`

	window, interval, baseline, grace time.Duration
}

// ParseChaosPlan decodes and validates a plan. It compiles every fault with
// the gateway's own code, so a plan that parses here is accepted there.
func ParseChaosPlan(raw []byte) (*ChaosPlan, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p ChaosPlan
	if err := dec.Decode(&p); err != nil {
		return nil, userErrorf("plan: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, userError("plan: trailing data after the JSON object")
	}
	if p.Schema != "" && p.Schema != chaosPlanSchema {
		return nil, userErrorf("plan: schema %q, want %s", p.Schema, chaosPlanSchema)
	}
	dur := func(what, s string, def time.Duration, allowZero bool) (time.Duration, error) {
		if s == "" {
			return def, nil
		}
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 || (d == 0 && !allowZero) {
			return 0, userErrorf("plan: %s %q must be a positive duration", what, s)
		}
		return d, nil
	}
	var err error
	g := &p.Guard
	if p.window, err = dur("guard.window", g.Window, 30*time.Second, false); err != nil {
		return nil, err
	}
	if p.interval, err = dur("guard.interval", g.Interval, 2*time.Second, false); err != nil {
		return nil, err
	}
	if p.baseline, err = dur("baseline", p.Baseline, 2*p.interval, true); err != nil {
		return nil, err
	}
	if p.grace, err = dur("ttlGrace", p.TTLGrace, 15*time.Second, false); err != nil {
		return nil, err
	}
	if g.MaxErrorRate <= 0 && g.MaxBurn <= 0 && g.MaxP99Ms <= 0 {
		return nil, userError("plan: guard needs at least one of maxErrorRate, maxBurn or maxP99Ms; a plan without a safety guard does not run")
	}
	if g.MaxErrorRate > 100 || g.MaxErrorRate < 0 || g.MaxBurn < 0 || g.MaxP99Ms < 0 {
		return nil, userError("plan: guard thresholds must be positive and maxErrorRate at most 100")
	}
	if g.Objective == 0 {
		g.Objective = 99.9
	}
	if g.Objective <= 0 || g.Objective >= 100 {
		return nil, userErrorf("plan: guard.objective %g must be between 0 and 100 exclusive", g.Objective)
	}
	if g.MinRequests == 0 {
		g.MinRequests = 20
	}
	switch g.Scope {
	case "":
		g.Scope = "targets"
	case "targets", "all":
	default:
		return nil, userErrorf("plan: guard.scope %q, want targets or all", g.Scope)
	}
	if p.MaxBlastPercent == 0 {
		p.MaxBlastPercent = 10
	}
	if p.MaxBlastPercent < 1 || p.MaxBlastPercent > 100 {
		return nil, userError("plan: maxBlastPercent must be from 1 to 100")
	}
	if len(p.Steps) == 0 {
		return nil, userError("plan: no steps")
	}
	var cursor time.Duration
	total := p.baseline
	for i := range p.Steps {
		st := &p.Steps[i]
		where := fmt.Sprintf("plan: step %d", i+1)
		if st.Name != "" {
			where += " (" + st.Name + ")"
		}
		if st.Name == "" {
			st.Name = fmt.Sprintf("step %d", i+1)
		}
		if st.dur, err = dur(where+" duration", st.Duration, 0, false); err != nil || st.dur == 0 {
			return nil, userErrorf("%s: duration is required", where)
		}
		st.at = cursor
		if st.At != "" {
			if st.at, err = dur(where+" at", st.At, 0, true); err != nil {
				return nil, err
			}
			if st.at < cursor {
				return nil, userErrorf("%s: starts at %s, before the previous step ends (%s)", where, st.at, cursor)
			}
		}
		cursor = st.at + st.dur
		perRoute := map[string]int{}
		for j, f := range st.Faults {
			fw := fmt.Sprintf("%s fault %d", where, j+1)
			if f.Route == "" {
				return nil, userErrorf("%s: route is required (namespace/name)", fw)
			}
			if f.Rule < 0 {
				return nil, userErrorf("%s: rule must not be negative", fw)
			}
			if f.Fault.TTL != "" || f.Fault.Expires != "" {
				return nil, userErrorf("%s: do not set ttl or expires; the runner sets the TTL to the step length plus ttlGrace", fw)
			}
			probe := f.Fault
			probe.TTL = "1m"
			if _, err := builtin.CompileFault(&probe); err != nil {
				return nil, userErrorf("%s: %v", fw, err)
			}
			blast := 0
			if f.Fault.Percent != nil {
				blast = *f.Fault.Percent
			}
			if blast > p.MaxBlastPercent {
				return nil, userErrorf("%s: selects %d%% of %s, over the plan's blast-radius cap of %d%%", fw, blast, f.Route, p.MaxBlastPercent)
			}
			perRoute[f.Route] += blast
			if perRoute[f.Route] > p.MaxBlastPercent {
				return nil, userErrorf("%s: faults on %s together select %d%%, over the blast-radius cap of %d%%", fw, f.Route, perRoute[f.Route], p.MaxBlastPercent)
			}
		}
	}
	total += cursor
	if total+p.grace > builtin.MaxFaultTTL {
		return nil, userErrorf("plan: runs %s, longer than the %s fault limit", total, builtin.MaxFaultTTL)
	}
	return &p, nil
}

func (p *ChaosPlan) targets() map[string]bool {
	out := map[string]bool{}
	for _, s := range p.Steps {
		for _, f := range s.Faults {
			out[f.Route] = true
		}
	}
	return out
}

// ---- report ----

// ChaosObserved is the traffic the guard watched over some period.
type ChaosObserved struct {
	Requests  int64   `json:"requests"`
	Errors    int64   `json:"errors"` // 5xx
	ErrorRate float64 `json:"errorRatePercent"`
	Burn      float64 `json:"budgetBurn"`
	P99Ms     float64 `json:"p99Ms"`
}

// ChaosGuardFire says why and when the guard aborted the run.
type ChaosGuardFire struct {
	At             string  `json:"at"`
	ElapsedSeconds float64 `json:"elapsedSeconds"`
	Step           string  `json:"step"`
	Metric         string  `json:"metric"` // error-rate, burn, p99 or visibility
	Observed       float64 `json:"observed"`
	Threshold      float64 `json:"threshold"`
	Reason         string  `json:"reason"`
}

// ChaosAppliedFault is what a step injected.
type ChaosAppliedFault struct {
	Route    string `json:"route"`
	Rule     int    `json:"rule"`
	Effect   string `json:"effect"`
	Selector string `json:"selector"`
	TTL      string `json:"ttl"`
	Injected int64  `json:"injected"` // requests the fault hit, from the gateway
}

// ChaosStepResult is one step of the report.
type ChaosStepResult struct {
	Name      string              `json:"name"`
	Start     string              `json:"start,omitempty"`
	End       string              `json:"end,omitempty"`
	Planned   string              `json:"planned"`
	Faults    []ChaosAppliedFault `json:"faults"`
	Observed  ChaosObserved       `json:"observed"`
	Completed bool                `json:"completed"`
}

// ChaosCleanup records that the faults are off again.
type ChaosCleanup struct {
	Stopped  bool   `json:"stopped"`
	Verified bool   `json:"verified"` // /chaos reports no active fault afterwards
	Error    string `json:"error,omitempty"`
}

// ChaosReport is the experiment report (setura.chaos-report/v1).
type ChaosReport struct {
	Schema          string            `json:"schema"`
	Plan            string            `json:"plan"`
	Admin           string            `json:"admin,omitempty"`
	Started         string            `json:"started"`
	Ended           string            `json:"ended"`
	DurationSeconds float64           `json:"durationSeconds"`
	Outcome         string            `json:"outcome"` // completed, guard-aborted, interrupted, refused, error
	MaxBlastPercent int               `json:"maxBlastPercent"`
	Guard           ChaosGuard        `json:"guard"`
	GuardFired      *ChaosGuardFire   `json:"guardFired,omitempty"`
	Baseline        *ChaosObserved    `json:"baseline,omitempty"`
	Peak            ChaosObserved     `json:"peak"` // worst value of each metric seen in any guard window
	Steps           []ChaosStepResult `json:"steps"`
	Cleanup         ChaosCleanup      `json:"cleanup"`
	Notes           []string          `json:"notes,omitempty"`
}

// ---- admin client ----

type chaosAdmin interface {
	statsAPI
	ChaosStatus(ctx context.Context) (*builtin.ChaosStatus, error)
	ChaosSet(ctx context.Context, req builtin.ChaosRequest) (*builtin.ChaosStatus, error)
	ChaosStop(ctx context.Context) (*builtin.ChaosStatus, error)
}

func (a *httpAdmin) chaosCall(ctx context.Context, method string, body any) (*builtin.ChaosStatus, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+"/chaos", rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	adminToken(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw))
		if resp.StatusCode == http.StatusNotFound {
			msg = "this gateway has no /chaos endpoint (upgrade it)"
		}
		return nil, fmt.Errorf("admin /chaos answered HTTP %d: %s", resp.StatusCode, msg)
	}
	var st builtin.ChaosStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("admin /chaos: %w", err)
	}
	return &st, nil
}

func (a *httpAdmin) ChaosStatus(ctx context.Context) (*builtin.ChaosStatus, error) {
	return a.chaosCall(ctx, http.MethodGet, nil)
}
func (a *httpAdmin) ChaosSet(ctx context.Context, r builtin.ChaosRequest) (*builtin.ChaosStatus, error) {
	return a.chaosCall(ctx, http.MethodPost, r)
}
func (a *httpAdmin) ChaosStop(ctx context.Context) (*builtin.ChaosStatus, error) {
	return a.chaosCall(ctx, http.MethodDelete, nil)
}

// ---- runner ----

type chaosRunner struct {
	plan     *ChaosPlan
	admin    chaosAdmin
	clock    rolloutClock
	logf     func(format string, a ...any)
	takeover bool
	adminAt  string

	rep     *ChaosReport
	start   time.Time
	samples []chaosSample
	scope   func(key string) bool
	fails   int
}

type chaosSample struct {
	t    time.Time
	snap *gwSnap
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// observe summarises the traffic between two readings in scope.
func (r *chaosRunner) observe(old, cur *gwSnap) ChaosObserved {
	var o ChaosObserved
	for _, d := range cur.deltas(old, r.scope) {
		if !strings.HasPrefix(d.Key, "route:") {
			continue
		}
		o.Requests += d.Requests
		o.Errors += d.Errors
	}
	for key := range cur.hist {
		if !strings.HasPrefix(key, "route:") || (r.scope != nil && !r.scope(key)) {
			continue
		}
		if ms, ok := quantileBetween(old.hist[key], cur.hist[key], 0.99); ok && ms > o.P99Ms {
			o.P99Ms = ms
		}
	}
	if o.Requests > 0 {
		o.ErrorRate = round(float64(o.Errors)*100/float64(o.Requests), 2)
		o.Burn = round(float64(o.Errors)/float64(o.Requests)/(1-r.plan.Guard.Objective/100), 2)
	}
	o.P99Ms = round(o.P99Ms, 1)
	return o
}

// window returns the reading at the start of the guard window ending at the
// newest sample, pruning older ones.
func (r *chaosRunner) windowStart(now time.Time) chaosSample {
	for len(r.samples) > 1 && !r.samples[1].t.After(now.Add(-r.plan.window)) {
		r.samples = r.samples[1:]
	}
	return r.samples[0]
}

// breach checks one observation against the guard.
func (r *chaosRunner) breach(o ChaosObserved) (metric string, observed, threshold float64, reason string) {
	g := r.plan.Guard
	if o.Requests < g.MinRequests {
		return
	}
	switch {
	case g.MaxErrorRate > 0 && o.ErrorRate > g.MaxErrorRate:
		return "error-rate", o.ErrorRate, g.MaxErrorRate, fmt.Sprintf("5xx rate %.2f%% over the last %s exceeds the %.2f%% limit (%d of %d requests)", o.ErrorRate, r.plan.window, g.MaxErrorRate, o.Errors, o.Requests)
	case g.MaxBurn > 0 && o.Burn > g.MaxBurn:
		return "burn", o.Burn, g.MaxBurn, fmt.Sprintf("error budget burn %.1fx (SLO %g%%) exceeds the %.1fx limit", o.Burn, g.Objective, g.MaxBurn)
	case g.MaxP99Ms > 0 && o.P99Ms > g.MaxP99Ms:
		return "p99", o.P99Ms, g.MaxP99Ms, fmt.Sprintf("p99 latency %.0f ms exceeds the %.0f ms limit", o.P99Ms, g.MaxP99Ms)
	}
	return
}

func (r *chaosRunner) peak(o ChaosObserved) {
	p := &r.rep.Peak
	if o.Requests < r.plan.Guard.MinRequests {
		return
	}
	p.ErrorRate = max(p.ErrorRate, o.ErrorRate)
	p.Burn = max(p.Burn, o.Burn)
	p.P99Ms = max(p.P99Ms, o.P99Ms)
	p.Errors = max(p.Errors, o.Errors)
	p.Requests = max(p.Requests, o.Requests)
}

var errGuard = fmt.Errorf("guard fired")

// tick sleeps one interval, reads the gateway and runs the guard. It returns
// errGuard when the run must stop, or the context error.
func (r *chaosRunner) tick(ctx context.Context, step string, wait time.Duration, armed bool) error {
	if err := r.clock.Sleep(ctx, wait); err != nil {
		return err
	}
	now := r.clock.Now()
	snap, err := r.admin.GatewayStats(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.fails++
		r.logf("cannot read the gateway's signals (%d of 3): %v", r.fails, err)
		if r.fails >= 3 && armed {
			r.fire(now, step, "visibility", float64(r.fails), 3, "the guard lost sight of the gateway (3 failed reads in a row) while faults were on")
			return errGuard
		}
		return nil
	}
	r.fails = 0
	r.samples = append(r.samples, chaosSample{now, snap})
	o := r.observe(r.windowStart(now).snap, snap)
	r.peak(o)
	if metric, obs, thr, why := r.breach(o); metric != "" {
		if armed {
			r.fire(now, step, metric, obs, thr, why)
			return errGuard
		}
		r.rep.Notes = append(r.rep.Notes, "baseline breach: "+why)
		r.fire(now, step, metric, obs, thr, why)
		return errGuard
	}
	return nil
}

func (r *chaosRunner) fire(now time.Time, step, metric string, obs, thr float64, why string) {
	if r.rep.GuardFired != nil {
		return
	}
	r.rep.GuardFired = &ChaosGuardFire{At: rfc(now), ElapsedSeconds: now.Sub(r.start).Seconds(), Step: step, Metric: metric, Observed: obs, Threshold: thr, Reason: why}
}

// clean removes every fault and checks they are gone. It runs on every exit.
func (r *chaosRunner) clean() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var last error
	for try := 0; try < 3; try++ {
		st, err := r.admin.ChaosStop(ctx)
		if err == nil {
			r.rep.Cleanup.Stopped = true
			r.rep.Cleanup.Verified = !st.Active
			r.rep.Cleanup.Error = ""
			if !st.Active {
				return
			}
			last = fmt.Errorf("%d fault(s) still active after the kill switch", len(st.Faults))
			continue
		}
		last = err
	}
	if last != nil {
		r.rep.Cleanup.Error = last.Error()
	}
}

func (r *chaosRunner) finish(outcome string) *ChaosReport {
	r.rep.Outcome = outcome
	end := r.clock.Now()
	r.rep.Ended = rfc(end)
	r.rep.DurationSeconds = round(end.Sub(r.start).Seconds(), 1)
	if r.rep.Steps == nil {
		r.rep.Steps = []ChaosStepResult{}
	}
	return r.rep
}

// run executes the plan. Exit code: 0 completed, 1 aborted, refused or
// interrupted (the faults are off in every case), 2 could not run at all.
func (r *chaosRunner) run(ctx context.Context) (*ChaosReport, int) {
	p := r.plan
	r.start = r.clock.Now()
	r.rep = &ChaosReport{Schema: chaosReportSchema, Plan: p.Name, Admin: r.adminAt, Started: rfc(r.start), MaxBlastPercent: p.MaxBlastPercent, Guard: p.Guard, Steps: []ChaosStepResult{}}
	targets := p.targets()
	if p.Guard.Scope == "targets" {
		r.scope = func(key string) bool {
			return targets[strings.TrimPrefix(key, "route:")] && strings.HasPrefix(key, "route:")
		}
	} else {
		r.scope = func(key string) bool { return strings.HasPrefix(key, "route:") }
	}

	st, err := r.admin.ChaosStatus(ctx)
	if err != nil {
		r.rep.Notes = append(r.rep.Notes, "cannot reach the gateway admin API: "+err.Error())
		return r.finish("error"), 2
	}
	if st.Active && !r.takeover {
		r.rep.Notes = append(r.rep.Notes, fmt.Sprintf("%d fault(s) are already active on the gateway; run setura chaos stop first or pass --takeover", len(st.Faults)))
		return r.finish("refused"), 1
	}
	snap, err := r.admin.GatewayStats(ctx)
	if err != nil {
		r.rep.Notes = append(r.rep.Notes, "cannot read the gateway's signals: "+err.Error())
		return r.finish("error"), 2
	}
	r.samples = []chaosSample{{r.start, snap}}
	defer func() {
		r.clean()
		if !r.rep.Cleanup.Verified {
			r.logf("WARNING: could not confirm that all faults are off: %s", r.rep.Cleanup.Error)
		}
	}()

	// baseline: no fault; the system must already be inside the guard
	if p.baseline > 0 {
		r.logf("baseline %s, no fault", p.baseline)
		base := snap
		for el := time.Duration(0); el < p.baseline; {
			w := min(p.interval, p.baseline-el)
			if err := r.tick(ctx, "baseline", w, false); err != nil {
				return r.abort(err, "refused", "baseline"), 1
			}
			el += w
		}
		o := r.observe(base, r.samples[len(r.samples)-1].snap)
		r.rep.Baseline = &o
	}

	expStart := r.clock.Now()
	for i := range p.Steps {
		step := &p.Steps[i]
		res := ChaosStepResult{Name: step.Name, Planned: step.dur.String(), Faults: []ChaosAppliedFault{}}
		// idle until the step's offset, guard still watching
		for r.clock.Now().Sub(expStart) < step.at {
			w := min(p.interval, step.at-r.clock.Now().Sub(expStart))
			if err := r.tick(ctx, step.Name, w, false); err != nil {
				return r.abort(err, "guard-aborted", step.Name), 1
			}
		}
		stepStart := r.clock.Now()
		res.Start = rfc(stepStart)
		r.logf("step %d of %d: %s, %s, %d fault(s)", i+1, len(p.Steps), step.Name, step.dur, len(step.Faults))
		if len(step.Faults) > 0 {
			ttl := step.dur + p.grace
			req := builtin.ChaosRequest{}
			for _, f := range step.Faults {
				ff := f.Fault
				ff.TTL = ttl.String()
				req.Faults = append(req.Faults, builtin.RuntimeFault{Route: f.Route, Rule: f.Rule, Fault: ff})
			}
			applied, err := r.admin.ChaosSet(ctx, req)
			if err != nil {
				if ctx.Err() != nil {
					return r.abort(ctx.Err(), "interrupted", step.Name), 1
				}
				r.rep.Notes = append(r.rep.Notes, "the gateway refused the faults: "+err.Error())
				r.rep.Steps = append(r.rep.Steps, res)
				return r.finish("error"), 2
			}
			for _, v := range applied.Faults {
				res.Faults = append(res.Faults, ChaosAppliedFault{Route: v.Route, Rule: v.Rule, Effect: v.Effect, Selector: v.Selector, TTL: ttl.String()})
			}
		}
		r.rep.Steps = append(r.rep.Steps, res)
		idx := len(r.rep.Steps) - 1
		from := r.samples[len(r.samples)-1].snap
		armed := len(step.Faults) > 0
		for {
			left := step.dur - r.clock.Now().Sub(stepStart)
			if left <= 0 {
				break
			}
			if err := r.tick(ctx, step.Name, min(p.interval, left), armed); err != nil {
				r.rep.Steps[idx].End = rfc(r.clock.Now())
				r.rep.Steps[idx].Observed = r.observe(from, r.samples[len(r.samples)-1].snap)
				r.collectInjected()
				return r.abort(err, "guard-aborted", step.Name), 1
			}
		}
		r.rep.Steps[idx].End = rfc(r.clock.Now())
		r.rep.Steps[idx].Observed = r.observe(from, r.samples[len(r.samples)-1].snap)
		r.rep.Steps[idx].Completed = true
		r.collectInjected()
	}
	r.logf("plan complete")
	return r.finish("completed"), 0
}

// collectInjected copies the gateway's per-fault hit counters into the last step.
func (r *chaosRunner) collectInjected() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := r.admin.ChaosStatus(ctx)
	if err != nil || len(r.rep.Steps) == 0 {
		return
	}
	res := &r.rep.Steps[len(r.rep.Steps)-1]
	for i := range res.Faults {
		for _, v := range st.Faults {
			if v.Route == res.Faults[i].Route && v.Rule == res.Faults[i].Rule && v.Effect == res.Faults[i].Effect {
				res.Faults[i].Injected = v.Injected
			}
		}
	}
}

func (r *chaosRunner) abort(err error, outcome, step string) *ChaosReport {
	if err == errGuard {
		g := r.rep.GuardFired
		if g != nil {
			r.logf("GUARD FIRED (%s): %s; removing every fault", g.Metric, g.Reason)
		}
		if outcome == "guard-aborted" || outcome == "refused" {
			return r.finish(outcome)
		}
	}
	if ctx := err; ctx == context.Canceled || ctx == context.DeadlineExceeded {
		r.logf("interrupted; removing every fault")
		return r.finish("interrupted")
	}
	return r.finish(outcome)
}

// ---- command ----

func runChaos(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui, tty bool) (int, error) {
	admin := fs.String("admin", builtin.DefaultAdmin, "gateway admin address")
	planPath := fs.String("plan", "", "experiment plan JSON file (chaos run)")
	reportPath := fs.String("report", "", "write the experiment report JSON to this file (chaos run)")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
	dry := fs.Bool("dry-run", false, "validate the plan and print its schedule; contact no gateway (chaos run)")
	takeover := fs.Bool("takeover", false, "run even though faults are already active; they are replaced (chaos run)")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura chaos: %s\n", msg)
		exampleHint(stderr, "chaos")
		return 2, usageError{msg}
	}
	if len(pos) != 1 || (pos[0] != "run" && pos[0] != "stop" && pos[0] != "status") {
		return bad("expected run, stop or status")
	}
	pretty, err := wantPretty(*format, tty)
	if err != nil {
		return bad(err.Error())
	}
	ad := newHTTPAdmin(*admin)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch pos[0] {
	case "stop":
		return chaosStop(ctx, ad, *format, pretty, stdout, stderr, u)
	case "status":
		st, err := ad.ChaosStatus(ctx)
		if err != nil {
			return 2, err
		}
		if !pretty {
			return 0, writeJSON(stdout, st)
		}
		fmt.Fprint(stdout, u.ChaosStatusPretty(st))
		return 0, nil
	}
	if *planPath == "" {
		return bad("run needs --plan FILE")
	}
	raw, err := os.ReadFile(*planPath)
	if err != nil {
		return 2, err
	}
	plan, err := ParseChaosPlan(raw)
	if err != nil {
		return 2, err
	}
	if *dry {
		fmt.Fprint(stdout, plan.schedule(u))
		return 0, nil
	}
	rn := &chaosRunner{plan: plan, admin: ad, clock: realClock{}, takeover: *takeover, adminAt: *admin,
		logf: func(f string, a ...any) { fmt.Fprintf(stderr, "  "+f+"\n", a...) }}
	rep, code := rn.run(ctx)
	if *reportPath != "" {
		var b bytes.Buffer
		writeJSON(&b, rep)
		if err := os.WriteFile(*reportPath, b.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "setura chaos: cannot write the report: %v\n", err)
			return 2, nil
		}
	}
	if pretty {
		fmt.Fprint(stdout, u.ChaosReportPretty(rep, *reportPath))
	} else if err := writeJSON(stdout, rep); err != nil {
		return 2, err
	}
	if !rep.Cleanup.Verified && rep.Outcome != "error" {
		return 1, nil
	}
	return code, nil
}

func chaosStop(ctx context.Context, ad chaosAdmin, format string, pretty bool, stdout, stderr io.Writer, u *ui) (int, error) {
	before, _ := ad.ChaosStatus(ctx)
	st, err := ad.ChaosStop(ctx)
	if err != nil {
		return 2, err
	}
	if !pretty {
		return boolExit(st.Active), writeJSON(stdout, st)
	}
	n := 0
	if before != nil {
		n = len(before.Faults)
	}
	if st.Active {
		fmt.Fprintf(stdout, "\n  %s %d fault(s) still active after the kill switch\n\n", u.failSym(), len(st.Faults))
		return 1, nil
	}
	fmt.Fprintf(stdout, "\n  %s all faults removed (%d were active); the config faults of the running table are off until the next reload\n\n", u.okSym(), n)
	return 0, nil
}

// ---- rendering ----

func (p *ChaosPlan) schedule(u *ui) string {
	var b strings.Builder
	name := p.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Fprintf(&b, "\n  %s  %s\n", u.bold("chaos plan"), name)
	fmt.Fprintf(&b, "  blast-radius cap %d%%; baseline %s; fault TTL = step length + %s\n", p.MaxBlastPercent, p.baseline, p.grace)
	g := p.Guard
	var gs []string
	if g.MaxErrorRate > 0 {
		gs = append(gs, fmt.Sprintf("5xx over %g%%", g.MaxErrorRate))
	}
	if g.MaxBurn > 0 {
		gs = append(gs, fmt.Sprintf("burn over %gx of a %g%% SLO", g.MaxBurn, g.Objective))
	}
	if g.MaxP99Ms > 0 {
		gs = append(gs, fmt.Sprintf("p99 over %g ms", g.MaxP99Ms))
	}
	fmt.Fprintf(&b, "  guard aborts and removes every fault on: %s (window %s, every %s, %s routes)\n\n", strings.Join(gs, ", "), p.window, p.interval, g.Scope)
	for i, s := range p.Steps {
		fmt.Fprintf(&b, "  %d. %-18s +%-8s for %s\n", i+1, s.Name, s.at, s.dur)
		for _, f := range s.Faults {
			c, _ := builtin.CompileFault(&builtin.Fault{Percent: f.Fault.Percent, Header: f.Fault.Header, Latency: f.Fault.Latency, Abort: f.Fault.Abort,
				Reset: f.Fault.Reset, Truncate: f.Fault.Truncate, Throttle: f.Fault.Throttle, TTL: "1m"})
			if c == nil {
				continue
			}
			rule := "all rules"
			if f.Rule > 0 {
				rule = fmt.Sprintf("rule %d", f.Rule)
			}
			fmt.Fprintf(&b, "       %s %s (%s): %s on %s\n", u.arrow(), f.Route, rule, c.Summary(), c.Selector())
		}
		if len(s.Faults) == 0 {
			fmt.Fprintf(&b, "       %s observe only\n", u.gray(u.sym("·", "-")))
		}
	}
	b.WriteString("\n")
	return b.String()
}

func (u *ui) ChaosStatusPretty(st *builtin.ChaosStatus) string {
	var b strings.Builder
	if !st.Active {
		fmt.Fprintf(&b, "\n  %s no fault injection is active\n", u.okSym())
		if st.KilledAt != "" {
			fmt.Fprintf(&b, "  %s\n", u.gray("kill switch used at "+st.KilledAt))
		}
		b.WriteString("\n")
		return b.String()
	}
	fmt.Fprintf(&b, "\n  %s %d fault(s) active\n\n", u.warnSym(), len(st.Faults))
	for _, f := range st.Faults {
		rule := "all rules"
		if f.Rule > 0 {
			rule = fmt.Sprintf("rule %d", f.Rule)
		}
		fmt.Fprintf(&b, "    %s (%s)  %s\n", f.Route, rule, f.Effect)
		fmt.Fprintf(&b, "      %s\n", u.gray(fmt.Sprintf("%s, %s, %ds left, hit %d requests", f.Selector, f.Source, f.RemainingSeconds, f.Injected)))
	}
	fmt.Fprintf(&b, "\n  Stop them now: setura chaos stop\n\n")
	return b.String()
}

func (u *ui) ChaosReportPretty(r *ChaosReport, path string) string {
	var b strings.Builder
	head := map[string]string{"completed": u.okSym() + " " + u.bold("experiment completed"), "guard-aborted": u.failSym() + " " + u.bold("guard aborted the experiment"),
		"interrupted": u.warnSym() + " " + u.bold("experiment interrupted"), "refused": u.failSym() + " " + u.bold("experiment did not start"), "error": u.failSym() + " " + u.bold("experiment could not run")}[r.Outcome]
	name := r.Plan
	if name == "" {
		name = "chaos"
	}
	fmt.Fprintf(&b, "\n  %s  %s  %s\n\n", head, name, u.gray(fmt.Sprintf("%.0fs", r.DurationSeconds)))
	if g := r.GuardFired; g != nil {
		fmt.Fprintf(&b, "  %s guard fired after %.0fs in %s: %s\n\n", u.arrow(), g.ElapsedSeconds, g.Step, g.Reason)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  %s %s\n", u.arrow(), n)
	}
	obs := func(o ChaosObserved) string {
		return fmt.Sprintf("%d req, 5xx %.2f%%, burn %.1fx, p99 %.0f ms", o.Requests, o.ErrorRate, o.Burn, o.P99Ms)
	}
	if r.Baseline != nil {
		fmt.Fprintf(&b, "  %-18s %s\n", "baseline", u.gray(obs(*r.Baseline)))
	}
	for _, s := range r.Steps {
		sym := u.okSym()
		if !s.Completed {
			sym = u.failSym()
		}
		fmt.Fprintf(&b, "  %s %-16s %s\n", sym, s.Name, u.gray(obs(s.Observed)))
		for _, f := range s.Faults {
			fmt.Fprintf(&b, "      %s %s: %s on %s, hit %d requests\n", u.arrow(), f.Route, f.Effect, f.Selector, f.Injected)
		}
	}
	fmt.Fprintf(&b, "\n  %-18s %s\n", "peak in any window", u.gray(obs(r.Peak)))
	switch {
	case r.Cleanup.Verified:
		fmt.Fprintf(&b, "  %s faults removed and confirmed off\n", u.okSym())
	default:
		fmt.Fprintf(&b, "  %s could not confirm the faults are off (%s). Run: setura chaos stop\n", u.failSym(), r.Cleanup.Error)
	}
	if path != "" {
		fmt.Fprintf(&b, "  report written to %s\n", path)
	}
	b.WriteString("\n")
	return b.String()
}
