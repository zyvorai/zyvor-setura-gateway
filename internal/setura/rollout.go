package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// rolloutClock is injectable so tests do not sleep.
type rolloutClock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// adminAPI reads the gateway admin /status document.
type adminAPI interface {
	Status(ctx context.Context) (*builtin.StatusDoc, error)
}

type httpAdmin struct {
	base   string
	client *http.Client
}

func newHTTPAdmin(addr string) *httpAdmin {
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	return &httpAdmin{base: strings.TrimRight(addr, "/"), client: &http.Client{Timeout: 3 * time.Second}}
}

func (a *httpAdmin) Status(ctx context.Context) (*builtin.StatusDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/status", nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin /status answered HTTP %d", resp.StatusCode)
	}
	var d builtin.StatusDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("admin /status: %w", err)
	}
	return &d, nil
}

// probeFn runs the checks once and returns one report per check case.
type probeFn func(ctx context.Context) ([]*Report, error)

func checksProbe(path string) probeFn {
	return func(ctx context.Context) ([]*Report, error) {
		type res struct {
			rows []*Report
			err  error
		}
		ch := make(chan res, 1)
		go func() { r, e := Check(path); ch <- res{r, e} }()
		select {
		case r := <-ch:
			return r.rows, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

type rolloutOptions struct {
	Config, New, Checks string
	Observe             time.Duration
	ProbeInterval       time.Duration
	ApplyTimeout        time.Duration
	ApplyPoll           time.Duration
	Steps               []int
	RollbackOnFail      bool
	Force               bool
	Keep                int
	MaxErrorRate        float64
	MaxP95              time.Duration
	NoSteps             bool          // apply the candidate directly even when it changes canary weights
	LockTimeout         time.Duration // heartbeat age after which a lock owner on another host counts as dead
}

// defaultSteps is used when the candidate changes canary weights and --steps is absent.
var defaultSteps = []int{10, 50, 100}

type stepResult struct {
	Name       string   `json:"name"`
	Weight     int      `json:"weight,omitempty"`
	Generation int64    `json:"generation"`
	Probes     int      `json:"probes"`
	Failures   int      `json:"failures"`
	ErrorRate  float64  `json:"errorRate"`
	P95MS      float64  `json:"p95Ms"`
	OK         bool     `json:"ok"`
	Evidence   []string `json:"evidence,omitempty"`
	// Gateway is the gateway's own view of this stage (/stats and /metrics
	// deltas over the window); absent when the admin API did not provide it.
	Gateway *gwStage `json:"gateway,omitempty"`
}

type rolloutResult struct {
	OK               bool         `json:"ok"`
	Outcome          string       `json:"outcome"` // success, rolled_back, failed_in_place, refused, interrupted
	Reason           string       `json:"reason,omitempty"`
	Evidence         []string     `json:"evidence,omitempty"`
	Backup           string       `json:"backup,omitempty"`
	FromGeneration   int64        `json:"fromGeneration"`
	Generation       int64        `json:"generation"`
	Steps            []stepResult `json:"steps"`
	Probes           int          `json:"probes"`
	Failures         int          `json:"failures"`
	RolledBack       bool         `json:"rolledBack"`
	RestoreConfirmed bool         `json:"restoreConfirmed"`
	// TrippedBy names the source of the verdict that failed the rollout:
	// "probes", "gateway /stats", "gateway /metrics", "apply" or "interrupt".
	TrippedBy string `json:"trippedBy,omitempty"`
	// CertDir is the directory relative certificate paths were resolved against.
	CertDir string `json:"certDir,omitempty"`
	// StepsNote says when --steps was defaulted or ignored.
	StepsNote string `json:"stepsNote,omitempty"`
	// GatewayStats says whether /stats and /metrics were used ("used") or why not.
	GatewayStats string `json:"gatewayStats,omitempty"`
}

type rollout struct {
	o     rolloutOptions
	clock rolloutClock
	admin adminAPI
	probe probeFn
	lint  func([]byte) (bool, string)
	log   io.Writer
	hist  histStore
	scope func(key string) bool // gateway series judged (nil: all)
}

func (r *rollout) logf(f string, a ...any) {
	if r.log != nil {
		fmt.Fprintf(r.log, "rollout: "+f+"\n", a...)
	}
}

// applyError distinguishes a rejected reload from a timeout.
type applyError struct {
	rejected bool
	msg      string
}

func (e *applyError) Error() string { return e.msg }

func gatewayConditionProblem(st *builtin.StatusDoc) string {
	keys := make([]string, 0, len(st.Gateways))
	for k := range st.Gateways {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := st.Gateways[k]
		for _, c := range g.Conditions {
			if (c.Type == "Accepted" || c.Type == "Programmed") && c.Status != "True" {
				return fmt.Sprintf("gateway %s condition %s is %s: %s", k, c.Type, c.Status, c.Message)
			}
		}
	}
	return ""
}

// install atomically replaces the live file with data and waits until the
// gateway reports that content as applied.
func (r *rollout) install(ctx context.Context, data []byte, prev *builtin.StatusDoc) (*builtin.StatusDoc, error) {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(r.o.Config); err == nil {
		mode = st.Mode().Perm()
	}
	if err := atomicWrite(r.o.Config, data, mode); err != nil {
		return nil, fmt.Errorf("write %s: %w", r.o.Config, err)
	}
	expected := ""
	if ld, err := (builtin.FileSource{Path: r.o.Config}).Load(ctx); err == nil {
		expected = ld.Hash
	}
	deadline := r.clock.Now().Add(r.o.ApplyTimeout)
	var last *builtin.StatusDoc
	for {
		st, err := r.admin.Status(ctx)
		if err == nil {
			last = st
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			switch {
			case expected != "" && st.ConfigHash == expected && st.LastReload.OK:
				if p := gatewayConditionProblem(st); p != "" {
					return st, &applyError{true, "gateway applied the config but " + p}
				}
				return st, nil
			case !st.LastReload.OK && (prev == nil || st.LastReload.Time != prev.LastReload.Time || st.LastReload.Error != prev.LastReload.Error):
				return st, &applyError{true, "gateway rejected the reload: " + strings.TrimSpace(st.LastReload.Error)}
			}
		}
		if !r.clock.Now().Before(deadline) {
			msg := fmt.Sprintf("gateway did not apply the new config within %s", r.o.ApplyTimeout)
			if err != nil {
				msg += ": admin API: " + err.Error()
			} else if last != nil {
				msg += fmt.Sprintf(" (still generation %d)", last.Generation)
			}
			return last, &applyError{false, msg}
		}
		if err := r.clock.Sleep(ctx, r.o.ApplyPoll); err != nil {
			return nil, err
		}
	}
}

// observeStats accumulates probe outcomes for one step.
type observeStats struct {
	probes, failures int
	lat              []float64
	evidence         []string
}

func (s *observeStats) rate() float64 {
	if s.probes == 0 {
		return 0
	}
	return float64(s.failures) / float64(s.probes)
}

func (s *observeStats) p95() float64 {
	if len(s.lat) == 0 {
		return 0
	}
	l := append([]float64(nil), s.lat...)
	sort.Float64s(l)
	idx := int(math.Ceil(0.95*float64(len(l)))) - 1
	if idx < 0 {
		idx = 0
	}
	return l[idx]
}

func failureEvidence(rep *Report) string {
	for _, name := range stages {
		st := rep.Steps[name]
		if st != nil && st.State() == "failed" {
			return fmt.Sprintf("%s: %s failed: %v", rep.URL, name, st.Get("reason"))
		}
	}
	return rep.URL + ": failed"
}

// breach returns a reason when the stats violate a threshold.
func (r *rollout) breach(s *observeStats, final bool) string {
	if r.o.MaxErrorRate <= 0 && s.failures > 0 {
		return fmt.Sprintf("%d of %d probes failed", s.failures, s.probes)
	}
	if final && r.o.MaxErrorRate > 0 && s.rate() > r.o.MaxErrorRate {
		return fmt.Sprintf("error rate %.1f%% exceeds the %.1f%% limit (%d of %d probes failed)", s.rate()*100, r.o.MaxErrorRate*100, s.failures, s.probes)
	}
	if r.o.MaxP95 > 0 && s.probes > 0 {
		if p := s.p95(); p > float64(r.o.MaxP95)/float64(time.Millisecond) {
			return fmt.Sprintf("p95 latency %.1f ms exceeds the %s limit", p, r.o.MaxP95)
		}
	}
	return ""
}

// restore puts the previous config back and waits for the gateway to confirm.
func (r *rollout) restore(prevRaw []byte, res *rolloutResult, st *builtin.StatusDoc) {
	ctx, cancel := context.WithTimeout(context.Background(), r.o.ApplyTimeout+5*time.Second)
	defer cancel()
	r.logf("restoring the previous configuration")
	cur, err := r.admin.Status(ctx)
	if err != nil {
		cur = st
	}
	got, err := r.install(ctx, prevRaw, cur)
	res.RolledBack = true
	if got != nil {
		res.Generation = got.Generation
	}
	if err != nil {
		res.Evidence = append(res.Evidence, "WARNING: the previous config was written back to "+r.o.Config+" but the gateway did not confirm it: "+err.Error())
		return
	}
	res.RestoreConfirmed = true
}

// run executes the rollout. code: 0 success, 1 failed (config restored when
// requested), 2 setup or usage error.
func (r *rollout) run(ctx context.Context) (*rolloutResult, int, error) {
	res := &rolloutResult{Steps: []stepResult{}}
	live, err := os.ReadFile(r.o.Config)
	if err != nil {
		return nil, 2, err
	}
	cand, err := os.ReadFile(r.o.New)
	if err != nil {
		return nil, 2, err
	}
	// Relative certificate paths resolve against the candidate's directory.
	candAbs, _ := filepath.Abs(r.o.New)
	liveAbs, _ := filepath.Abs(r.o.Config)
	certDir := filepath.Dir(candAbs)
	cand, certs, err := resolveCandidateCerts(cand, certDir, filepath.Dir(liveAbs))
	if err != nil {
		return nil, 2, err
	}
	if certs != nil {
		res.CertDir = certs.Dir
		r.logf("%s", certs.describe(filepath.Dir(liveAbs)))
		if len(certs.Missing) > 0 && !r.o.Force {
			res.Outcome, res.Reason = "refused", "candidate references certificate files that do not exist (use --force to roll out anyway)"
			res.Evidence = certs.Missing
			return res, 1, nil
		}
		for _, m := range certs.Missing {
			r.logf("warning: %s", m)
		}
	}
	if raw, err := os.ReadFile(r.o.Checks); err != nil {
		return nil, 2, err
	} else {
		var v any
		if json.Unmarshal(raw, &v) != nil || len(asList(v)) == 0 {
			return nil, 2, userError("checks file must be a nonempty JSON array")
		}
		// An undefined {{variable}} must stop the rollout before anything changes.
		if _, err := (*Vars)(nil).expand(v); err != nil {
			return nil, 2, err
		}
	}

	lintOK, lintText := true, ""
	if r.lint != nil {
		lintOK, lintText = r.lint(cand)
	}
	if !lintOK && !r.o.Force {
		res.Outcome, res.Reason = "refused", "candidate has lint errors (use --force to roll out anyway)"
		res.Evidence = nonEmptyLines(lintText, 12)
		return res, 1, nil
	}
	var plan []planStage
	steps, defaulted := r.o.Steps, false
	if len(steps) == 0 && !r.o.NoSteps {
		steps, defaulted = defaultSteps, true
	}
	if len(steps) > 0 {
		plan, err = canaryPlan(live, cand, steps)
		if err != nil {
			return nil, 2, err
		}
		switch {
		case len(plan) == 0 && !defaulted:
			res.StepsNote = "--steps ignored: no canary weight change between live and candidate; the candidate is applied directly"
		case len(plan) > 0 && defaulted:
			res.StepsNote = "the candidate changes canary weights and --steps was not given: using the default 10,50,100 (--no-steps applies it directly)"
		}
		if res.StepsNote != "" {
			r.logf("%s", res.StepsNote)
		}
	}
	plan = append(plan, planStage{name: "candidate", data: cand})
	r.scope = gatewayScope(live, cand)

	st0, err := r.admin.Status(ctx)
	if err != nil {
		return nil, 2, fmt.Errorf("cannot read the gateway admin API: %w", err)
	}
	res.FromGeneration, res.Generation = st0.Generation, st0.Generation
	if st0.ConfigHash != "" {
		if ld, err := (builtin.FileSource{Path: r.o.Config}).Load(ctx); err == nil && ld.Hash != st0.ConfigHash {
			r.logf("warning: the gateway is not serving the current contents of %s (generation %d)", r.o.Config, st0.Generation)
		}
	}

	unlock, err := r.hist.lockWith(r.logf)
	if err != nil {
		return nil, 2, err
	}
	defer unlock()

	liveLintOK, liveLint := true, ""
	if r.lint != nil {
		liveLintOK, liveLint = r.lint(live)
	}
	meta, err := r.hist.add(live, histMeta{Reason: "rollout", Generation: st0.Generation, LintOK: liveLintOK,
		LintSummary: firstLine(liveLint), Diff: summarizeDiff(live, cand)}, r.clock.Now())
	if err != nil {
		return nil, 2, fmt.Errorf("backup: %w", err)
	}
	res.Backup = meta.ID
	r.hist.prune(r.o.Keep)
	r.logf("backed up the live config as %s", meta.ID)

	fail := func(outcome, reason string, evidence []string) (*rolloutResult, int, error) {
		res.OK, res.Outcome, res.Reason, res.Evidence = false, outcome, reason, evidence
		return res, 1, nil
	}
	cur := st0
	for _, stg := range plan {
		r.logf("applying %s", stg.name)
		got, err := r.install(ctx, stg.data, cur)
		if ctx.Err() != nil {
			r.restore(live, res, cur)
			res.TrippedBy = "interrupt"
			return fail("interrupted", "interrupted while applying "+stg.name+"; the previous config was restored", nil)
		}
		if got != nil {
			cur = got
			res.Generation = got.Generation
		}
		sr := stepResult{Name: stg.name, Weight: stg.weight, Generation: res.Generation}
		if err != nil {
			sr.Evidence = []string{err.Error()}
			res.Steps = append(res.Steps, sr)
			res.TrippedBy = "apply"
			return r.failStep(res, live, cur, fmt.Sprintf("%s: %v", stg.name, err), nil)
		}
		gw := r.openWindow(ctx, res)
		stats, v, oerr := r.observe(ctx, gw)
		sr.Gateway = gw.summary()
		sr.Probes, sr.Failures, sr.ErrorRate, sr.P95MS, sr.Evidence = stats.probes, stats.failures, math.Round(stats.rate()*10000)/10000, stats.p95(), stats.evidence
		res.Probes += stats.probes
		res.Failures += stats.failures
		if oerr != nil {
			res.Steps = append(res.Steps, sr)
			r.restore(live, res, cur)
			res.TrippedBy = "interrupt"
			return fail("interrupted", "interrupted during "+stg.name+" observation; the previous config was restored", stats.evidence)
		}
		if v.why != "" {
			res.Steps = append(res.Steps, sr)
			res.TrippedBy = v.source
			return r.failStep(res, live, cur, fmt.Sprintf("%s: %s", stg.name, v.why), stats.evidence)
		}
		sr.OK = true
		res.Steps = append(res.Steps, sr)
	}
	res.OK, res.Outcome = true, "success"
	return res, 0, nil
}

func (r *rollout) failStep(res *rolloutResult, live []byte, cur *builtin.StatusDoc, reason string, evidence []string) (*rolloutResult, int, error) {
	res.OK, res.Reason, res.Evidence = false, reason, evidence
	if r.o.RollbackOnFail {
		r.restore(live, res, cur)
		res.Outcome = "rolled_back"
	} else {
		res.Outcome = "failed_in_place"
		res.Evidence = append(res.Evidence, "--rollback-on-fail=false: the failing config was left in place; undo with: setura gateway rollback --config "+r.o.Config)
	}
	return res, 1, nil
}

func nonEmptyLines(s string, max int) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(out) == max {
				out = append(out, "...")
				break
			}
			out = append(out, l)
		}
	}
	return out
}

// planStage is one config to apply during a rollout.
type planStage struct {
	name   string
	weight int
	data   []byte
}

func decodeNumbers(raw []byte) (obj, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc obj
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func refWeight(m obj) int {
	if w, ok := num(m["weight"]); ok {
		return int(w)
	}
	return 1
}

func refKey(m obj) string { return asStr(m["name"]) + ":" + fmt.Sprint(m["port"]) }

type canaryRule struct {
	refs  []obj // the candidate's backendRefs (inside the decoded doc)
	w     []int // their candidate weights
	newer int   // index of the backend whose weight grows
}

// canaryPlan builds one intermediate config per step. Rules of the candidate
// that have two or more backendRefs and whose weights differ from live are
// canaries; the ref whose weight grows most is the new backend. It gets the
// step percentage and the other refs share the rest in their candidate ratio.
func canaryPlan(liveRaw, candRaw []byte, steps []int) ([]planStage, error) {
	live, err := decodeNumbers(liveRaw)
	if err != nil {
		return nil, userErrorf("live config is not valid JSON: %v", err)
	}
	cand, err := decodeNumbers(candRaw)
	if err != nil {
		return nil, userErrorf("candidate is not valid JSON: %v", err)
	}
	var rules []canaryRule
	liveRes, candRes := asMap(live["resources"]), asMap(cand["resources"])
	for _, key := range sortedKeys(candRes) {
		cr := asList(asMap(candRes[key])["rules"])
		lr := asList(asMap(liveRes[key])["rules"])
		for i, rule := range cr {
			refs := asList(asMap(rule)["backendRefs"])
			if len(refs) < 2 {
				continue
			}
			liveW := map[string]int{}
			if i < len(lr) {
				for _, x := range asList(asMap(lr[i])["backendRefs"]) {
					liveW[refKey(asMap(x))] = refWeight(asMap(x))
				}
			}
			cr := canaryRule{newer: -1}
			best := 0
			changed := false
			for j, x := range refs {
				m := asMap(x)
				cr.refs = append(cr.refs, m)
				cr.w = append(cr.w, refWeight(m))
				d := refWeight(m) - liveW[refKey(m)]
				if d != 0 {
					changed = true
				}
				if d > best {
					best, cr.newer = d, j
				}
			}
			if changed && cr.newer >= 0 {
				rules = append(rules, cr)
			}
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}
	prev := 0
	var out []planStage
	for _, p := range steps {
		if p < 1 || p > 100 || p <= prev {
			return nil, userErrorf("--steps must be increasing percentages between 1 and 100, got %d after %d", p, prev)
		}
		prev = p
		for _, cr := range rules {
			applyShift(cr, p)
		}
		b, err := json.MarshalIndent(cand, "", "  ")
		if err != nil {
			return nil, err
		}
		out = append(out, planStage{name: fmt.Sprintf("canary %d%%", p), weight: p, data: append(b, '\n')})
	}
	return out, nil
}

func applyShift(cr canaryRule, pct int) {
	var others []int
	total := 0
	for j := range cr.refs {
		if j != cr.newer {
			others = append(others, j)
			total += cr.w[j]
		}
	}
	cr.refs[cr.newer]["weight"] = pct
	rest := 100 - pct
	left := rest
	for n, j := range others {
		w := 0
		switch {
		case n == len(others)-1:
			w = left
		case total > 0:
			w = int(math.Round(float64(rest) * float64(cr.w[j]) / float64(total)))
		default:
			w = rest / len(others)
		}
		if w > left {
			w = left
		}
		left -= w
		cr.refs[j]["weight"] = w
	}
}

// --- command line -----------------------------------------------------------

func parseSteps(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 100 {
			return nil, userErrorf("--steps %q: want percentages between 1 and 100, for example 10,50,100", s)
		}
		out = append(out, n)
	}
	return out, nil
}

// runRolloutCommand dispatches rollout, history and rollback.
func runRolloutCommand(sub string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gateway "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	usage := func(err error) int {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "setura gateway %s: %v\n", sub, err)
		return 2
	}
	var o rolloutOptions
	config := fs.String("config", "", "live snapshot file served by the gateway (required)")
	format := fs.String("format", "pretty", "pretty or json")
	admin := fs.String("admin", builtin.DefaultAdmin, "gateway admin address")
	fs.IntVar(&o.Keep, "keep", 10, "backups to keep in .setura-history")
	fs.DurationVar(&o.ApplyTimeout, "apply-timeout", 15*time.Second, "how long to wait for the gateway to apply a config")
	lockTimeout := fs.Duration("lock-timeout", time.Minute, "heartbeat age after which a lock held from another host counts as stale")
	var newCfg, checks, steps, to string
	switch sub {
	case "rollout":
		fs.StringVar(&newCfg, "new", "", "candidate snapshot file (required)")
		fs.StringVar(&checks, "checks", "", "checks file run against the gateway (required)")
		fs.DurationVar(&o.Observe, "observe", 30*time.Second, "observation window per step")
		fs.StringVar(&steps, "steps", "", "progressive canary weights for the new backend, for example 10,50,100 (default 10,50,100 when the candidate changes canary weights)")
		fs.BoolVar(&o.NoSteps, "no-steps", false, "apply the candidate directly even when it changes canary weights")
		fs.BoolVar(&o.RollbackOnFail, "rollback-on-fail", true, "restore the previous config on failure")
		fs.BoolVar(&o.Force, "force", false, "roll out a candidate that has lint errors")
		fs.Float64Var(&o.MaxErrorRate, "max-error-rate", 0, "tolerated error fraction for probes and the gateway's own /stats (0 to 1; default 0 fails on any failure)")
		fs.DurationVar(&o.MaxP95, "max-p95", 0, "fail when p95 latency exceeds this, for probes and the gateway's own /metrics (0 disables)")
		fs.DurationVar(&o.ProbeInterval, "probe-interval", time.Second, "pause between probe rounds")
	case "rollback":
		fs.StringVar(&to, "to", "", "backup ID to restore (default: the newest)")
	case "history":
	}
	if err := fs.Parse(args); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}
	if *format != "pretty" && *format != "json" {
		return usage(userError("--format must be pretty or json"))
	}
	pretty := *format == "pretty"
	var err error
	if *config == "" {
		return usage(errors.New("--config is required"))
	}
	o.Config = *config
	o.ApplyPoll = 100 * time.Millisecond
	hist := newHistStore(o.Config)
	if *lockTimeout <= 0 {
		return usage(errors.New("--lock-timeout must be positive"))
	}
	hist.hbTimeout = *lockTimeout

	switch sub {
	case "history":
		return historyCommand(hist, pretty, stdout, stderr)
	case "rollback":
		return rollbackCommand(hist, o, to, *admin, pretty, stdout, stderr)
	}
	if newCfg == "" || checks == "" {
		return usage(errors.New("--new and --checks are required"))
	}
	if o.Steps, err = parseSteps(steps); err != nil {
		return usage(err)
	}
	if o.NoSteps && len(o.Steps) > 0 {
		return usage(errors.New("--steps and --no-steps contradict each other"))
	}
	if o.MaxErrorRate < 0 || o.MaxErrorRate > 1 || o.Observe < 0 || o.Keep < 1 {
		return usage(errors.New("--max-error-rate must be 0-1, --observe must not be negative, --keep must be at least 1"))
	}
	o.New, o.Checks = newCfg, checks

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := &rollout{o: o, clock: realClock{}, admin: newHTTPAdmin(*admin), probe: checksProbe(checks),
		lint: gatewayLint, log: stderr, hist: hist}
	res, code, err := r.run(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway rollout: %v\n", err)
		return 2
	}
	writeRollout(stdout, res, pretty)
	return code
}

func writeRollout(w io.Writer, res *rolloutResult, pretty bool) {
	if !pretty {
		writeJSON(w, res)
		return
	}
	if res.OK {
		fmt.Fprintf(w, "ROLLOUT OK  generation %d -> %d, %d step(s), %d probes, %d failed\n", res.FromGeneration, res.Generation, len(res.Steps), res.Probes, res.Failures)
	} else {
		fmt.Fprintf(w, "ROLLOUT FAILED (%s): %s\n", res.Outcome, res.Reason)
	}
	for _, s := range res.Steps {
		mark := "ok  "
		if !s.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(w, "  %s %-14s generation %d  probes %d  failed %d  error-rate %.1f%%  p95 %.1f ms\n", mark, s.Name, s.Generation, s.Probes, s.Failures, s.ErrorRate*100, s.P95MS)
		if g := s.Gateway; g != nil {
			fmt.Fprintf(w, "       gateway /stats+/metrics: %d requests, %d 5xx (%.1f%%, before %.1f%% over %d), p95 %.1f ms\n", g.Requests, g.Errors, g.ErrorRate*100, g.BeforeErrorRate*100, g.BeforeRequests, g.P95Ms)
		}
	}
	if res.TrippedBy != "" && !res.OK {
		fmt.Fprintf(w, "  tripped by: %s\n", res.TrippedBy)
	}
	for _, e := range res.Evidence {
		fmt.Fprintf(w, "  evidence: %s\n", e)
	}
	for _, s := range res.Steps {
		if !s.OK {
			for _, e := range s.Evidence {
				fmt.Fprintf(w, "  evidence: %s\n", e)
			}
		}
	}
	if res.RolledBack {
		if res.RestoreConfirmed {
			fmt.Fprintf(w, "  previous config restored; the gateway is serving generation %d\n", res.Generation)
		} else {
			fmt.Fprintln(w, "  previous config restored on disk, NOT confirmed by the gateway")
		}
	}
	if res.Backup != "" {
		fmt.Fprintf(w, "  backup %s (setura gateway rollback --to %s)\n", res.Backup, res.Backup)
	}
}

func historyCommand(h histStore, pretty bool, stdout, stderr io.Writer) int {
	list, err := h.list()
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway history: %v\n", err)
		return 2
	}
	if !pretty {
		if list == nil {
			list = []histMeta{}
		}
		writeJSON(stdout, list)
		return 0
	}
	if len(list) == 0 {
		fmt.Fprintf(stdout, "no backups in %s\n", h.dir)
		return 0
	}
	fmt.Fprintf(stdout, "%-30s %-20s %-4s %-5s %s\n", "ID", "TIME", "GEN", "LINT", "DIFF (backup -> what replaced it)")
	for _, m := range list {
		lint := "ok"
		if !m.LintOK {
			lint = "FAIL"
		}
		fmt.Fprintf(stdout, "%-30s %-20s %-4d %-5s %s\n", m.ID, m.Time, m.Generation, lint, m.Diff)
	}
	return 0
}

func rollbackCommand(h histStore, o rolloutOptions, to, admin string, pretty bool, stdout, stderr io.Writer) int {
	r := &rollout{o: o, clock: realClock{}, admin: newHTTPAdmin(admin), lint: gatewayLint, log: stderr, hist: h}
	res, code, err := r.rollback(context.Background(), to)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway rollback: %v\n", err)
		return 2
	}
	if !pretty {
		writeJSON(stdout, res)
		return code
	}
	if res.OK {
		fmt.Fprintf(stdout, "restored %s; ", res.Reason)
		if res.RestoreConfirmed {
			fmt.Fprintf(stdout, "the gateway is serving generation %d\n", res.Generation)
		} else {
			fmt.Fprintln(stdout, "the gateway could not be reached, so the reload is unconfirmed")
		}
		fmt.Fprintf(stdout, "  the config it replaced is saved as %s\n", res.Backup)
	} else {
		fmt.Fprintf(stdout, "ROLLBACK FAILED: %s\n", res.Reason)
		for _, e := range res.Evidence {
			fmt.Fprintf(stdout, "  %s\n", e)
		}
	}
	return code
}

// rollback restores a backup (default: the newest) as the live config.
func (r *rollout) rollback(ctx context.Context, id string) (*rolloutResult, int, error) {
	res := &rolloutResult{Steps: []stepResult{}}
	if id == "" {
		all, err := r.hist.list()
		if err != nil {
			return nil, 2, err
		}
		if len(all) == 0 {
			return nil, 2, userErrorf("no backups in %s", r.hist.dir)
		}
		id = all[0].ID
	}
	raw, m, err := r.hist.get(id)
	if err != nil {
		return nil, 2, err
	}
	unlock, err := r.hist.lockWith(r.logf)
	if err != nil {
		return nil, 2, err
	}
	defer unlock()
	live, err := os.ReadFile(r.o.Config)
	if err != nil {
		return nil, 2, err
	}
	st0, aerr := r.admin.Status(ctx)
	if aerr != nil {
		r.logf("warning: admin API unreachable (%v); the file is restored but the reload cannot be confirmed", aerr)
	}
	var gen int64
	if st0 != nil {
		gen = st0.Generation
	}
	lintOK, lintText := true, ""
	if r.lint != nil {
		lintOK, lintText = r.lint(live)
	}
	meta, err := r.hist.add(live, histMeta{Reason: "rollback", Generation: gen, LintOK: lintOK, LintSummary: firstLine(lintText),
		Diff: summarizeDiff(live, raw)}, r.clock.Now())
	if err != nil {
		return nil, 2, fmt.Errorf("backup: %w", err)
	}
	r.hist.prune(r.o.Keep)
	res.Backup, res.Reason, res.FromGeneration, res.Generation = meta.ID, m.ID, gen, gen
	if aerr != nil {
		mode := os.FileMode(0o644)
		if st, err := os.Stat(r.o.Config); err == nil {
			mode = st.Mode().Perm()
		}
		if err := atomicWrite(r.o.Config, raw, mode); err != nil {
			return nil, 2, err
		}
		res.OK, res.Outcome = true, "restored_unconfirmed"
		return res, 0, nil
	}
	got, err := r.install(ctx, raw, st0)
	if got != nil {
		res.Generation = got.Generation
	}
	if err != nil {
		res.Outcome, res.Reason = "failed", "restoring "+m.ID+": "+err.Error()
		return res, 1, nil
	}
	res.OK, res.Outcome, res.RestoreConfirmed = true, "restored", true
	return res, 0, nil
}
