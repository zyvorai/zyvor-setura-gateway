package setura

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// minWatchInterval is the shortest interval the CLI accepts.
const minWatchInterval = time.Second

// WatchEvent is one observed state change (or the initial baseline).
type WatchEvent struct {
	Time   time.Time
	Target string
	Kind   string // "initial" or "change"
	Text   string
}

type targetState struct {
	seen     bool
	ok       bool
	stage    string
	backend  string
	rounds   int
	failures int
	changes  int
}

// watcher re-runs probes and reports state changes. Clock, ticker and probe
// function are injectable so tests do not need to sleep.
type watcher struct {
	targets  []ProbeOptions
	interval time.Duration
	count    int           // stop after this many rounds; 0 means unlimited
	duration time.Duration // stop after this long; 0 means unlimited

	probe   func(ProbeOptions) (*Report, error)
	now     func() time.Time
	newTick func(time.Duration) (<-chan time.Time, func())
	after   func(time.Duration) <-chan time.Time
	out     io.Writer
	history io.Writer
	metrics *metricsStore
	alerts  *alerter
	OnEvent func(WatchEvent)
	state   map[string]*targetState
}

func newWatcher(targets []ProbeOptions, interval time.Duration, out io.Writer) *watcher {
	return &watcher{
		targets: targets, interval: interval, probe: Probe, now: time.Now, out: out,
		newTick: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		after: time.After,
		state: map[string]*targetState{},
	}
}

// failure returns the failing stage name and its reason, or "" when the probe passed.
func failure(r *Report) (stage, reason string) {
	if r.OK {
		return "", ""
	}
	for _, name := range stages {
		if s := r.Step(name); s.State() == "failed" {
			return name, asStr(s.Get("reason"))
		}
	}
	return "unknown", ""
}

func backendOf(r *Report) string { return asStr(r.Step("backend").Get("identity")) }

// observe folds one probe result into the per-target state and returns any events.
func (w *watcher) observe(r *Report) []WatchEvent {
	st := w.state[r.URL]
	if st == nil {
		st = &targetState{}
		w.state[r.URL] = st
	}
	now := w.now()
	stage, reason := failure(r)
	backend := backendOf(r)
	st.rounds++
	if !r.OK {
		st.failures++
	}
	describe := func() string {
		if r.OK {
			s := "ok"
			if backend != "" {
				s += " backend=" + backend
			}
			return s
		}
		return fmt.Sprintf("failed at %s: %s", stage, reason)
	}
	var evs []WatchEvent
	add := func(kind, text string) {
		evs = append(evs, WatchEvent{Time: now, Target: r.URL, Kind: kind, Text: text})
	}
	switch {
	case !st.seen:
		add("initial", describe())
	case st.ok && !r.OK:
		add("change", "ok -> "+describe())
	case !st.ok && r.OK:
		add("change", "failed -> "+describe())
	case !r.OK && stage != st.stage:
		add("change", fmt.Sprintf("still failing, now at %s: %s (was %s)", stage, reason, st.stage))
	case r.OK && backend != st.backend:
		add("change", fmt.Sprintf("backend identity %q -> %q", st.backend, backend))
	}
	for _, e := range evs {
		if e.Kind == "change" {
			st.changes++
		}
	}
	st.seen, st.ok, st.stage, st.backend = true, r.OK, stage, backend
	return evs
}

func (w *watcher) emit(evs []WatchEvent) {
	for _, e := range evs {
		if w.OnEvent != nil {
			w.OnEvent(e)
		}
		fmt.Fprintf(w.out, "%s  %s  %s\n", e.Time.UTC().Format(time.RFC3339), e.Target, e.Text)
	}
}

type historyLine struct {
	Time         string  `json:"time"`
	Target       string  `json:"target"`
	OK           bool    `json:"ok"`
	FailingStage string  `json:"failing_stage"`
	ElapsedMS    float64 `json:"elapsed_ms"`
}

// round probes every target concurrently, then processes results in order.
func (w *watcher) round() error {
	reports := make([]*Report, len(w.targets))
	errs := make([]error, len(w.targets))
	var wg sync.WaitGroup
	for i, t := range w.targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i], errs[i] = w.probe(t)
		}()
	}
	wg.Wait()
	for i, r := range reports {
		if errs[i] != nil {
			return errs[i]
		}
		if w.metrics != nil {
			w.metrics.Record(r)
		}
		if w.history != nil {
			stage, _ := failure(r)
			line, _ := json.Marshal(historyLine{w.now().UTC().Format(time.RFC3339), r.URL, r.OK, stage, r.ElapsedMS})
			if _, err := fmt.Fprintf(w.history, "%s\n", line); err != nil {
				return err
			}
		}
		if w.alerts != nil {
			stage, reason := failure(r)
			w.alerts.observe(r.URL, r.OK, stage, reason, r.ElapsedMS)
		}
		w.emit(w.observe(r))
	}
	return nil
}

// Run watches until ctx ends, --count rounds are done or --duration elapses.
// It returns true when the last state of any target is failing.
func (w *watcher) Run(ctx context.Context) (failing bool, err error) {
	var stop <-chan time.Time
	if w.duration > 0 {
		stop = w.after(w.duration)
	}
	tick, cancel := w.newTick(w.interval)
	defer cancel()
	defer w.alerts.wait()
	for rounds := 1; ; rounds++ {
		if err := w.round(); err != nil {
			return false, err
		}
		if w.count > 0 && rounds >= w.count {
			break
		}
		select {
		case <-ctx.Done():
			return w.anyFailing(), nil
		case <-stop:
			return w.anyFailing(), nil
		case <-tick:
		}
	}
	return w.anyFailing(), nil
}

func (w *watcher) anyFailing() bool {
	for _, st := range w.state {
		if st.seen && !st.ok {
			return true
		}
	}
	return false
}

func (w *watcher) summary() {
	fmt.Fprintf(w.out, "summary: %d target(s)\n", len(w.targets))
	for _, t := range w.targets {
		st := w.state[t.URL]
		if st == nil {
			continue
		}
		last := "ok"
		if !st.ok {
			last = "failed at " + st.stage
		}
		fmt.Fprintf(w.out, "  %s  probes=%d failed=%d changes=%d last=%s\n", t.URL, st.rounds, st.failures, st.changes, last)
	}
}

// parseWatchFile reads a checks.json style file into probe options without probing.
func parseWatchFile(path string) ([]ProbeOptions, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, userErrorf("invalid check file JSON: %v", err)
	}
	cases := asList(v)
	if len(cases) == 0 {
		return nil, userError("check file must be a nonempty JSON array")
	}
	allowed := map[string]bool{"url": true, "address": true, "status": true, "backend": true, "ca": true, "timeout": true,
		"headers": true, "body_contains": true, "max_ms": true}
	var out []ProbeOptions
	for _, c := range cases {
		m := asMap(c)
		valid := m != nil && asStr(m["url"]) != ""
		for k := range m {
			valid = valid && allowed[k]
		}
		if !valid {
			return nil, userError("invalid check case; see examples/checks.json")
		}
		o := NewProbe(asStr(m["url"]))
		o.Address, o.Backend, o.CA = str(m, "address", ""), str(m, "backend", ""), str(m, "ca", "")
		o.BodyContains = str(m, "body_contains", "")
		for key, dst := range map[string]*float64{"timeout": &o.Timeout, "max_ms": &o.MaxMS} {
			if x, ok := m[key]; ok {
				f, isNum := num(x)
				if !isNum {
					return nil, userErrorf("%s must be a number", key)
				}
				*dst = f
			}
		}
		if s, ok := m["status"]; ok {
			f, isNum := num(s)
			if !isNum || f != float64(int(f)) {
				return nil, userError("invalid port or expected HTTP status")
			}
			o.Status = int(f)
		}
		if h, ok := m["headers"]; ok {
			hm := asMap(h)
			if hm == nil {
				return nil, userError("headers must be an object of header names to values")
			}
			o.Headers = map[string]string{}
			for k, x := range hm {
				sv, ok := x.(string)
				if !ok {
					return nil, userErrorf("header %s must be a string", k)
				}
				o.Headers[k] = sv
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// runWatch implements "setura watch". Flags have already been parsed.
func runWatch(w *watcher, ctx context.Context, listen string, allowRemote bool, historyPath string, stderr io.Writer) (int, error) {
	if len(w.targets) == 0 {
		fmt.Fprintln(stderr, "setura watch: expected URL... or --file FILE")
		return 2, usageError{"targets"}
	}
	if w.interval < minWatchInterval {
		return 0, userError("--interval must be at least 1s")
	}
	if w.count < 0 || w.duration < 0 {
		return 0, userError("--count and --duration must not be negative")
	}
	if listen != "" {
		w.metrics = newMetricsStore()
		addr, stop, err := serveMetrics(listen, allowRemote, w.metrics)
		if err != nil {
			return 0, err
		}
		defer stop()
		fmt.Fprintf(stderr, "setura watch: metrics on http://%s/metrics\n", addr)
	}
	if historyPath != "" {
		f, err := os.OpenFile(historyPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		w.history = f
	}
	failing, err := w.Run(ctx)
	if err != nil {
		return 0, err
	}
	w.summary()
	return boolExit(failing), nil
}

// watchCommand parses flags for "setura watch" and runs it.
func watchCommand(rest []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("watch", stderr)
	file := fs.String("file", "", "watch the cases in a checks.json style FILE")
	interval := fs.Duration("interval", 10*time.Second, "time between probe rounds (minimum 1s)")
	count := fs.Int("count", 0, "stop after N probe rounds (0 = until interrupted)")
	duration := fs.Duration("duration", 0, "stop after this long (0 = until interrupted)")
	listen := fs.String("listen", "", "serve Prometheus metrics on ADDR, for example 127.0.0.1:9464")
	allowRemote := fs.Bool("allow-remote", false, "allow --listen on a non-loopback address")
	history := fs.String("history", "", "append one JSON line per probe to FILE")
	alertWebhook := fs.String("alert-webhook", "", "POST generic JSON to this URL on failure and recovery (secret; also from $SETURA_ALERT_WEBHOOK)")
	alertSlack := fs.String("alert-slack", "", "post to this Slack incoming webhook URL on failure and recovery (secret; also from $SETURA_ALERT_SLACK)")
	alertCooldown := fs.Duration("alert-cooldown", defaultAlertCooldown, "minimum time between alerts for one target")
	alertRetries := fs.Int("alert-retries", defaultAlertRetries, "delivery retries with exponential backoff")
	backend := fs.String("backend", "", "expected X-Setura-Backend response header")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	address := fs.String("address", "", "connect to this numeric IP")
	status := fs.Int("status", 200, "expected HTTP status")
	timeout := fs.Float64("timeout", 4, "per-operation timeout in seconds")
	body := fs.String("body-contains", "", "require this text in the response body")
	maxMS := fs.Float64("max-ms", 0, "fail when a probe takes longer than this many milliseconds")
	var headers stringList
	fs.Var(&headers, "header", `require a response header, "Name: value" or "Name: *"; repeatable`)
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	var targets []ProbeOptions
	if *file != "" {
		if targets, err = parseWatchFile(*file); err != nil {
			return 0, err
		}
	}
	for _, u := range pos {
		o := ProbeOptions{URL: u, Address: *address, CA: *ca, Backend: *backend, Status: *status, Timeout: *timeout,
			BodyContains: *body, MaxMS: *maxMS}
		for _, h := range headers {
			name, value, ok := strings.Cut(h, ":")
			if !ok || strings.TrimSpace(name) == "" {
				return 0, userErrorf("--header expects \"Name: value\", got %q", h)
			}
			if o.Headers == nil {
				o.Headers = map[string]string{}
			}
			o.Headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
		targets = append(targets, o)
	}
	if *alertWebhook == "" {
		*alertWebhook = os.Getenv("SETURA_ALERT_WEBHOOK")
	}
	if *alertSlack == "" {
		*alertSlack = os.Getenv("SETURA_ALERT_SLACK")
	}
	w := newWatcher(targets, *interval, stdout)
	w.count, w.duration = *count, *duration
	if w.alerts, err = newAlerter(alertConfig{Webhook: *alertWebhook, Slack: *alertSlack, Cooldown: *alertCooldown, Retries: *alertRetries}, stderr); err != nil {
		return 0, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWatch(w, ctx, *listen, *allowRemote, *history, stderr)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}
