package setura

import (
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Service level objectives and multi-window burn rates, as in the Google SRE
// Workbook: an alert fires when the error budget burns faster than a factor
// over a long window AND over a short window (the short one makes it reset
// quickly once the problem is fixed). The data comes from probe history
// (setura watch --history) or from the gateway's own /metrics.

func init() {
	// Flags and the command are listed once for shell completion.
	gatewayFlags = append(gatewayFlags, "--with-monitoring", "--otlp-protocol", "--otlp-logs-endpoint", "--syslog", "--loki-url", "--loki-labels",
		"--loki-tenant", "--logsink-queue", "--logsink-batch", "--logsink-interval", "--logsink-retries", "--logsink-backoff")
	flagSets = append(flagSets, struct {
		cmd   string
		flags []string
	}{"slo", sloFlags})
	for i, n := range commandNames {
		if n == "history" {
			commandNames = append(commandNames[:i+1], append([]string{"slo"}, commandNames[i+1:]...)...)
			break
		}
	}
}

var sloFlags = []string{"--config", "--history", "--admin", "--state", "--route", "--objective", "--window", "--latency-ms",
	"--latency-objective", "--format", "--fail-on"}

// SLODef is one objective.
type SLODef struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`      // availability or latency
	Objective   float64 `json:"objective"` // percent of good events, for example 99.9
	Window      string  `json:"window"`    // compliance window, for example 30d
	Route       string  `json:"route,omitempty"`
	ThresholdMS float64 `json:"threshold_ms,omitempty"` // latency: a request is good when it is at least this fast
}

// BurnRule is one multi-window burn rate alert.
type BurnRule struct {
	Long     string  `json:"long"`
	Short    string  `json:"short"`
	Factor   float64 `json:"factor"`
	Severity string  `json:"severity"` // page or ticket
}

// SLOConfig is the SLO file (JSON).
type SLOConfig struct {
	SLOs []SLODef   `json:"slos"`
	Burn []BurnRule `json:"burn,omitempty"`
}

// DefaultBurnRules are the Workbook's recommended windows for a 30 day SLO:
// 2% of the budget in 1h pages, 5% in 6h pages, 10% in 3d opens a ticket.
var DefaultBurnRules = []BurnRule{
	{Long: "1h", Short: "5m", Factor: 14.4, Severity: "page"},
	{Long: "6h", Short: "30m", Factor: 6, Severity: "page"},
	{Long: "3d", Short: "6h", Factor: 1, Severity: "ticket"},
}

// ParseWindow reads 5m, 6h, 3d, 1w or any time.ParseDuration text.
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'w') {
		f, err := strconv.ParseFloat(s[:n-1], 64)
		if err != nil || f <= 0 || math.IsInf(f, 0) {
			return 0, fmt.Errorf("window %q: want a positive number before %c", s, s[n-1])
		}
		unit := 24 * time.Hour
		if s[n-1] == 'w' {
			unit = 7 * 24 * time.Hour
		}
		return time.Duration(f * float64(unit)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("window %q: want a duration such as 5m, 6h or 30d", s)
	}
	return d, nil
}

// ParseSLOConfig reads and validates an SLO file. Unknown fields are errors.
func ParseSLOConfig(r io.Reader) (*SLOConfig, error) {
	var c SLOConfig
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("SLO config: %w", err)
	}
	return &c, c.validate()
}

func (c *SLOConfig) validate() error {
	if len(c.SLOs) == 0 {
		return errors.New("SLO config: no slos")
	}
	seen := map[string]bool{}
	for i := range c.SLOs {
		d := &c.SLOs[i]
		switch {
		case d.Name == "":
			return fmt.Errorf("SLO config: slos[%d] has no name", i)
		case seen[d.Name]:
			return fmt.Errorf("SLO config: duplicate name %q", d.Name)
		case d.Type != "availability" && d.Type != "latency":
			return fmt.Errorf("SLO %s: type %q, want availability or latency", d.Name, d.Type)
		case !(d.Objective > 0 && d.Objective < 100):
			return fmt.Errorf("SLO %s: objective %v, want a percentage above 0 and below 100 (for example 99.9)", d.Name, d.Objective)
		case d.Type == "latency" && !(d.ThresholdMS > 0):
			return fmt.Errorf("SLO %s: a latency SLO needs threshold_ms", d.Name)
		}
		if d.Window == "" {
			d.Window = "30d"
		}
		if _, err := ParseWindow(d.Window); err != nil {
			return fmt.Errorf("SLO %s: %w", d.Name, err)
		}
		seen[d.Name] = true
	}
	if len(c.Burn) == 0 {
		c.Burn = append([]BurnRule(nil), DefaultBurnRules...)
	}
	for i, b := range c.Burn {
		l, err1 := ParseWindow(b.Long)
		s, err2 := ParseWindow(b.Short)
		switch {
		case err1 != nil || err2 != nil:
			return fmt.Errorf("SLO config: burn[%d]: long and short must be durations such as 1h and 5m", i)
		case s >= l:
			return fmt.Errorf("SLO config: burn[%d]: short (%s) must be shorter than long (%s)", i, b.Short, b.Long)
		case !(b.Factor > 0):
			return fmt.Errorf("SLO config: burn[%d]: factor must be positive", i)
		case b.Severity != "page" && b.Severity != "ticket":
			return fmt.Errorf("SLO config: burn[%d]: severity %q, want page or ticket", i, b.Severity)
		}
	}
	return nil
}

// ---- results ----

// WindowResult is the error ratio and burn rate over one window.
type WindowResult struct {
	Window   string   `json:"window"`
	Total    float64  `json:"total"`
	Bad      float64  `json:"bad"`
	BadRatio *float64 `json:"bad_ratio,omitempty"`
	Burn     *float64 `json:"burn_rate,omitempty"`
	Coverage float64  `json:"coverage"` // share of the window the data spans, 0 to 1
}

// AlertResult is one burn rule evaluated for an SLO.
type AlertResult struct {
	Severity  string   `json:"severity"`
	Long      string   `json:"long"`
	Short     string   `json:"short"`
	Factor    float64  `json:"factor"`
	LongBurn  *float64 `json:"long_burn,omitempty"`
	ShortBurn *float64 `json:"short_burn,omitempty"`
	Firing    bool     `json:"firing"`
}

// SLOResult is the evaluation of one SLO.
type SLOResult struct {
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	Objective       float64        `json:"objective"`
	Window          string         `json:"window"`
	Route           string         `json:"route,omitempty"`
	ThresholdMS     float64        `json:"threshold_ms,omitempty"`
	MeasuredAtMS    float64        `json:"measured_at_ms,omitempty"` // latency from /metrics: the histogram bucket actually used
	Status          string         `json:"status"`                   // ok, at_risk, burning, breached, no_data
	SLI             *float64       `json:"sli,omitempty"`            // percent of good events over the window
	BudgetRemaining *float64       `json:"budget_remaining,omitempty"`
	Compliance      WindowResult   `json:"compliance"`
	Windows         []WindowResult `json:"windows"`
	Alerts          []AlertResult  `json:"alerts"`
}

// SLOReport is the result of "setura slo".
type SLOReport struct {
	Source  string      `json:"source"`
	Now     string      `json:"now"`
	Verdict string      `json:"verdict"`
	SLOs    []SLOResult `json:"slos"`
}

var statusRank = map[string]int{"ok": 0, "no_data": 1, "at_risk": 2, "breached": 3, "burning": 4}

// counts is how a data source answers "how many events, how many bad".
type counts interface {
	// count returns the events and bad events of def in the last w ending at now,
	// and how much of w the data spans (0 to 1).
	count(def SLODef, now time.Time, w time.Duration) (total, bad, coverage float64)
	// measuredAt reports the latency threshold actually used, when it differs.
	measuredAt(def SLODef) float64
}

func ratio(bad, total float64) *float64 {
	if total <= 0 {
		return nil
	}
	v := bad / total
	return &v
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func rp(v *float64, places int) *float64 {
	if v == nil {
		return nil
	}
	r := round(*v, places)
	return &r
}

// minCoverage is how much of a window the data must span before a burn rate
// over it is believed.
const minCoverage = 0.5

// EvaluateSLOs computes every SLO at now from src.
func EvaluateSLOs(cfg *SLOConfig, src counts, source string, now time.Time) *SLOReport {
	rep := &SLOReport{Source: source, Now: now.UTC().Format(time.RFC3339), Verdict: "ok"}
	win := func(def SLODef, name string, w time.Duration, budget float64) WindowResult {
		total, bad, cov := src.count(def, now, w)
		r := WindowResult{Window: name, Total: total, Bad: bad, Coverage: round(math.Min(cov, 1), 3)}
		if br := ratio(bad, total); br != nil && cov >= minCoverage {
			burn := *br / budget
			r.BadRatio, r.Burn = rp(br, 6), rp(&burn, 2)
		} else if br != nil {
			r.BadRatio = rp(br, 6) // some data, but too little to call a burn rate
		}
		return r
	}
	for _, def := range cfg.SLOs {
		budget := 1 - def.Objective/100
		res := SLOResult{Name: def.Name, Type: def.Type, Objective: def.Objective, Window: def.Window, Route: def.Route,
			ThresholdMS: def.ThresholdMS, MeasuredAtMS: src.measuredAt(def), Alerts: []AlertResult{}, Windows: []WindowResult{}}
		cw, _ := ParseWindow(def.Window)
		res.Compliance = win(def, def.Window, cw, budget)
		if br := ratio(res.Compliance.Bad, res.Compliance.Total); br != nil {
			sli := 100 * (1 - *br)
			rem := 100 * (1 - *br/budget)
			res.SLI, res.BudgetRemaining = rp(&sli, 4), rp(&rem, 1)
		}
		seen := map[string]bool{}
		for _, rule := range cfg.Burn {
			lw, _ := ParseWindow(rule.Long)
			sw, _ := ParseWindow(rule.Short)
			for _, p := range []struct {
				n string
				d time.Duration
			}{{rule.Long, lw}, {rule.Short, sw}} {
				if !seen[p.n] {
					seen[p.n] = true
					res.Windows = append(res.Windows, win(def, p.n, p.d, budget))
				}
			}
			a := AlertResult{Severity: rule.Severity, Long: rule.Long, Short: rule.Short, Factor: rule.Factor}
			for _, w := range res.Windows {
				if w.Window == rule.Long {
					a.LongBurn = w.Burn
				}
				if w.Window == rule.Short {
					a.ShortBurn = w.Burn
				}
			}
			a.Firing = a.LongBurn != nil && a.ShortBurn != nil && *a.LongBurn >= rule.Factor && *a.ShortBurn >= rule.Factor
			res.Alerts = append(res.Alerts, a)
		}
		sort.SliceStable(res.Windows, func(i, j int) bool {
			a, _ := ParseWindow(res.Windows[i].Window)
			b, _ := ParseWindow(res.Windows[j].Window)
			return a < b
		})
		res.Status = "ok"
		page, ticket := false, false
		for _, a := range res.Alerts {
			if a.Firing {
				page = page || a.Severity == "page"
				ticket = ticket || a.Severity == "ticket"
			}
		}
		switch {
		case res.SLI == nil:
			res.Status = "no_data"
		case page:
			res.Status = "burning"
		case res.BudgetRemaining != nil && *res.BudgetRemaining < 0:
			res.Status = "breached"
		case ticket:
			res.Status = "at_risk"
		}
		if statusRank[res.Status] > statusRank[rep.Verdict] {
			rep.Verdict = res.Status
		}
		rep.SLOs = append(rep.SLOs, res)
	}
	return rep
}

// ---- probe history source ----

type probeEvent struct {
	t      time.Time
	target string
	ok     bool
	ms     float64
}

type probeSource struct {
	ev    []probeEvent
	first time.Time
}

// LoadProbeEvents reads watch history lines; malformed lines are skipped.
func LoadProbeEvents(r io.Reader) (*probeSource, int, error) {
	p := &probeSource{}
	skipped := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), historyMaxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h historyLine
		err := json.Unmarshal([]byte(line), &h)
		var t time.Time
		if err == nil {
			t, err = time.Parse(time.RFC3339, h.Time)
		}
		if err != nil || h.Target == "" {
			skipped++
			continue
		}
		p.ev = append(p.ev, probeEvent{t: t, target: h.Target, ok: h.OK, ms: h.ElapsedMS})
		if p.first.IsZero() || t.Before(p.first) {
			p.first = t
		}
	}
	return p, skipped, sc.Err()
}

func routeMatches(want, got string) bool {
	return want == "" || got == want || strings.Contains(got, want)
}

func (p *probeSource) measuredAt(SLODef) float64 { return 0 }

func (p *probeSource) count(def SLODef, now time.Time, w time.Duration) (total, bad, cov float64) {
	start := now.Add(-w)
	for _, e := range p.ev {
		if e.t.After(now) || !e.t.After(start) || !routeMatches(def.Route, e.target) {
			continue
		}
		if def.Type == "latency" {
			if !e.ok {
				continue // a failed probe is an availability matter
			}
			total++
			if e.ms > def.ThresholdMS {
				bad++
			}
			continue
		}
		total++
		if !e.ok {
			bad++
		}
	}
	if !p.first.IsZero() && now.After(p.first) {
		cov = float64(now.Sub(p.first)) / float64(w)
	}
	return total, bad, math.Min(cov, 1)
}

// ---- gateway /metrics source ----

type promSample struct {
	name   string
	labels map[string]string
	val    float64
}

// ParseProm reads the Prometheus text format (comments and exemplars ignored).
func ParseProm(r io.Reader) ([]promSample, error) {
	var out []promSample
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || ln[0] == '#' {
			continue
		}
		if i := strings.Index(ln, " # "); i >= 0 { // OpenMetrics exemplar
			ln = ln[:i]
		}
		var s promSample
		rest := ln
		if i := strings.IndexByte(ln, '{'); i >= 0 {
			j := strings.LastIndexByte(ln, '}')
			if j < i {
				continue
			}
			s.name, s.labels = ln[:i], promLabelSet(ln[i+1:j])
			rest = strings.TrimSpace(ln[j+1:])
		} else {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			s.name, rest = f[0], f[1]
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		s.val = v
		out = append(out, s)
	}
	return out, sc.Err()
}

func promLabelSet(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		eq := strings.Index(s, `="`)
		if eq < 0 {
			break
		}
		key := strings.TrimLeft(s[:eq], ", ")
		s = s[eq+2:]
		var val strings.Builder
		i := 0
		for ; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				if s[i] == 'n' {
					val.WriteByte('\n')
				} else {
					val.WriteByte(s[i])
				}
				continue
			}
			if s[i] == '"' {
				break
			}
			val.WriteByte(s[i])
		}
		out[key] = val.String()
		if i+1 > len(s) {
			break
		}
		s = s[i+1:]
	}
	return out
}

// sloSample is the cumulative count of one SLO at one scrape.
type sloSample struct {
	T     time.Time `json:"t"`
	SLO   string    `json:"slo"`
	Total float64   `json:"total"`
	Bad   float64   `json:"bad"`
}

// cumulative computes the lifetime total and bad events of def from a scrape.
// For latency the histogram bucket at or below the threshold is the "good"
// count, so a threshold between bucket bounds is measured at the lower one.
func cumulative(def SLODef, ms []promSample) (total, bad, measuredMS float64) {
	if def.Type != "latency" {
		for _, s := range ms {
			if s.name == "setura_gateway_route_requests_total" && routeMatches(def.Route, s.labels["route"]) {
				total += s.val
				if s.labels["code"] == "5xx" {
					bad += s.val
				}
			}
		}
		return total, bad, 0
	}
	thr := def.ThresholdMS / 1000
	var best = -1.0
	for _, s := range ms {
		if s.name == "setura_gateway_request_duration_seconds_bucket" && routeMatches(def.Route, s.labels["route"]) {
			if le, err := strconv.ParseFloat(s.labels["le"], 64); err == nil && !math.IsInf(le, 1) && le <= thr+1e-9 && le > best {
				best = le
			}
		}
	}
	var good float64
	for _, s := range ms {
		if !routeMatches(def.Route, s.labels["route"]) {
			continue
		}
		switch s.name {
		case "setura_gateway_request_duration_seconds_count":
			total += s.val
		case "setura_gateway_request_duration_seconds_bucket":
			if le, err := strconv.ParseFloat(s.labels["le"], 64); err == nil && best >= 0 && math.Abs(le-best) < 1e-9 {
				good += s.val
			}
		}
	}
	if best < 0 {
		best = 0
	}
	return total, math.Max(total-good, 0), best * 1000
}

type metricSource struct {
	samples map[string][]sloSample // by SLO name, oldest first
	at      map[string]float64
}

func (m *metricSource) measuredAt(def SLODef) float64 {
	if def.Type == "latency" && m.at[def.Name] != def.ThresholdMS {
		return m.at[def.Name]
	}
	return 0
}

func (m *metricSource) count(def SLODef, now time.Time, w time.Duration) (total, bad, cov float64) {
	ss := m.samples[def.Name]
	if len(ss) < 2 {
		return 0, 0, 0
	}
	start := now.Add(-w)
	base := 0
	for i, s := range ss {
		if !s.T.After(start) {
			base = i
		}
	}
	for i := base; i+1 < len(ss); i++ {
		dt, db := ss[i+1].Total-ss[i].Total, ss[i+1].Bad-ss[i].Bad
		if dt < 0 || db < 0 { // the gateway restarted: its counters began again at zero
			dt, db = ss[i+1].Total, ss[i+1].Bad
		}
		total += dt
		bad += db
	}
	cov = float64(ss[len(ss)-1].T.Sub(ss[base].T)) / float64(w)
	return total, bad, math.Min(cov, 1)
}

// loadSLOState reads the sample file, ignoring malformed lines.
func loadSLOState(path string) ([]sloSample, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []sloSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s sloSample
		if json.Unmarshal(sc.Bytes(), &s) == nil && s.SLO != "" && !s.T.IsZero() {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// saveSLOState appends the new samples and drops those older than keep.
func saveSLOState(path string, old, add []sloSample, now time.Time, keep time.Duration) error {
	if path == "" {
		return nil
	}
	var kept []sloSample
	for _, s := range old {
		if now.Sub(s.T) <= keep {
			kept = append(kept, s)
		}
	}
	kept = append(kept, add...)
	var b bytes.Buffer
	for _, s := range kept {
		j, _ := json.Marshal(s)
		b.Write(j)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// scrapeGateway reads the admin /metrics of a built-in gateway.
func scrapeGateway(ctx context.Context, admin string) ([]promSample, error) {
	base := admin
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the gateway admin endpoint at %s: %w", admin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s/metrics answered %s", admin, resp.Status)
	}
	return ParseProm(io.LimitReader(resp.Body, 32<<20))
}

// ---- rendering ----

func pctText(v float64) string {
	s := strconv.FormatFloat(round(v, 3), 'f', -1, 64)
	return s + "%"
}

func burnText(b *float64) string {
	if b == nil {
		return "no data"
	}
	return fmt.Sprintf("%.1fx", *b)
}

var verdictText = map[string]string{
	"ok":       "Within budget",
	"no_data":  "Not enough data yet",
	"at_risk":  "Budget is burning slowly",
	"breached": "Budget is spent",
	"burning":  "Budget is burning fast",
}

// SLOPretty renders the report for a terminal: one verdict line, a short block
// per SLO and a Next hint.
func (u *ui) SLOPretty(r *SLOReport) string {
	var b strings.Builder
	sym := map[string]string{"ok": u.okSym(), "no_data": u.idleSym(), "at_risk": u.warnSym(), "breached": u.failSym(), "burning": u.failSym()}
	dot := u.gray(" " + u.sym("·", "|") + " ")
	n := len(r.SLOs)
	count := fmt.Sprintf("%d SLO", n)
	if n != 1 {
		count += "s"
	}
	fmt.Fprintf(&b, "\n  %s %s%s%s\n", sym[r.Verdict], u.bold(verdictText[r.Verdict]), dot, u.gray(count+" from "+r.Source))
	for _, s := range r.SLOs {
		head := s.Name
		scope := fmt.Sprintf("%s over %s", pctText(s.Objective), s.Window)
		if s.Type == "latency" {
			scope = fmt.Sprintf("%s under %s over %s", pctText(s.Objective), fmtMS(s.ThresholdMS), s.Window)
		}
		fmt.Fprintf(&b, "\n  %s %s  %s\n", sym[s.Status], u.bold(head), u.gray(scope))
		if s.SLI == nil {
			fmt.Fprintf(&b, "    %s\n", u.gray("no events in the window yet"))
		} else {
			left := "budget left " + fmt.Sprintf("%.0f%%", *s.BudgetRemaining)
			if *s.BudgetRemaining < 0 {
				left = u.red("budget overspent by " + fmt.Sprintf("%.0f%%", -*s.BudgetRemaining))
			}
			span := ""
			if s.Compliance.Coverage < 0.999 {
				span = u.gray(dot + fmt.Sprintf("data covers %.0f%% of the window", 100*s.Compliance.Coverage))
			}
			fmt.Fprintf(&b, "    %s now%s%s%s\n", pctText(*s.SLI), dot, left, span)
		}
		var parts []string
		for _, w := range s.Windows {
			parts = append(parts, w.Window+" "+burnText(w.Burn))
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, "    %s %s\n", u.gray("burn"), strings.Join(parts, u.gray("  "+u.sym("·", "|")+"  ")))
		}
		for _, a := range s.Alerts {
			if a.Firing {
				fmt.Fprintf(&b, "    %s %s\n", u.red(a.Severity), fmt.Sprintf("%.1fx over %s and %s (limit %gx)", *a.LongBurn, a.Long, a.Short, a.Factor))
			}
		}
		if s.MeasuredAtMS > 0 {
			fmt.Fprintf(&b, "    %s\n", u.gray(fmt.Sprintf("measured at the %s histogram bucket", fmtMS(s.MeasuredAtMS))))
		}
	}
	b.WriteString("\n")
	if h := sloNext(r); h != "" {
		fmt.Fprintf(&b, "  %s %s\n\n", u.blue("Next:"), h)
	}
	return b.String()
}

func sloNext(r *SLOReport) string {
	switch r.Verdict {
	case "burning", "breached", "at_risk":
		if strings.HasPrefix(r.Source, "gateway") {
			return "Find what is failing with: setura connections --filter status=5xx"
		}
		return "See which route regressed with: setura history " + strings.TrimPrefix(r.Source, "probes ") + " --since 1h"
	case "no_data":
		if strings.HasPrefix(r.Source, "gateway") {
			return "Run this on a schedule with --state slo.jsonl; burn rates need samples across each window."
		}
		return "Collect probes with: setura watch URL --history probes.jsonl"
	}
	return ""
}

// ---- command ----

type sloArgs struct {
	config, history, admin, state, route, format, failOn string
	objective, latencyObj, latencyMS                     float64
	window                                               string
}

func addSLOFlags(fs *flag.FlagSet, a *sloArgs) {
	fs.StringVar(&a.config, "config", "", "SLO config file (JSON); without it one availability SLO is built from the flags")
	fs.StringVar(&a.history, "history", "", "probe history FILE written by setura watch --history")
	fs.StringVar(&a.admin, "admin", builtin.DefaultAdmin, "gateway admin address to scrape /metrics from (used without --history)")
	fs.StringVar(&a.state, "state", "", "keep scrape samples in FILE so later runs can compute burn rates over each window")
	fs.StringVar(&a.route, "route", "", "only routes whose name or target equals or contains this text")
	fs.Float64Var(&a.objective, "objective", 99.9, "availability objective in percent")
	fs.StringVar(&a.window, "window", "30d", "compliance window")
	fs.Float64Var(&a.latencyMS, "latency-ms", 0, "also check a latency SLO: requests faster than this are good")
	fs.Float64Var(&a.latencyObj, "latency-objective", 99, "latency objective in percent")
	fs.StringVar(&a.format, "format", "table", "table or json")
	fs.StringVar(&a.failOn, "fail-on", "page", "exit 1 when an SLO is: page (burning or breached), ticket (also burning slowly) or never")
}

func (a *sloArgs) config0() (*SLOConfig, error) {
	var cfg *SLOConfig
	if a.config != "" {
		f, err := os.Open(a.config)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if cfg, err = ParseSLOConfig(f); err != nil {
			return nil, userError(err.Error())
		}
	} else {
		cfg = &SLOConfig{SLOs: []SLODef{{Name: "availability", Type: "availability", Objective: a.objective, Window: a.window}}}
		if a.latencyMS > 0 {
			cfg.SLOs = append(cfg.SLOs, SLODef{Name: "latency", Type: "latency", Objective: a.latencyObj, Window: a.window, ThresholdMS: a.latencyMS})
		}
		if err := cfg.validate(); err != nil {
			return nil, userError(err.Error())
		}
	}
	for i := range cfg.SLOs {
		if cfg.SLOs[i].Route == "" {
			cfg.SLOs[i].Route = a.route
		}
	}
	return cfg, nil
}

// sloNow is replaceable in tests.
var sloNow = time.Now

// runSLO implements "setura slo".
func runSLO(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui) (int, error) {
	var a sloArgs
	addSLOFlags(fs, &a)
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura slo: %s\n", msg)
		exampleHint(stderr, "slo")
		return 2, usageError{msg}
	}
	if len(pos) != 0 {
		return bad("unexpected arguments")
	}
	return runSLOWith(a, stdout, stderr, u, bad)
}

func runSLOWith(a sloArgs, stdout, stderr io.Writer, u *ui, bad func(string) (int, error)) (int, error) {
	switch {
	case a.format != "table" && a.format != "json":
		return bad(fmt.Sprintf("--format %q: want table or json", a.format))
	case a.failOn != "page" && a.failOn != "ticket" && a.failOn != "never":
		return bad(fmt.Sprintf("--fail-on %q: want page, ticket or never", a.failOn))
	}
	cfg, err := a.config0()
	if err != nil {
		return 0, err
	}
	now := sloNow()
	var rep *SLOReport
	if a.history != "" {
		f, err := os.Open(a.history)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		src, _, err := LoadProbeEvents(f)
		if err != nil {
			return 0, err
		}
		rep = EvaluateSLOs(cfg, src, "probes "+a.history, now)
	} else {
		ms, err := scrapeGateway(context.Background(), a.admin)
		if err != nil {
			return 0, err
		}
		old, err := loadSLOState(a.state)
		if err != nil {
			return 0, err
		}
		src := &metricSource{samples: map[string][]sloSample{}, at: map[string]float64{}}
		var add []sloSample
		longest := time.Hour
		for _, def := range cfg.SLOs {
			total, badN, at := cumulative(def, ms)
			src.at[def.Name] = at
			add = append(add, sloSample{T: now.UTC(), SLO: def.Name, Total: total, Bad: badN})
			if w, _ := ParseWindow(def.Window); w > longest {
				longest = w
			}
		}
		for _, s := range old {
			src.samples[s.SLO] = append(src.samples[s.SLO], s)
		}
		for _, s := range add {
			src.samples[s.SLO] = append(src.samples[s.SLO], s)
		}
		for k := range src.samples {
			ss := src.samples[k]
			sort.SliceStable(ss, func(i, j int) bool { return ss[i].T.Before(ss[j].T) })
		}
		if err := saveSLOState(a.state, old, add, now, 2*longest); err != nil {
			return 0, err
		}
		rep = EvaluateSLOs(cfg, src, "gateway "+a.admin, now)
	}
	if a.format == "json" {
		if err := writeJSON(stdout, rep); err != nil {
			return 0, err
		}
	} else {
		fmt.Fprint(stdout, u.SLOPretty(rep))
	}
	rank := statusRank[rep.Verdict]
	switch {
	case a.failOn == "never":
		return 0, nil
	case a.failOn == "ticket":
		return boolExit(rank >= statusRank["at_risk"]), nil
	}
	return boolExit(rank >= statusRank["breached"]), nil
}
