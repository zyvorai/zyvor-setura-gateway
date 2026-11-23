package setura

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// setura pr-check: the traffic impact of a pull request.
//
// It reads recorded traffic (the same access-log and recording formats replay
// reads), resolves every request through the routing table of a base config and
// of a head config with the data plane's own match code, and reports what a
// merge would change: the share of traffic that is routed differently, each
// route's traffic share before and after, requests that would start to get a
// 404, 500 or a redirect, rewrite and auth changes. Nothing is sent anywhere.

const prSchema = "setura.pr-check/v1"

// pr-check change classes, in display order.
const (
	prRoute     = "route"
	prBackend   = "backend"
	prRedirect  = "redirect"
	prRewrite   = "rewrite"
	prTo404     = "to404"
	prTo500     = "to500"
	prServed    = "served"
	prFilters   = "filters"
	prAuth      = "auth"
	prRate      = "ratelimit"
	prWeights   = "weights"
	prUnknown   = "unknown"
	prMarkerTag = "<!-- setura-pr-check -->"
)

var prClasses = []struct {
	name, title string
	changes     bool // counts toward the changed-traffic percentage
}{
	{prRoute, "served by a different route", true},
	{prBackend, "sent to different backends", true},
	{prTo404, "would turn into 404 (no listener or no route matches)", true},
	{prTo500, "would turn into 500 (route without a usable backend)", true},
	{prServed, "newly served (was 404 or 500)", true},
	{prRedirect, "redirect added, removed or changed", true},
	{prRewrite, "URL rewrite changed", true},
	{prAuth, "auth policy changed (new gates can answer 401 or 403)", false},
	{prRate, "rate limit changed (a tighter limit can answer 429)", false},
	{prFilters, "other filters changed (headers, CORS, external auth)", false},
	{prWeights, "traffic split between backends changed", false},
	{prUnknown, "depends on request headers the recording lacks", false},
}

// PRCheckOptions configure one run.
type PRCheckOptions struct {
	Base, Head, Traffic string
	DefaultHost         string
	BaseRate, HeadRate  string
	Limit               int // examples per class and rows per table
	FailOver            float64
	FailOverSet         bool
}

// PRExample is a representative request for a class.
type PRExample struct {
	Request  string `json:"request"`
	Requests int64  `json:"requests"` // how many recorded requests share its shape
	Before   string `json:"before"`
	After    string `json:"after"`
}

// PRClass is one class of change with its requests and examples.
type PRClass struct {
	Name     string      `json:"name"`
	Title    string      `json:"title"`
	Requests int64       `json:"requests"`
	Percent  float64     `json:"percent"`
	Changes  bool        `json:"counts_as_changed"`
	Examples []PRExample `json:"examples,omitempty"`
}

// PRRoute is one route's share of traffic before and after.
type PRRoute struct {
	Route         string  `json:"route"`
	Before        int64   `json:"before_requests"`
	After         int64   `json:"after_requests"`
	BeforePercent float64 `json:"before_percent"`
	AfterPercent  float64 `json:"after_percent"`
	DeltaPoints   float64 `json:"delta_points"`
}

// PRRouteChange is a route that exists in only one of the configs.
type PRRouteChange struct {
	Route    string `json:"route"`
	Requests int64  `json:"requests"` // recorded requests it serves (head) or served (base)
}

// PRCheckReport is the result (setura.pr-check/v1).
type PRCheckReport struct {
	Schema  string      `json:"schema"`
	Base    string      `json:"base"`
	Head    string      `json:"head"`
	Traffic string      `json:"traffic"`
	Input   ReplayInput `json:"input"`
	// ChangedRequests is the requests in at least one class that counts as a
	// routing change; ChangedPercent is its share of all replayed requests.
	ChangedRequests int64            `json:"changed_requests"`
	ChangedPercent  float64          `json:"changed_percent"`
	Classes         []PRClass        `json:"classes"`
	Routes          []PRRoute        `json:"routes"`
	NewRoutes       []PRRouteChange  `json:"new_routes"`
	RemovedRoutes   []PRRouteChange  `json:"removed_routes"`
	RateLimit       *ReplayRateLimit `json:"rate_limit,omitempty"`
	Threshold       *float64         `json:"fail_if_changed_over,omitempty"`
	Failed          bool             `json:"failed"`
}

// resolveConfigPath accepts a config file or a directory that holds one.
func resolveConfigPath(p string) (string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return p, nil
	}
	for _, n := range []string{"setura.json", "gateway.json", "snapshot.json", "routes.json", "config.json"} {
		if f := filepath.Join(p, n); fileExists(f) {
			return f, nil
		}
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return "", err
	}
	var found []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(p, e.Name()))
		if err == nil && bytes.Contains(raw, []byte(builtin.SnapshotSchema)) {
			found = append(found, filepath.Join(p, e.Name()))
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", userErrorf("%s holds no gateway config (setura.json, gateway.json, or one *.json with schema %s)", p, builtin.SnapshotSchema)
	}
	return "", userErrorf("%s holds %d gateway configs; name one of them: %s", p, len(found), strings.Join(found, ", "))
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// prEntry is the memoised verdict for one distinct request.
type prEntry struct {
	b, a   builtin.Decision
	bl, al string
	cats   []int
	shape  string
}

// prAgg accumulates one class.
type prAgg struct {
	n   int64
	ex  map[string]*PRExample
	cap int
}

func is404(d builtin.Decision) bool {
	return d.Outcome == builtin.OutcomeNoListener || d.Outcome == builtin.OutcomeNoRoute
}

func decisionLabel(d builtin.Decision) string {
	if d.Route != "" {
		return d.Route
	}
	switch d.Outcome {
	case builtin.OutcomeNoListener:
		return "(404 no listener)"
	case builtin.OutcomeNoRoute:
		return "(404 no route)"
	}
	return "(" + d.Outcome + ")"
}

// describeDecision is the one line shown in examples.
func describeDecision(d builtin.Decision) string {
	var s string
	switch d.Outcome {
	case builtin.OutcomeNoListener:
		s = "404, no listener serves the host"
	case builtin.OutcomeNoRoute:
		s = "404, no route matches"
	case builtin.OutcomeNoBackend:
		s = fmt.Sprintf("500, %s rule %d has no usable backend", d.Route, d.Rule+1)
	case builtin.OutcomeRedirect:
		s = fmt.Sprintf("%s rule %d redirects %d to %s", d.Route, d.Rule+1, d.Status, d.Location)
	default:
		var bs []string
		for _, w := range d.Backends {
			bs = append(bs, fmt.Sprintf("%s %.0f%%", w.Key, w.Percent))
		}
		s = fmt.Sprintf("%s rule %d -> %s", d.Route, d.Rule+1, strings.Join(bs, ", "))
	}
	if d.Rewrite != "" {
		s += "; rewrite " + d.Rewrite
	}
	if d.Auth != "" {
		s += "; auth " + d.Auth
	}
	if len(d.Filters) > 0 {
		s += "; " + strings.Join(d.Filters, "; ")
	}
	if d.HeaderDependent {
		s += " (header rules in " + strings.Join(d.HeaderRoutes, ", ") + " could also match)"
	}
	return s
}

// ratePerSecond reads a ratePolicy string back to a rate, 0 for none.
func ratePerSecond(norm string) float64 {
	if norm == "" {
		return math.Inf(1)
	}
	var v float64
	fmt.Sscanf(norm, "%g/s", &v)
	return v
}

func classifyPR(b, a builtin.Decision, rateChanged bool) []string {
	var out []string
	if b.HeaderDependent || a.HeaderDependent {
		out = append(out, prUnknown)
		if decisionSig(b, true) == decisionSig(a, true) {
			return out
		}
	}
	if b.Route != a.Route {
		out = append(out, prRoute)
	}
	if hasBackends(b) && hasBackends(a) && backendKeys(b) != backendKeys(a) {
		out = append(out, prBackend)
	}
	switch {
	case (b.Outcome == builtin.OutcomeRedirect || a.Outcome == builtin.OutcomeRedirect) &&
		(b.Outcome != a.Outcome || b.Status != a.Status || b.Location != a.Location):
		out = append(out, prRedirect)
	}
	if is404(a) && !is404(b) {
		out = append(out, prTo404)
	}
	if a.Outcome == builtin.OutcomeNoBackend && b.Outcome != builtin.OutcomeNoBackend {
		out = append(out, prTo500)
	}
	if (is404(b) || b.Outcome == builtin.OutcomeNoBackend) && a.Outcome == builtin.OutcomeRouted {
		out = append(out, prServed)
	}
	if b.Rewrite != a.Rewrite {
		out = append(out, prRewrite)
	}
	if b.Auth != a.Auth {
		out = append(out, prAuth)
	}
	if strings.Join(b.Filters, "\n") != strings.Join(a.Filters, "\n") {
		out = append(out, prFilters)
	}
	if hasBackends(b) && hasBackends(a) && backendKeys(b) == backendKeys(a) && !sameDistribution(b, a) {
		out = append(out, prWeights)
	}
	if rateChanged && b.Kind == "" && (b.Route != "" || a.Route != "") {
		out = append(out, prRate)
	}
	return out
}

func classIndex(name string) int {
	for i, c := range prClasses {
		if c.name == name {
			return i
		}
	}
	return -1
}

// PRCheck streams the traffic through both configs.
func PRCheck(o PRCheckOptions, stdin io.Reader) (*PRCheckReport, error) {
	bp, err := resolveConfigPath(o.Base)
	if err != nil {
		return nil, fmt.Errorf("--base: %w", err)
	}
	hp, err := resolveConfigPath(o.Head)
	if err != nil {
		return nil, fmt.Errorf("--head: %w", err)
	}
	base, err := loadReplayTable(bp)
	if err != nil {
		return nil, err
	}
	head, err := loadReplayTable(hp)
	if err != nil {
		return nil, err
	}
	rd, closeFn, err := openReplayLog(o.Traffic, stdin)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	rep, err := prStream(rd, o, base, head)
	if err != nil {
		return nil, err
	}
	rep.Base, rep.Head = bp, hp
	return rep, nil
}

const prExampleKeys = 2000 // distinct example shapes kept per class

func prStream(rd io.Reader, o PRCheckOptions, base, head *builtin.Table) (*PRCheckReport, error) {
	if o.Limit < 1 {
		o.Limit = 3
	}
	rep := &PRCheckReport{Schema: prSchema, Traffic: o.Traffic}
	rep.Input.Formats = map[string]int64{}
	bRate, err := ratePolicy(o.BaseRate)
	if err != nil {
		return nil, err
	}
	hRate, err := ratePolicy(o.HeadRate)
	if err != nil {
		return nil, err
	}
	rateChanged := bRate != hRate
	if rateChanged || bRate != "" {
		rep.RateLimit = &ReplayRateLimit{Before: bRate, After: hRate}
	}
	tighter := rateChanged && ratePerSecond(hRate) < ratePerSecond(bRate)
	aggs := make([]*prAgg, len(prClasses))
	for i := range aggs {
		aggs[i] = &prAgg{ex: map[string]*PRExample{}}
	}
	before, after := map[string]int64{}, map[string]int64{}
	cache := map[string]*prEntry{}
	var changed int64
	var in interner
	var rec logRec
	var key []byte
	err = replayLines(rd, func(line []byte, tooLong bool) {
		rep.Input.Lines++
		line = bytes.TrimSpace(line)
		if tooLong || len(line) == 0 || !in.parseLogLine(line, &rec, o.DefaultHost) {
			rep.Input.SkippedNonJSON++
			return
		}
		rep.Input.Formats[rec.format]++
		tls := rec.method == "TLS" && len(rec.path) == 0
		if len(rec.host) == 0 || (len(rec.path) == 0 && !tls) {
			rep.Input.SkippedIncomplete++
			return
		}
		method := rec.method
		if method == "" {
			method = "GET"
		} else if !tls && !isUpper(method) {
			method = strings.ToUpper(method)
		}
		rep.Input.Requests++
		grpc := !tls && isGRPCLog(&rec)
		key = append(key[:0], rec.listener...)
		key = append(key, 0)
		key = append(key, rec.host...)
		key = append(key, 0)
		key = append(key, method...)
		key = append(key, 0)
		key = append(key, rec.path...)
		if grpc {
			key = append(key, 0, 'g')
		}
		e := cache[string(key)]
		if e == nil {
			host, path := string(rec.host), string(rec.path)
			spec := builtin.ReqSpec{Port: base.ListenerPort(rec.listener), Host: host, Method: method, Path: path, GRPC: grpc}
			if tls {
				spec.SNI, spec.Host, spec.Method, spec.Path = host, "", "", ""
			}
			b, a := base.Resolve(spec), head.Resolve(spec)
			req := method + " " + host + path
			if tls {
				req = "TLS " + host
			}
			e = &prEntry{b: b, a: a, bl: decisionLabel(b), al: decisionLabel(a), shape: strings.ToLower(host) + " " + method + " " + pathShape(path)}
			for _, c := range classifyPR(b, a, rateChanged) {
				e.cats = append(e.cats, classIndex(c))
			}
			e.shape = req + "\x00" + e.shape
			if len(cache) < replayCacheLimit {
				cache[string(key)] = e
			}
		}
		if e.b.Kind == "grpc" {
			rep.Input.GRPC++
		} else if e.b.Kind == "tls" {
			rep.Input.TLS++
		}
		before[e.bl]++
		after[e.al]++
		if rec.route != "" && rec.route != e.b.Route {
			rep.Input.LoggedRouteMismatch++
		}
		isChange := false
		for _, ci := range e.cats {
			ag := aggs[ci]
			ag.n++
			if prClasses[ci].changes {
				isChange = true
			}
			ex, shape, _ := strings.Cut(e.shape, "\x00")
			if p := ag.ex[shape]; p != nil {
				p.Requests++
			} else if len(ag.ex) < prExampleKeys {
				ag.ex[shape] = &PRExample{Request: ex, Requests: 1, Before: describeDecision(e.b), After: describeDecision(e.a)}
			}
		}
		if isChange {
			changed++
		}
	})
	if err != nil {
		return nil, err
	}
	n := rep.Input.Requests
	if n == 0 {
		return nil, userErrorf("%s holds no replayable requests (%d lines, %d skipped)", o.Traffic, rep.Input.Lines, rep.Input.SkippedNonJSON+rep.Input.SkippedIncomplete)
	}
	share := func(x int64) float64 { return round(float64(x)*100/float64(n), 2) }
	rep.ChangedRequests, rep.ChangedPercent = changed, share(changed)
	for i, c := range prClasses {
		ag := aggs[i]
		pc := PRClass{Name: c.name, Title: c.title, Requests: ag.n, Percent: share(ag.n), Changes: c.changes}
		if c.name == prRate && !tighter && rateChanged {
			pc.Title = "rate limit changed (not tighter, so no new 429s expected)"
		}
		ex := make([]*PRExample, 0, len(ag.ex))
		for _, e := range ag.ex {
			ex = append(ex, e)
		}
		sort.Slice(ex, func(a, b int) bool {
			if ex[a].Requests != ex[b].Requests {
				return ex[a].Requests > ex[b].Requests
			}
			return ex[a].Request < ex[b].Request
		})
		for j := 0; j < len(ex) && j < o.Limit; j++ {
			pc.Examples = append(pc.Examples, *ex[j])
		}
		rep.Classes = append(rep.Classes, pc)
	}
	labels := map[string]bool{}
	for l := range before {
		labels[l] = true
	}
	for l := range after {
		labels[l] = true
	}
	for l := range labels {
		r := PRRoute{Route: l, Before: before[l], After: after[l], BeforePercent: share(before[l]), AfterPercent: share(after[l])}
		r.DeltaPoints = round(r.AfterPercent-r.BeforePercent, 2)
		rep.Routes = append(rep.Routes, r)
	}
	sort.Slice(rep.Routes, func(i, j int) bool {
		a, b := rep.Routes[i], rep.Routes[j]
		if ma, mb := max(a.Before, a.After), max(b.Before, b.After); ma != mb {
			return ma > mb
		}
		return a.Route < b.Route
	})
	bk, hk := map[string]bool{}, map[string]bool{}
	for _, k := range base.RouteKeys() {
		bk[k] = true
	}
	rep.NewRoutes, rep.RemovedRoutes = []PRRouteChange{}, []PRRouteChange{}
	for _, k := range head.RouteKeys() {
		hk[k] = true
		if !bk[k] {
			rep.NewRoutes = append(rep.NewRoutes, PRRouteChange{Route: k, Requests: after[k]})
		}
	}
	for k := range bk {
		if !hk[k] {
			rep.RemovedRoutes = append(rep.RemovedRoutes, PRRouteChange{Route: k, Requests: before[k]})
		}
	}
	sort.Slice(rep.RemovedRoutes, func(i, j int) bool { return rep.RemovedRoutes[i].Route < rep.RemovedRoutes[j].Route })
	if o.FailOverSet {
		t := o.FailOver
		rep.Threshold = &t
		rep.Failed = rep.ChangedPercent > t
	}
	return rep, nil
}

// ---- rendering ----

func prVerdict(r *PRCheckReport) string {
	n := r.Input.Requests
	switch {
	case r.ChangedRequests == 0:
		return fmt.Sprintf("No recorded request is routed differently (%s replayed).", commas(n))
	default:
		return fmt.Sprintf("%s of %s recorded requests (%.2f%%) would be routed differently.", commas(r.ChangedRequests), commas(n), r.ChangedPercent)
	}
}

func (u *ui) PRCheckPretty(r *PRCheckReport, limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s  %s %s %s\n", u.bold("setura pr-check"), filepath.Base(r.Base), u.arrow(), filepath.Base(r.Head))
	fmt.Fprintf(&b, "  %s: %s lines, %s requests replayed, %s skipped\n\n", filepath.Base(r.Traffic), commas(r.Input.Lines), commas(r.Input.Requests), commas(r.Input.SkippedNonJSON+r.Input.SkippedIncomplete))
	sym := u.okSym()
	if r.ChangedRequests > 0 {
		sym = u.warnSym()
	}
	if r.Failed {
		sym = u.failSym()
	}
	fmt.Fprintf(&b, "  %s %s\n", sym, prVerdict(r))
	if r.Threshold != nil {
		verdict := "within"
		if r.Failed {
			verdict = "OVER"
		}
		fmt.Fprintf(&b, "    %s the --fail-if-changed-over limit of %g%%\n", verdict, *r.Threshold)
	}
	b.WriteString("\n  Impact\n")
	for _, c := range r.Classes {
		if c.Requests == 0 {
			continue
		}
		fmt.Fprintf(&b, "    %s %-9d %7.2f%%  %s\n", u.warnSym(), c.Requests, c.Percent, c.Title)
	}
	if r.ChangedRequests == 0 && allZero(r.Classes) {
		fmt.Fprintf(&b, "    %s nothing differs for the recorded traffic\n", u.okSym())
	}
	for _, c := range r.Classes {
		if len(c.Examples) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n  %s\n", u.bold(c.Title))
		for _, e := range c.Examples {
			fmt.Fprintf(&b, "    %s  (%s request%s)\n", e.Request, commas(e.Requests), plural1(e.Requests))
			fmt.Fprintf(&b, "      %s %s\n      %s %s\n", u.gray("base:"), e.Before, u.gray("head:"), e.After)
		}
	}
	if len(r.NewRoutes)+len(r.RemovedRoutes) > 0 {
		b.WriteString("\n  Routes\n")
		for _, n := range r.NewRoutes {
			fmt.Fprintf(&b, "    + new      %s (%s recorded requests land on it)\n", n.Route, commas(n.Requests))
		}
		for _, n := range r.RemovedRoutes {
			fmt.Fprintf(&b, "    - removed  %s (served %s recorded requests)\n", n.Route, commas(n.Requests))
		}
	}
	b.WriteString("\n  Traffic share per route\n")
	fmt.Fprintf(&b, "    %-44s %9s %9s %9s\n", "", "base", "head", "change")
	for i, rt := range r.Routes {
		if i >= max(limit, 10) {
			fmt.Fprintf(&b, "    %s\n", u.gray(fmt.Sprintf("... %d more (see --format json)", len(r.Routes)-i)))
			break
		}
		fmt.Fprintf(&b, "    %-44s %8.2f%% %8.2f%% %+8.2f\n", clip(rt.Route, 44, false), rt.BeforePercent, rt.AfterPercent, rt.DeltaPoints)
	}
	b.WriteString("\n")
	return b.String()
}

func allZero(cs []PRClass) bool {
	for _, c := range cs {
		if c.Requests > 0 {
			return false
		}
	}
	return true
}

func plural1(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// PRCheckMarkdown renders the GitHub-flavoured Markdown of a PR comment.
func PRCheckMarkdown(r *PRCheckReport, limit int) string {
	var b strings.Builder
	b.WriteString(prMarkerTag + "\n")
	b.WriteString("### Traffic impact\n\n")
	status := "No change"
	switch {
	case r.Failed:
		status = "Over the limit"
	case r.ChangedRequests > 0:
		status = "Routing changes"
	}
	fmt.Fprintf(&b, "**%s.** %s\n\n", status, prVerdict(r))
	if r.Threshold != nil {
		fmt.Fprintf(&b, "Limit `--fail-if-changed-over %g`: **%.2f%%** changed, %s.\n\n", *r.Threshold, r.ChangedPercent, map[bool]string{true: "check fails", false: "within the limit"}[r.Failed])
	}
	fmt.Fprintf(&b, "Replayed %s requests from `%s` (%s skipped) through `%s` (base) and `%s` (head).\n\n", commas(r.Input.Requests), filepath.Base(r.Traffic), commas(r.Input.SkippedNonJSON+r.Input.SkippedIncomplete), r.Base, r.Head)
	anyRow := false
	b.WriteString("| Impact | Requests | Share |\n|---|---:|---:|\n")
	for _, c := range r.Classes {
		if c.Requests > 0 {
			anyRow = true
			fmt.Fprintf(&b, "| %s | %s | %.2f%% |\n", mdEscape(c.Title), commas(c.Requests), c.Percent)
		}
	}
	if !anyRow {
		b.WriteString("| nothing differs for the recorded traffic | 0 | 0.00% |\n")
	}
	if len(r.NewRoutes)+len(r.RemovedRoutes) > 0 {
		b.WriteString("\n**Routes**\n\n")
		for _, n := range r.NewRoutes {
			fmt.Fprintf(&b, "- added `%s` (%s recorded requests land on it)\n", n.Route, commas(n.Requests))
		}
		for _, n := range r.RemovedRoutes {
			fmt.Fprintf(&b, "- removed `%s` (served %s recorded requests)\n", n.Route, commas(n.Requests))
		}
	}
	b.WriteString("\n<details><summary>Traffic share per route</summary>\n\n| Route | Base | Head | Change |\n|---|---:|---:|---:|\n")
	for i, rt := range r.Routes {
		if i >= max(limit, 10) {
			fmt.Fprintf(&b, "| ... %d more | | | |\n", len(r.Routes)-i)
			break
		}
		fmt.Fprintf(&b, "| `%s` | %.2f%% | %.2f%% | %+.2f |\n", mdEscape(rt.Route), rt.BeforePercent, rt.AfterPercent, rt.DeltaPoints)
	}
	b.WriteString("\n</details>\n")
	for _, c := range r.Classes {
		if len(c.Examples) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n<details><summary>Examples: %s</summary>\n\n", mdEscape(c.Title))
		for _, e := range c.Examples {
			fmt.Fprintf(&b, "- `%s` (%s request%s)\n  - base: %s\n  - head: %s\n", e.Request, commas(e.Requests), plural1(e.Requests), mdCode(e.Before), mdCode(e.After))
		}
		b.WriteString("\n</details>\n")
	}
	return b.String()
}

func mdCode(s string) string { return "`" + strings.ReplaceAll(s, "`", "'") + "`" }

func runPRCheck(fs *flag.FlagSet, rest []string, u *ui, tty bool, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	baseP := fs.String("base", "", "base gateway config: a snapshot file or a directory holding one (required)")
	headP := fs.String("head", "", "head gateway config from the pull request: file or directory (required)")
	traffic := fs.String("traffic", "", "recorded traffic: gateway access log (JSON, text or Common Log Format), FILE, FILE.gz or - for stdin (required)")
	format := fs.String("format", "auto", "auto (table on a terminal, JSON when piped), table, json or markdown")
	failOver := fs.Float64("fail-if-changed-over", -1, "exit 1 when more than this percent of requests is routed differently")
	limit := fs.Int("limit", 3, "examples per class; the route table shows at least 10 rows")
	defHost := fs.String("default-host", "", "Host for Common Log Format lines, which do not record one")
	baseRate := fs.String("base-rate-limit", "", "the base gateway's --rate-limit, as 100/s[,burst=N][,key=ip|route|header:NAME]")
	headRate := fs.String("head-rate-limit", "", "the head gateway's --rate-limit, same syntax")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura pr-check: %s\n", msg)
		exampleHint(stderr, "pr-check")
		return 2, usageError{msg}
	}
	if len(pos) > 0 || *baseP == "" || *headP == "" || *traffic == "" {
		return bad("--base, --head and --traffic are required")
	}
	if *limit < 1 {
		return bad("--limit must be at least 1")
	}
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == "fail-if-changed-over" })
	if set && (*failOver < 0 || *failOver > 100) {
		return bad("--fail-if-changed-over wants a percentage from 0 to 100")
	}
	mode := *format
	switch mode {
	case "table", "pretty":
		mode = "pretty"
	case "md":
		mode = "markdown"
	case "markdown", "json":
	case "auto":
		mode = "json"
		if tty {
			mode = "pretty"
		}
	default:
		return bad(fmt.Sprintf("--format %q: want auto, table, json or markdown", *format))
	}
	rep, err := PRCheck(PRCheckOptions{Base: *baseP, Head: *headP, Traffic: *traffic, DefaultHost: *defHost, BaseRate: *baseRate, HeadRate: *headRate,
		Limit: *limit, FailOver: *failOver, FailOverSet: set}, stdin)
	if err != nil {
		return 2, err
	}
	switch mode {
	case "pretty":
		fmt.Fprint(stdout, u.PRCheckPretty(rep, *limit))
	case "markdown":
		fmt.Fprint(stdout, PRCheckMarkdown(rep, *limit))
	default:
		if err := writeJSON(stdout, rep); err != nil {
			return 2, err
		}
	}
	return boolExit(rep.Failed), nil
}
