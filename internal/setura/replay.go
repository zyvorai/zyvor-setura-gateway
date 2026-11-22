package setura

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Change classes reported by setura replay.
const (
	classRoute   = "route"
	classBackend = "backend"
	classOutcome = "outcome"
	classWeights = "weights"
	classUnknown = "unknown"
)

var replayClasses = []string{classRoute, classBackend, classOutcome, classWeights, classUnknown}

const (
	replayMaxLine    = 4 << 20 // longer lines are skipped, never buffered whole
	replayCacheLimit = 100000  // exact-request memo entries
)

// ReplayOptions configure one replay run.
type ReplayOptions struct {
	Log, Before, After string
	Limit              int
	IgnoreWeights      bool
}

// ReplayInput counts what was read from the access log.
type ReplayInput struct {
	Lines             int64 `json:"lines"`
	Requests          int64 `json:"requests"`
	SkippedNonJSON    int64 `json:"skipped_non_json"`
	SkippedIncomplete int64 `json:"skipped_incomplete"`
	// LoggedRouteMismatch counts requests whose logged route differs from what
	// the "before" config resolves: a sign the log and before file disagree.
	LoggedRouteMismatch int64 `json:"logged_route_mismatch"`
}

// ReplayExample is one concrete request for a change class.
type ReplayExample struct {
	Request string `json:"request"`
	Before  string `json:"before"`
	After   string `json:"after"`
}

// ReplayClass summarizes one change class.
type ReplayClass struct {
	Class    string         `json:"class"`
	Requests int64          `json:"requests"`
	Groups   int            `json:"groups"`
	Example  *ReplayExample `json:"example,omitempty"`
}

// ReplayGroup is a set of identical (host, method, path shape) requests that
// resolve the same way under both configs.
type ReplayGroup struct {
	Host     string           `json:"host"`
	Method   string           `json:"method"`
	Shape    string           `json:"path_shape"`
	Requests int64            `json:"requests"`
	Classes  []string         `json:"classes"`
	Example  string           `json:"example"`
	Before   builtin.Decision `json:"before"`
	After    builtin.Decision `json:"after"`
}

// ReplayRoute is the impact on one before-to-after route transition.
type ReplayRoute struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Requests int64    `json:"requests"`
	Classes  []string `json:"classes"`
}

// ReplayShiftBackend is one backend's share before and after.
type ReplayShiftBackend struct {
	Backend       string  `json:"backend"`
	BeforePercent float64 `json:"before_percent"`
	AfterPercent  float64 `json:"after_percent"`
}

// ReplayShift is a traffic distribution change for one rule transition.
type ReplayShift struct {
	From     string               `json:"from"`
	To       string               `json:"to"`
	Requests int64                `json:"requests"`
	Backends []ReplayShiftBackend `json:"backends"`
}

// ReplayReport is the full result.
type ReplayReport struct {
	Schema        string        `json:"schema"`
	Log           string        `json:"log"`
	Before        string        `json:"before"`
	After         string        `json:"after"`
	IgnoreWeights bool          `json:"ignore_weights,omitempty"`
	Input         ReplayInput   `json:"input"`
	Changed       int64         `json:"changed_requests"`
	Unchanged     int64         `json:"unchanged_requests"`
	Classes       []ReplayClass `json:"classes"`
	TopRoutes     []ReplayRoute `json:"top_routes"`
	TopGroups     []ReplayGroup `json:"top_groups"`
	WeightShifts  []ReplayShift `json:"weight_shifts"`
	FailOn        []string      `json:"fail_on,omitempty"`
	Failed        bool          `json:"failed"`
}

func (r *ReplayReport) class(name string) *ReplayClass {
	for i := range r.Classes {
		if r.Classes[i].Class == name {
			return &r.Classes[i]
		}
	}
	return nil
}

type replayLine struct {
	Listener string `json:"listener"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Route    string `json:"route"`
}

// replayLabel names a decision's route or outcome for transitions.
func replayLabel(d builtin.Decision) string {
	if d.Route != "" {
		return d.Route
	}
	return d.Outcome
}

func decisionSig(d builtin.Decision) string {
	var b strings.Builder
	b.WriteString(d.Outcome)
	b.WriteByte('|')
	b.WriteString(d.Route)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(d.Rule))
	for _, w := range d.Backends {
		fmt.Fprintf(&b, "|%s:%d", w.Key, w.Weight)
	}
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(d.Status))
	b.WriteString(d.Location)
	if d.HeaderDependent {
		b.WriteString("|hdr:" + strings.Join(d.HeaderRoutes, ","))
	}
	return b.String()
}

func backendKeys(d builtin.Decision) string {
	k := make([]string, len(d.Backends))
	for i, w := range d.Backends {
		k[i] = w.Key
	}
	return strings.Join(k, ",")
}

func sameDistribution(a, b builtin.Decision) bool {
	if len(a.Backends) != len(b.Backends) {
		return false
	}
	for i := range a.Backends {
		if a.Backends[i].Key != b.Backends[i].Key || math.Abs(a.Backends[i].Percent-b.Backends[i].Percent) > 0.005 {
			return false
		}
	}
	return true
}

func hasBackends(d builtin.Decision) bool {
	return d.Outcome == builtin.OutcomeRouted || d.Outcome == builtin.OutcomeNoBackend
}

// classifyReplay lists the change classes between two decisions.
func classifyReplay(b, a builtin.Decision, ignoreWeights bool) []string {
	if b.HeaderDependent || a.HeaderDependent {
		if decisionSig(b) == decisionSig(a) {
			return nil
		}
		return []string{classUnknown}
	}
	var out []string
	if b.Route != a.Route {
		out = append(out, classRoute)
	}
	if hasBackends(b) && hasBackends(a) && backendKeys(b) != backendKeys(a) {
		out = append(out, classBackend)
	}
	if b.Outcome != a.Outcome || (b.Outcome == builtin.OutcomeRedirect && (b.Status != a.Status || b.Location != a.Location)) {
		out = append(out, classOutcome)
	}
	if !ignoreWeights && hasBackends(b) && hasBackends(a) && backendKeys(b) == backendKeys(a) && !sameDistribution(b, a) {
		out = append(out, classWeights)
	}
	return out
}

// pathShape collapses ids so a million distinct URLs become a few shapes, and
// keeps only the names of query parameters.
func pathShape(target string) string {
	p, q, _ := strings.Cut(target, "?")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = segShape(s)
	}
	out := strings.Join(segs, "/")
	if q != "" {
		var names []string
		for _, kv := range strings.Split(q, "&") {
			n, _, _ := strings.Cut(kv, "=")
			if n != "" {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		out += "?" + strings.Join(names, "&")
	}
	return out
}

func segShape(s string) string {
	if s == "" {
		return s
	}
	digits, hex, alnum := 0, 0, 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digits++
			hex++
			alnum++
		case (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
			hex++
			alnum++
		case (c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z'):
			alnum++
		}
	}
	switch {
	case digits == len(s):
		return ":n"
	case len(s) == 36 && strings.Count(s, "-") == 4 && hex == 32:
		return ":uuid"
	case len(s) >= 12 && hex == len(s):
		return ":id"
	case len(s) >= 20 && alnum == len(s) && digits > 0:
		return ":id"
	}
	return s
}

// replayLines streams newline separated lines. Overlong lines are reported
// with a nil slice instead of being buffered.
func replayLines(r io.Reader, fn func(line []byte, tooLong bool)) error {
	br := bufio.NewReaderSize(r, 256<<10)
	var acc []byte
	over := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(chunk) > 0 || err == nil {
			switch {
			case over:
			case len(acc)+len(chunk) > replayMaxLine:
				over, acc = true, acc[:0]
			case isPrefix || len(acc) > 0:
				acc = append(acc, chunk...)
			}
			if !isPrefix {
				switch {
				case over:
					fn(nil, true)
				case len(acc) > 0:
					fn(acc, false)
				default:
					fn(chunk, false)
				}
				acc, over = acc[:0], false
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// openReplayLog opens a path, "-" for stdin, transparently gunzipping.
func openReplayLog(path string, stdin io.Reader) (io.Reader, func(), error) {
	var src io.Reader
	closer := func() {}
	if path == "-" {
		src = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		src, closer = f, func() { f.Close() }
	}
	br := bufio.NewReaderSize(src, 64<<10)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			closer()
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return zr, closer, nil
	}
	return br, closer, nil
}

func loadReplayTable(path string) (*builtin.Table, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	t, err := builtin.ParseReplayConfig(raw, filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// Replay streams the access log through both configs.
func Replay(o ReplayOptions, stdin io.Reader) (*ReplayReport, error) {
	before, err := loadReplayTable(o.Before)
	if err != nil {
		return nil, err
	}
	after, err := loadReplayTable(o.After)
	if err != nil {
		return nil, err
	}
	rd, closeFn, err := openReplayLog(o.Log, stdin)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	return replayStream(rd, o, before, after)
}

func replayStream(rd io.Reader, o ReplayOptions, before, after *builtin.Table) (*ReplayReport, error) {
	rep := &ReplayReport{Schema: "setura.replay/v1", Log: o.Log, Before: o.Before, After: o.After, IgnoreWeights: o.IgnoreWeights}
	groups := map[string]*ReplayGroup{}
	cache := map[string]*ReplayGroup{}
	var ln replayLine
	err := replayLines(rd, func(line []byte, tooLong bool) {
		rep.Input.Lines++
		line = bytes.TrimSpace(line)
		if tooLong || len(line) == 0 || line[0] != '{' {
			rep.Input.SkippedNonJSON++
			return
		}
		ln = replayLine{}
		if json.Unmarshal(line, &ln) != nil {
			rep.Input.SkippedNonJSON++
			return
		}
		if ln.Host == "" || ln.Path == "" {
			rep.Input.SkippedIncomplete++
			return
		}
		method := strings.ToUpper(ln.Method)
		if method == "" {
			method = "GET"
		}
		rep.Input.Requests++
		exact := ln.Listener + "\x00" + ln.Host + "\x00" + method + "\x00" + ln.Path
		g := cache[exact]
		if g == nil {
			spec := builtin.ReqSpec{Port: before.ListenerPort(ln.Listener), Host: ln.Host, Method: method, Path: ln.Path}
			b, a := before.Resolve(spec), after.Resolve(spec)
			host := strings.ToLower(ln.Host)
			shape := pathShape(ln.Path)
			key := host + "\x00" + method + "\x00" + shape + "\x00" + decisionSig(b) + "\x00" + decisionSig(a)
			g = groups[key]
			if g == nil {
				g = &ReplayGroup{Host: host, Method: method, Shape: shape, Example: method + " " + ln.Host + ln.Path,
					Before: b, After: a, Classes: classifyReplay(b, a, o.IgnoreWeights)}
				groups[key] = g
			}
			if len(cache) < replayCacheLimit {
				cache[exact] = g
			}
		}
		g.Requests++
		if ln.Route != "" && ln.Route != g.Before.Route {
			rep.Input.LoggedRouteMismatch++
		}
	})
	if err != nil {
		return nil, err
	}
	summarizeReplay(rep, groups, o)
	return rep, nil
}

func summarizeReplay(rep *ReplayReport, groups map[string]*ReplayGroup, o ReplayOptions) {
	limit := o.Limit
	if limit <= 0 {
		limit = 10
	}
	all := make([]*ReplayGroup, 0, len(groups))
	for _, g := range groups {
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Requests != all[j].Requests {
			return all[i].Requests > all[j].Requests
		}
		return all[i].Example < all[j].Example
	})
	classes := map[string]*ReplayClass{}
	for _, c := range replayClasses {
		classes[c] = &ReplayClass{Class: c}
	}
	routes := map[string]*ReplayRoute{}
	type shiftAcc struct {
		ReplayShift
		before, after map[string]float64
	}
	shifts := map[string]*shiftAcc{}
	for _, g := range all { // descending, so the first group per class is its biggest
		if len(g.Classes) == 0 {
			rep.Unchanged += g.Requests
			continue
		}
		rep.Changed += g.Requests
		for _, c := range g.Classes {
			cl := classes[c]
			cl.Requests += g.Requests
			cl.Groups++
			if cl.Example == nil {
				cl.Example = &ReplayExample{Request: g.Example, Before: g.Before.String(), After: g.After.String()}
			}
		}
		rk := replayLabel(g.Before) + "\x00" + replayLabel(g.After)
		r := routes[rk]
		if r == nil {
			r = &ReplayRoute{From: replayLabel(g.Before), To: replayLabel(g.After)}
			routes[rk] = r
		}
		r.Requests += g.Requests
		for _, c := range g.Classes {
			if !hasStr(r.Classes, c) {
				r.Classes = append(r.Classes, c)
			}
		}
		if hasBackends(g.Before) && hasBackends(g.After) && !g.Before.HeaderDependent && !g.After.HeaderDependent && len(g.Before.Backends)+len(g.After.Backends) > 0 &&
			(len(g.Classes) > 0 && (hasStr(g.Classes, classWeights) || hasStr(g.Classes, classBackend))) {
			from := fmt.Sprintf("%s rule %d", g.Before.Route, g.Before.Rule+1)
			to := fmt.Sprintf("%s rule %d", g.After.Route, g.After.Rule+1)
			sk := from + "\x00" + to
			s := shifts[sk]
			if s == nil {
				s = &shiftAcc{ReplayShift: ReplayShift{From: from, To: to}, before: map[string]float64{}, after: map[string]float64{}}
				shifts[sk] = s
			}
			s.Requests += g.Requests
			for _, w := range g.Before.Backends {
				s.before[w.Key] += float64(g.Requests) * w.Percent
			}
			for _, w := range g.After.Backends {
				s.after[w.Key] += float64(g.Requests) * w.Percent
			}
		}
		if len(rep.TopGroups) < limit {
			rep.TopGroups = append(rep.TopGroups, *g)
		}
	}
	for _, c := range replayClasses {
		rep.Classes = append(rep.Classes, *classes[c])
	}
	for _, r := range routes {
		sort.Strings(r.Classes)
		rep.TopRoutes = append(rep.TopRoutes, *r)
	}
	sort.Slice(rep.TopRoutes, func(i, j int) bool {
		a, b := rep.TopRoutes[i], rep.TopRoutes[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.From+a.To < b.From+b.To
	})
	if len(rep.TopRoutes) > limit {
		rep.TopRoutes = rep.TopRoutes[:limit]
	}
	for _, s := range shifts {
		n := float64(s.Requests)
		names := map[string]bool{}
		for k := range s.before {
			names[k] = true
		}
		for k := range s.after {
			names[k] = true
		}
		for _, k := range sortedKeys(names) {
			s.Backends = append(s.Backends, ReplayShiftBackend{Backend: k, BeforePercent: round1(s.before[k] / n), AfterPercent: round1(s.after[k] / n)})
		}
		rep.WeightShifts = append(rep.WeightShifts, s.ReplayShift)
	}
	sort.Slice(rep.WeightShifts, func(i, j int) bool {
		a, b := rep.WeightShifts[i], rep.WeightShifts[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.From+a.To < b.From+b.To
	})
	if len(rep.WeightShifts) > limit {
		rep.WeightShifts = rep.WeightShifts[:limit]
	}
	if rep.TopGroups == nil {
		rep.TopGroups = []ReplayGroup{}
	}
}

func hasStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// parseFailOn expands --fail-on. "any" is route, backend, outcome and weights;
// header-dependent unknowns only fail when asked for explicitly.
func parseFailOn(v string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "":
		case "any":
			for _, c := range []string{classRoute, classBackend, classOutcome, classWeights} {
				if !hasStr(out, c) {
					out = append(out, c)
				}
			}
		case classRoute, classBackend, classOutcome, classWeights, classUnknown:
			if !hasStr(out, p) {
				out = append(out, p)
			}
		default:
			return nil, userErrorf("--fail-on must be route, backend, outcome, weights, unknown or any, got %q", p)
		}
	}
	return out, nil
}

func (r *ReplayReport) applyFailOn(failOn []string) {
	r.FailOn = failOn
	for _, c := range failOn {
		if cl := r.class(c); cl != nil && cl.Requests > 0 {
			r.Failed = true
		}
	}
}

func runReplay(fs *flag.FlagSet, rest []string, u *ui, tty bool, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	logPath := fs.String("log", "", "gateway JSON access log: FILE, FILE.gz or - for stdin (required)")
	beforeP := fs.String("before", "", "current gateway config (required)")
	afterP := fs.String("after", "", "proposed gateway config (required)")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty, json or github")
	limit := fs.Int("limit", 10, "show this many top routes, groups and shifts")
	ignoreW := fs.Bool("ignore-weights", false, "do not report weight-only distribution changes")
	failOn := fs.String("fail-on", "", "exit 1 when impact of this kind is found: route, backend, outcome, weights, unknown or any (comma separated)")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura replay: %s\n", msg)
		exampleHint(stderr, "replay")
		return 2, usageError{msg}
	}
	if len(pos) > 0 || *logPath == "" || *beforeP == "" || *afterP == "" {
		return bad("--log, --before and --after are required")
	}
	if *limit < 1 {
		return bad("--limit must be at least 1")
	}
	fail, err := parseFailOn(*failOn)
	if err != nil {
		return bad(err.Error())
	}
	pretty := false
	if *format != "github" {
		if pretty, err = wantPretty(*format, tty); err != nil {
			return bad(err.Error())
		}
	}
	rep, err := Replay(ReplayOptions{Log: *logPath, Before: *beforeP, After: *afterP, Limit: *limit, IgnoreWeights: *ignoreW}, stdin)
	if err != nil {
		return 2, err
	}
	rep.applyFailOn(fail)
	switch {
	case *format == "github":
		fmt.Fprint(stdout, rep.Annotations())
	case pretty:
		fmt.Fprint(stdout, u.ReplayPretty(rep))
	default:
		if err := writeJSON(stdout, rep); err != nil {
			return 2, err
		}
	}
	return boolExit(rep.Failed), nil
}

func commas(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func pct(n, total int64) string {
	if total == 0 {
		return "0%"
	}
	p := float64(n) * 100 / float64(total)
	if p > 0 && p < 0.01 {
		return "<0.01%"
	}
	return strconv.FormatFloat(round2(p), 'f', -1, 64) + "%"
}

var replayClassText = map[string]string{
	classRoute:   "route changed",
	classBackend: "backend set changed",
	classOutcome: "outcome changed",
	classWeights: "weight distribution shifted",
	classUnknown: "unknown, depends on headers",
}

// ReplayPretty renders the report for a terminal.
func (u *ui) ReplayPretty(r *ReplayReport) string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("\n  %s  %s %s %s\n", u.bold("setura replay"), r.Before, u.arrow(), r.After)
	p("  %s\n\n", u.gray(fmt.Sprintf("%s: %s lines, %s requests replayed, %s skipped",
		r.Log, commas(r.Input.Lines), commas(r.Input.Requests), commas(r.Input.SkippedNonJSON+r.Input.SkippedIncomplete))))
	total := r.Input.Requests
	switch {
	case total == 0:
		p("  %s %s\n\n", u.warnSym(), u.bold("no replayable requests found in the log"))
		return b.String()
	case r.Changed == 0:
		p("  %s %s\n", u.okSym(), u.bold("no impact: every request resolves the same way"))
	default:
		p("  %s %s\n", u.warnSym(), u.bold(fmt.Sprintf("%s of %s requests (%s) resolve differently",
			commas(r.Changed), commas(total), pct(r.Changed, total))))
	}
	p("\n  %s\n", u.blue("Impact"))
	for _, c := range r.Classes {
		sym := u.okSym()
		if c.Requests > 0 {
			sym = u.failSym()
			if c.Class == classUnknown || c.Class == classWeights {
				sym = u.warnSym()
			}
		}
		line := fmt.Sprintf("%s  %s", pad(replayClassText[c.Class], 30), pad(commas(c.Requests), 12))
		if c.Requests > 0 {
			line += u.gray(fmt.Sprintf("%s  %s", pad(pct(c.Requests, total), 8), plural(c.Groups, "group", "groups")))
		}
		p("    %s %s\n", sym, line)
	}
	if len(r.TopRoutes) > 0 {
		p("\n  %s\n", u.blue("Most impacted routes"))
		for _, t := range r.TopRoutes {
			p("    %s  %s %s %s  %s\n", pad(commas(t.Requests), 10), t.From, u.arrow(), t.To, u.gray(strings.Join(t.Classes, ", ")))
		}
	}
	p("\n  %s\n", u.blue("Examples"))
	shown := false
	for _, c := range r.Classes {
		if c.Example == nil {
			continue
		}
		shown = true
		p("    %s %s\n", u.bold(replayClassText[c.Class]), u.gray("("+commas(c.Requests)+" requests)"))
		p("      %s\n", c.Example.Request)
		p("      %s %s\n", u.gray("before"), c.Example.Before)
		p("      %s %s\n", u.gray("after "), c.Example.After)
	}
	if !shown {
		p("    %s\n", u.gray("none"))
	}
	if len(r.WeightShifts) > 0 {
		p("\n  %s\n", u.blue("Traffic distribution"))
		for _, s := range r.WeightShifts {
			p("    %s %s %s  %s\n", s.From, u.arrow(), s.To, u.gray(commas(s.Requests)+" requests"))
			for _, bk := range s.Backends {
				p("      %s  %s %s %s\n", pad(bk.Backend, 28), pad(fmt.Sprintf("%.1f%%", bk.BeforePercent), 7), u.arrow(), fmt.Sprintf("%.1f%%", bk.AfterPercent))
			}
		}
	}
	if len(r.TopGroups) > 0 {
		p("\n  %s\n", u.blue("Top changed request groups"))
		for _, g := range r.TopGroups {
			p("    %s  %s %s%s  %s\n", pad(commas(g.Requests), 10), g.Method, g.Host, g.Shape, u.gray(strings.Join(g.Classes, ", ")))
			p("      %s %s\n      %s %s\n", u.gray("before"), g.Before.String(), u.gray("after "), g.After.String())
		}
	}
	if m := r.Input.LoggedRouteMismatch; m > 0 {
		p("\n  %s %s\n", u.warnSym(), fmt.Sprintf("%s requests were logged with a route the before config does not resolve; is --before the config that served this log?", commas(m)))
	}
	if r.Failed {
		p("\n  %s %s\n", u.failSym(), u.bold("failing: --fail-on "+strings.Join(r.FailOn, ",")))
	}
	p("\n")
	return b.String()
}

func ghEscape(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

// Annotations renders GitHub Actions workflow commands.
func (r *ReplayReport) Annotations() string {
	var b strings.Builder
	found := false
	for _, c := range r.Classes {
		if c.Requests == 0 {
			continue
		}
		found = true
		level := "warning"
		if hasStr(r.FailOn, c.Class) {
			level = "error"
		}
		msg := fmt.Sprintf("%s for %s of %d requests (%s). Example: %s: %s => %s", replayClassText[c.Class], commas(c.Requests), r.Input.Requests,
			pct(c.Requests, r.Input.Requests), c.Example.Request, c.Example.Before, c.Example.After)
		fmt.Fprintf(&b, "::%s title=setura replay %s::%s\n", level, c.Class, ghEscape(msg))
	}
	if !found {
		fmt.Fprintf(&b, "::notice title=setura replay::no impact across %s replayed requests\n", commas(r.Input.Requests))
	}
	return b.String()
}
