package setura

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	classPolicy  = "policy"    // retry or timeout of a logged route changed
	classMirror  = "mirror"    // mirror or shadow-diff added, removed or changed
	classRate    = "ratelimit" // the gateway's rate-limit policy changed (--before/--after-rate-limit)
	classHealth  = "health"    // traffic now goes to a backend the log shows failing
)

var replayClasses = []string{classRoute, classBackend, classOutcome, classWeights, classUnknown, classPolicy, classMirror, classRate, classHealth}

// A backend is flagged unhealthy when the log shows at least healthMinReqs
// requests to it and at least half answered 5xx. The log cannot say whether
// the cause was ejection, an outage or a bad deploy, so replay flags it and
// never changes a verdict because of it.
const healthMinReqs = 20

const (
	replayMaxLine    = 4 << 20 // longer lines are skipped, never buffered whole
	replayCacheLimit = 100000  // exact-request memo entries
	// replayGroupLimit bounds the request groups. Past it, requests whose
	// (host, path shape) is new share one overflow group per method and
	// decision pair, so memory stays flat on logs with unbounded distinct
	// paths (slugs, asset hashes). Counts stay exact; only the label coarsens.
	replayGroupLimit = 20000
)

// ReplayOptions configure one replay run.
type ReplayOptions struct {
	Log, Before, After string
	Limit              int
	IgnoreWeights      bool
	DefaultHost        string // Host for Common Log Format lines, which carry none
	BeforeRate         string // rate-limit policy of the before gateway ("100/s,burst=20,key=route"), empty for none
	AfterRate          string
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
	// Formats counts the lines read per access-log format (json, text, common).
	Formats map[string]int64 `json:"formats,omitempty"`
	// GRPC and TLS count the requests replayed as gRPC calls and as TLS
	// passthrough connections instead of plain HTTP.
	GRPC int64 `json:"grpc,omitempty"`
	TLS  int64 `json:"tls,omitempty"`
	// MergedShapes counts requests folded into overflow groups because the
	// log had more distinct (host, path shape) pairs than replayGroupLimit.
	MergedShapes int64 `json:"merged_shapes,omitempty"`
}

// ReplayBackendHealth is a backend the log shows failing.
type ReplayBackendHealth struct {
	Backend  string  `json:"backend"`
	Requests int64   `json:"requests"`
	Errors   int64   `json:"errors_5xx"`
	Percent  float64 `json:"error_percent"`
}

// ReplayPolicy is a retry, timeout or mirror change on a route with logged traffic.
type ReplayPolicy struct {
	Route    string `json:"route"`
	Field    string `json:"field"` // retry, timeout or mirror
	Before   string `json:"before"`
	After    string `json:"after"`
	Requests int64  `json:"requests"`
}

// ReplayRateLimit reports a change of the gateway-wide rate-limit policy.
type ReplayRateLimit struct {
	Before   string `json:"before"`
	After    string `json:"after"`
	Requests int64  `json:"requests"` // replayed HTTP requests the policy applies to
	Logged   int64  `json:"logged_429"`
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
	Suspect  []string         `json:"suspect_backends,omitempty"`
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
	Schema        string                `json:"schema"`
	Log           string                `json:"log"`
	Before        string                `json:"before"`
	After         string                `json:"after"`
	IgnoreWeights bool                  `json:"ignore_weights,omitempty"`
	Input         ReplayInput           `json:"input"`
	Changed       int64                 `json:"changed_requests"`
	Unchanged     int64                 `json:"unchanged_requests"`
	Classes       []ReplayClass         `json:"classes"`
	TopRoutes     []ReplayRoute         `json:"top_routes"`
	TopGroups     []ReplayGroup         `json:"top_groups"`
	WeightShifts  []ReplayShift         `json:"weight_shifts"`
	PolicyChanges []ReplayPolicy        `json:"policy_changes,omitempty"`
	RateLimit     *ReplayRateLimit      `json:"rate_limit,omitempty"`
	BackendHealth []ReplayBackendHealth `json:"backend_health,omitempty"`
	FailOn        []string              `json:"fail_on,omitempty"`
	Failed        bool                  `json:"failed"`
}

func (r *ReplayReport) class(name string) *ReplayClass {
	for i := range r.Classes {
		if r.Classes[i].Class == name {
			return &r.Classes[i]
		}
	}
	return nil
}

// replayLabel names a decision's route or outcome for transitions.
func replayLabel(d builtin.Decision) string {
	if d.Route != "" {
		return d.Route
	}
	return d.Outcome
}

func decisionSig(d builtin.Decision, withLocation bool) string {
	buf := make([]byte, 0, 128)
	buf = append(buf, d.Outcome...)
	buf = append(buf, '|')
	buf = append(buf, d.Route...)
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, int64(d.Rule), 10)
	for _, w := range d.Backends {
		buf = append(buf, '|')
		buf = append(buf, w.Key...)
		buf = append(buf, ':')
		buf = strconv.AppendInt(buf, int64(w.Weight), 10)
	}
	buf = append(buf, '|')
	buf = strconv.AppendInt(buf, int64(d.Status), 10)
	if withLocation {
		buf = append(buf, d.Location...)
	}
	if d.HeaderDependent {
		buf = append(buf, "|hdr:"...)
		for i, r := range d.HeaderRoutes {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, r...)
		}
	}
	buf = append(buf, '|')
	buf = append(buf, d.Kind...)
	buf = append(buf, '|')
	buf = append(buf, d.Retry...)
	buf = append(buf, '|')
	buf = append(buf, d.Timeout...)
	buf = append(buf, '|')
	for i, m := range d.Mirrors {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, m...)
	}
	return string(buf)
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
		if decisionSig(b, true) == decisionSig(a, true) {
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
	if hasBackends(b) && hasBackends(a) {
		if b.Retry != a.Retry || b.Timeout != a.Timeout {
			out = append(out, classPolicy)
		}
		if strings.Join(b.Mirrors, ",") != strings.Join(a.Mirrors, ",") {
			out = append(out, classMirror)
		}
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
	return collapseDigitRuns(s)
}

// collapseDigitRuns turns runs of five or more digits inside a segment into
// ":n", so cache-busted names such as app.839201.js share one shape.
func collapseDigitRuns(s string) string {
	var out []byte
	last := 0 // s[:last] is already in out
	for i := 0; i < len(s); {
		if s[i] < '0' || s[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-i >= 5 {
			out = append(out, s[last:i]...)
			out = append(out, ":n"...)
			last = j
		}
		i = j
	}
	if last == 0 && out == nil {
		return s
	}
	return string(append(out, s[last:]...))
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

// ratePolicy normalises "100/s,burst=20,key=route" the way the gateway's
// limiter reads it, so two spellings of one policy compare equal.
func ratePolicy(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	parts := strings.Split(v, ",")
	rate, per, err := builtin.ParseRate(parts[0])
	if err != nil {
		return "", userErrorf("rate limit: %v", err)
	}
	cfg := builtin.RateLimitConfig{Rate: rate, Per: per, Key: "ip"}
	for _, p := range parts[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch k {
		case "burst":
			if cfg.Burst, err = strconv.Atoi(val); err != nil || cfg.Burst < 0 {
				return "", userErrorf("rate limit burst %q is not a number", val)
			}
		case "key":
			cfg.Key = val
		default:
			return "", userErrorf("rate limit option %q: want burst=N or key=ip|route|header:NAME", p)
		}
	}
	perSec := cfg.Rate / cfg.Per.Seconds()
	burst := cfg.Burst
	if burst <= 0 {
		burst = int(math.Max(1, math.Ceil(perSec)))
	}
	return fmt.Sprintf("%g/s burst %d key %s", perSec, burst, cfg.Key), nil
}

type beStat struct{ n, errs int64 }

func replayStream(rd io.Reader, o ReplayOptions, before, after *builtin.Table) (*ReplayReport, error) {
	rep := &ReplayReport{Schema: "setura.replay/v1", Log: o.Log, Before: o.Before, After: o.After, IgnoreWeights: o.IgnoreWeights}
	rep.Input.Formats = map[string]int64{}
	bRate, err := ratePolicy(o.BeforeRate)
	if err != nil {
		return nil, err
	}
	aRate, err := ratePolicy(o.AfterRate)
	if err != nil {
		return nil, err
	}
	rateChanged := bRate != aRate
	if rateChanged || bRate != "" {
		rep.RateLimit = &ReplayRateLimit{Before: bRate, After: aRate}
	}
	groups := map[string]*ReplayGroup{}
	cache := map[string]*ReplayGroup{}
	stats := map[string]*beStat{}
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
		if rec.status == 429 && rep.RateLimit != nil {
			rep.RateLimit.Logged++
		}
		if rec.backend != "" {
			st := stats[rec.backend]
			if st == nil {
				if len(stats) >= 100000 {
					st = &beStat{} // detached: a log with that many backends is not a real gateway
				} else {
					st = &beStat{}
					stats[rec.backend] = st
				}
			}
			st.n++
			if rec.status >= 500 {
				st.errs++
			}
		}
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
		g := cache[string(key)]
		if g == nil {
			host, path := string(rec.host), string(rec.path)
			spec := builtin.ReqSpec{Port: before.ListenerPort(rec.listener), Host: host, Method: method, Path: path, GRPC: grpc}
			if tls {
				spec.SNI, spec.Host, spec.Method, spec.Path = host, "", "", ""
			}
			b, a := before.Resolve(spec), after.Resolve(spec)
			lhost := strings.ToLower(host)
			shape := pathShape(path)
			sigs := decisionSig(b, false) + "\x00" + decisionSig(a, false) + "\x00" + strconv.FormatBool(b.Location == a.Location)
			gkey := lhost + "\x00" + method + "\x00" + shape + "\x00" + sigs
			g = groups[gkey]
			if g == nil && len(groups) >= replayGroupLimit {
				lhost, shape = "(other)", "(many shapes)"
				gkey = lhost + "\x00" + method + "\x00" + shape + "\x00" + sigs
				g = groups[gkey]
				rep.Input.MergedShapes++
			}
			if g == nil {
				ex := method + " " + host + path
				if tls {
					ex = "TLS " + host
				}
				g = &ReplayGroup{Host: lhost, Method: method, Shape: shape, Example: ex,
					Before: b, After: a, Classes: classifyReplay(b, a, o.IgnoreWeights)}
				if rateChanged && b.Kind == "" && !b.HeaderDependent && (b.Route != "" || a.Route != "") {
					g.Classes = append(g.Classes, classRate)
				}
				groups[gkey] = g
			}
			if len(cache) < replayCacheLimit {
				cache[string(key)] = g
			}
		}
		g.Requests++
		switch g.Before.Kind {
		case "grpc":
			rep.Input.GRPC++
		case "tls":
			rep.Input.TLS++
		}
		if rep.RateLimit != nil && g.Before.Kind == "" && (g.Before.Route != "" || g.After.Route != "") {
			rep.RateLimit.Requests++
		}
		if rec.route != "" && rec.route != g.Before.Route {
			rep.Input.LoggedRouteMismatch++
		}
	})
	if err != nil {
		return nil, err
	}
	flagUnhealthy(rep, groups, stats)
	summarizeReplay(rep, groups, o)
	return rep, nil
}

func isUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return false
		}
	}
	return true
}

// flagUnhealthy lists the backends the log shows failing and marks groups the
// after config newly sends to one of them. It flags; it never changes a verdict.
func flagUnhealthy(rep *ReplayReport, groups map[string]*ReplayGroup, stats map[string]*beStat) {
	bad := map[string]bool{}
	for k, st := range stats {
		if st.n >= healthMinReqs && st.errs*2 >= st.n {
			bad[k] = true
			rep.BackendHealth = append(rep.BackendHealth, ReplayBackendHealth{Backend: k, Requests: st.n, Errors: st.errs, Percent: round1(float64(st.errs) * 100 / float64(st.n))})
		}
	}
	sort.Slice(rep.BackendHealth, func(i, j int) bool {
		a, b := rep.BackendHealth[i], rep.BackendHealth[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Backend < b.Backend
	})
	if len(bad) == 0 {
		return
	}
	for _, g := range groups {
		if g.Before.HeaderDependent || g.After.HeaderDependent {
			continue
		}
		had := map[string]bool{}
		for _, w := range g.Before.Backends {
			had[w.Key] = true
		}
		for _, w := range g.After.Backends {
			if bad[w.Key] && !had[w.Key] {
				g.Suspect = append(g.Suspect, w.Key)
			}
		}
		if len(g.Suspect) > 0 {
			g.Classes = append(g.Classes, classHealth)
		}
	}
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
	rep.PolicyChanges = policyChanges(all, limit)
	if len(rep.BackendHealth) > limit {
		rep.BackendHealth = rep.BackendHealth[:limit]
	}
	if rep.TopGroups == nil {
		rep.TopGroups = []ReplayGroup{}
	}
}

// policyChanges aggregates retry, timeout and mirror changes per route.
func policyChanges(all []*ReplayGroup, limit int) []ReplayPolicy {
	acc := map[string]*ReplayPolicy{}
	add := func(g *ReplayGroup, field, b, a string) {
		route := g.Before.Route
		k := route + "\x00" + field + "\x00" + b + "\x00" + a
		p := acc[k]
		if p == nil {
			p = &ReplayPolicy{Route: route, Field: field, Before: b, After: a}
			acc[k] = p
		}
		p.Requests += g.Requests
	}
	none := func(s string) string {
		if s == "" {
			return "none"
		}
		return s
	}
	for _, g := range all {
		if g.Before.HeaderDependent || g.After.HeaderDependent || !hasBackends(g.Before) || !hasBackends(g.After) {
			continue
		}
		if g.Before.Retry != g.After.Retry {
			add(g, "retry", none(g.Before.Retry), none(g.After.Retry))
		}
		if g.Before.Timeout != g.After.Timeout {
			add(g, "timeout", none(g.Before.Timeout), none(g.After.Timeout))
		}
		if bm, am := strings.Join(g.Before.Mirrors, ", "), strings.Join(g.After.Mirrors, ", "); bm != am {
			add(g, "mirror", none(bm), none(am))
		}
	}
	var out []ReplayPolicy
	for _, p := range acc {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Route+a.Field+a.After < b.Route+b.Field+b.After
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
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
		case classRoute, classBackend, classOutcome, classWeights, classUnknown, classPolicy, classMirror, classRate, classHealth:
			if !hasStr(out, p) {
				out = append(out, p)
			}
		default:
			return nil, userErrorf("--fail-on must be route, backend, outcome, weights, unknown, policy, mirror, ratelimit, health or any, got %q", p)
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
	failOn := fs.String("fail-on", "", "exit 1 when impact of this kind is found: route, backend, outcome, weights, unknown, policy, mirror, ratelimit, health or any (comma separated)")
	defHost := fs.String("default-host", "", "Host for Common Log Format lines, which do not record one")
	beforeRate := fs.String("before-rate-limit", "", "the before gateway's --rate-limit, as 100/s[,burst=N][,key=ip|route|header:NAME]")
	afterRate := fs.String("after-rate-limit", "", "the after gateway's --rate-limit, same syntax")
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
	rep, err := Replay(ReplayOptions{Log: *logPath, Before: *beforeP, After: *afterP, Limit: *limit, IgnoreWeights: *ignoreW,
		DefaultHost: *defHost, BeforeRate: *beforeRate, AfterRate: *afterRate}, stdin)
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
	classPolicy:  "retry/timeout policy changed",
	classMirror:  "mirror/shadow-diff changed",
	classRate:    "rate-limit policy changed",
	classHealth:  "routed to a failing backend",
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
			if c.Class == classUnknown || c.Class == classWeights || c.Class == classPolicy || c.Class == classMirror || c.Class == classRate || c.Class == classHealth {
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
	if len(r.PolicyChanges) > 0 {
		p("\n  %s\n", u.blue("Policy changes on logged routes"))
		for _, c := range r.PolicyChanges {
			p("    %s  %s %s: %s %s %s\n", pad(commas(c.Requests), 10), c.Route, c.Field, c.Before, u.arrow(), c.After)
		}
	}
	if rl := r.RateLimit; rl != nil && rl.Before != rl.After {
		show := func(s string) string {
			if s == "" {
				return "none"
			}
			return s
		}
		p("\n  %s\n    rate limit %s %s %s  %s\n", u.blue("Rate limit"), show(rl.Before), u.arrow(), show(rl.After), u.gray(commas(rl.Requests)+" replayed requests; "+commas(rl.Logged)+" were logged as 429"))
	}
	if len(r.BackendHealth) > 0 {
		p("\n  %s\n", u.blue("Backends failing in the log (flagged, not modelled)"))
		for _, h := range r.BackendHealth {
			p("    %s  %s  %s\n", pad(h.Backend, 32), pad(fmt.Sprintf("%.1f%% 5xx", h.Percent), 10), u.gray(fmt.Sprintf("of %s logged requests; ejected, down or a bad deploy, the log cannot tell", commas(h.Requests))))
		}
	}
	if in := r.Input; in.GRPC+in.TLS > 0 {
		p("\n  %s\n", u.gray(fmt.Sprintf("%s requests replayed as gRPC calls, %s as TLS passthrough connections", commas(in.GRPC), commas(in.TLS))))
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
