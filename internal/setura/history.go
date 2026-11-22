package setura

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// Regression thresholds, compared with the previous window of equal length.
const (
	regressionUptimeDrop  = 1.0  // percentage points
	regressionLatencyPct  = 25.0 // p95 growth in percent...
	regressionLatencyAbs  = 10.0 // ...and at least this many milliseconds
	defaultHistoryWindow  = 24 * time.Hour
	historyMaxLineBytes   = 1 << 20
	historyRegressionMark = "REGRESSION"
)

type windowStats struct {
	Probes    int     `json:"probes"`
	OK        int     `json:"ok"`
	UptimePct float64 `json:"uptime_pct"`
	P50MS     float64 `json:"p50_ms"`
	P95MS     float64 `json:"p95_ms"`
}

type lastFailure struct {
	Time  string `json:"time"`
	Stage string `json:"stage"`
}

// RouteHistory is the summary of one route over the selected window.
type RouteHistory struct {
	Route    string       `json:"route"`
	Current  windowStats  `json:"current"`
	Previous *windowStats `json:"previous,omitempty"`
	// LastFailure is the newest failing probe anywhere in the file's selected
	// windows, nil when none failed.
	LastFailure       *lastFailure `json:"last_failure"`
	Regression        bool         `json:"regression"`
	RegressionReasons []string     `json:"regression_reasons,omitempty"`
}

// HistorySummary is the result of "setura history".
type HistorySummary struct {
	Since        string         `json:"since"`
	From         string         `json:"from"`
	To           string         `json:"to"`
	Routes       []RouteHistory `json:"routes"`
	SkippedLines int            `json:"skipped_lines"`
}

type routeAcc struct {
	cur, prev     []float64
	curOK, prevOK int
	last          *lastFailure
	lastAt        time.Time
}

func (a *routeAcc) stats(lat []float64, ok int) windowStats {
	s := windowStats{Probes: len(lat), OK: ok}
	if len(lat) == 0 {
		return s
	}
	s.UptimePct = round2(100 * float64(ok) / float64(len(lat)))
	sorted := append([]float64(nil), lat...)
	sort.Float64s(sorted)
	s.P50MS, s.P95MS = round2(histPercentile(sorted, 50)), round2(histPercentile(sorted, 95))
	return s
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// histPercentile is the nearest-rank percentile of an ascending slice.
func histPercentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// SummarizeHistory reads watch history lines (JSONL) and summarizes the window
// (now-since, now] per route against the window before it. A route matches when
// route is empty, equal to the target, or contained in it. Malformed lines are
// counted and skipped.
func SummarizeHistory(r io.Reader, now time.Time, since time.Duration, route string) (*HistorySummary, error) {
	if since <= 0 {
		return nil, userError("--since must be positive")
	}
	curStart, prevStart := now.Add(-since), now.Add(-2*since)
	accs := map[string]*routeAcc{}
	sum := &HistorySummary{Since: since.String(), From: curStart.UTC().Format(time.RFC3339), To: now.UTC().Format(time.RFC3339)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), historyMaxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h historyLine
		t, err := time.Time{}, json.Unmarshal([]byte(line), &h)
		if err == nil {
			t, err = time.Parse(time.RFC3339, h.Time)
		}
		if err != nil || h.Target == "" {
			sum.SkippedLines++
			continue
		}
		if route != "" && h.Target != route && !strings.Contains(h.Target, route) {
			continue
		}
		if t.After(now) || !t.After(prevStart) {
			continue
		}
		a := accs[h.Target]
		if a == nil {
			a = &routeAcc{}
			accs[h.Target] = a
		}
		inCur := t.After(curStart)
		switch {
		case inCur:
			a.cur = append(a.cur, h.ElapsedMS)
			if h.OK {
				a.curOK++
			}
		default:
			a.prev = append(a.prev, h.ElapsedMS)
			if h.OK {
				a.prevOK++
			}
		}
		if !h.OK && inCur && !t.Before(a.lastAt) {
			a.lastAt, a.last = t, &lastFailure{Time: t.UTC().Format(time.RFC3339), Stage: h.FailingStage}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, target := range sortedKeys(accs) {
		a := accs[target]
		if len(a.cur) == 0 {
			continue // only seen in the previous window: nothing current to report
		}
		rh := RouteHistory{Route: target, Current: a.stats(a.cur, a.curOK), LastFailure: a.last}
		if len(a.prev) > 0 {
			p := a.stats(a.prev, a.prevOK)
			rh.Previous = &p
			if drop := p.UptimePct - rh.Current.UptimePct; drop >= regressionUptimeDrop {
				rh.RegressionReasons = append(rh.RegressionReasons, fmt.Sprintf("uptime fell %.2f points (%.2f%% to %.2f%%)", drop, p.UptimePct, rh.Current.UptimePct))
			}
			grew := rh.Current.P95MS - p.P95MS
			if grew >= regressionLatencyAbs && p.P95MS > 0 && 100*grew/p.P95MS >= regressionLatencyPct {
				rh.RegressionReasons = append(rh.RegressionReasons, fmt.Sprintf("p95 latency rose %.0f ms to %.0f ms", p.P95MS, rh.Current.P95MS))
			}
			rh.Regression = len(rh.RegressionReasons) > 0
		}
		sum.Routes = append(sum.Routes, rh)
	}
	if sum.Routes == nil {
		sum.Routes = []RouteHistory{}
	}
	return sum, nil
}

// Table renders the summary for a terminal.
func (s *HistorySummary) Table() string {
	var b strings.Builder
	w := len("ROUTE")
	for _, r := range s.Routes {
		w = max(w, len([]rune(r.Route)))
	}
	fmt.Fprintf(&b, "window: last %s (%s to %s)\n", s.Since, s.From, s.To)
	row := func(cols ...string) {
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s  %s\n", pad(cols[0], w), pad(cols[1], 6), pad(cols[2], 8), pad(cols[3], 9), pad(cols[4], 9), pad(cols[5], 26), cols[6])
	}
	row("ROUTE", "PROBES", "UPTIME", "P50", "P95", "LAST FAILURE", "TREND")
	for _, r := range s.Routes {
		last, trend := "-", "ok"
		if r.LastFailure != nil {
			last = r.LastFailure.Time
			if r.LastFailure.Stage != "" {
				last += " " + r.LastFailure.Stage
			}
		}
		switch {
		case r.Regression:
			trend = historyRegressionMark + ": " + strings.Join(r.RegressionReasons, "; ")
		case r.Previous == nil:
			trend = "no previous data"
		}
		row(r.Route, fmt.Sprint(r.Current.Probes), fmt.Sprintf("%.2f%%", r.Current.UptimePct), fmtMS(r.Current.P50MS), fmtMS(r.Current.P95MS), last, trend)
	}
	if s.SkippedLines > 0 {
		fmt.Fprintf(&b, "skipped %d malformed line(s)\n", s.SkippedLines)
	}
	return b.String()
}

// historyNow is replaceable in tests.
var historyNow = time.Now

// runHistory implements "setura history [FILE]".
func runHistory(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	since := fs.Duration("since", defaultHistoryWindow, "summarize this long back from now, compared with the window before it")
	route := fs.String("route", "", "only routes whose target equals or contains this text")
	format := fs.String("format", "table", "table or json")
	file := fs.String("file", "", "history FILE written by setura watch --history (or give it as an argument)")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if *file != "" {
		pos = append(pos, *file)
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura history: expected FILE")
		exampleHint(stderr, "history")
		return 2, usageError{"FILE"}
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "setura history: --format must be table or json")
		return 2, usageError{"format"}
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sum, err := SummarizeHistory(f, historyNow(), *since, *route)
	if err != nil {
		return 0, err
	}
	if *format == "json" {
		return 0, writeJSON(stdout, sum)
	}
	fmt.Fprint(stdout, sum.Table())
	return 0, nil
}
