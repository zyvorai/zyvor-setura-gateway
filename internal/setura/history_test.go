package setura

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var histNow = time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

func histLine(ago time.Duration, target string, ok bool, stage string, ms float64) string {
	return fmt.Sprintf(`{"time":%q,"target":%q,"ok":%t,"failing_stage":%q,"elapsed_ms":%g}`,
		histNow.Add(-ago).Format(time.RFC3339), target, ok, stage, ms)
}

func TestSummarizeHistoryStatsAndRegression(t *testing.T) {
	var lines []string
	// previous window (2h..1h ago): 10 probes, all ok, ~10ms
	for i := 0; i < 10; i++ {
		lines = append(lines, histLine(time.Hour+time.Duration(i+1)*time.Minute, "http://a/", true, "", 10))
	}
	// current window: 10 probes, 2 failures, slow tail
	for i := 0; i < 10; i++ {
		ok, stage, ms := true, "", float64(10)
		if i >= 8 {
			ok, stage, ms = false, "http", 100
		}
		lines = append(lines, histLine(time.Duration(i+1)*time.Minute, "http://a/", ok, stage, ms))
	}
	// a steady route and noise
	for i := 0; i < 4; i++ {
		lines = append(lines, histLine(30*time.Minute+time.Duration(i)*time.Minute, "http://b/", true, "", 5))
		lines = append(lines, histLine(90*time.Minute+time.Duration(i)*time.Minute, "http://b/", true, "", 5))
	}
	lines = append(lines, "not json", "", histLine(5*time.Hour, "http://old/", false, "dns", 1))
	sum, err := SummarizeHistory(strings.NewReader(strings.Join(lines, "\n")), histNow, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	is(t, sum.SkippedLines, 1)
	is(t, len(sum.Routes), 2)
	a, b := sum.Routes[0], sum.Routes[1]
	is(t, a.Route, "http://a/")
	is(t, a.Current.Probes, 10)
	is(t, a.Current.UptimePct, 80)
	is(t, a.Current.P50MS, 10)
	is(t, a.Current.P95MS, 100)
	is(t, a.LastFailure.Stage, "http")
	is(t, a.LastFailure.Time, histNow.Add(-9*time.Minute).Format(time.RFC3339)) // newest failure is i=8
	is(t, a.Previous.UptimePct, 100)
	is(t, a.Regression, true)
	is(t, len(a.RegressionReasons), 2)
	is(t, b.Regression, false)
	is(t, b.LastFailure == nil, true)
	table := sum.Table()
	contains(t, table, "REGRESSION")
	contains(t, table, "http://b/")
}

func TestSummarizeHistoryRouteFilterAndNoPrevious(t *testing.T) {
	in := histLine(time.Minute, "http://orders/x", true, "", 3) + "\n" + histLine(time.Minute, "http://cart/", true, "", 3)
	sum, err := SummarizeHistory(strings.NewReader(in), histNow, time.Hour, "orders")
	if err != nil {
		t.Fatal(err)
	}
	is(t, len(sum.Routes), 1)
	is(t, sum.Routes[0].Previous == nil, true)
	is(t, sum.Routes[0].Regression, false)
	if _, err := SummarizeHistory(strings.NewReader(""), histNow, 0, ""); err == nil {
		t.Fatal("zero --since accepted")
	}
}

func TestHistoryCommand(t *testing.T) {
	old := historyNow
	historyNow = func() time.Time { return histNow }
	defer func() { historyNow = old }()
	file := filepath.Join(t.TempDir(), "h.jsonl")
	os.WriteFile(file, []byte(histLine(time.Minute, "http://a/", false, "tls", 7)+"\n"), 0o600)

	code, out, _ := cli(t, nil, "history", file, "--since", "2h")
	is(t, code, 0)
	contains(t, out, "http://a/")
	contains(t, out, "tls")

	code, out, _ = cli(t, nil, "history", "--file", file, "--format", "json")
	is(t, code, 0)
	routes := asList(asMap(decodeOut(t, out))["routes"])
	is(t, asMap(asMap(routes[0])["last_failure"])["stage"], "tls")

	for _, args := range [][]string{{"history"}, {"history", file, "--format", "xml"}, {"history", file, "--since", "-1h"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := cli(t, nil, "history", filepath.Join(t.TempDir(), "missing")); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
}
