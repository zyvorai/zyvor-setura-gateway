package setura

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var sloT0 = time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

// probeLines writes a probe every 5 minutes for four days back from sloT0;
// fn decides the outcome at each age.
func probeFile(t *testing.T, fn func(ago time.Duration) (ok bool, ms float64)) string {
	t.Helper()
	var b strings.Builder
	for ago := time.Duration(0); ago <= 4*24*time.Hour; ago += 5 * time.Minute {
		ok, ms := fn(ago)
		stage := ""
		if !ok {
			stage = "http"
		}
		fmt.Fprintf(&b, `{"time":%q,"target":"http://orders/","ok":%t,"failing_stage":%q,"elapsed_ms":%g}`+"\n",
			sloT0.Add(-ago).Format(time.RFC3339), ok, stage, ms)
	}
	path := filepath.Join(t.TempDir(), "probes.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func asciiUI() *ui { return newUI(false, termOptions{ASCII: true}, func(string) string { return "" }) }

func runSLOArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	old := sloNow
	sloNow = func() time.Time { return sloT0 }
	defer func() { sloNow = old }()
	var out, errb strings.Builder
	code, err := runSLO(newFlagSet("slo", &errb), args, &out, &errb, asciiUI())
	if err != nil {
		t.Fatalf("runSLO: %v\n%s", err, errb.String())
	}
	return code, out.String(), errb.String()
}

func jsonReport(t *testing.T, args ...string) (int, *SLOReport) {
	t.Helper()
	code, out, _ := runSLOArgs(t, append(args, "--format", "json")...)
	var r SLOReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return code, &r
}

func TestParseWindow(t *testing.T) {
	for in, want := range map[string]time.Duration{"5m": 5 * time.Minute, "6h": 6 * time.Hour, "3d": 72 * time.Hour, "1w": 168 * time.Hour, "1.5d": 36 * time.Hour} {
		got, err := ParseWindow(in)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "-1h", "0m", "abc", "3x"} {
		if _, err := ParseWindow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSLOConfigValidation(t *testing.T) {
	ok := `{"slos":[{"name":"a","type":"availability","objective":99.9},{"name":"l","type":"latency","objective":99,"threshold_ms":300,"window":"7d","route":"orders"}]}`
	c, err := ParseSLOConfig(strings.NewReader(ok))
	if err != nil {
		t.Fatal(err)
	}
	is(t, c.SLOs[0].Window, "30d")
	is(t, len(c.Burn), 3)
	is(t, c.Burn[0].Factor, 14.4)
	for name, bad := range map[string]string{
		"empty":       `{"slos":[]}`,
		"no name":     `{"slos":[{"type":"availability","objective":99}]}`,
		"dup":         `{"slos":[{"name":"a","type":"availability","objective":99},{"name":"a","type":"availability","objective":99}]}`,
		"type":        `{"slos":[{"name":"a","type":"errors","objective":99}]}`,
		"objective":   `{"slos":[{"name":"a","type":"availability","objective":100}]}`,
		"fraction":    `{"slos":[{"name":"a","type":"availability","objective":0}]}`,
		"no thr":      `{"slos":[{"name":"a","type":"latency","objective":99}]}`,
		"window":      `{"slos":[{"name":"a","type":"availability","objective":99,"window":"soon"}]}`,
		"unknown":     `{"slos":[{"name":"a","type":"availability","objective":99,"target":1}]}`,
		"burn order":  `{"slos":[{"name":"a","type":"availability","objective":99}],"burn":[{"long":"5m","short":"1h","factor":2,"severity":"page"}]}`,
		"burn sev":    `{"slos":[{"name":"a","type":"availability","objective":99}],"burn":[{"long":"1h","short":"5m","factor":2,"severity":"loud"}]}`,
		"burn factor": `{"slos":[{"name":"a","type":"availability","objective":99}],"burn":[{"long":"1h","short":"5m","factor":0,"severity":"page"}]}`,
	} {
		if _, err := ParseSLOConfig(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSLOHealthyProbes(t *testing.T) {
	f := probeFile(t, func(time.Duration) (bool, float64) { return true, 20 })
	code, r := jsonReport(t, "--history", f)
	is(t, code, 0)
	is(t, r.Verdict, "ok")
	s := r.SLOs[0]
	is(t, s.Status, "ok")
	is(t, *s.SLI, 100.0)
	is(t, *s.BudgetRemaining, 100.0)
	for _, a := range s.Alerts {
		is(t, a.Firing, false)
	}
	is(t, len(s.Windows), 5) // 5m 30m 1h 6h 3d
}

func TestSLOIncidentBurnsAndPages(t *testing.T) {
	f := probeFile(t, func(ago time.Duration) (bool, float64) { return ago > 30*time.Minute, 20 })
	code, r := jsonReport(t, "--history", f)
	is(t, code, 1) // default --fail-on page
	s := r.SLOs[0]
	is(t, s.Status, "burning")
	is(t, r.Verdict, "burning")
	if !s.Alerts[0].Firing || !s.Alerts[1].Firing {
		t.Errorf("page alerts must fire: %+v", s.Alerts)
	}
	if *s.Alerts[0].ShortBurn < 100 {
		t.Errorf("short burn %v", *s.Alerts[0].ShortBurn)
	}
	// --fail-on never and ticket
	f2 := f
	c2, _, _ := runSLOArgs(t, "--history", f2, "--fail-on", "never")
	is(t, c2, 0)
}

func TestSLOShortWindowResetsPage(t *testing.T) {
	// Failures 30 to 55 minutes ago, healthy since: the 1h window still burns but the 5m window is clean.
	f := probeFile(t, func(ago time.Duration) (bool, float64) { return !(ago >= 30*time.Minute && ago <= 55*time.Minute), 20 })
	_, r := jsonReport(t, "--history", f)
	s := r.SLOs[0]
	if s.Alerts[0].Firing || s.Alerts[1].Firing {
		t.Errorf("a recovered incident must not page: %+v", s.Alerts)
	}
	if s.Alerts[0].LongBurn == nil || *s.Alerts[0].LongBurn < 14.4 || s.Alerts[0].ShortBurn == nil || *s.Alerts[0].ShortBurn != 0 {
		t.Errorf("windows %+v", s.Alerts[0])
	}
	// The 3d/6h ticket rule still sees the incident, and the budget is spent.
	is(t, s.Status, "breached")
	if !s.Alerts[2].Firing {
		t.Errorf("ticket alert should fire: %+v", s.Alerts[2])
	}
}

func TestSLOLatencyFromProbes(t *testing.T) {
	f := probeFile(t, func(ago time.Duration) (bool, float64) {
		if ago < 20*time.Minute {
			return true, 900 // slow
		}
		return true, 50
	})
	_, r := jsonReport(t, "--history", f, "--latency-ms", "300", "--latency-objective", "99")
	var lat *SLOResult
	for i := range r.SLOs {
		if r.SLOs[i].Name == "latency" {
			lat = &r.SLOs[i]
		}
	}
	if lat == nil {
		t.Fatal("no latency SLO")
	}
	is(t, lat.Status, "burning")
	if r.SLOs[0].Status != "ok" {
		t.Errorf("slow successes are not an availability problem: %s", r.SLOs[0].Status)
	}
}

func TestSLONoDataAndPartialCoverage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.jsonl")
	var b strings.Builder
	for ago := time.Duration(0); ago <= 10*time.Minute; ago += time.Minute {
		fmt.Fprintf(&b, `{"time":%q,"target":"http://x/","ok":false,"elapsed_ms":5}`+"\n", sloT0.Add(-ago).Format(time.RFC3339))
	}
	os.WriteFile(path, []byte(b.String()), 0o644)
	code, r := jsonReport(t, "--history", path)
	s := r.SLOs[0]
	// every probe failed but ten minutes cannot tell a one hour burn rate: no page yet
	is(t, code, 1) // the budget is spent, which is still worth failing a CI gate for
	is(t, s.Status, "breached")
	for _, a := range s.Alerts {
		is(t, a.Firing, false)
	}
	_, r = jsonReport(t, "--history", path, "--route", "nothing-matches")
	is(t, r.SLOs[0].Status, "no_data")
	is(t, r.Verdict, "no_data")
}

func TestSLOPrettyIsQuietAndRespectsASCII(t *testing.T) {
	f := probeFile(t, func(ago time.Duration) (bool, float64) { return ago > 30*time.Minute, 20 })
	_, out, _ := runSLOArgs(t, "--history", f)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.Contains(lines[0], "Budget is burning fast") {
		t.Errorf("first line is the verdict: %q", lines[0])
	}
	contains(t, out, "Next:")
	contains(t, out, "setura history")
	contains(t, out, "99.9% over 30d")
	contains(t, out, "burn")
	for _, r := range out {
		if r > 127 {
			t.Fatalf("--ascii output has %q:\n%s", r, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("escape codes in plain output")
	}
	// NO_COLOR: the unicode mode has glyphs but no colour
	u := newUI(true, termOptions{}, func(k string) string {
		if k == "NO_COLOR" {
			return "1"
		}
		return ""
	})
	var rep SLOReport
	_, jout, _ := runSLOArgs(t, "--history", f, "--format", "json")
	json.Unmarshal([]byte(jout), &rep)
	pretty := u.SLOPretty(&rep)
	if strings.Contains(pretty, "\x1b") || !strings.Contains(pretty, "✗") {
		t.Errorf("NO_COLOR rendering:\n%q", pretty)
	}
	// healthy report has no Next hint
	g := probeFile(t, func(time.Duration) (bool, float64) { return true, 20 })
	_, ok, _ := runSLOArgs(t, "--history", g)
	if strings.Contains(ok, "Next:") || !strings.Contains(strings.Split(strings.TrimSpace(ok), "\n")[0], "Within budget") {
		t.Errorf("healthy output:\n%s", ok)
	}
}

func TestHistorySLOFlag(t *testing.T) {
	f := probeFile(t, func(ago time.Duration) (bool, float64) { return ago > 30*time.Minute, 20 })
	cfg := filepath.Join(t.TempDir(), "slo.json")
	os.WriteFile(cfg, []byte(`{"slos":[{"name":"orders","type":"availability","objective":99.5,"window":"7d","route":"orders"}]}`), 0o644)
	old := sloNow
	sloNow = func() time.Time { return sloT0 }
	defer func() { sloNow = old }()
	var out, errb strings.Builder
	code, err := runHistory(newFlagSet("history", &errb), []string{f, "--slo", "--slo-config", cfg, "--format", "json"}, &out, &errb, asciiUI())
	if err != nil || code != 1 {
		t.Fatalf("code %d err %v %s", code, err, errb.String())
	}
	var r SLOReport
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatal(err)
	}
	is(t, r.SLOs[0].Name, "orders")
	is(t, r.SLOs[0].Objective, 99.5)
	is(t, r.SLOs[0].Status, "burning")
}

// ---- gateway metrics source ----

func metricsText(total5xx, total2xx int, fast250, count int) string {
	return fmt.Sprintf(`# HELP setura_gateway_route_requests_total Requests per route and status class.
# TYPE setura_gateway_route_requests_total counter
setura_gateway_route_requests_total{route="t/orders",code="2xx"} %d
setura_gateway_route_requests_total{route="t/orders",code="5xx"} %d
setura_gateway_route_requests_total{route="t/other",code="5xx"} 7
# TYPE setura_gateway_request_duration_seconds histogram
setura_gateway_request_duration_seconds_bucket{route="t/orders",le="0.1"} %d # {trace_id="abc"} 0.05 1700000000.000
setura_gateway_request_duration_seconds_bucket{route="t/orders",le="0.25"} %d
setura_gateway_request_duration_seconds_bucket{route="t/orders",le="0.5"} %d
setura_gateway_request_duration_seconds_bucket{route="t/orders",le="+Inf"} %d
setura_gateway_request_duration_seconds_sum{route="t/orders"} 10
setura_gateway_request_duration_seconds_count{route="t/orders"} %d
`, total2xx, total5xx, fast250/2, fast250, fast250, count, count)
}

type sloGateway struct {
	srv  *httptest.Server
	body atomic.Value
	auth atomic.Value
}

func newSLOGateway(t *testing.T) *sloGateway {
	g := &sloGateway{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.auth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, g.body.Load().(string))
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *sloGateway) addr() string { return strings.TrimPrefix(g.srv.URL, "http://") }

func runAt(t *testing.T, now time.Time, args ...string) *SLOReport {
	t.Helper()
	old := sloNow
	sloNow = func() time.Time { return now }
	defer func() { sloNow = old }()
	var out, errb strings.Builder
	_, err := runSLO(newFlagSet("slo", &errb), append(args, "--format", "json", "--fail-on", "never"), &out, &errb, asciiUI())
	if err != nil {
		t.Fatalf("%v %s", err, errb.String())
	}
	var r SLOReport
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	return &r
}

func TestSLOFromGatewayMetricsAcrossRuns(t *testing.T) {
	t.Setenv("SETURA_ADMIN_TOKEN", "tok")
	g := newSLOGateway(t)
	state := filepath.Join(t.TempDir(), "slo.jsonl")
	cfg := filepath.Join(t.TempDir(), "slo.json")
	os.WriteFile(cfg, []byte(`{"slos":[{"name":"avail","type":"availability","objective":99.9,"route":"orders"},{"name":"fast","type":"latency","objective":99,"threshold_ms":300,"route":"orders"}]}`), 0o644)

	g.body.Store(metricsText(0, 1000, 1000, 1000))
	r := runAt(t, sloT0.Add(-time.Hour), "--admin", g.addr(), "--config", cfg, "--state", state)
	is(t, g.auth.Load().(string), "Bearer tok")
	is(t, r.Verdict, "no_data") // one sample: nothing to difference yet
	is(t, r.SLOs[0].SLI == nil, true)

	// An hour later half of the new requests failed and half were slow.
	g.body.Store(metricsText(500, 1500, 1500, 2000))
	r = runAt(t, sloT0, "--admin", g.addr(), "--config", cfg, "--state", state)
	a, l := r.SLOs[0], r.SLOs[1]
	is(t, a.Status, "burning")
	is(t, a.Compliance.Total, 1000.0)
	is(t, a.Compliance.Bad, 500.0)
	if a.Alerts[0].LongBurn == nil || *a.Alerts[0].LongBurn < 400 {
		t.Errorf("1h burn %+v", a.Alerts[0])
	}
	// 300 ms is measured at the 250 ms bucket: 500 of the new 1000 fell outside it
	is(t, l.Status, "burning")
	is(t, l.MeasuredAtMS, 250.0)
	is(t, l.Compliance.Bad, 500.0)
	// the state file holds both runs, per SLO
	b, _ := os.ReadFile(state)
	is(t, strings.Count(string(b), "\n"), 4)

	// a restarted gateway starts its counters again: the new value counts as the delta
	g.body.Store(metricsText(0, 10, 10, 10))
	r = runAt(t, sloT0.Add(30*time.Minute), "--admin", g.addr(), "--config", cfg, "--state", state)
	if r.SLOs[0].Compliance.Total != 1010 || r.SLOs[0].Compliance.Bad != 500 {
		t.Errorf("after restart: %+v", r.SLOs[0].Compliance)
	}
}

func TestSLOGatewayUnreachableIsAnError(t *testing.T) {
	var errb strings.Builder
	var out strings.Builder
	_, err := runSLO(newFlagSet("slo", &errb), []string{"--admin", "127.0.0.1:1"}, &out, &errb, asciiUI())
	if err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("err %v", err)
	}
}

func TestSLOFlagErrors(t *testing.T) {
	for _, args := range [][]string{{"--format", "xml"}, {"--fail-on", "sometimes"}, {"extra"}, {"--objective", "100", "--history", "x"}} {
		var errb, out strings.Builder
		code, _ := runSLO(newFlagSet("slo", &errb), args, &out, &errb, asciiUI())
		if code != 2 && !(len(args) == 4) {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

func TestParsePromHandlesExemplarsAndEscapes(t *testing.T) {
	in := "# TYPE x counter\n" +
		`x_total{route="a\"b",code="2xx"} 5` + "\n" +
		`h_bucket{route="r",le="0.1"} 3 # {trace_id="t"} 0.05 1700000000.000` + "\n" +
		"plain 2\nbroken line\n"
	ss, err := ParseProm(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	is(t, len(ss), 3)
	is(t, ss[0].labels["route"], `a"b`)
	is(t, ss[1].val, 3.0)
	is(t, ss[2].name, "plain")
}
