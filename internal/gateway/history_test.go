package gateway

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func seriesByName(series []map[string]any) map[string][]float64 {
	out := map[string][]float64{}
	for _, s := range series {
		out[s["name"].(string)] = s["points"].([]float64)
	}
	return out
}

func TestHistoryRingRequestsErrorsAndP95(t *testing.T) {
	h := newHistory()
	// Second 1: 20 requests, 2 server errors, 18 fast and 2 slow: p95 falls in the slow bucket.
	for i := 0; i < 18; i++ {
		h.observe("t/r", 200, 800*time.Microsecond)
	}
	h.observe("t/r", 500, 300*time.Millisecond)
	h.observe("t/r", 503, 300*time.Millisecond)
	h.sample()
	// Second 2: 19 fast and 1 slow: p95 stays in the fast bucket.
	for i := 0; i < 19; i++ {
		h.observe("t/r", 404, 800*time.Microsecond) // 4xx is not a server error
	}
	h.observe("t/r", 200, 300*time.Millisecond)
	h.sample()
	h.sample() // an idle second is a zero point, not a gap

	got := seriesByName(h.series())
	if g := got["t/r requests"]; len(g) != 3 || g[0] != 20 || g[1] != 20 || g[2] != 0 {
		t.Errorf("requests = %v", g)
	}
	if g := got["t/r error rate"]; len(g) != 3 || g[0] != 10 || g[1] != 0 || g[2] != 0 {
		t.Errorf("error rate = %v, want 10%% then 0", g)
	}
	if g := got["t/r p95 latency"]; len(g) != 3 || g[0] != 500 || g[1] != 1 || g[2] != 0 {
		t.Errorf("p95 = %v, want the 500ms bucket then the 1ms bucket", g)
	}
	for _, s := range h.series() {
		if s["unit"] == "" || s["name"] == "" {
			t.Errorf("series %v lacks name or unit", s)
		}
	}
}

func TestHistoryRingKeepsOnlyTheLastWindowAndForgetsIdleRoutes(t *testing.T) {
	h := newHistory()
	for i := 1; i <= historySize+30; i++ {
		h.observe("busy", 200, time.Millisecond)
		h.sample()
	}
	pts := seriesByName(h.series())["busy requests"]
	if len(pts) != historySize {
		t.Fatalf("%d points kept, want %d", len(pts), historySize)
	}
	h.observe("once", 200, time.Millisecond)
	h.sample()
	for i := 0; i < historySize; i++ {
		h.sample()
	}
	if _, ok := h.routes["once"]; ok {
		t.Error("a route silent for the whole window must be forgotten")
	}
}

func TestHistoryDrawsOnlyTheBusiestRoutes(t *testing.T) {
	h := newHistory()
	for i, name := range []string{"a", "b", "c", "d", "e"} {
		for j := 0; j <= i; j++ {
			h.observe(name, 200, time.Millisecond)
		}
	}
	h.sample()
	series := h.series()
	if len(series) != historyMaxRoutes*3 {
		t.Fatalf("%d series, want %d", len(series), historyMaxRoutes*3)
	}
	names := seriesByName(series)
	for _, want := range []string{"e requests", "d requests", "c requests"} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	if (&history{routes: map[string]*routeHist{}}).series() != nil {
		t.Error("no samples, no series")
	}
	h.observe("", 200, time.Millisecond) // unmatched requests are not a route
	if _, ok := h.routes[""]; ok {
		t.Error("empty route recorded")
	}
}

func TestHistorySamplerRunsAndStopsWithTheServer(t *testing.T) {
	h := newHistory()
	h.start(5 * time.Millisecond)
	h.observe("r", 200, time.Millisecond)
	eventually(t, func() bool { return len(h.series()) > 0 })
	h.close()
	h.close() // idempotent
	h.start(time.Millisecond)
	if h.stop != nil && h.done == nil {
		t.Error("restart after close")
	}
}

func TestServerUIStateCarriesHistory(t *testing.T) {
	withBuilder(t)
	up := newUpstream(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": up.addr()}),
		func(o *Options) { o.HistoryInterval = -1 })
	for i := 0; i < 5; i++ {
		get(t, s, "x.test", "/")
	}
	get(t, s, "x.test", "/") // matched
	s.hist.sample()
	st, ok := s.UIState().(map[string]any)
	if !ok {
		t.Fatal("state is not a map")
	}
	hs, ok := st["history"].(map[string]any)
	if !ok {
		t.Fatalf("state has no history section: %v", st)
	}
	raw, _ := json.Marshal(hs)
	var doc struct {
		Series []struct {
			Name   string
			Unit   string
			Points []float64
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Series) != 3 {
		t.Fatalf("history = %s (%v)", raw, err)
	}
	if doc.Series[0].Name != "t/r requests" || doc.Series[0].Unit != "req/s" || doc.Series[0].Points[0] != 6 {
		t.Errorf("first series = %+v, want 6 requests in the first second", doc.Series[0])
	}
}

func TestGatewayUISnapshotCarriesGrantsAndNamespacedKeys(t *testing.T) {
	seen := withBuilder(t)
	cfgJSON := `{
	  "schema": "setura.route-specs/v1", "namespace": "t",
	  "resources": {
	    "gateways.gateway.networking.k8s.io/gw": {"gatewayClassName": "setura", "listeners": [{"name": "web", "protocol": "HTTP", "port": 8080}]},
	    "httproutes.gateway.networking.k8s.io/other/r": {"parentRefs": [{"name": "gw", "namespace": "t"}], "rules": [{"backendRefs": [{"name": "b", "port": 80}]}]},
	    "grpcroutes.gateway.networking.k8s.io/g": {"parentRefs": [{"name": "gw"}], "rules": [{"backendRefs": [{"name": "b", "port": 80}]}]}
	  },
	  "referenceGrants": [{"metadata": {"namespace": "t"}, "spec": {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "other"}], "to": [{"group": "", "kind": "Service", "name": "b"}]}}],
	  "backends": {"t/b:80": "127.0.0.1:1", "other/b:80": "127.0.0.1:1"}
	}`
	cfg, err := ParseConfig([]byte(cfgJSON), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off", HistoryInterval: -1})
	t.Cleanup(s.Close)
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	if s.UIState() == nil {
		t.Fatal("no state")
	}
	var snapDoc struct {
		Resources       map[string]json.RawMessage
		ReferenceGrants []struct {
			Metadata struct{ Namespace string }
			Spec     struct {
				From []struct{ Group, Kind, Namespace string }
				To   []struct{ Group, Kind, Name string }
			}
		}
	}
	if err := json.Unmarshal(seen.Snapshot, &snapDoc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"gateways.gateway.networking.k8s.io/gw", "httproutes.gateway.networking.k8s.io/other/r", "grpcroutes.gateway.networking.k8s.io/g"} {
		if _, ok := snapDoc.Resources[key]; !ok {
			t.Errorf("snapshot lacks %s: %s", key, seen.Snapshot)
		}
	}
	if len(snapDoc.ReferenceGrants) != 1 || snapDoc.ReferenceGrants[0].Metadata.Namespace != "t" ||
		snapDoc.ReferenceGrants[0].Spec.From[0].Kind != "HTTPRoute" || snapDoc.ReferenceGrants[0].Spec.To[0].Name != "b" {
		t.Errorf("grants in snapshot: %+v (raw %s)", snapDoc.ReferenceGrants, seen.Snapshot)
	}
	if !strings.Contains(string(seen.Snapshot), `"kind":"HTTPRoute"`) {
		t.Errorf("grant fields must be lower-camel JSON: %s", seen.Snapshot)
	}
	// A source that supplied no grants does not claim to have captured any.
	cfg2, _ := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": "127.0.0.1:1"}), "")
	if err := s.Apply(&Loaded{Config: cfg2, Hash: "h2"}); err != nil {
		t.Fatal(err)
	}
	s.UIState()
	if strings.Contains(string(seen.Snapshot), "referenceGrants") {
		t.Errorf("grants claimed without being captured: %s", seen.Snapshot)
	}
}

// ---- command-line wiring ----

func parseRunFlags(t *testing.T, args ...string) (*runFlags, error) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	var rf runFlags
	addRunFlags(fs, &rf)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return &rf, nil
}

func TestRunFlagsLeaveUnsetResilienceOptionsToTheConfigFile(t *testing.T) {
	rf, err := parseRunFlags(t, "--access-log", "off")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rf.finish(&bytes.Buffer{}, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	r := rf.opts.Resilience
	if r.RetryBudgetPercent != 0 || r.OutlierFailures != 0 || r.OutlierBaseEject != 0 || r.HealthInterval != 0 || r.Circuit != (CircuitOptions{}) {
		t.Errorf("unset flags must stay zero so the file block can fill them: %+v", r)
	}
	if got := newResilience(r).opt(); got.RetryBudgetPercent != 20 || got.OutlierFailures != 5 || got.HealthInterval != 5*time.Second {
		t.Errorf("built-in defaults lost: %+v", got)
	}
}

func TestRunFlagsMapExplicitValues(t *testing.T) {
	dir := t.TempDir()
	rf, err := parseRunFlags(t, "--access-log", filepath.Join(dir, "a.log"), "--access-log-max-size", "1k", "--access-log-keep", "2", "--access-log-gzip",
		"--retry-budget", "40", "--retry-cross-backend", "--retry-jitter", "0.25", "--outlier-failures", "0",
		"--cb-max-requests", "7", "--cb-max-pending", "3", "--cb-max-connections", "9", "--cb-failures", "4", "--cb-open-for", "9s", "--cb-probes", "2",
		"--rate-limit", "40/s", "--rate-limit-share", "4", "--trusted-proxies", "10.0.0.0/8", "--otlp-retries", "-1")
	if err != nil {
		t.Fatal(err)
	}
	closeLog, err := rf.finish(&bytes.Buffer{}, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLog()
	r := rf.opts.Resilience
	if r.RetryBudgetPercent != 40 || !r.RetryCrossBackend || r.RetryJitter != 0.25 || r.OutlierFailures != -1 {
		t.Errorf("retry/outlier = %+v", r)
	}
	if r.Circuit != (CircuitOptions{MaxRequests: 7, MaxPending: 3, MaxConnections: 9, FailureThreshold: 4, OpenFor: 9 * time.Second, HalfOpenProbes: 2}) {
		t.Errorf("circuit = %+v", r.Circuit)
	}
	rot, ok := rf.opts.AccessLog.(*rotatingFile)
	if !ok || rot.o.MaxSize != 1024 || rot.o.Keep != 2 || !rot.o.Gzip {
		t.Errorf("access log writer = %#v", rf.opts.AccessLog)
	}
	if rf.opts.Obs.RateLimit.Share != 4 || len(rf.opts.Obs.TrustedProxies) != 1 || rf.opts.Obs.OTLP.Retries != -1 {
		t.Errorf("obs = %+v", rf.opts.Obs)
	}
}

func TestRunFlagsRejectBadValues(t *testing.T) {
	for _, args := range [][]string{{"--retry-budget", "101"}, {"--retry-jitter", "2"}, {"--access-log-max-size", "lots"}, {"--access-log-keep", "-1"},
		{"--trusted-proxies", "xyz"}, {"--rate-limit-share", "-2"}, {"--rate-limit", "5/s", "--rate-limit-share", "-1"}} {
		rf, err := parseRunFlags(t, append([]string{"--access-log", "off"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rf.finish(&bytes.Buffer{}, &bytes.Buffer{}, nil); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestAccessLogRotatesOnSIGHUP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	rf, err := parseRunFlags(t, "--access-log", path)
	if err != nil {
		t.Fatal(err)
	}
	closeLog, err := rf.finish(&bytes.Buffer{}, &bytes.Buffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLog()
	w := rf.opts.AccessLog
	w.Write([]byte("before\n"))
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Skip("cannot signal ourselves:", err)
	}
	eventually(t, func() bool { m, _ := filepath.Glob(path + ".*"); return len(m) == 1 })
	w.Write([]byte("after\n"))
	if b, _ := os.ReadFile(path); string(b) != "after\n" {
		t.Errorf("current file = %q", b)
	}
}

func TestUsageMentionsNewFlags(t *testing.T) {
	for _, f := range []string{"--access-log-max-size", "--access-log-keep", "--access-log-gzip", "--trusted-proxies", "--rate-limit-share",
		"--retry-cross-backend", "--retry-jitter", "--cb-max-requests", "--cb-failures", "--otlp-retries", "SIGHUP", "resilience"} {
		if !strings.Contains(usage, f) {
			t.Errorf("usage lacks %s", f)
		}
	}
}
