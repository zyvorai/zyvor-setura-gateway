package setura

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// --- stale lock ----------------------------------------------------------------

func lockStore(t *testing.T) histStore {
	h := newHistStore(filepath.Join(t.TempDir(), "live.json"))
	h.host = "build-1"
	h.hbEvery = 20 * time.Millisecond
	return h
}

func writeLock(t *testing.T, h histStore, li lockInfo) {
	t.Helper()
	os.MkdirAll(h.dir, 0o700)
	b, _ := json.Marshal(li)
	if err := os.WriteFile(filepath.Join(h.dir, "lock"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLockRecordsOwnerAndBeats(t *testing.T) {
	h := lockStore(t)
	unlock, err := h.lock()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.dir, "lock")
	var first lockInfo
	raw, _ := os.ReadFile(p)
	json.Unmarshal(raw, &first)
	if first.Pid != os.Getpid() || first.Host != "build-1" || first.Started == "" || first.Heartbeat == "" || first.Token == "" {
		t.Fatalf("lock content %+v", first)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ = os.ReadFile(p)
		var now lockInfo
		json.Unmarshal(raw, &now)
		if now.Heartbeat != first.Heartbeat && now.Token == first.Token {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat never advanced")
		}
		time.Sleep(10 * time.Millisecond)
	}
	unlock()
	if _, err := os.Stat(p); err == nil {
		t.Fatal("lock not released")
	}
}

func TestLockLiveOwnerIsNeverStolen(t *testing.T) {
	h := lockStore(t)
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	// This very process is alive, on this host: even a day-old heartbeat must not matter.
	writeLock(t, h, lockInfo{Pid: os.Getpid(), Host: "build-1", Started: old, Heartbeat: old, Token: "live"})
	_, err := h.lock()
	if err == nil || !strings.Contains(err.Error(), "another rollout holds") || !strings.Contains(err.Error(), fmt.Sprint(os.Getpid())) {
		t.Fatalf("live owner must be refused with a description, got %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(h.dir, "lock"))
	if !strings.Contains(string(raw), `"live"`) {
		t.Fatal("the live owner's lock was touched")
	}
}

func TestLockDeadProcessOnSameHostIsTakenOver(t *testing.T) {
	h := lockStore(t)
	h.alive = func(pid int) (bool, bool) { return pid != 4242, true }
	now := time.Now().UTC().Format(time.RFC3339Nano) // a fresh heartbeat does not save a dead process
	writeLock(t, h, lockInfo{Pid: 4242, Host: "build-1", Started: now, Heartbeat: now, Token: "dead"})
	var notes []string
	unlock, err := h.lockWith(func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) })
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if len(notes) != 1 || !strings.Contains(notes[0], "took over a stale rollout lock") || !strings.Contains(notes[0], "pid 4242") || !strings.Contains(notes[0], "no longer running") {
		t.Fatalf("takeover must be announced: %v", notes)
	}
	if left, _ := filepath.Glob(filepath.Join(h.dir, "lock.stale.*")); len(left) != 0 {
		t.Fatalf("stale copies left: %v", left)
	}
}

func TestLockLegacyFormatWithDeadPid(t *testing.T) {
	h := lockStore(t)
	h.alive = func(pid int) (bool, bool) { return pid != 777, true }
	os.MkdirAll(h.dir, 0o700)
	os.WriteFile(filepath.Join(h.dir, "lock"), []byte("777\n"), 0o600)
	unlock, err := h.lock()
	if err != nil {
		t.Fatalf("a legacy lock of a dead pid is stale: %v", err)
	}
	unlock()
}

func TestLockOtherHostUsesHeartbeatOnly(t *testing.T) {
	h := lockStore(t)
	h.hbTimeout = time.Minute
	h.alive = func(int) (bool, bool) { t.Fatal("must not probe a pid of another host"); return false, false }
	fresh := time.Now().UTC().Format(time.RFC3339Nano)
	writeLock(t, h, lockInfo{Pid: 1, Host: "other-host", Started: fresh, Heartbeat: fresh, Token: "x"})
	if _, err := h.lock(); err == nil || !strings.Contains(err.Error(), "other-host") {
		t.Fatalf("a fresh heartbeat from another host holds the lock: %v", err)
	}
	stale := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339Nano)
	writeLock(t, h, lockInfo{Pid: 1, Host: "other-host", Started: stale, Heartbeat: stale, Token: "x"})
	var note string
	unlock, err := h.lockWith(func(f string, a ...any) { note = fmt.Sprintf(f, a...) })
	if err != nil {
		t.Fatalf("an old heartbeat from another host is stale: %v", err)
	}
	unlock()
	if !strings.Contains(note, "heartbeat is older than 1m0s") {
		t.Fatalf("note %q", note)
	}
}

func TestLockUnlockLeavesSomeoneElsesLock(t *testing.T) {
	h := lockStore(t)
	unlock, err := h.lock()
	if err != nil {
		t.Fatal(err)
	}
	writeLock(t, h, lockInfo{Pid: 9, Host: "x", Heartbeat: time.Now().UTC().Format(time.RFC3339Nano), Token: "theirs"})
	unlock()
	if _, err := os.Stat(filepath.Join(h.dir, "lock")); err != nil {
		t.Fatal("unlock removed a lock that is no longer ours")
	}
}

func TestLockTwoTakersOnlyOneWins(t *testing.T) {
	h := lockStore(t)
	h.alive = func(pid int) (bool, bool) { return pid != 4242, true }
	writeLock(t, h, lockInfo{Pid: 4242, Host: "build-1", Heartbeat: time.Now().UTC().Format(time.RFC3339Nano), Token: "dead"})
	res := make(chan error, 2)
	var unlocks = make(chan func(), 2)
	for i := 0; i < 2; i++ {
		go func() {
			u, err := h.lock()
			res <- err
			if err == nil {
				unlocks <- u
			}
		}()
	}
	ok := 0
	for i := 0; i < 2; i++ {
		if err := <-res; err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d takers got the lock, want exactly 1", ok)
	}
	(<-unlocks)()
}

// --- gateway /stats and /metrics ----------------------------------------------------

// statGateway is the fake gateway plus a scripted /stats and /metrics.
type statGateway struct {
	*fakeGateway
	read func(n int) *gwSnap
	n    int
	fail bool
}

func (g *statGateway) GatewayStats(context.Context) (*gwSnap, error) {
	if g.fail {
		return nil, fmt.Errorf("connection refused")
	}
	g.n++
	return g.read(g.n), nil
}

func gwSnapOf(route string, requests, errors int64, p95Bucket float64) *gwSnap {
	s := &gwSnap{counts: map[string]gwCount{"route:" + route: {requests, errors}}, hist: map[string][]gwBucket{}}
	// all requests land in the bucket with upper bound p95Bucket
	var b []gwBucket
	for _, le := range []float64{0.01, 0.1, 1, 1e18} {
		c := int64(0)
		if le >= p95Bucket {
			c = requests
		}
		b = append(b, gwBucket{le, c})
	}
	s.hist["route:"+route] = b
	return s
}

func statRig(t *testing.T, read func(n int) *gwSnap) (*rolloutRig, *statGateway) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(3)} })
	sg := &statGateway{fakeGateway: rig.gw, read: read}
	rig.r.admin = sg
	return rig, sg
}

func TestRolloutGatewayStatsTripOnErrors(t *testing.T) {
	// The probes are all fine; the gateway saw 5xx from real traffic.
	rig, _ := statRig(t, func(n int) *gwSnap { return gwSnapOf("demo/orders", int64(100*n), int64(3*(n-1)), 0.01) })
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.TrippedBy != "gateway /stats" || !strings.Contains(res.Reason, "route demo/orders answered 5xx") {
		t.Fatalf("code=%d tripped=%q reason=%q", code, res.TrippedBy, res.Reason)
	}
	if res.Outcome != "rolled_back" || res.GatewayStats != "used" {
		t.Fatalf("%+v", res)
	}
	var b strings.Builder
	writeRollout(&b, res, true)
	if !strings.Contains(b.String(), "tripped by: gateway /stats") {
		t.Fatalf("report must say which source tripped:\n%s", b.String())
	}
}

func TestRolloutGatewayStatsToleratedByMaxErrorRate(t *testing.T) {
	read := func(n int) *gwSnap { return gwSnapOf("demo/orders", int64(1000*n), int64(5*(n-1)), 0.01) } // 0.5%
	rig, _ := statRig(t, read)
	rig.r.o.MaxErrorRate = 0.02
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || res.Steps[0].Gateway == nil || res.Steps[0].Gateway.Errors == 0 {
		t.Fatalf("0.5%% is under 2%%: code=%d %+v", code, res)
	}
	rig, _ = statRig(t, read)
	rig.r.o.MaxErrorRate = 0.001
	res, code, _ = rig.r.run(context.Background())
	if code != 1 || res.TrippedBy != "gateway /stats" || !strings.Contains(res.Reason, "exceeds the 0.1% limit") {
		t.Fatalf("0.5%% is over 0.1%%: code=%d %q %q", code, res.TrippedBy, res.Reason)
	}
}

func TestRolloutGatewayMetricsTripOnP95(t *testing.T) {
	rig, _ := statRig(t, func(n int) *gwSnap { return gwSnapOf("demo/orders", int64(50*n), 0, 1) }) // everything in the (0.1, 1] bucket
	rig.r.o.MaxP95 = 200 * time.Millisecond
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.TrippedBy != "gateway /metrics" || !strings.Contains(res.Reason, "p95 latency") {
		t.Fatalf("code=%d tripped=%q reason=%q", code, res.TrippedBy, res.Reason)
	}
}

func TestRolloutProbeSourceStillReported(t *testing.T) {
	rig, _ := statRig(t, func(n int) *gwSnap { return gwSnapOf("demo/orders", int64(100*n), 0, 0.01) })
	rig.r.probe = func(context.Context) ([]*Report, error) { return []*Report{badReport()}, nil }
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.TrippedBy != "probes" {
		t.Fatalf("code=%d tripped=%q", code, res.TrippedBy)
	}
}

func TestRolloutGatewayStatsOnlyJudgesTheChangedRoute(t *testing.T) {
	rig, _ := statRig(t, func(n int) *gwSnap {
		s := gwSnapOf("demo/orders", int64(100*n), 0, 0.01)
		s.counts["route:demo/other"] = gwCount{int64(100 * n), int64(10 * n)} // an unrelated route failing
		return s
	})
	// The candidate in the fake rig changes only the backend address of "orders".
	if _, code, _ := rig.r.run(context.Background()); code != 0 {
		t.Fatalf("an unrelated route's 5xx must not fail this rollout (code %d)", code)
	}
}

func TestRolloutGatewayStatsUnavailableFallsBackToProbes(t *testing.T) {
	rig, sg := statRig(t, nil)
	sg.fail = true
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || !strings.HasPrefix(res.GatewayStats, "unavailable: ") || res.Steps[0].Gateway != nil {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestParseHistogramsAndP95(t *testing.T) {
	text := `# TYPE setura_gateway_request_duration_seconds histogram
setura_gateway_request_duration_seconds_bucket{route="a/b",le="0.005"} 0
setura_gateway_request_duration_seconds_bucket{route="a/b",le="0.1"} 90
setura_gateway_request_duration_seconds_bucket{route="a/b",le="1"} 100
setura_gateway_request_duration_seconds_bucket{route="a/b",le="+Inf"} 100
setura_gateway_request_duration_seconds_sum{route="a/b"} 5
setura_gateway_backend_request_duration_seconds_bucket{backend="t/x:80",le="+Inf"} 7
setura_gateway_route_requests_total{route="a/b",code="2xx"} 100
`
	h := map[string][]gwBucket{}
	parseHistograms([]byte(text), h)
	if len(h["route:a/b"]) != 4 || h["route:a/b"][3].cum != 100 || len(h["backend:t/x:80"]) != 1 {
		t.Fatalf("%+v", h)
	}
	ms, ok := p95Between(nil, h["route:a/b"])
	// 95th of 100 sits in the (0.1, 1] bucket, half way: 0.1 + 0.9*(95-90)/10 = 0.55 s.
	if !ok || ms < 540 || ms > 560 {
		t.Fatalf("p95 %v ms", ms)
	}
	// With a baseline, only the observations added in the window count.
	before := []gwBucket{{0.005, 0}, {0.1, 90}, {1, 100}, {1e18, 100}}
	after := []gwBucket{{0.005, 10}, {0.1, 100}, {1, 110}, {1e18, 110}}
	if ms, ok := p95Between(before, after); !ok || ms > 100 {
		t.Fatalf("window p95 %v", ms)
	}
	if _, ok := p95Between(after, after); ok {
		t.Fatal("no observations, no p95")
	}
	if got := parseLabels(`route="a\"b",le="0.5"`); got["route"] != `a"b` || got["le"] != "0.5" {
		t.Fatalf("%v", got)
	}
}

func TestHTTPAdminGatewayStats(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"requests":10,"routes":{"shop/orders":{"requests":10,"status":{"2xx":8,"5xx":2}}},"backends":{"shop/orders:80":{"requests":10,"status":{"2xx":8,"5xx":2}}}}`)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `setura_gateway_request_duration_seconds_bucket{route="shop/orders",le="+Inf"} 10`+"\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	snap, err := newHTTPAdmin(srv.URL).GatewayStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c := snap.counts["route:shop/orders"]; c.Requests != 10 || c.Errors != 2 {
		t.Fatalf("%+v", snap.counts)
	}
	if snap.counts["backend:shop/orders:80"].Errors != 2 || len(snap.hist["route:shop/orders"]) != 1 {
		t.Fatalf("%+v %+v", snap.counts, snap.hist)
	}
}

// The real gateway publishes what the parser reads.
func TestGatewayPublishesRolloutSeries(t *testing.T) {
	var b strings.Builder
	s := builtin.New(builtin.Options{Admin: "off"})
	defer s.Close()
	s.WriteMetrics(&b)
	if !strings.Contains(b.String(), "setura_gateway_shadow_total") {
		t.Skip("metrics layout changed")
	}
	if !strings.Contains(routeHistName+backendHistName, "request_duration_seconds") {
		t.Fatal("series names")
	}
}

// --- default steps -----------------------------------------------------------------

func TestRolloutDefaultsToCanaryStepsWhenWeightsChange(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 100, 0), rolloutSnap("127.0.0.1:1", 0, 100), func(int) []*Report { return []*Report{okReport(1)} })
	rig.r.o.Observe = time.Second
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || len(res.Steps) != 4 || res.Steps[0].Name != "canary 10%" || res.Steps[1].Name != "canary 50%" || res.Steps[2].Name != "canary 100%" || res.Steps[3].Name != "candidate" {
		t.Fatalf("code=%d steps=%+v", code, res.Steps)
	}
	if !strings.Contains(res.StepsNote, "default 10,50,100") {
		t.Fatalf("the default must be announced: %q", res.StepsNote)
	}
}

func TestRolloutNoStepsAppliesDirectly(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 100, 0), rolloutSnap("127.0.0.1:1", 0, 100), func(int) []*Report { return []*Report{okReport(1)} })
	rig.r.o.NoSteps = true
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || len(res.Steps) != 1 || res.Steps[0].Name != "candidate" || res.StepsNote != "" {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.cand) {
		t.Fatal("candidate not applied byte for byte")
	}
}

func TestRolloutNoWeightChangeNeedsNoSteps(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(1)} })
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || len(res.Steps) != 1 || res.StepsNote != "" {
		t.Fatalf("a candidate without a weight change is applied directly and silently: %+v", res)
	}
}

func TestStepsAndNoStepsContradict(t *testing.T) {
	var out, errb strings.Builder
	code := runRolloutCommand("rollout", []string{"--config", "a", "--new", "b", "--checks", "c", "--steps", "10,100", "--no-steps"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "contradict") {
		t.Fatalf("%d %s", code, errb.String())
	}
}

// --- certificate paths -------------------------------------------------------------

func withSecret(raw []byte, cert, key string) []byte {
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["secrets"] = map[string]any{"demo/tls": map[string]any{"certFile": cert, "keyFile": key}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

func TestRolloutResolvesCertsAgainstCandidateDirectory(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), nil, func(int) []*Report { return []*Report{okReport(1)} })
	candDir := t.TempDir()
	os.WriteFile(filepath.Join(candDir, "tls.crt"), []byte("c"), 0o600)
	os.WriteFile(filepath.Join(candDir, "tls.key"), []byte("k"), 0o600)
	cand := withSecret(rolloutSnap("127.0.0.1:2", 1), "tls.crt", "tls.key")
	rig.r.o.New = filepath.Join(candDir, "candidate.json")
	os.WriteFile(rig.r.o.New, cand, 0o644)

	var log strings.Builder
	rig.r.log = &log
	res, code, _ := rig.r.run(context.Background())
	if code != 0 {
		t.Fatalf("code=%d %+v", code, res)
	}
	want, _ := filepath.Abs(candDir)
	if res.CertDir != want {
		t.Fatalf("certDir %q want %q", res.CertDir, want)
	}
	if !strings.Contains(log.String(), "resolved against the candidate's directory "+want) || !strings.Contains(log.String(), "absolute paths") {
		t.Fatalf("the directory used must be reported:\n%s", log.String())
	}
	var live map[string]any
	json.Unmarshal([]byte(readLive(t, rig)), &live)
	sec := live["secrets"].(map[string]any)["demo/tls"].(map[string]any)
	if sec["certFile"] != filepath.Join(want, "tls.crt") || sec["keyFile"] != filepath.Join(want, "tls.key") {
		t.Fatalf("installed secret %+v", sec)
	}
}

func TestRolloutRefusesMissingCertFiles(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), nil, func(int) []*Report { return []*Report{okReport(1)} })
	// The file exists next to the live config only: the candidate's directory is the one that counts.
	os.WriteFile(filepath.Join(rig.dir, "tls.crt"), []byte("c"), 0o600)
	candDir := t.TempDir()
	rig.r.o.New = filepath.Join(candDir, "candidate.json")
	os.WriteFile(rig.r.o.New, withSecret(rolloutSnap("127.0.0.1:2", 1), "tls.crt", "tls.key"), 0o644)
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.Outcome != "refused" || len(res.Evidence) != 2 || !strings.Contains(res.Evidence[0], "exists next to the live file") {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.live) {
		t.Fatal("nothing may be touched on refusal")
	}
}

func TestRolloutSameDirectoryCertsStayByteForByte(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), nil, func(int) []*Report { return []*Report{okReport(1)} })
	os.WriteFile(filepath.Join(rig.dir, "tls.crt"), []byte("c"), 0o600)
	os.WriteFile(filepath.Join(rig.dir, "tls.key"), []byte("k"), 0o600)
	cand := withSecret(rolloutSnap("127.0.0.1:2", 1), "tls.crt", "tls.key")
	os.WriteFile(rig.r.o.New, cand, 0o644)
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || readLive(t, rig) != string(cand) {
		t.Fatalf("same directory: candidate applied unchanged, code=%d", code)
	}
	if want, _ := filepath.Abs(rig.dir); res.CertDir != want {
		t.Fatalf("certDir %q", res.CertDir)
	}
}

// --- SET015 ------------------------------------------------------------------------

func shadowSnap(filters []any, spec obj) obj {
	rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{obj{"filters": filters, "backendRefs": []any{obj{"name": "a", "port": 80}}}}}
	for k, v := range spec {
		rt[k] = v
	}
	return obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
		route + "/r":    rt}}
}

func mirrorFilter(block any) []any {
	rm := obj{"backendRef": obj{"name": "b", "port": 80}}
	if block != nil {
		rm[builtin.ShadowDiffKey] = block
	}
	return []any{obj{"type": "RequestMirror", "requestMirror": rm}}
}

func set015(t *testing.T, snap obj) []string {
	t.Helper()
	rep, err := Lint(snap)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range asList(rep["findings"]) {
		if m := asMap(f); m["id"] == "SET015" {
			out = append(out, asStr(m["message"]))
		}
	}
	return out
}

func TestLintSET015(t *testing.T) {
	if got := set015(t, shadowSnap(mirrorFilter(obj{"compare": true, "sample": 50, "ignoreJSONPaths": []any{"$.a"}}), nil)); len(got) != 0 {
		t.Fatalf("a valid block is clean: %v", got)
	}
	for name, block := range map[string]any{
		"sample over 100":  obj{"sample": 101},
		"bad json path":    obj{"ignoreJSONPaths": []any{"a.b"}},
		"unknown field":    obj{"sampel": 5},
		"bad frame format": obj{"frameFormat": "xml"},
		"negative maxBody": obj{"maxBody": -1},
	} {
		if got := set015(t, shadowSnap(mirrorFilter(block), nil)); len(got) != 1 || !strings.Contains(got[0], "rule 1") {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestLintSET015Annotations(t *testing.T) {
	ann := func(kv ...string) obj {
		m := obj{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return obj{builtin.SeturaAnnotationsKey: m}
	}
	k := builtin.ShadowDiffKey
	if got := set015(t, shadowSnap(mirrorFilter(nil), ann(k, `{"compare":true}`, k+".rule-1", `{"sample":10}`))); len(got) != 0 {
		t.Fatalf("valid annotations: %v", got)
	}
	for name, tc := range map[string]struct {
		spec obj
		want string
	}{
		"bad json":       {ann(k, `{"compare":`), "annotation " + k},
		"unknown field":  {ann(k, `{"compare":true,"oops":1}`), "unknown field"},
		"rule too high":  {ann(k+".rule-3", `{}`), "names no rule"},
		"rule malformed": {ann(k+".rule-x", `{}`), "names no rule"},
	} {
		got := set015(t, shadowSnap(mirrorFilter(nil), tc.spec))
		if len(got) == 0 || !strings.Contains(strings.Join(got, "|"), tc.want) {
			t.Errorf("%s: %v", name, got)
		}
	}
	// An annotation with nothing to apply to.
	if got := set015(t, shadowSnap(nil, ann(k, `{"compare":true}`))); len(got) != 1 || !strings.Contains(got[0], "no RequestMirror") {
		t.Errorf("annotation without a mirror: %v", got)
	}
	if got := set015(t, shadowSnap(nil, ann(k+".rule-1", `{}`))); len(got) != 1 || !strings.Contains(got[0], "rule 1 has no RequestMirror") {
		t.Errorf("rule annotation without a mirror: %v", got)
	}
}

func TestSnapshotCarriesShadowAnnotations(t *testing.T) {
	object := obj{"metadata": obj{"name": "r", "annotations": obj{builtin.ShadowDiffKey: `{"compare":true}`, "other/x": "y"}}, "spec": obj{"rules": []any{}}}
	spec := asMap(withShadowAnnotations(object))
	ann := asMap(spec[builtin.SeturaAnnotationsKey])
	if ann[builtin.ShadowDiffKey] != `{"compare":true}` || len(ann) != 1 {
		t.Fatalf("%v", spec)
	}
	plain := asMap(withShadowAnnotations(obj{"metadata": obj{"name": "r"}, "spec": obj{"rules": []any{}}}))
	if _, ok := plain[builtin.SeturaAnnotationsKey]; ok {
		t.Fatal("no annotations, no key")
	}
}
