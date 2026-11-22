package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// fakeClock advances virtual time instead of sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.t = c.t.Add(d)
	return nil
}

// fakeGateway plays the gateway: it "applies" whatever hash the live file has.
type fakeGateway struct {
	path     string
	gen      int64
	hash     string
	reject   func(raw []byte) string // non-empty reason rejects
	lastLoad builtin.ReloadInfo
	stuck    bool // never applies anything
	polls    int
}

func (g *fakeGateway) Status(context.Context) (*builtin.StatusDoc, error) {
	g.polls++
	if !g.stuck {
		raw, _ := os.ReadFile(g.path)
		if ld, err := (builtin.FileSource{Path: g.path}).Load(context.Background()); err == nil {
			switch {
			case ld.Hash == g.hash:
				if !g.lastLoad.OK {
					g.lastLoad = builtin.ReloadInfo{OK: true, Time: fmt.Sprint(g.polls)}
				}
			case g.reject != nil && g.reject(raw) != "":
				g.lastLoad = builtin.ReloadInfo{OK: false, Time: fmt.Sprint(g.polls), Error: g.reject(raw)}
			default:
				g.gen++
				g.hash = ld.Hash
				g.lastLoad = builtin.ReloadInfo{OK: true, Time: fmt.Sprint(g.polls)}
			}
		}
	}
	return &builtin.StatusDoc{Generation: g.gen, ConfigHash: g.hash, LastReload: g.lastLoad,
		Gateways: map[string]*builtin.GatewayStatus{"demo/dev": {Conditions: []builtin.Condition{
			{Type: "Accepted", Status: "True"}, {Type: "Programmed", Status: "True"}}}}}, nil
}

func rolloutSnap(backend string, weights ...int) []byte {
	refs := []any{}
	names := []string{"orders-v1", "orders-v2", "orders-v3"}
	for i, w := range weights {
		ref := map[string]any{"name": names[i], "port": 80}
		if w >= 0 {
			ref["weight"] = w
		}
		refs = append(refs, ref)
	}
	backends := map[string]any{}
	for _, n := range names[:len(weights)] {
		backends[n+":80"] = map[string]any{"endpoints": []any{backend}}
	}
	raw, _ := json.MarshalIndent(map[string]any{"schema": snapshotSchema, "namespace": "demo",
		"resources": map[string]any{
			"gateways.gateway.networking.k8s.io/dev": map[string]any{"gatewayClassName": "setura", "listeners": []any{
				map[string]any{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "orders.mactra.test"}}},
			"httproutes.gateway.networking.k8s.io/orders": map[string]any{
				"parentRefs": []any{map[string]any{"name": "dev", "sectionName": "web"}},
				"hostnames":  []any{"orders.mactra.test"},
				"rules": []any{map[string]any{
					"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/checkout"}}},
					"backendRefs": refs}}}},
		"backends": backends}, "", "  ")
	return raw
}

type rolloutRig struct {
	r     *rollout
	gw    *fakeGateway
	clock *fakeClock
	dir   string
	live  []byte
	cand  []byte
	calls int
}

func newRig(t *testing.T, live, cand []byte, probe func(call int) []*Report) *rolloutRig {
	t.Helper()
	dir := t.TempDir()
	rig := &rolloutRig{dir: dir, live: live, cand: cand, clock: &fakeClock{t: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}}
	cfg, nw, chk := filepath.Join(dir, "live.json"), filepath.Join(dir, "candidate.json"), filepath.Join(dir, "checks.json")
	os.WriteFile(cfg, live, 0o644)
	os.WriteFile(nw, cand, 0o644)
	os.WriteFile(chk, []byte(`[{"url":"http://x.test/"}]`), 0o644)
	rig.gw = &fakeGateway{path: cfg}
	rig.gw.Status(context.Background()) // serve the live config at generation 1
	rig.r = &rollout{
		o: rolloutOptions{Config: cfg, New: nw, Checks: chk, Observe: 5 * time.Second, ProbeInterval: time.Second,
			ApplyTimeout: 3 * time.Second, ApplyPoll: 100 * time.Millisecond, RollbackOnFail: true, Keep: 3},
		clock: rig.clock, admin: rig.gw, lint: gatewayLint, hist: newHistStore(cfg),
		probe: func(context.Context) ([]*Report, error) { rig.calls++; return probe(rig.calls), nil },
	}
	return rig
}

func okReport(ms float64) *Report {
	return &Report{URL: "http://x.test/", OK: true, ElapsedMS: ms, Steps: map[string]*Step{}}
}

func badReport() *Report {
	st := Step{{"state", "failed"}, {"reason", "expected HTTP 200, received 500"}}
	return &Report{URL: "http://x.test/", Steps: map[string]*Step{"http": &st}}
}

func readLive(t *testing.T, rig *rolloutRig) string {
	t.Helper()
	b, err := os.ReadFile(rig.r.o.Config)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRolloutSuccess(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(3), okReport(4)} })
	res, code, err := rig.r.run(context.Background())
	if err != nil || code != 0 || !res.OK {
		t.Fatalf("code=%d err=%v res=%+v", code, err, res)
	}
	if res.Generation != 2 || res.FromGeneration != 1 || len(res.Steps) != 1 || res.Probes < 6 || res.Failures != 0 {
		t.Fatalf("summary: %+v", res)
	}
	if readLive(t, rig) != string(rig.cand) {
		t.Fatal("live file is not the candidate")
	}
	if l, _ := rig.r.hist.list(); len(l) != 1 || l[0].ID != res.Backup || l[0].Generation != 1 || !l[0].LintOK {
		t.Fatalf("history: %+v", l)
	}
	if _, err := os.Stat(filepath.Join(rig.dir, historyDirName, "lock")); err == nil {
		t.Fatal("lock left behind")
	}
}

func TestRolloutRollsBackOnProbeFailure(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{badReport()} })
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.OK || res.Outcome != "rolled_back" || !res.RestoreConfirmed {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.live) {
		t.Fatal("live config not restored")
	}
	if rig.gw.gen != 3 || !strings.Contains(strings.Join(res.Evidence, " "), "received 500") {
		t.Fatalf("gen=%d evidence=%v", rig.gw.gen, res.Evidence)
	}
	if rig.calls != 1 {
		t.Fatalf("should abort on the first failing round, ran %d", rig.calls)
	}
}

func TestRolloutErrorRateTolerance(t *testing.T) {
	probe := func(call int) []*Report {
		r := make([]*Report, 20)
		for i := range r {
			r[i] = okReport(1)
		}
		if call == 1 {
			r[0] = badReport() // 1 of 20 in the first round, 1 of 100 overall
		}
		return r
	}
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), probe)
	rig.r.o.MaxErrorRate = 0.05
	if res, code, _ := rig.r.run(context.Background()); code != 0 {
		t.Fatalf("1%% should be tolerated: %+v", res)
	}
	rig = newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), probe)
	rig.r.o.MaxErrorRate = 0.001
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || !strings.Contains(res.Reason, "error rate") {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestRolloutP95(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(900)} })
	rig.r.o.MaxP95 = 200 * time.Millisecond
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || !strings.Contains(res.Reason, "p95") || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestRolloutRejectedReload(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(1)} })
	rig.gw.reject = func(raw []byte) string {
		if bytes.Equal(raw, rig.cand) {
			return "refusing configuration with lint errors"
		}
		return ""
	}
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.Outcome != "rolled_back" || !strings.Contains(res.Reason, "rejected") {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.live) || rig.calls != 0 {
		t.Fatalf("live restored=%v probes=%d", readLive(t, rig) == string(rig.live), rig.calls)
	}
}

func TestRolloutApplyTimeout(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(1)} })
	rig.gw.stuck = true
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || !strings.Contains(res.Reason, "did not apply") {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.live) || !res.RolledBack {
		t.Fatal("file must be restored")
	}
}

func TestRolloutNoRollbackLeavesCandidate(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{badReport()} })
	rig.r.o.RollbackOnFail = false
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.Outcome != "failed_in_place" || readLive(t, rig) != string(rig.cand) {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestRolloutLintRefusalAndForce(t *testing.T) {
	bad := rolloutSnap("127.0.0.1:2", 1)
	bad = bytes.Replace(bad, []byte(`"parentRefs"`), []byte(`"noParents"`), 1) // SET001
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), bad, func(int) []*Report { return []*Report{okReport(1)} })
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.Outcome != "refused" || readLive(t, rig) != string(rig.live) || len(res.Evidence) == 0 {
		t.Fatalf("code=%d %+v", code, res)
	}
	if l, _ := rig.r.hist.list(); len(l) != 0 {
		t.Fatal("a refused candidate must not touch history")
	}
	rig.r.o.Force = true
	if res, code, _ := rig.r.run(context.Background()); code != 0 {
		t.Fatalf("--force: code=%d %+v", code, res)
	}
}

func TestRolloutInterruptRestores(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(call int) []*Report {
		if call == 2 {
			cancel() // Ctrl-C during the observation window
		}
		return []*Report{okReport(1)}
	})
	res, code, _ := rig.r.run(ctx)
	if code != 1 || res.Outcome != "interrupted" || !res.RestoreConfirmed || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestRolloutCheckerErrorRollsBack(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), nil)
	rig.r.probe = func(context.Context) ([]*Report, error) { return nil, errors.New("boom") }
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || !strings.Contains(res.Reason, "checks could not run") || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d %+v", code, res)
	}
}

func TestRolloutUnreachableAdminIsSetupError(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return nil })
	rig.r.admin = adminFunc(func(context.Context) (*builtin.StatusDoc, error) { return nil, errors.New("connection refused") })
	_, code, err := rig.r.run(context.Background())
	if code != 2 || err == nil || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

type adminFunc func(context.Context) (*builtin.StatusDoc, error)

func (f adminFunc) Status(ctx context.Context) (*builtin.StatusDoc, error) { return f(ctx) }

func weightsOf(t *testing.T, raw []byte) []int {
	t.Helper()
	var doc obj
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []int
	for _, x := range asList(asMap(asList(asMap(asMap(doc["resources"])["httproutes.gateway.networking.k8s.io/orders"])["rules"])[0])["backendRefs"]) {
		w, _ := num(asMap(x)["weight"])
		out = append(out, int(w))
	}
	return out
}

func TestCanaryPlanWeights(t *testing.T) {
	live := rolloutSnap("127.0.0.1:1", 100, 0)
	cand := rolloutSnap("127.0.0.1:1", 0, 100)
	plan, err := canaryPlan(live, cand, []int{10, 50, 100})
	if err != nil || len(plan) != 3 {
		t.Fatalf("%v %d", err, len(plan))
	}
	want := [][]int{{90, 10}, {50, 50}, {0, 100}}
	for i, p := range plan {
		if got := weightsOf(t, p.data); fmt.Sprint(got) != fmt.Sprint(want[i]) {
			t.Errorf("step %d: %v want %v", i, got, want[i])
		}
	}
	// three backends: the others share the remainder in their candidate ratio
	plan, _ = canaryPlan(rolloutSnap("127.0.0.1:1", 90, 10, 0), rolloutSnap("127.0.0.1:1", 60, 20, 20), []int{50})
	if got := weightsOf(t, plan[0].data); got[2] != 50 || got[0]+got[1]+got[2] != 100 || got[0] < 36 || got[0] > 39 {
		t.Errorf("three way: %v", got)
	}
	if plan, _ := canaryPlan(live, live, []int{10}); len(plan) != 0 {
		t.Error("no weight change means no canary stages")
	}
	if _, err := canaryPlan(live, cand, []int{50, 10}); err == nil {
		t.Error("steps must increase")
	}
}

func TestRolloutProgressiveSteps(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 100, 0), rolloutSnap("127.0.0.1:1", 0, 100), func(int) []*Report { return []*Report{okReport(1)} })
	rig.r.o.Steps = []int{10, 50, 100}
	res, code, _ := rig.r.run(context.Background())
	if code != 0 || len(res.Steps) != 4 || res.Steps[0].Name != "canary 10%" || res.Steps[3].Name != "candidate" || res.Generation != 5 {
		t.Fatalf("code=%d %+v", code, res)
	}
	if readLive(t, rig) != string(rig.cand) {
		t.Fatal("final state must be the candidate verbatim")
	}
}

func TestRolloutProgressiveFailureAtStepRestores(t *testing.T) {
	var rig *rolloutRig
	rig = newRig(t, rolloutSnap("127.0.0.1:1", 100, 0), rolloutSnap("127.0.0.1:1", 0, 100), func(call int) []*Report {
		raw, _ := os.ReadFile(rig.r.o.Config)
		if w := weightsOf(t, raw); w[1] >= 50 {
			return []*Report{badReport()}
		}
		return []*Report{okReport(1)}
	})
	rig.r.o.Steps = []int{10, 50, 100}
	res, code, _ := rig.r.run(context.Background())
	if code != 1 || res.Outcome != "rolled_back" || !strings.Contains(res.Reason, "canary 50%") || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d %+v", code, res)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("steps: %+v", res.Steps)
	}
}

func TestHistoryPruneAndDiff(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "live.json")
	h := newHistStore(cfg)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 5; i++ {
		m, err := h.add(rolloutSnap("127.0.0.1:1", i+1), histMeta{Reason: "rollout"}, now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	h.prune(2)
	l, _ := h.list()
	if len(l) != 2 || l[0].ID != ids[4] || l[1].ID != ids[3] {
		t.Fatalf("%+v", l)
	}
	if _, _, err := h.get(ids[0]); err == nil {
		t.Fatal("pruned backup must be gone")
	}
	if raw, _, err := h.get(ids[4][:20]); err != nil || len(raw) == 0 {
		t.Fatalf("prefix lookup: %v", err)
	}
	d := summarizeDiff(rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:1", 1, 1))
	if d.Added != 1 || d.Changed != 1 || d.Removed != 0 || !strings.Contains(d.String(), "1 changed, 1 added") {
		t.Fatalf("%+v %s", d, d)
	}
	if lk, err := h.lock(); err != nil {
		t.Fatal(err)
	} else if _, err := h.lock(); err == nil {
		t.Fatal("second lock must fail")
	} else {
		lk()
	}
}

func TestRollbackCommandRestoresAndKeepsUndo(t *testing.T) {
	rig := newRig(t, rolloutSnap("127.0.0.1:1", 1), rolloutSnap("127.0.0.1:2", 1), func(int) []*Report { return []*Report{okReport(1)} })
	res, code, _ := rig.r.run(context.Background())
	if code != 0 {
		t.Fatalf("%+v", res)
	}
	rb, code, err := rig.r.rollback(context.Background(), "")
	if err != nil || code != 0 || !rb.RestoreConfirmed || readLive(t, rig) != string(rig.live) {
		t.Fatalf("code=%d err=%v %+v", code, err, rb)
	}
	// the candidate that was replaced is itself a backup now, so rollback is undoable
	if raw, m, err := rig.r.hist.get(rb.Backup); err != nil || string(raw) != string(rig.cand) || m.Reason != "rollback" {
		t.Fatalf("%v %+v", err, m)
	}
	if _, code, err := rig.r.rollback(context.Background(), "nonexistent"); err == nil || code != 2 {
		t.Fatalf("unknown id: %d %v", code, err)
	}
}

func TestRolloutCommandUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runGateway([]string{"rollout", "--config", "x.json"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--new and --checks") {
		t.Fatalf("%d %s", code, errb.String())
	}
	errb.Reset()
	if code := runGateway([]string{"rollout", "--config", "x", "--new", "y", "--checks", "z", "--steps", "0,5"}, &out, &errb); code != 2 {
		t.Fatalf("%d %s", code, errb.String())
	}
	errb.Reset()
	cfg := filepath.Join(t.TempDir(), "live.json")
	if code := runGateway([]string{"history", "--config", cfg}, &out, &errb); code != 0 || !strings.Contains(out.String(), "no backups") {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := runGateway([]string{"history", "--config", cfg, "--format", "json"}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("%d %q", code, out.String())
	}
}

func TestRolloutHelpManCompletion(t *testing.T) {
	var b bytes.Buffer
	Man(&b)
	if !strings.Contains(b.String(), "rollout") {
		t.Error("man page lacks rollout")
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		b.Reset()
		Completion(sh, &b)
		if !strings.Contains(b.String(), "rollback-on-fail") {
			t.Errorf("%s completion lacks gateway flags", sh)
		}
	}
}
