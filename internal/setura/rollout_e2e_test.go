package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

type e2eEnv struct {
	dir, live, checks string
	port, admin       string
	eps               [3]string // v1, v2, bad
	gw                *builtin.Server
}

func e2eBackend(t *testing.T, name string, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, "served by %s", name)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// e2eSnap routes /checkout to the named endpoints with the given weights
// (a negative weight leaves the field unset).
func (e *e2eEnv) snap(refs ...[2]any) []byte {
	var backendRefs []any
	backends := map[string]any{}
	for _, r := range refs {
		name, w := r[0].(string), r[1].(int)
		ref := map[string]any{"name": name, "port": 80}
		if w >= 0 {
			ref["weight"] = w
		}
		backendRefs = append(backendRefs, ref)
		ep := map[string]string{"orders-v1": e.eps[0], "orders-v2": e.eps[1], "orders-bad": e.eps[2]}[name]
		backends[name+":80"] = map[string]any{"endpoints": []any{ep}}
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
					"backendRefs": backendRefs}}}},
		"backends": backends}, "", "  ")
	return append(raw, '\n')
}

func newE2E(t *testing.T, bodyWant string) *e2eEnv {
	t.Helper()
	e := &e2eEnv{dir: t.TempDir()}
	e.eps = [3]string{e2eBackend(t, "v1", 200), e2eBackend(t, "v2", 200), e2eBackend(t, "bad", 500)}
	e.live = filepath.Join(e.dir, "live.json")
	if err := os.WriteFile(e.live, e.snap([2]any{"orders-v1", -1}), 0o640); err != nil {
		t.Fatal(err)
	}
	e.gw = builtin.New(builtin.Options{PortMap: map[int]int{8080: 0}, Admin: "127.0.0.1:0", Lint: gatewayLint, Diag: io.Discard})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.gw.Run(ctx, builtin.FileSource{Path: e.live}, 50*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; !e.gw.Ready(); i++ {
		if i > 200 {
			t.Fatal("gateway never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, e.port, _ = net.SplitHostPort(e.gw.Addr(8080))
	e.admin = e.gw.AdminAddr()
	e.checks = filepath.Join(e.dir, "checks.json")
	body := fmt.Sprintf(`[{"url":"http://orders.mactra.test:%s/checkout","address":"127.0.0.1","status":200,"body_contains":%q}]`, e.port, bodyWant)
	os.WriteFile(e.checks, []byte(body), 0o644)
	return e
}

func (e *e2eEnv) candidate(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(e.dir, "candidate.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// serve returns the status and body the running gateway answers right now.
func (e *e2eEnv) serve(t *testing.T) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+e.port+"/checkout", nil)
	req.Host = "orders.mactra.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *e2eEnv) rollout(t *testing.T, cand string, extra ...string) (int, rolloutResult) {
	t.Helper()
	args := append([]string{"rollout", "--config", e.live, "--new", cand, "--checks", e.checks, "--admin", e.admin,
		"--observe", "400ms", "--probe-interval", "100ms", "--format", "json"}, extra...)
	var out, errb bytes.Buffer
	code := runGateway(args, &out, &errb)
	var res rolloutResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("exit %d, no JSON result: %v\nstdout: %s\nstderr: %s", code, err, out.String(), errb.String())
	}
	return code, res
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestE2ERolloutSuccess(t *testing.T) {
	e := newE2E(t, "served by v2")
	candRaw := e.snap([2]any{"orders-v2", -1})
	code, res := e.rollout(t, e.candidate(t, candRaw))
	if code != 0 || !res.OK || res.Outcome != "success" {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if res.Generation <= res.FromGeneration || res.Probes < 2 || res.Failures != 0 || len(res.Steps) != 1 {
		t.Fatalf("summary: %+v", res)
	}
	if mustRead(t, e.live) != string(candRaw) {
		t.Fatal("live file is not the candidate")
	}
	if st, body := e.serve(t); st != 200 || body != "served by v2" {
		t.Fatalf("serving %d %q", st, body)
	}
	if st := e.gw.Status(); st.Generation != res.Generation {
		t.Fatalf("admin generation %d, result %d", st.Generation, res.Generation)
	}
	// history lists the backup with its generation and diff
	var out, errb bytes.Buffer
	if code := runGateway([]string{"history", "--config", e.live}, &out, &errb); code != 0 || !strings.Contains(out.String(), res.Backup) || !strings.Contains(out.String(), "changed") {
		t.Fatalf("history: %d\n%s%s", code, out.String(), errb.String())
	}
	// and rollback brings v1 back through the real gateway
	out.Reset()
	if code := runGateway([]string{"rollback", "--config", e.live, "--admin", e.admin}, &out, &errb); code != 0 {
		t.Fatalf("rollback: %d\n%s%s", code, out.String(), errb.String())
	}
	if st, body := e.serve(t); st != 200 || body != "served by v1" {
		t.Fatalf("after rollback: %d %q", st, body)
	}
}

func TestE2ERolloutAutoRollbackOn500(t *testing.T) {
	e := newE2E(t, "served by")
	before := mustRead(t, e.live)
	code, res := e.rollout(t, e.candidate(t, e.snap([2]any{"orders-bad", -1})))
	if code != 1 || res.OK || res.Outcome != "rolled_back" || !res.RestoreConfirmed {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if !strings.Contains(strings.Join(res.Evidence, "\n"), "received 500") {
		t.Fatalf("evidence should show the 500s: %v", res.Evidence)
	}
	if mustRead(t, e.live) != before {
		t.Fatal("live file was not restored byte for byte")
	}
	if st, body := e.serve(t); st != 200 || body != "served by v1" {
		t.Fatalf("gateway still serves the bad candidate: %d %q", st, body)
	}
}

func TestE2ERolloutRefusedByLint(t *testing.T) {
	e := newE2E(t, "served by")
	before := mustRead(t, e.live)
	bad := bytes.Replace(e.snap([2]any{"orders-v2", -1}), []byte(`"parentRefs"`), []byte(`"noParents"`), 1)
	gen := e.gw.Status().Generation
	code, res := e.rollout(t, e.candidate(t, bad))
	if code != 1 || res.Outcome != "refused" || !strings.Contains(strings.Join(res.Evidence, " "), "SET001") {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if mustRead(t, e.live) != before || e.gw.Status().Generation != gen {
		t.Fatal("a refused candidate must leave the live config and gateway untouched")
	}
	if _, err := os.Stat(filepath.Join(e.dir, historyDirName)); err == nil {
		if l, _ := newHistStore(e.live).list(); len(l) != 0 {
			t.Fatal("no backup expected")
		}
	}
}

func TestE2ERolloutReloadRejectedByGateway(t *testing.T) {
	e := newE2E(t, "served by")
	before := mustRead(t, e.live)
	bad := bytes.Replace(e.snap([2]any{"orders-v2", -1}), []byte(`"parentRefs"`), []byte(`"noParents"`), 1)
	code, res := e.rollout(t, e.candidate(t, bad), "--force")
	if code != 1 || res.Outcome != "rolled_back" || !strings.Contains(res.Reason, "rejected") {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if mustRead(t, e.live) != before {
		t.Fatal("live file not restored")
	}
	if st, body := e.serve(t); st != 200 || body != "served by v1" {
		t.Fatalf("serving %d %q", st, body)
	}
	if lr := e.gw.Status().LastReload; !lr.OK {
		t.Fatalf("gateway should be healthy again after the restore: %+v", lr)
	}
}

func TestE2ERolloutProgressiveCanary(t *testing.T) {
	e := newE2E(t, "served by")
	os.WriteFile(e.live, e.snap([2]any{"orders-v1", 100}, [2]any{"orders-v2", 0}), 0o640)
	for i := 0; e.gw.Status().LastReload.OK && i < 100 && e.gw.Status().Generation < 2; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	candRaw := e.snap([2]any{"orders-v1", 0}, [2]any{"orders-v2", 100})
	code, res := e.rollout(t, e.candidate(t, candRaw), "--steps", "25,100")
	if code != 0 || len(res.Steps) != 3 || res.Steps[0].Name != "canary 25%" || res.Steps[2].Name != "candidate" {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if mustRead(t, e.live) != string(candRaw) {
		t.Fatal("final state must be the candidate")
	}
	if _, body := e.serve(t); body != "served by v2" {
		t.Fatalf("serving %q", body)
	}
}

func TestE2ERolloutSIGINTRestores(t *testing.T) {
	e := newE2E(t, "served by v2")
	before := mustRead(t, e.live)
	candRaw := e.snap([2]any{"orders-v2", -1})
	cand := e.candidate(t, candRaw)

	// a stray SIGINT must never kill the test binary, even before the command installs its handler
	guard := make(chan os.Signal, 4)
	signal.Notify(guard, syscall.SIGINT)
	defer signal.Stop(guard)
	go func() {
		for i := 0; i < 500; i++ {
			if b, _ := os.ReadFile(e.live); string(b) == string(candRaw) && e.gw.Status().Generation >= 2 {
				time.Sleep(250 * time.Millisecond) // well inside the 30s observation window
				syscall.Kill(os.Getpid(), syscall.SIGINT)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	start := time.Now()
	args := []string{"rollout", "--config", e.live, "--new", cand, "--checks", e.checks, "--admin", e.admin,
		"--observe", "30s", "--probe-interval", "100ms", "--format", "json"}
	var out, errb bytes.Buffer
	code := runGateway(args, &out, &errb)
	var res rolloutResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("exit %d: %v\n%s\n%s", code, err, out.String(), errb.String())
	}
	if code != 1 || res.Outcome != "interrupted" || !res.RestoreConfirmed {
		t.Fatalf("exit %d: %+v", code, res)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("interrupt should stop the rollout promptly")
	}
	if mustRead(t, e.live) != before {
		t.Fatal("interrupted rollout did not restore the previous config")
	}
	if st, body := e.serve(t); st != 200 || body != "served by v1" {
		t.Fatalf("serving %d %q", st, body)
	}
}
