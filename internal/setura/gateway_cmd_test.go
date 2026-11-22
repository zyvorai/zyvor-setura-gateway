package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func gwxSnapshot(backend string, parents bool) []byte {
	route := map[string]any{
		"hostnames": []any{"orders.mactra.test"},
		"rules": []any{map[string]any{
			"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/checkout"}}},
			"backendRefs": []any{map[string]any{"name": "orders-v1", "port": 80}}}},
	}
	if parents {
		route["parentRefs"] = []any{map[string]any{"name": "dev", "sectionName": "web"}}
	}
	raw, _ := json.Marshal(map[string]any{"schema": snapshotSchema, "namespace": "demo",
		"resources": map[string]any{
			"gateways.gateway.networking.k8s.io/dev": map[string]any{"gatewayClassName": "setura", "listeners": []any{
				map[string]any{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "orders.mactra.test"}}},
			"httproutes.gateway.networking.k8s.io/orders": route},
		"backends": map[string]any{"orders-v1:80": backend}})
	return raw
}

func gwxServe(t *testing.T) (*builtin.Server, string) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "orders service ready") }))
	t.Cleanup(up.Close)
	cfg, err := builtin.ParseConfig(gwxSnapshot(strings.TrimPrefix(up.URL, "http://"), true), "")
	if err != nil {
		t.Fatal(err)
	}
	s := builtin.New(builtin.Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	t.Cleanup(s.Close)
	if err := s.Apply(&builtin.Loaded{Config: cfg, Hash: "x"}); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(s.Addr(8080))
	return s, port
}

func gwxRun(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runWith(nil, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestBuiltinGatewayWorksWithExistingProbeTooling(t *testing.T) {
	_, port := gwxServe(t)
	url := "http://orders.mactra.test:" + port + "/checkout"
	code, out, errs := gwxRun("explain", url, "--address", "127.0.0.1", "--backend", "orders-v1", "--body-contains", "ready")
	if code != 0 {
		t.Fatalf("explain exit %d: %s %s", code, out, errs)
	}
	if code, out, _ := gwxRun("explain", url, "--address", "127.0.0.1", "--backend", "orders-v2"); code != 1 {
		t.Fatalf("wrong backend should fail with exit 1, got %d: %s", code, out)
	}
	checks := filepath.Join(t.TempDir(), "checks.json")
	os.WriteFile(checks, []byte(fmt.Sprintf(`[{"url":%q,"address":"127.0.0.1","backend":"orders-v1","status":200}]`, url)), 0o600)
	if code, out, errs := gwxRun("check", checks); code != 0 {
		t.Fatalf("check exit %d: %s %s", code, out, errs)
	}
}

func TestBuiltinGatewayStatusSatisfiesRouteState(t *testing.T) {
	s, _ := gwxServe(t)
	raw, _ := json.Marshal(s.Status().Routes["demo/orders"])
	var status map[string]any
	json.Unmarshal(raw, &status)
	gen := status["observedGeneration"]
	o := obj{"metadata": obj{"namespace": "demo", "generation": gen}, "status": status}
	state := RouteState(o, "dev", "demo", "web", builtin.ControllerName)
	if state["ok"] != true {
		t.Fatalf("RouteState = %v", state)
	}
}

func TestBuiltinGatewayLintGate(t *testing.T) {
	if ok, report := gatewayLint(gwxSnapshot("127.0.0.1:1", true)); !ok {
		t.Fatalf("clean snapshot refused: %s", report)
	}
	ok, report := gatewayLint(gwxSnapshot("127.0.0.1:1", false)) // no parentRefs -> SET001
	if ok || !strings.Contains(report, "SET001") {
		t.Fatalf("lint gate let SET001 through: %v %s", ok, report)
	}
	if ok, _ := gatewayLint([]byte("nope")); ok {
		t.Fatal("garbage accepted")
	}
}

func TestGatewayCommandUsageAndInstall(t *testing.T) {
	if code, _, _ := gwxRun("gateway"); code != 2 {
		t.Errorf("bare gateway exit %d, want 2", code)
	}
	if code, _, errs := gwxRun("gateway", "run"); code != 2 || !strings.Contains(errs, "--config") {
		t.Errorf("run without source: %d %q", code, errs)
	}
	if code, _, _ := gwxRun("gateway", "run", "--config", "/nonexistent.json", "--admin", "off"); code != 2 {
		t.Errorf("missing config exit %d, want 2", code)
	}
	if code, _, _ := gwxRun("gateway", "run", "--config", "x", "--kubernetes"); code != 2 {
		t.Errorf("both sources exit %d, want 2", code)
	}
	if code, _, _ := gwxRun("gateway", "run", "--config", "x", "--port-map", "bad"); code != 2 {
		t.Errorf("bad port map exit %d, want 2", code)
	}
	code, out, _ := gwxRun("gateway", "install", "--namespace", "gw-sys", "--image", "example.test/setura:1")
	if code != 0 {
		t.Fatalf("install exit %d", code)
	}
	for _, want := range []string{"controllerName: zyvor.dev/setura-gateway", "namespace: gw-sys", "image: example.test/setura:1",
		"kind: ClusterRoleBinding", "kind: GatewayClass", "kind: Deployment", "kind: Service", "kind: ServiceAccount", "httproutes/status"} {
		contains(t, out, want)
	}
	if strings.Contains(out, "NS") && strings.Contains(strings.ReplaceAll(out, "SNI", ""), "namespace: NS") {
		t.Error("placeholder leaked")
	}
	if code, out, _ := gwxRun("version"); code != 0 || !strings.Contains(out, "setura") {
		t.Errorf("version broke: %d %s", code, out)
	}
}

func TestBuiltinDemoExampleIsLintCleanAndParses(t *testing.T) {
	raw, err := os.ReadFile("../../examples/builtin-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	if ok, report := gatewayLint(raw); !ok {
		t.Fatalf("demo has lint errors: %s", report)
	}
	cfg, err := builtin.ParseConfig(raw, "")
	if err != nil || len(cfg.Backends) != 2 {
		t.Fatalf("parse: %v %+v", err, cfg)
	}
}
