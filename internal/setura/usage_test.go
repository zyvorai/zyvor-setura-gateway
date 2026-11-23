package setura

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

const usagePlans = `{
  "defaultPlan": "free",
  "plans": {
    "free": {"requestsPerMonth": 100},
    "pro":  {"requestsPerMonth": 1000, "includedRequests": 1, "pricePer1kRequests": 4, "currency": "EUR", "description": "paid"}
  },
  "identities": {"apikey:acme": "pro"}
}`

func usageSnapshot(backend string) []byte {
	raw, _ := json.MarshalIndent(map[string]any{"schema": snapshotSchema, "namespace": "demo",
		"resources": map[string]any{
			"gateways.gateway.networking.k8s.io/dev": map[string]any{"gatewayClassName": "setura", "listeners": []any{
				map[string]any{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "api.test"}}},
			"httproutes.gateway.networking.k8s.io/orders": map[string]any{
				"parentRefs": []any{map[string]any{"name": "dev"}}, "hostnames": []any{"api.test"},
				"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "orders", "port": 80}},
					"setura.zyvor.dev/auth": map[string]any{"apiKey": map[string]any{"keys": []any{
						map[string]any{"name": "acme", "key": "k-acme"}, map[string]any{"name": "bob", "key": "k-bob"}}}}}}}},
		"backends": map[string]any{"demo/orders:80": map[string]any{"endpoints": []any{backend}}}}, "", "  ")
	return raw
}

// usageGateway runs a real gateway with plans on loopback and returns its admin address.
func usageGateway(t *testing.T) (admin, dir, cfgPath, plansPath string, call func(key string) int) {
	t.Helper()
	dir = t.TempDir()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(up.Close)
	cfgPath, plansPath = filepath.Join(dir, "gw.json"), filepath.Join(dir, "plans.json")
	os.WriteFile(cfgPath, usageSnapshot(strings.TrimPrefix(up.URL, "http://")), 0o600)
	os.WriteFile(plansPath, []byte(usagePlans), 0o600)
	gw := builtin.New(builtin.Options{PortMap: map[int]int{8080: 0}, Admin: "127.0.0.1:0", Diag: io.Discard,
		Meter: builtin.MeterOptions{PlansFile: plansPath, PlansInterval: -1, StateInterval: -1}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gw.Run(ctx, builtin.FileSource{Path: cfgPath}, 50*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; !gw.Ready(); i++ {
		if i > 500 {
			t.Fatal("gateway never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	do := func(key string) int {
		req, _ := http.NewRequest("GET", "http://"+gw.Addr(8080)+"/", nil)
		req.Host = "api.test"
		req.Header.Set("X-API-Key", "k-"+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	t.Cleanup(func() { gw.FlushAccessLog() })
	return gw.AdminAddr(), dir, cfgPath, plansPath, func(key string) int {
		c := do(key)
		gw.FlushAccessLog()
		return c
	}
}

func TestUsageCommand(t *testing.T) {
	admin, _, _, plans, call := usageGateway(t)
	for _, k := range []string{"acme", "acme", "acme", "bob"} {
		if c := call(k); c != 200 {
			t.Fatalf("%s: %d", k, c)
		}
	}
	code, out, errs := cli(t, nil, "usage", "--admin", admin)
	if code != 0 || !strings.Contains(out, "apikey:acme") || !strings.Contains(out, "apikey:bob") || !strings.Contains(out, "TOTAL") || !strings.Contains(out, "REQUESTS") {
		t.Fatalf("table: %d %q %q", code, out, errs)
	}
	code, out, _ = cli(t, nil, "usage", "--admin", admin, "--format", "json", "--by", "plan")
	var rep builtin.UsageReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || len(rep.Rows) != 2 || rep.Totals.Requests != 4 {
		t.Fatalf("json: %d %v %s", code, err, out)
	}
	code, out, _ = cli(t, nil, "usage", "--admin", admin, "--format", "csv", "--by", "key,route", "--identity", "apikey:a*", "--since", "7d")
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if code != 0 || err != nil || len(rows) != 2 || rows[0][0] != "identity" || rows[0][1] != "route" || rows[1][0] != "apikey:acme" || rows[1][2] != "3" {
		t.Fatalf("csv: %d %v %q", code, err, out)
	}
	// invoice: prices from the gateway's /plans, then from a file
	period := time.Now().UTC().Format("2006-01")
	code, out, errs = cli(t, nil, "usage", "invoice", "--admin", admin, "--period", period, "--format", "json")
	var inv builtin.Invoice
	if err := json.Unmarshal([]byte(out), &inv); err != nil || code != 0 {
		t.Fatalf("invoice: %d %v %s %s", code, err, out, errs)
	}
	if len(inv.Lines) != 2 || inv.Lines[0].Identity != "apikey:acme" || inv.Lines[0].Chargeable != 2 || inv.Lines[0].Currency != "EUR" || inv.Lines[0].Amount != 0.01 {
		t.Fatalf("invoice lines: %+v", inv.Lines)
	}
	code, out, _ = cli(t, nil, "usage", "invoice", "--admin", admin, "--period", period, "--plans", plans)
	if code != 0 || !strings.Contains(out, "Invoice summary") || !strings.Contains(out, "4 EUR") || !strings.Contains(out, "0.01 EUR") {
		t.Fatalf("invoice table: %d %q", code, out)
	}
	code, out, _ = cli(t, nil, "usage", "invoice", "--admin", admin, "--period", period, "--format", "csv")
	if code != 0 || !strings.HasPrefix(out, "period,identity,plan,") || !strings.Contains(out, period+",apikey:acme,pro,3,3,1,2,") {
		t.Fatalf("invoice csv: %d %q", code, out)
	}
	if code, out, _ = cli(t, nil, "usage", "invoice", "--admin", admin, "--period", "2001-01"); code != 0 || !strings.Contains(out, "no usage recorded") {
		t.Fatalf("empty period: %d %q", code, out)
	}
}

func TestUsageCommandErrors(t *testing.T) {
	for _, args := range [][]string{
		{"usage", "--format", "xml"}, {"usage", "--by", "colour"}, {"usage", "extra"}, {"usage", "invoice"},
		{"usage", "invoice", "--period", "2026-13"}, {"usage", "--period", "2026-11", "--since", "7d"},
	} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if code, _, errs := cli(t, nil, "usage", "--admin", "127.0.0.1:1"); code != 2 || !strings.Contains(errs, "cannot reach") {
		t.Fatalf("%d %q", code, errs)
	}
	admin, _, _, _, _ := usageGateway(t)
	if code, _, errs := cli(t, nil, "usage", "--admin", admin, "--since", "yesterday-ish"); code != 2 || !strings.Contains(errs, "400") {
		t.Fatalf("bad since: %d %q", code, errs)
	}
}

func TestWhyPlans(t *testing.T) {
	_, _, cfg, plans, _ := usageGateway(t)
	code, out, errs := cli(t, nil, "--color", "never", "why", "GET", "http://api.test:8080/", "-H", "X-API-Key: k-acme", "--config", cfg, "--plans", plans)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"plan pro for apikey:acme", "identities[apikey:acme]", "requestsPerMonth 1000", "admitted"} {
		contains(t, out, want)
	}
	code, out, _ = cli(t, nil, "why", "GET", "http://api.test:8080/", "-H", "X-API-Key: k-bob", "--config", cfg, "--plans", plans, "--format", "json")
	var tr builtin.Trace
	if err := json.Unmarshal([]byte(out), &tr); err != nil || code != 0 || tr.Winner.Plan == nil || tr.Winner.Plan.Plan != "free" || tr.Winner.Plan.Source != "defaultPlan" {
		t.Fatalf("json: %d %v %s", code, err, out)
	}
	if strings.Contains(out, "k-bob") {
		t.Error("credential leaked into the trace")
	}
	if code, _, _ := cli(t, nil, "why", "GET", "http://api.test:8080/", "--config", cfg, "--plans", filepath.Join(t.TempDir(), "missing.json")); code == 0 {
		t.Error("a missing plan file should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"plans":{}}`), 0o600)
	if code, _, errs := cli(t, nil, "why", "GET", "http://api.test:8080/", "--config", cfg, "--plans", bad); code != 2 || !strings.Contains(errs, "define at least one plan") {
		t.Fatalf("%d %q", code, errs)
	}
	if code, _, _ := cli(t, nil, "why", "GET", "http://api.test:8080/", "--admin", "127.0.0.1:1", "--plans", plans); code != 2 {
		t.Fatalf("--plans with --admin: %d", code)
	}
}

func TestLintPlans(t *testing.T) {
	_, dir, cfg, plans, _ := usageGateway(t)
	code, out, errs := cli(t, nil, "lint", "--snapshot", cfg, "--plans", plans)
	if code != 0 || strings.Contains(out, "SET02") {
		t.Fatalf("a good plan file: %d %q %q", code, out, errs)
	}
	bad := filepath.Join(dir, "bad-plans.json")
	os.WriteFile(bad, []byte(`{"unmeteredRoutes":["demo/health*"],"plans":{"a":{"routes":["demo/orders","demo/ghost"]}},"identities":{"apikey:acme":"a","apikey:ghost":"a"}}`), 0o600)
	code, out, _ = cli(t, nil, "lint", "--snapshot", cfg, "--plans", bad)
	if code != 0 {
		t.Fatalf("warnings alone do not fail: %d %s", code, out)
	}
	contains(t, out, "SET021")
	contains(t, out, "demo/ghost")
	contains(t, out, "demo/health*")
	contains(t, out, "SET022")
	contains(t, out, `apikey:ghost`)
	if strings.Contains(out, "apikey:acme") {
		t.Errorf("a declared key was flagged:\n%s", out)
	}
	if code, _, _ = cli(t, nil, "lint", "--snapshot", cfg, "--plans", bad, "--strict"); code != 1 {
		t.Errorf("--strict: %d", code)
	}
	invalid := filepath.Join(dir, "invalid.json")
	os.WriteFile(invalid, []byte(`{"plans":{"a":{"requestsPerDay":-5}}}`), 0o600)
	code, out, _ = cli(t, nil, "lint", "--snapshot", cfg, "--plans", invalid, "--format", "json")
	var rep struct {
		OK       bool `json:"ok"`
		Findings []struct{ ID, Severity, Resource string }
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 1 || rep.OK {
		t.Fatalf("invalid file: %d %v %s", code, err, out)
	}
	found := false
	for _, f := range rep.Findings {
		found = found || (f.ID == "SET020" && f.Severity == "error" && f.Resource == "PlanFile/invalid.json")
	}
	if !found {
		t.Fatalf("no SET020: %s", out)
	}
	if code, out, _ := cli(t, nil, "lint", "--rules"); !strings.Contains(out, "SET020") || !strings.Contains(out, "SET022") || code != 0 {
		t.Fatalf("rules: %q", out)
	}
}

func TestCompletionOffersMeteringFlags(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, _ := cli(t, nil, "completion", shell)
		if code != 0 {
			t.Fatal(shell, code)
		}
		for _, want := range []string{"usage", "plans", "usage-state", "usage-max-series", "since"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s completion lacks %q", shell, want)
			}
		}
	}
}
