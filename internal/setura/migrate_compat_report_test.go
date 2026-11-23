package setura

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func TestMigrateConvertCompatReport(t *testing.T) {
	code, out, errs := cli(t, nil, "migrate", "convert", "--from", "envoy-gateway", "--compat-report")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d %s", code, errs)
	}
	for _, want := range []string{"BackendTrafficPolicy", "retry.numRetries", "Supported", "Partial", "Unsupported", "loadBalancer", "rule retry.attempts"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	code, out, _ = cli(t, nil, "migrate", "convert", "--from", "envoy-gateway", "--compat-report", "--format", "json")
	var rep struct {
		Schema string
		Counts map[string]int
		Fields []builtin.CompatRow
	}
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.Schema != "setura.envoy-compat/v1" || len(rep.Fields) != len(builtin.EnvoyCompatTable) {
		t.Fatalf("json: %d %v", code, out)
	}
	if rep.Counts["Supported"]+rep.Counts["Partial"]+rep.Counts["Unsupported"] != len(rep.Fields) {
		t.Errorf("counts %v", rep.Counts)
	}
	// The generated document is the committed one.
	_, md, _ := cli(t, nil, "migrate", "convert", "--from", "envoy-gateway", "--compat-report", "--format", "markdown")
	if want, err := os.ReadFile("../../docs/envoy-gateway-compat.md"); err != nil || md != string(want) {
		t.Errorf("docs/envoy-gateway-compat.md is stale; run make compat (%v)", err)
	}
	for _, args := range [][]string{
		{"migrate", "convert", "--compat-report"},
		{"migrate", "convert", "--from", "traefik", "--compat-report"},
		{"migrate", "convert", "--from", "envoy-gateway", "--compat-report", "--format", "yaml"},
	} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestCompletionOffersEnvoyCompat(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		var b strings.Builder
		if err := Completion(shell, &b); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"envoy-compat", "compat-report"} {
			if !strings.Contains(b.String(), f) {
				t.Errorf("%s completion lacks %s", shell, f)
			}
		}
	}
}
