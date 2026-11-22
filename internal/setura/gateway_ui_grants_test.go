package setura

import (
	"encoding/json"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

const grantRoutes = `
  "schema": "setura.route-specs/v1", "namespace": "shop",
  "resources": {
    "gateways.gateway.networking.k8s.io/edge": {"gatewayClassName": "setura",
      "listeners": [{"name": "web", "protocol": "HTTP", "port": 8080}]},
    "httproutes.gateway.networking.k8s.io/orders": {
      "parentRefs": [{"name": "edge"}],
      "rules": [{"backendRefs": [{"name": "db", "namespace": "data", "port": 80}]}]}
  },
  "backends": {"data/db:80": "127.0.0.1:1"}`

// findingSeverity returns the severity of the first finding with the given
// rule id in any JSON document, or "" when there is none.
func findingSeverity(t *testing.T, doc any, id string) string {
	t.Helper()
	raw, _ := json.Marshal(doc)
	var v any
	json.Unmarshal(raw, &v)
	var walk func(any) string
	walk = func(n any) string {
		switch x := n.(type) {
		case map[string]any:
			if x["id"] == id {
				if s, _ := x["severity"].(string); s != "" {
					return s
				}
			}
			for _, c := range x {
				if s := walk(c); s != "" {
					return s
				}
			}
		case []any:
			for _, c := range x {
				if s := walk(c); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return walk(v)
}

func gatewayUIState(t *testing.T, raw string) any {
	t.Helper()
	cfg, err := builtin.ParseConfig([]byte(raw), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := builtin.New(builtin.Options{PortMap: map[int]int{8080: 0}, Admin: "off", HistoryInterval: -1})
	t.Cleanup(s.Close)
	if err := s.Apply(&builtin.Loaded{Config: cfg, Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	st := s.UIState()
	if st == nil {
		t.Fatal("no UI state")
	}
	return st
}

func fileLintSeverity(t *testing.T, raw string) string {
	t.Helper()
	var snap obj
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatal(err)
	}
	report, err := Lint(snap)
	if err != nil {
		t.Fatal(err)
	}
	return findingSeverity(t, report, "SET004")
}

// The dashboard of the built-in gateway must grade a missing ReferenceGrant
// the way linting the same file does: an error when the grants are known, a
// warning when they are not.
func TestGatewayUIStateIncludesReferenceGrants(t *testing.T) {
	for _, c := range []struct {
		name, doc, want string
	}{
		{"grants unknown", "{" + grantRoutes + "}", "warning"},
		{"grants known, none match", "{" + grantRoutes + `, "referenceGrants": []}`, "error"},
		{"grants known, one permits", "{" + grantRoutes + `, "referenceGrants": [{"metadata": {"namespace": "data"},
		   "spec": {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "shop"}],
		            "to": [{"group": "", "kind": "Service", "name": "db"}]}}]}`, ""},
		{"grant as a resource", "{" + grantRoutes[:strings.Index(grantRoutes, `"resources": {`)+len(`"resources": {`)] +
			`"referencegrants.gateway.networking.k8s.io/data/allow": {"from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "shop"}],
		     "to": [{"group": "", "kind": "Service"}]},` + grantRoutes[strings.Index(grantRoutes, `"resources": {`)+len(`"resources": {`):] + "}", ""},
	} {
		file := fileLintSeverity(t, c.doc)
		ui := findingSeverity(t, gatewayUIState(t, c.doc), "SET004")
		if file != c.want || ui != c.want {
			t.Errorf("%s: file lint %q, dashboard %q, want both %q", c.name, file, ui, c.want)
		}
	}
}
