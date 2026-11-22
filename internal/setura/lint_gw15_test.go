package setura

import (
	"strings"
	"testing"
)

func gw15Snapshot(rule obj, extra obj) obj {
	res := obj{
		"gateways.gateway.networking.k8s.io/gw":  obj{"gatewayClassName": "setura", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
		"httproutes.gateway.networking.k8s.io/r": obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}},
	}
	for k, v := range extra {
		res[k] = v
	}
	return obj{"schema": snapshotSchema, "namespace": "shop", "resources": res}
}

func set016(t *testing.T, snap obj) []string {
	t.Helper()
	rep, err := Lint(snap)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range asList(rep["findings"]) {
		if m := asMap(f); m["id"] == "SET016" {
			out = append(out, asStr(m["resource"])+": "+asStr(m["message"]))
		}
	}
	return out
}

func TestLintSET016(t *testing.T) {
	back := []any{obj{"name": "a", "port": 80}}
	good := obj{"backendRefs": back, "filters": []any{
		obj{"type": "CORS", "cors": obj{"allowOrigins": []any{"https://app.example.com", "https://*.dev.example.com"}}},
		obj{"type": "ExternalAuth", "externalAuth": obj{"protocol": "HTTP", "backendRef": obj{"name": "authz", "port": 80}}},
	}, "timeouts": obj{"request": "10s", "backendRequest": "5s"}, "sessionPersistence": obj{"type": "Cookie", "sessionName": "sid"}}
	if got := set016(t, gw15Snapshot(good, nil)); len(got) != 0 {
		t.Errorf("a valid rule: %v", got)
	}
	for name, rule := range map[string]obj{
		"cors origin":     {"backendRefs": back, "filters": []any{obj{"type": "CORS", "cors": obj{"allowOrigins": []any{"example.com"}}}}},
		"cors missing":    {"backendRefs": back, "filters": []any{obj{"type": "CORS"}}},
		"auth protocol":   {"backendRefs": back, "filters": []any{obj{"type": "ExternalAuth", "externalAuth": obj{"protocol": "SOAP", "backendRef": obj{"name": "x"}}}}},
		"auth backend":    {"backendRefs": back, "filters": []any{obj{"type": "ExternalAuth", "externalAuth": obj{"protocol": "HTTP"}}}},
		"session type":    {"backendRefs": back, "sessionPersistence": obj{"type": "Bogus"}},
		"backend timeout": {"backendRefs": back, "timeouts": obj{"request": "1s", "backendRequest": "5s"}},
	} {
		if got := set016(t, gw15Snapshot(rule, nil)); len(got) != 1 || !strings.Contains(got[0], "HTTPRoute/shop/r") {
			t.Errorf("%s: %v", name, got)
		}
	}
	pol := func(spec obj) obj {
		return obj{"backendtlspolicies.gateway.networking.k8s.io/p": spec}
	}
	target := []any{obj{"kind": "Service", "name": "a"}}
	if got := set016(t, gw15Snapshot(good, pol(obj{"targetRefs": target, "validation": obj{"hostname": "a.internal", "caCertificateRefs": []any{obj{"kind": "ConfigMap", "name": "ca"}}}}))); len(got) != 0 {
		t.Errorf("a valid policy: %v", got)
	}
	if got := set016(t, gw15Snapshot(good, pol(obj{"targetRefs": target, "validation": obj{"caCertificateRefs": []any{obj{"kind": "ConfigMap", "name": "ca"}}}}))); len(got) != 1 || !strings.Contains(got[0], "BackendTLSPolicy/shop/p") {
		t.Errorf("a policy without hostname: %v", got)
	}
	if got := set016(t, gw15Snapshot(good, pol(obj{"targetRefs": target, "validation": obj{"hostname": "h"}}))); len(got) != 1 {
		t.Errorf("a policy without a CA source: %v", got)
	}
}
