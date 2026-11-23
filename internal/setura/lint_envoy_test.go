package setura

import (
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func lintEnvoy(t *testing.T, policies obj) map[string][]string {
	t.Helper()
	res := obj{
		"gateways.gateway.networking.k8s.io/edge": obj{"gatewayClassName": "setura", "listeners": []any{obj{"name": "web", "port": 80, "protocol": "HTTP"}}},
		"httproutes.gateway.networking.k8s.io/orders": obj{"parentRefs": []any{obj{"name": "edge"}},
			"rules": []any{obj{"backendRefs": []any{obj{"name": "orders", "port": 80}}}}},
	}
	for k, v := range policies {
		res[k] = v
	}
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "shop", "resources": res})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range asList(rep["findings"]) {
		fm := asMap(f)
		out[asStr(fm["id"])] = append(out[asStr(fm["id"])], asStr(fm["resource"])+": "+asStr(fm["message"]))
	}
	return out
}

func TestLintEnvoyPolicies(t *testing.T) {
	bt := "backendtrafficpolicies." + builtin.EnvoyGroup
	sp := "securitypolicies." + builtin.EnvoyGroup
	ref := func(kind, name string) any { return obj{"kind": kind, "name": name} }
	got := lintEnvoy(t, obj{
		bt + "/slow":    obj{"targetRefs": []any{ref("HTTPRoute", "orders")}, "retry": obj{"numRetries": 1}, "dns": obj{"lookupFamily": "IPv4"}},
		bt + "/also":    obj{"targetRefs": []any{ref("HTTPRoute", "orders")}, "retry": obj{"numRetries": 2}},
		bt + "/ghost":   obj{"targetRefs": []any{ref("HTTPRoute", "nosuch")}, "retry": obj{"numRetries": 2}},
		sp + "/basic":   obj{"targetRefs": []any{ref("Gateway", "edge")}, "basicAuth": obj{"users": obj{"name": "u"}}},
		sp + "/healthy": obj{"targetRefs": []any{ref("HTTPRoute", "orders")}, "cors": obj{"allowOrigins": []any{"*"}}},
	})
	has := func(id, sub string) {
		t.Helper()
		for _, m := range got[id] {
			if strings.Contains(m, sub) {
				return
			}
		}
		t.Errorf("%s: no finding with %q in %v", id, sub, got[id])
	}
	has("SET080", "BackendTrafficPolicy/shop/slow: Setura ignores these fields: dns")
	has("SET081", "BackendTrafficPolicy/shop/ghost: target HTTPRoute nosuch")
	has("SET082", "BackendTrafficPolicy/shop/also")
	has("SET082", "BackendTrafficPolicy/shop/slow")
	has("SET083", "SecurityPolicy/shop/basic: Setura cannot enforce basicAuth")
	for id, ms := range got {
		for _, m := range ms {
			if strings.Contains(m, "healthy") {
				t.Errorf("%s flags the healthy policy: %s", id, m)
			}
		}
	}
	// Every rule is documented.
	for _, id := range []string{"SET080", "SET081", "SET082", "SET083"} {
		if _, ok := ruleHelp[id]; !ok {
			t.Errorf("%s has no ruleHelp entry", id)
		}
		if ruleSeverity(id) != SeverityWarning {
			t.Errorf("%s severity", id)
		}
	}
}
