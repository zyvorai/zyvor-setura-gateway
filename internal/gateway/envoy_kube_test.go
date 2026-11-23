package gateway

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func init() {
	for _, k := range EnvoyKinds {
		fakeColl[envoyBase+"/"+k.Plural] = k.Plural
	}
}

func putEnvoy(api *fakeAPI, kind, plural, ns, name, created string, spec m) {
	api.put(plural, ns, name, m{"kind": kind, "metadata": m{"creationTimestamp": created, "generation": 2}, "spec": spec})
}

func conditionsOf(t *testing.T, api *fakeAPI, plural, ns, name string) map[string]m {
	t.Helper()
	st, _ := api.get(plural, ns, name)["status"].(m)
	out := map[string]m{}
	anc, _ := st["ancestors"].([]any)
	if len(anc) == 0 {
		return out
	}
	for _, c := range anc[0].(m)["conditions"].([]any) {
		out[c.(m)["type"].(string)] = c.(m)
	}
	return out
}

func seedEnvoy(api *fakeAPI, upstream string) {
	api.seed(upstream)
	// two named rules on the route "orders" (the seed's route has one)
	api.put("httproutes", "shop", "orders", m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z", "generation": 3},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}}, "rules": l{
			m{"name": "read", "matches": l{m{"path": m{"type": "PathPrefix", "value": "/orders"}}}, "backendRefs": l{m{"name": "orders", "port": 80}}},
			m{"name": "admin", "matches": l{m{"path": m{"type": "PathPrefix", "value": "/admin"}}}, "backendRefs": l{m{"name": "orders", "port": 80}}},
			m{"name": "gone", "matches": l{m{"path": m{"type": "PathPrefix", "value": "/old"}}}, "filters": l{
				m{"type": "ExtensionRef", "extensionRef": m{"group": EnvoyGroup, "kind": "HTTPRouteFilter", "name": "gone"}}}},
			m{"name": "ext", "matches": l{m{"path": m{"type": "PathPrefix", "value": "/ext"}}}, "backendRefs": l{
				m{"group": EnvoyGroup, "kind": "Backend", "name": "up", "port": 80}}},
		}}})
}

func TestKubernetesEnvoyCompat(t *testing.T) {
	up := newUpstream(t, "u1")
	api := newFakeAPI(t)
	seedEnvoy(api, up.addr())
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080, "allowedRoutes": m{"namespaces": m{"from": "All"}}}}}})
	// A Gateway wide policy in "infra" cannot target shop's route; policies live beside their targets.
	putEnvoy(api, "BackendTrafficPolicy", "backendtrafficpolicies", "infra", "defaults", "2026-01-01T00:00:00Z", m{
		"targetRefs": l{target("Gateway", "edge")}, "timeout": m{"http": m{"requestTimeout": "10s"}},
		"compression": l{m{"type": "Gzip"}}})
	putEnvoy(api, "BackendTrafficPolicy", "backendtrafficpolicies", "shop", "orders", "2026-01-02T00:00:00Z", m{
		"targetRefs": l{target("HTTPRoute", "orders")}, "timeout": m{"http": m{"requestTimeout": "3s"}},
		"retry":          m{"numRetries": 2, "retryOn": m{"httpStatusCodes": l{503}}},
		"circuitBreaker": m{"maxConnections": 4}, "loadBalancer": m{"type": "Random"}, "dns": m{"lookupFamily": "IPv4"}})
	putEnvoy(api, "SecurityPolicy", "securitypolicies", "shop", "admin", "2026-01-02T00:00:00Z", m{
		"targetRefs":    l{target("HTTPRoute", "orders", "admin")},
		"authorization": m{"defaultAction": "Deny", "rules": l{m{"action": "Allow", "principal": m{"clientCIDRs": l{"10.99.0.0/16"}}}}}})
	putEnvoy(api, "SecurityPolicy", "securitypolicies", "shop", "late", "2026-01-03T00:00:00Z", m{
		"targetRefs": l{target("HTTPRoute", "orders", "admin")}, "basicAuth": m{"users": m{"name": "creds"}}})
	putEnvoy(api, "SecurityPolicy", "securitypolicies", "shop", "nowhere", "2026-01-03T00:00:00Z", m{
		"targetRefs": l{target("HTTPRoute", "nosuch")}, "cors": m{"allowOrigins": l{"*"}}})
	api.put("httproutefilters", "shop", "gone", m{"spec": m{"directResponse": m{"statusCode": 410, "contentType": "text/plain", "body": m{"inline": "moved on"}}}})
	api.put("backends", "shop", "up", m{"spec": m{"endpoints": l{m{"ip": m{"address": hostOf(up.addr()), "port": portOf(up.addr())}}}}})

	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll = true
	ks.EnvoyCompat = true
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done; s.Close() })
	waitFor(t, "ready", s.Ready)
	c := client(s.Addr(8080), nil)

	// The route policy replaced the gateway one: 3s, retries, and the circuit breaker reached the backend.
	var rt *Route
	for _, r := range s.Table().Cfg.Routes {
		if r.Name == "orders" {
			rt = r
		}
	}
	if rt == nil || rt.Rules[0].Timeouts == nil || rt.Rules[0].Timeouts.Request != "3s" || rt.Rules[0].Retry == nil || *rt.Rules[0].Retry.Attempts != 2 {
		t.Fatalf("read rule: %+v", rt)
	}
	if def := s.Table().Cfg.Backends["shop/orders:80"]; def == nil || def.CircuitBreaker == nil || def.CircuitBreaker.MaxConnections != 4 || def.LoadBalancer == nil || def.LoadBalancer.Algorithm != AlgoRandom {
		t.Fatalf("backend: %+v", s.Table().Cfg.Backends["shop/orders:80"])
	}
	if r := req(t, c, "http", "GET", "any.test", "/orders/1", ""); r.Status != 200 || r.Echo.Name != "u1" {
		t.Fatalf("read: %d %s", r.Status, r.Body)
	}
	// The older admin policy allows 10.99.0.0/16 only; the later basicAuth policy loses the conflict, so the client is refused by the CIDR list.
	if r := req(t, c, "http", "GET", "any.test", "/admin", ""); r.Status != 403 {
		t.Fatalf("admin from 127.0.0.1: %d %s", r.Status, r.Body)
	}
	// HTTPRouteFilter direct response and a Backend object.
	if r := req(t, c, "http", "GET", "any.test", "/old", ""); r.Status != 410 || r.Body != "moved on" {
		t.Fatalf("direct response: %d %q", r.Status, r.Body)
	}
	if r := req(t, c, "http", "GET", "any.test", "/ext", ""); r.Status != 200 || r.Echo.Name != "u1" {
		t.Fatalf("Backend: %d %s", r.Status, r.Body)
	}

	// Status: conditions on the policies, with the ignored fields named.
	waitFor(t, "policy status", func() bool {
		return conditionsOf(t, api, "backendtrafficpolicies", "shop", "orders")["Accepted"] != nil &&
			conditionsOf(t, api, "securitypolicies", "shop", "nowhere")["Accepted"] != nil &&
			conditionsOf(t, api, "securitypolicies", "shop", "late")["Accepted"] != nil &&
			conditionsOf(t, api, "backendtrafficpolicies", "infra", "defaults")["Accepted"] != nil
	})
	acc := conditionsOf(t, api, "backendtrafficpolicies", "shop", "orders")["Accepted"]
	if acc["status"] != "True" || acc["reason"] != "Unsupported" || !strings.Contains(acc["message"].(string), "dns") || strings.Contains(acc["message"].(string), "loadBalancer") || acc["observedGeneration"].(float64) != 2 {
		t.Errorf("orders Accepted: %v", acc)
	}
	if ov := conditionsOf(t, api, "backendtrafficpolicies", "infra", "defaults")["Overridden"]; ov == nil || ov["status"] != "True" || !strings.Contains(ov["message"].(string), "BackendTrafficPolicy/shop/orders") {
		t.Errorf("defaults Overridden: %v", ov)
	}
	if cf := conditionsOf(t, api, "securitypolicies", "shop", "late"); cf["Conflicted"] == nil || cf["Accepted"]["status"] != "False" {
		t.Errorf("late: %v", cf)
	}
	if nf := conditionsOf(t, api, "securitypolicies", "shop", "nowhere")["Accepted"]; nf["status"] != "False" || nf["reason"] != "TargetNotFound" {
		t.Errorf("nowhere: %v", nf)
	}
	st := api.get("backendtrafficpolicies", "shop", "orders")["status"].(m)["ancestors"].([]any)[0].(m)
	if st["controllerName"] != ControllerName || st["ancestorRef"].(m)["name"] != "edge" {
		t.Errorf("ancestor: %v", st)
	}

	// Converged: no further writes. Other controllers' ancestors survive.
	n := len(api.patchLog())
	time.Sleep(200 * time.Millisecond)
	if got := len(api.patchLog()); got != n {
		t.Fatalf("policy status rewritten while converged: %d -> %d", n, got)
	}
	// The Secret behind an API key changes: the data plane follows.
	api.put("secrets", "shop", "keys", m{"data": m{"alice": base64.StdEncoding.EncodeToString([]byte("k-1"))}})
	putEnvoy(api, "SecurityPolicy", "securitypolicies", "shop", "keys", "2026-01-01T00:00:00Z", m{
		"targetRefs": l{target("HTTPRoute", "orders", "read")}, "apiKeyAuth": m{"credentialRefs": l{m{"name": "keys"}}}})
	waitFor(t, "api key policy", func() bool {
		return req(t, c, "http", "GET", "any.test", "/orders", "").Status == 401
	})
	if r := req(t, c, "http", "GET", "any.test", "/orders", "", "X-API-Key", "k-1"); r.Status != 200 {
		t.Fatalf("valid key: %d %s", r.Status, r.Body)
	}
	api.put("secrets", "shop", "keys", m{"data": m{"alice": base64.StdEncoding.EncodeToString([]byte("k-2"))}})
	waitFor(t, "rotated key", func() bool {
		return req(t, c, "http", "GET", "any.test", "/orders", "", "X-API-Key", "k-1").Status == 401 &&
			req(t, c, "http", "GET", "any.test", "/orders", "", "X-API-Key", "k-2").Status == 200
	})
}

// Without --envoy-compat the CRDs are never read, even when they exist.
func TestKubernetesEnvoyCompatOffIgnoresPolicies(t *testing.T) {
	up := newUpstream(t, "u1")
	api := newFakeAPI(t)
	api.seed(up.addr())
	putEnvoy(api, "SecurityPolicy", "securitypolicies", "shop", "deny", "2026-01-01T00:00:00Z", m{
		"targetRefs": l{target("HTTPRoute", "orders")}, "basicAuth": m{"users": m{"name": "x"}}})
	s, _, _ := kubeServer(t, api, nil)
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", ""); r.Status != 200 {
		t.Fatalf("status %d: policies must be ignored without the flag", r.Status)
	}
	time.Sleep(100 * time.Millisecond)
	if api.get("securitypolicies", "shop", "deny")["status"] != nil {
		t.Error("status written without --envoy-compat")
	}
}

// The CRDs are optional: absent (403 from the fake API) changes nothing.
func TestKubernetesEnvoyCompatAbsentCRDs(t *testing.T) {
	up := newUpstream(t, "u1")
	api := newFakeAPI(t)
	api.seed(up.addr())
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll, ks.EnvoyCompat = true, true
	loaded, err := ks.Load(context.Background())
	if err != nil || len(loaded.Config.Routes) != 1 {
		t.Fatalf("load: %v", err)
	}
}
