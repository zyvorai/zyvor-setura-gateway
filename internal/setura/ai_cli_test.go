package setura

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func aiLint(t *testing.T, rule obj, spec obj) map[string][]string {
	t.Helper()
	rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}}
	for k, v := range spec {
		rt[k] = v
	}
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
		route + "/r":    rt}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range asList(rep["findings"]) {
		m := asMap(f)
		out[asStr(m["id"])] = append(out[asStr(m["id"])], asStr(m["message"]))
	}
	return out
}

func aiProviderBlock(extra obj) obj {
	b := obj{"providers": []any{obj{"name": "openai", "baseURL": "https://api.openai.com/v1", "apiKey": obj{"env": "OPENAI_API_KEY"}}}}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

var keyAuth = obj{"apiKey": obj{"keys": []any{obj{"name": "a", "hash": "sha256$AAAA$" + strings.Repeat("0", 64)}}}}

func TestLintAIRules(t *testing.T) {
	ruleOf := func(ai obj, auth obj) obj {
		r := obj{builtin.AIKey: ai}
		if auth != nil {
			r[builtin.AuthKey] = auth
		}
		return r
	}
	// A sound AI rule: authenticated, budget per API key, no backendRefs. SET003 must not fire.
	good := ruleOf(aiProviderBlock(obj{"identity": "apikey", "budget": obj{"default": obj{"tokensPerDay": 1000}}}), keyAuth)
	if got := aiLint(t, good, nil); len(got) != 0 {
		t.Fatalf("clean AI rule: %v", got)
	}
	for _, c := range []struct {
		name string
		rule obj
		want string
	}{
		{"invalid block", ruleOf(obj{"providers": []any{}}, keyAuth), "SET040"},
		{"unknown field", ruleOf(aiProviderBlock(obj{"bogus": 1}), keyAuth), "SET040"},
		{"budget without auth", ruleOf(aiProviderBlock(obj{"identity": "apikey", "budget": obj{"default": obj{"tokensPerDay": 1}}}), nil), "SET041"},
		{"apikey identity on a jwt rule", ruleOf(aiProviderBlock(obj{"identity": "apikey", "budget": obj{"default": obj{"tokensPerDay": 1}}}),
			obj{"jwt": obj{"audience": []any{"a"}, "jwksUri": "https://idp.test/j"}}), "SET041"},
		{"claim identity without jwt", ruleOf(aiProviderBlock(obj{"identity": "claim:org", "budget": obj{"default": obj{"tokensPerDay": 1}}}), keyAuth), "SET041"},
		{"header identity", ruleOf(aiProviderBlock(obj{"identity": "header:X-Tenant", "budget": obj{"default": obj{"tokensPerDay": 1}}}), nil), "SET042"},
		{"http with key", ruleOf(obj{"providers": []any{obj{"name": "p", "baseURL": "http://llm.example.com/v1", "apiKey": obj{"env": "K"}}}}, keyAuth), "SET043"},
		{"open route", ruleOf(aiProviderBlock(nil), nil), "SET044"},
		{"shared cache on authenticated route", ruleOf(aiProviderBlock(obj{"cache": obj{"enabled": true, "scope": "route"}}), keyAuth), "SET045"},
		{"cost budget without prices", ruleOf(aiProviderBlock(obj{"identity": "apikey", "budget": obj{"default": obj{"monthlyCost": 50}}}), keyAuth), "SET046"},
	} {
		if got := aiLint(t, c.rule, nil); len(got[c.want]) != 1 {
			t.Errorf("%s: want one %s, got %v", c.name, c.want, got)
		}
	}
	// In-cluster http is fine; prices silence SET046.
	inCluster := ruleOf(obj{"providers": []any{obj{"name": "p", "baseURL": "http://vllm.llm.svc:8000/v1", "apiKey": obj{"env": "K"}}},
		"prices": obj{"m": obj{"input": 1, "output": 1}}, "identity": "apikey", "budget": obj{"default": obj{"monthlyCost": 5}}}, keyAuth)
	if got := aiLint(t, inCluster, nil); len(got) != 0 {
		t.Errorf("in-cluster provider: %v", got)
	}
	// backendRefs are ignored.
	both := ruleOf(aiProviderBlock(nil), keyAuth)
	both["backendRefs"] = []any{obj{"name": "x", "port": 80}}
	if got := aiLint(t, both, nil); len(got["SET047"]) != 1 {
		t.Errorf("backendRefs with an AI block: %v", got)
	}
	// Annotations: a valid one is an AI rule too, a bad or orphan one is SET040.
	ann := func(v string) obj { return obj{builtin.SeturaAnnotationsKey: obj{builtin.AIKey: v}} }
	valid, _ := json.Marshal(aiProviderBlock(nil))
	if got := aiLint(t, obj{builtin.AuthKey: keyAuth}, ann(string(valid))); len(got) != 0 {
		t.Errorf("annotation AI rule: %v", got)
	}
	if got := aiLint(t, obj{builtin.AuthKey: keyAuth, "backendRefs": []any{obj{"name": "x", "port": 80}}}, obj{builtin.SeturaAnnotationsKey: obj{builtin.AIKey + ".rule-4": string(valid)}}); len(got["SET040"]) != 1 {
		t.Errorf("orphan annotation: %v", got)
	}
	if got := aiLint(t, obj{}, ann(`{"providers":`)); len(got["SET040"]) != 1 {
		t.Errorf("broken annotation: %v", got)
	}
}

func TestWhyShowsAIRoute(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "openai.key")
	os.WriteFile(keyFile, []byte("sk-test-0123456789\n"), 0o600)
	cfg := `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
	  "gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":8080}]},
	  "httproutes.gateway.networking.k8s.io/llm":{"parentRefs":[{"name":"gw"}],"hostnames":["ai.test"],"rules":[{
	    "setura.zyvor.dev/auth":{"apiKey":{"keys":[{"name":"alice","key":"k-alice"}]}},
	    "setura.zyvor.dev/ai":{"identity":"apikey","providers":[
	      {"name":"primary","baseURL":"https://api.openai.com/v1","weight":3,"apiKey":{"file":` + jsonString(keyFile) + `}},
	      {"name":"backup","baseURL":"https://eu.example.com/v1","weight":1,"apiKey":{"file":` + jsonString(keyFile) + `}},
	      {"name":"cold","baseURL":"https://cold.example.com/v1","priority":1,"apiKey":{"file":` + jsonString(keyFile) + `}}],
	      "budget":{"default":{"tokensPerMinute":50000,"monthlyTokens":1000000}},"cache":{"enabled":true},"pii":{"mode":"redact"}}}]}}}`
	path := filepath.Join(dir, "gw.json")
	os.WriteFile(path, []byte(cfg), 0o600)
	var out, errb bytes.Buffer
	code := Main([]string{"why", "POST", "http://ai.test:8080/v1/chat/completions", "--config", path, "--ascii", "-H", "X-Api-Key: k-alice"}, &out, &errb)
	if code != 0 {
		t.Fatalf("code %d: %s %s", code, out.String(), errb.String())
	}
	for _, want := range []string{"AI route (chat API)", "primary 75%", "backup 25%", "failover order after the first choice: backup, cold",
		"identity: the name of the API key that matched: alice", "50000 tokens/minute", "exact-match cache", "prompt PII redact", "file " + keyFile} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "sk-test-0123456789") {
		t.Error("the provider key is printed")
	}
	out.Reset()
	Main([]string{"why", "POST", "http://ai.test:8080/v1/chat/completions", "--config", path, "--format", "json", "-H", "X-Api-Key: k-alice"}, &out, &errb)
	if strings.Contains(out.String(), "sk-test-0123456789") || !strings.Contains(out.String(), `"primary": "primary"`) {
		t.Errorf("json:\n%s", out.String())
	}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

func fakeAIAdmin(t *testing.T, doc builtin.AIUsage) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ai/usage" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", 401)
			return
		}
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGatewayAIUsageCommand(t *testing.T) {
	doc := builtin.AIUsage{Currency: "USD", Routes: []builtin.AIRouteUsage{
		{Route: "shop/llm/1", Requests: 12, TokensIn: 1200, TokensOut: 800, CostEstimate: 0.0123,
			Cache:  &builtin.AICacheUsage{Hits: 3, Misses: 9, Entries: 9},
			Denied: map[string]int64{"tokens_per_minute": 2},
			Providers: []builtin.AIProviderUsage{{Name: "openai", State: "ejected", Attempts: 9, Failures: 5, TokensIn: 1000, TokensOut: 700, Cost: 0.01, Weight: 1},
				{Name: "backup", State: "healthy", Priority: 1, Weight: 1, Attempts: 5, TokensIn: 200, TokensOut: 100}},
			Keys: []builtin.AIKeyUsage{
				{Key: "alice", Requests: 8, TokensIn: 900, TokensOut: 600, Budget: []builtin.AIBudgetWindow{{Limit: "tokens_per_minute", Used: 1500, Max: 2000, ResetsInSec: 33}, {Limit: "monthly_tokens", Used: 1500, Max: 1e6, ResetsInSec: 86400 * 9}}},
				{Key: "bob", Requests: 4, TokensIn: 300, TokensOut: 200}}},
		{Route: "shop/other/1"}}}
	srv := fakeAIAdmin(t, doc)
	addr := strings.TrimPrefix(srv.URL, "http://")
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runGateway(append([]string{"ai-usage"}, args...), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, errs := run("--admin", addr, "--admin-token", "tok", "--format", "table")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"shop/llm/1", "12 requests, 1200 tokens in, 800 out", "ejected", "backup", "cache: 3 hits, 9 misses (25% hit rate)",
		"refused by budget: tokens_per_minute 2", "alice", "tokens_per_minute", "75%", "1500 of 2000, resets in 33s", "resets in 9d0h", "shop/other/1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	code, out, _ = run("--admin", addr, "--admin-token", "tok", "--format", "json", "--route", "llm", "--key", "alice")
	var got builtin.AIUsage
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got.Routes) != 1 || len(got.Routes[0].Keys) != 1 || got.Routes[0].Keys[0].Key != "alice" {
		t.Errorf("json filter: %d %s", code, out)
	}
	if code, _, errs = run("--admin", addr, "--format", "table"); code != 1 || !strings.Contains(errs, "401") {
		t.Errorf("no token: %d %s", code, errs)
	}
	if code, _, errs = run("--admin", "127.0.0.1:1", "--admin-token", "tok"); code != 1 || !strings.Contains(errs, "cannot reach") {
		t.Errorf("unreachable: %d %s", code, errs)
	}
	if code, _, _ = run("--format", "xml"); code != 2 {
		t.Errorf("bad format: %d", code)
	}
	if code, _, _ = run("--admin", "not a host"); code != 2 {
		t.Errorf("bad admin: %d", code)
	}
	empty := fakeAIAdmin(t, builtin.AIUsage{Routes: []builtin.AIRouteUsage{}})
	if code, out, _ = run("--admin", strings.TrimPrefix(empty.URL, "http://"), "--admin-token", "tok", "--format", "table"); code != 0 || !strings.Contains(out, "No AI routes") {
		t.Errorf("empty: %d %s", code, out)
	}
}

func TestAIFlagsHelpManCompletion(t *testing.T) {
	var b bytes.Buffer
	Man(&b)
	for _, w := range []string{"AI GATEWAY", "ai\\-usage", "ai\\-prices", "SET040"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("man page lacks %q", w)
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		b.Reset()
		Completion(sh, &b)
		for _, f := range []string{"ai-prices", "ai-max-key-labels"} {
			if !strings.Contains(b.String(), f) {
				t.Errorf("%s completion lacks %s", sh, f)
			}
		}
	}
	// A bad price table is a usage error before anything starts.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gw.json")
	os.WriteFile(cfg, []byte(`{"schema":"setura.route-specs/v1","resources":{}}`), 0o600)
	var out, errb bytes.Buffer
	if code := runGateway([]string{"run", "--config", cfg, "--admin", "off", "--ai-prices", filepath.Join(dir, "missing.json")}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--ai-prices") {
		t.Errorf("missing prices: %d %s", code, errb.String())
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"models":{"m":{"input":-1}}}`), 0o600)
	errb.Reset()
	if code := runGateway([]string{"run", "--config", cfg, "--admin", "off", "--ai-prices", bad}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "per million tokens") {
		t.Errorf("bad prices: %d %s", code, errb.String())
	}
	errb.Reset()
	if code := runGateway([]string{"run", "--config", cfg, "--admin", "off", "--ai-max-key-labels", "-1"}, &out, &errb); code != 2 {
		t.Errorf("negative labels: %d %s", code, errb.String())
	}
}
