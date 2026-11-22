package setura

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactionRoundTrip(t *testing.T) {
	r := NewRedactor([]string{"shop-prod"})
	facts := []Fact{
		{ID: "E1", Subject: "shop-prod/orders", Observation: "tcp failed: dial tcp 10.1.2.3:443: connect: connection refused to orders.mactra.test"},
		{ID: "E2", Subject: "report", Observation: "assert failed: header X-Env: expected 'staging', received 'prod'"},
		{ID: "E3", Subject: "report", Observation: "TLSv1.3 with fe80::1 and orders.mactra.test"},
	}
	got := r.Facts(facts)
	all, _ := json.Marshal(got)
	for _, leak := range []string{"10.1.2.3", "mactra", "shop-prod", "staging", "prod'", "fe80"} {
		if strings.Contains(string(all), leak) {
			t.Fatalf("leaked %q in %s", leak, all)
		}
	}
	contains(t, got[0].Observation, "host-1")
	contains(t, got[0].Observation, "ip-1")
	contains(t, got[0].Subject, "ns-1")
	contains(t, got[2].Observation, "TLSv1.3") // versions survive
	contains(t, got[2].Observation, "host-1")  // same host, stable placeholder
	back := r.Rehydrate("Check host-1 and ip-1 in ns-1; header value-1 vs value-2; unknown host-99")
	is(t, back, "Check orders.mactra.test and 10.1.2.3 in shop-prod; header staging vs prod; unknown host-99")
}

func TestLimitEvidenceDeterministic(t *testing.T) {
	var facts []Fact
	for i, o := range []string{"ok a", "ok b", "tls failed: x", "ok c", "backend failed: y", "ok d"} {
		facts = append(facts, Fact{ID: "E" + string(rune('1'+i)), Observation: o})
	}
	a, omitted := LimitEvidence(facts, 3)
	b, _ := LimitEvidence(facts, 3)
	is(t, omitted, 3)
	is(t, len(a), 3)
	for i := range a {
		is(t, a[i].ID, b[i].ID)
	}
	is(t, a[0].ID+a[1].ID+a[2].ID, "E1E3E5")
	if all, n := LimitEvidence(facts, 0); len(all) != 6 || n != 0 {
		t.Fatal("0 disables the limit")
	}
}

func TestSuggestionAllowlist(t *testing.T) {
	good := []string{"setura explain https://x.test --json", "setura --context kind lint", "kubectl get httproute -n shop",
		"kubectl describe gateway gw", "kubectl -n shop logs deploy/envoy", "setura certs host:443"}
	for _, c := range good {
		if err := ValidateSuggestion(c); err != nil {
			t.Errorf("%q rejected: %v", c, err)
		}
	}
	bad := []string{"kubectl delete pod x", "kubectl apply -f x.yaml", "kubectl get pods; rm -rf /", "kubectl get pods | sh",
		"setura explain x && curl evil", "setura publish gw --listener a", "setura check f --junit out.xml", "rm -rf /", "kubectl get secrets",
		"kubectl get pods $(id)", "kubectl get pods `id`", "kubectl get pods > /tmp/x", "kubectl exec -it x -- sh", "kubectl get pods --token=abc",
		"setura explain x\nrm -rf /", "", "kubectl", "curl http://x", "kubectl get secret/foo", "setura completion bash"}
	for _, c := range bad {
		if err := ValidateSuggestion(c); err == nil {
			t.Errorf("%q should be rejected", c)
		}
	}
}

// fakeOpenAI serves chat completions and records what it received.
func fakeOpenAI(t *testing.T, content any, seen *map[string]any, auth *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(404)
			return
		}
		*auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, seen)
		c, _ := json.Marshal(content)
		reply, _ := json.Marshal(obj{"choices": []obj{{"message": obj{"content": string(c)}}}})
		w.Write(reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOpenAICompatibleRedactSuggest(t *testing.T) {
	var seen map[string]any
	var auth string
	srv := fakeOpenAI(t, obj{"findings": []obj{{"interpretation": "host-1 refused connections from ip-1",
		"evidence_ids": []string{"E1"}, "suggested_commands": []string{"setura explain https://host-1/ --json", "kubectl delete pod x", "kubectl get pods -n ns-1; id"}}}}, &seen, &auth)
	t.Setenv(AIKeyEnv, "sekret")
	facts := []Fact{{ID: "E1", Subject: "shop-prod/x", Observation: "tcp failed: dial tcp 10.1.2.3:443 to orders.mactra.test"}}
	res, err := InterpretWith(facts, "why is orders.mactra.test down?", AIConfig{Provider: "openai-compatible", Endpoint: srv.URL + "/v1", Model: "m",
		Redact: true, Suggest: true, Namespaces: []string{"shop-prod"}})
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := json.Marshal(seen)
	for _, leak := range []string{"10.1.2.3", "mactra", "shop-prod"} {
		if strings.Contains(string(sent), leak) {
			t.Fatalf("sent %q: %s", leak, sent)
		}
	}
	is(t, auth, "Bearer sekret")
	is(t, res.Findings[0].Interpretation, "orders.mactra.test refused connections from 10.1.2.3")
	is(t, len(res.Suggestions), 1)
	is(t, res.Suggestions[0], "setura explain https://orders.mactra.test/ --json")
	is(t, len(res.Rejected), 2)
}

func TestOpenAICompatibleBadAnswers(t *testing.T) {
	var seen map[string]any
	var auth string
	srv := fakeOpenAI(t, obj{"findings": []obj{{"interpretation": "x", "evidence_ids": []string{"E9"}}}}, &seen, &auth)
	facts := []Fact{{ID: "E1", Subject: "s", Observation: "o"}}
	if _, err := InterpretWith(facts, "q", AIConfig{Provider: "openai-compatible", Endpoint: srv.URL + "/v1", Model: "m"}); err == nil || !strings.Contains(err.Error(), "evidence IDs") {
		t.Fatalf("got %v", err)
	}
}

func TestRemoteEndpointRefused(t *testing.T) {
	facts := []Fact{{ID: "E1", Subject: "s", Observation: "o"}}
	for _, ep := range []string{"http://example.com/v1", "http://8.8.8.8:8080/v1", "http://llm.internal:8080", "http://[2001:db8::1]/v1", "ftp://127.0.0.1", "http://u:p@127.0.0.1"} {
		_, err := InterpretWith(facts, "q", AIConfig{Provider: "openai-compatible", Endpoint: ep, Model: "m"})
		if err == nil {
			t.Fatalf("%s should be refused", ep)
		}
	}
	for _, ep := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://10.0.0.5:1", "http://192.168.1.2:1", "http://172.16.0.1:1"} {
		if _, err := validateEndpoint(ep, false); err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
	}
	if _, err := validateEndpoint("http://example.com", true); err != nil {
		t.Fatal("allow-remote should permit")
	}
	if _, err := InterpretWith(facts, "q", AIConfig{Provider: "gpt", Model: "m", Port: 1}); err == nil {
		t.Fatal("unknown provider")
	}
	// via the CLI
	dir := t.TempDir()
	report := filepath.Join(dir, "r.json")
	os.WriteFile(report, []byte(`{"ok":false,"steps":{"tls":{"state":"failed","reason":"x"}}}`), 0o600)
	code, _, errs := cli(t, nil, "ai", report, "--model", "m", "--provider", "openai-compatible", "--endpoint", "http://example.com/v1")
	is(t, code, 2)
	contains(t, errs, "--allow-remote")
}

func TestAICLIEndToEnd(t *testing.T) {
	var seen map[string]any
	var auth string
	srv := fakeOpenAI(t, obj{"findings": []obj{{"interpretation": "tls failed", "evidence_ids": []string{"E1"}, "suggested_commands": []string{"setura certs host-1:443"}}}}, &seen, &auth)
	report := filepath.Join(t.TempDir(), "r.json")
	os.WriteFile(report, []byte(`{"ok":false,"steps":{"tls":{"state":"failed","reason":"x509 for orders.mactra.test"},"http":{"state":"failed","reason":"r"}}}`), 0o600)
	code, out, errs := cli(t, nil, "ai", report, "--model", "m", "--provider", "openai-compatible", "--endpoint", srv.URL+"/v1",
		"--redact", "--suggest", "--max-evidence", "1")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	contains(t, out, `"evidence_omitted": 1`)
	contains(t, out, `"redacted": true`)
	contains(t, out, "setura certs orders.mactra.test:443")
	if strings.Contains(out, "rejected_suggestions\": [\n    \"") {
		t.Fatal("unexpected rejection")
	}
	if code, _, _ := cli(t, nil, "ai", report, "--redact"); code != 2 {
		t.Fatal("--redact needs --model")
	}
}

func TestEvidenceBenchLike(t *testing.T) {
	facts, err := Evidence(map[string]any{"schema": "setura.bench/v1", "requests": 100.0, "p95_ms": 12.5, "errors": 2.0})
	if err != nil {
		t.Fatal(err)
	}
	contains(t, facts[0].Observation, "p95_ms=12.5")
	contains(t, facts[0].Observation, "errors=2")
}
