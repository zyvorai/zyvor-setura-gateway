package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAIChatForwardsWithVaultedKeyAndAccountsUsage(t *testing.T) {
	up := newLLM(t, "openai-a", "openai")
	prices := filepath.Join(t.TempDir(), "prices.json")
	os.WriteFile(prices, []byte(`{"currency":"USD","models":{"gpt-4o":{"input":2.5,"output":10}}}`), 0o600)
	s, log := aiServer(t, m{"providers": l{llmProv(t, up, nil)}}, func(o *Options) { o.AI.PricesFile = prices })

	r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o-2024-08-06", "hello"),
		"Authorization", "Bearer client-secret-token", "X-Api-Key", "client-key", "Cookie", "sid=1", "X-Setura-Auth-Subject", "root")
	if r.Status != 200 || !strings.Contains(r.Body, "hi from openai-a") {
		t.Fatalf("chat: %d %s", r.Status, r.Body)
	}
	got := up.seen()
	if len(got) != 1 || got[0].Path != "/v1/chat/completions" {
		t.Fatalf("upstream saw %+v", got)
	}
	h := got[0].Header
	if h.Get("Authorization") != "Bearer sk-openai-a-SECRET-0123456789" {
		t.Errorf("provider key not injected: %q", h.Get("Authorization"))
	}
	for _, bad := range []string{"X-Api-Key", "Cookie", "X-Setura-Auth-Subject"} {
		if h.Get(bad) != "" {
			t.Errorf("client header %s reached the provider", bad)
		}
	}
	if r.Header.Get(AIProviderHeader) != "openai-a" {
		t.Errorf("provider header %q", r.Header.Get(AIProviderHeader))
	}

	rec := lastLine(t, s, log)
	if rec["provider"] != "openai-a" || rec["model"] != "gpt-4o-2024-08-06" || num(rec, "tokens_in") != 11 || num(rec, "tokens_out") != 7 {
		t.Fatalf("log record %v", rec)
	}
	want := (11*2.5 + 7*10) / 1e6
	if c := num(rec, "cost_estimate"); c < want-1e-12 || c > want+1e-12 {
		t.Errorf("cost %v, want %v", c, want)
	}
	if strings.Contains(log.String(), "client-secret-token") || strings.Contains(log.String(), "SECRET-0123456789") {
		t.Error("a credential reached the access log")
	}
	mt := metricsText(s)
	for _, w := range []string{
		`setura_ai_tokens_total{route="t/r/1",provider="openai-a",model="gpt-4o-2024-08-06",direction="prompt"} 11`,
		`setura_ai_tokens_total{route="t/r/1",provider="openai-a",model="gpt-4o-2024-08-06",direction="completion"} 7`,
		`setura_ai_requests_total{route="t/r/1",provider="openai-a",model="gpt-4o-2024-08-06",outcome="ok"} 1`,
		`setura_ai_key_tokens_total{route="t/r/1",key="anonymous",direction="prompt"} 11`,
		`setura_ai_provider_up{route="t/r/1",provider="openai-a"} 1`,
	} {
		if !strings.Contains(mt, w) {
			t.Errorf("metrics lack %s", w)
		}
	}
	if !strings.Contains(mt, "setura_ai_cost_estimate_total{") {
		t.Error("no cost metric")
	}
}

func TestAIEmbeddingsAndAnthropicShapes(t *testing.T) {
	oa := newLLM(t, "oa", "openai")
	an := newLLM(t, "claude", "anthropic")
	s, log := aiServer(t, m{"providers": l{llmProv(t, oa, nil), llmProv(t, an, nil)}}, nil)

	r := postJSON(t, s, "/v1/embeddings", m{"model": "text-embedding-3-small", "input": "hello world"})
	if r.Status != 200 {
		t.Fatalf("embeddings: %d %s", r.Status, r.Body)
	}
	rec := lastLine(t, s, log)
	if num(rec, "tokens_in") != 11 || num(rec, "tokens_out") != 0 || rec["provider"] != "oa" {
		t.Errorf("embeddings record %v", rec)
	}

	r = postJSON(t, s, "/v1/messages", m{"model": "claude-sonnet", "max_tokens": 50, "messages": l{m{"role": "user", "content": "hi"}}},
		"Authorization", "Bearer nope")
	if r.Status != 200 || !strings.Contains(r.Body, "hi from claude") {
		t.Fatalf("messages: %d %s", r.Status, r.Body)
	}
	rec = lastLine(t, s, log)
	// 11 input + 3 cache read tokens count as input.
	if rec["provider"] != "claude" || num(rec, "tokens_in") != 14 || num(rec, "tokens_out") != 7 {
		t.Errorf("anthropic record %v", rec)
	}
	h := an.seen()[0].Header
	if h.Get("X-Api-Key") != "sk-claude-SECRET-0123456789" || h.Get("Authorization") != "" || h.Get("Anthropic-Version") == "" {
		t.Errorf("anthropic headers %v", h)
	}
	if len(oa.seen()) != 1 {
		t.Errorf("the messages API went to the OpenAI provider")
	}
}

func TestAIStreamingUsage(t *testing.T) {
	oa := newLLM(t, "oa", "openai")
	an := newLLM(t, "claude", "anthropic")
	s, log := aiServer(t, m{"providers": l{llmProv(t, oa, nil), llmProv(t, an, nil)}}, nil)

	// The client did not ask for usage: the gateway asks the provider and hides the extra chunk.
	r := postJSON(t, s, "/v1/chat/completions", m{"model": "gpt-4o", "stream": true, "messages": l{m{"role": "user", "content": "hi"}}})
	if r.Status != 200 || !strings.Contains(r.Body, `"hel"`) || !strings.Contains(r.Body, "[DONE]") {
		t.Fatalf("stream: %d %q", r.Status, r.Body)
	}
	if strings.Contains(r.Body, `"usage"`) {
		t.Errorf("the injected usage chunk reached a client that did not ask for it: %q", r.Body)
	}
	if v, _ := oa.seen()[0].Body["stream_options"].(map[string]any)["include_usage"].(bool); !v {
		t.Error("the gateway did not ask the provider for usage")
	}
	if rec := lastLine(t, s, log); num(rec, "tokens_in") != 11 || num(rec, "tokens_out") != 7 {
		t.Errorf("stream record %v", rec)
	}

	// The client asked for usage: it keeps the chunk.
	r = postJSON(t, s, "/v1/chat/completions", m{"model": "gpt-4o", "stream": true, "stream_options": m{"include_usage": true}, "messages": l{m{"role": "user", "content": "hi"}}})
	if !strings.Contains(r.Body, `"usage"`) {
		t.Errorf("the usage chunk the client asked for was dropped: %q", r.Body)
	}

	// Anthropic: message_start carries the input, message_delta the output.
	r = postJSON(t, s, "/v1/messages", m{"model": "claude", "stream": true, "max_tokens": 10, "messages": l{m{"role": "user", "content": "hi"}}})
	if !strings.Contains(r.Body, "message_stop") || !strings.Contains(r.Body, "event: message_start") {
		t.Fatalf("anthropic stream %q", r.Body)
	}
	if rec := lastLine(t, s, log); rec["provider"] != "claude" || num(rec, "tokens_in") != 11 || num(rec, "tokens_out") != 7 {
		t.Errorf("anthropic stream record %v", rec)
	}
}

func TestAIStreamWithoutUsageIsEstimated(t *testing.T) {
	oa := newLLM(t, "oa", "openai")
	oa.noUsage = true
	s, log := aiServer(t, m{"providers": l{llmProv(t, oa, nil)}}, nil)
	postJSON(t, s, "/v1/chat/completions", m{"model": "gpt-4o", "stream": true, "messages": l{m{"role": "user", "content": "twelve chars"}}})
	rec := lastLine(t, s, log)
	if rec["tokens_estimated"] != true || num(rec, "tokens_in") == 0 {
		t.Errorf("estimate not flagged: %v", rec)
	}
}

func TestAIRejectsWhatItDoesNotServe(t *testing.T) {
	oa := newLLM(t, "oa", "openai")
	s, _ := aiServer(t, m{"providers": l{llmProv(t, oa, nil)}, "allowedModels": l{"gpt-4o*"}, "maxRequestBytes": 200}, nil)
	for _, c := range []struct {
		path, body string
		status     int
		code       string
	}{
		{"/v1/chat/completions", `not json`, 400, "invalid_json"},
		{"/v1/chat/completions", `{"messages":[]}`, 400, "model_required"},
		{"/v1/chat/completions", `{"model":"llama","messages":[]}`, 403, "model_not_allowed"},
		{"/v1/images", `{"model":"gpt-4o"}`, 404, "unsupported_path"},
		{"/v1/messages", `{"model":"gpt-4o"}`, 404, "no_provider"},
		{"/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.Repeat("x", 300) + `"}]}`, 413, "request_too_large"},
	} {
		r := postJSON(t, s, c.path, c.body)
		if r.Status != c.status || !strings.Contains(r.Body, `"code":"`+c.code+`"`) {
			t.Errorf("%s %.30s: %d %s", c.path, c.body, r.Status, r.Body)
		}
	}
	if r := get(t, s, "a.test", "/v1/chat/completions"); r.Status != 405 {
		t.Errorf("GET: %d", r.Status)
	}
	if len(oa.seen()) != 0 {
		t.Error("a rejected request reached a provider")
	}
}

func TestAIConfigValidation(t *testing.T) {
	for _, c := range []struct{ name, json, want string }{
		{"no providers", `{"providers":[]}`, "at least one provider"},
		{"unknown field", `{"providers":[{"name":"a","baseURL":"https://x"}],"bogus":1}`, "bogus"},
		{"bad url", `{"providers":[{"name":"a","baseURL":"ftp://x"}]}`, "baseURL"},
		{"inline key", `{"providers":[{"name":"a","baseURL":"https://x","apiKey":{"env":"A","file":"/b"}}]}`, "exactly one"},
		{"literal key", `{"providers":[{"name":"a","baseURL":"https://x","apiKey":"sk-abc"}]}`, "apiKey"},
		{"dup name", `{"providers":[{"name":"a","baseURL":"https://x"},{"name":"a","baseURL":"https://y"}]}`, "twice"},
		{"cred header", `{"providers":[{"name":"a","baseURL":"https://x","headers":{"Authorization":"x"}}]}`, "credentials come from apiKey"},
		{"bad identity", `{"providers":[{"name":"a","baseURL":"https://x"}],"identity":"nope"}`, "identity"},
		{"bad pii", `{"providers":[{"name":"a","baseURL":"https://x"}],"pii":{"mode":"x"}}`, "pii.mode"},
		{"bad regex", `{"providers":[{"name":"a","baseURL":"https://x"}],"pii":{"custom":[{"name":"c","pattern":"("}]}}`, "pii.custom"},
		{"negative budget", `{"providers":[{"name":"a","baseURL":"https://x"}],"budget":{"default":{"tokensPerDay":-1}}}`, "negative"},
	} {
		if _, err := ParseAIBlock([]byte(c.json)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	p, err := ParseAIBlock([]byte(`{"providers":[{"name":"a","baseURL":"https://api.openai.com/v1","apiKey":{"secret":{"name":"s","key":"k"}}}]}`))
	if err != nil || p.Providers[0].APIKey.Secret.Key != "k" {
		t.Fatalf("valid block: %v", err)
	}
}

func TestAIRouteWithMissingSecretIsInvalidNotOpen(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	pr := llmProv(t, up, m{"apiKey": m{"env": "SETURA_TEST_NO_SUCH_KEY"}})
	s, _ := aiServer(t, m{"providers": l{pr}}, nil)
	r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if r.Status == 200 || len(up.seen()) != 0 {
		t.Fatalf("a route without its provider key must not serve: %d", r.Status)
	}
	var msg string
	for _, rr := range s.Status().Routes {
		for _, c := range rr.Parents {
			for _, cd := range c.Conditions {
				msg += cd.Message
			}
		}
	}
	if !strings.Contains(msg, "SETURA_TEST_NO_SUCH_KEY") {
		t.Errorf("status does not say why: %q", msg)
	}
}

func TestAIKeyFromFileRotates(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	dir := t.TempDir()
	kf := filepath.Join(dir, "key")
	os.WriteFile(kf, []byte("sk-first-0123456789\n"), 0o600)
	old := aiSecretRecheck
	aiSecretRecheck = 0
	t.Cleanup(func() { aiSecretRecheck = old })
	pr := m{"name": "oa", "baseURL": up.URL + "/v1", "apiKey": m{"file": kf}}
	s, _ := aiServer(t, m{"providers": l{pr}}, nil)
	postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if got := up.seen()[0].Header.Get("Authorization"); got != "Bearer sk-first-0123456789" {
		t.Fatalf("file key: %q", got)
	}
	// Rotation: the file changes and the next request signs with the new key.
	os.WriteFile(kf, []byte("sk-second-0123456789 and more\n"), 0o600)
	postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if got := up.seen()[1].Header.Get("Authorization"); got != "Bearer sk-second-0123456789 and more" {
		t.Errorf("rotated key: %q", got)
	}
	prov := s.Table().aiRules()[0].provs[0]
	if prov.key.desc != "file "+kf {
		t.Errorf("desc %q", prov.key.desc)
	}
}
