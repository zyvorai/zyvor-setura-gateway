package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// aiServerRule is aiServer with extra fields on the rule (an auth policy, for identities).
func aiServerRule(t *testing.T, policy, extra m, mod func(*Options)) (*Server, *syncBuf) {
	t.Helper()
	log := &syncBuf{}
	r := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/"}}}, aiKeyT: policy}
	for k, v := range extra {
		r[k] = v
	}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, nil), func(o *Options) {
		o.AccessLog = log
		o.AuthClock = func() time.Time { return t0 }
		if mod != nil {
			mod(o)
		}
	})
	return s, log
}

func apiKeyAuth(names ...string) m {
	var ks l
	for _, n := range names {
		ks = append(ks, m{"name": n, "key": "k-" + n})
	}
	return m{"setura.zyvor.dev/auth": m{"apiKey": m{"header": "X-Api-Key", "keys": ks}}}
}

func attemptsOf(t *testing.T, raw string) []aiTry {
	t.Helper()
	var doc struct {
		Error struct {
			Attempts []aiTry `json:"attempts"`
		} `json:"error"`
	}
	json.Unmarshal([]byte(raw), &doc)
	return doc.Error.Attempts
}

// ---- failover -------------------------------------------------------------

func TestAIFailoverReSignsAndEjectsOutlier(t *testing.T) {
	p1, p2 := newLLM(t, "p1", "openai"), newLLM(t, "p2", "openai")
	p1.status = func(int) int { return 500 }
	s, log := aiServer(t, m{"providers": l{llmProv(t, p1, nil), llmProv(t, p2, m{"priority": 1})}},
		func(o *Options) { o.Resilience.OutlierFailures = 2 })

	for i := 0; i < 2; i++ {
		r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
		if r.Status != 200 || r.Header.Get(AIProviderHeader) != "p2" {
			t.Fatalf("request %d: %d via %q: %s", i, r.Status, r.Header.Get(AIProviderHeader), r.Body)
		}
	}
	// Each provider was called with its own key: the request was re-signed for the second.
	if got := p1.seen()[0].Header.Get("Authorization"); got != "Bearer sk-p1-SECRET-0123456789" {
		t.Errorf("p1 key %q", got)
	}
	if got := p2.seen()[0].Header.Get("Authorization"); got != "Bearer sk-p2-SECRET-0123456789" {
		t.Errorf("p2 key %q", got)
	}
	rec := lastLine(t, s, log)
	if rec["provider"] != "p2" || num(rec, "retries") != 1 {
		t.Errorf("log %v", rec)
	}
	// Two consecutive failures ejected p1 (the existing outlier machinery): it is skipped now.
	before := p1.count()
	r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if r.Status != 200 || p1.count() != before {
		t.Errorf("ejected provider was called again (%d -> %d)", before, p1.count())
	}
	mt := metricsText(s)
	for _, w := range []string{
		`setura_ai_failovers_total{route="t/r/1",from="p1",to="p2"} 2`,
		`setura_ai_provider_up{route="t/r/1",provider="p1"} 0`,
		`setura_ai_provider_up{route="t/r/1",provider="p2"} 1`,
		`setura_gateway_ejections_total{backend="ai/t/r/1"} 1`,
	} {
		if !strings.Contains(mt, w) {
			t.Errorf("metrics lack %s", w)
		}
	}
}

func TestAIFailoverOn429AndTimeout(t *testing.T) {
	p1, p2 := newLLM(t, "p1", "openai"), newLLM(t, "p2", "openai")
	p1.status = func(n int) int {
		if n == 1 {
			return 429
		}
		return 0
	}
	p1.hang = func(n int) bool { return n == 2 }
	s, _ := aiServer(t, m{"providers": l{llmProv(t, p1, m{"timeout": "100ms"}), llmProv(t, p2, m{"priority": 1})}}, nil)
	for i, name := range []string{"429", "timeout"} {
		r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
		if r.Status != 200 || r.Header.Get(AIProviderHeader) != "p2" {
			t.Fatalf("%s: %d via %q: %s", name, r.Status, r.Header.Get(AIProviderHeader), r.Body)
		}
		if p1.count() != i+1 {
			t.Fatalf("%s: p1 calls %d", name, p1.count())
		}
	}
	// A 4xx other than 429 is the client's problem: no failover.
	p1.status = func(int) int { return 400 }
	if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); r.Status != 400 || p2.count() != 2 {
		t.Errorf("400 must not fail over: %d, p2 calls %d", r.Status, p2.count())
	}
}

func TestAIAllProvidersFailRelaysLastAndScrubsKeys(t *testing.T) {
	p1, p2 := newLLM(t, "p1", "openai"), newLLM(t, "p2", "openai")
	p1.status = func(int) int { return 500 }
	p2.status = func(int) int { return 429 }
	s, log := aiServer(t, m{"providers": l{llmProv(t, p1, nil), llmProv(t, p2, m{"priority": 1})}}, nil)
	r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if r.Status != 429 || r.Header.Get("Retry-After") != "7" {
		t.Fatalf("last answer should be relayed: %d %v", r.Status, r.Header)
	}
	if strings.Contains(r.Body, "SECRET-0123456789") || strings.Contains(log.String(), "SECRET-0123456789") {
		t.Errorf("provider key leaked: %s", r.Body)
	}
	if !strings.Contains(r.Body, redacted) {
		t.Errorf("expected the quoted key to be replaced: %s", r.Body)
	}

	// Transport failures on every provider: 502 with the attempt list.
	dead := newLLM(t, "dead", "openai")
	dead.Close()
	s2, _ := aiServer(t, m{"providers": l{llmProv(t, dead, nil)}}, nil)
	r = postJSON(t, s2, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if r.Status != 502 || len(attemptsOf(t, r.Body)) != 1 || strings.Contains(r.Body, "SECRET") {
		t.Errorf("dead provider: %d %s", r.Status, r.Body)
	}
}

func TestAIWeightsAndPriority(t *testing.T) {
	a, b, standby := newLLM(t, "a", "openai"), newLLM(t, "b", "openai"), newLLM(t, "standby", "openai")
	s, _ := aiServer(t, m{"providers": l{llmProv(t, a, m{"weight": 3}), llmProv(t, b, m{"weight": 1}), llmProv(t, standby, m{"priority": 1})}}, nil)
	for i := 0; i < 200; i++ {
		if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); r.Status != 200 {
			t.Fatal(r.Status)
		}
	}
	if standby.count() != 0 {
		t.Errorf("a lower priority provider got %d requests while the first tier was healthy", standby.count())
	}
	if a.count() < 2*b.count() || b.count() < 20 || a.count()+b.count() != 200 {
		t.Errorf("weights 3:1 gave %d:%d", a.count(), b.count())
	}
}

func TestAIProviderModelsAndModelMap(t *testing.T) {
	small, big := newLLM(t, "small", "openai"), newLLM(t, "big", "openai")
	s, _ := aiServer(t, m{"providers": l{
		llmProv(t, small, m{"models": l{"mini*"}, "modelMap": m{"mini-1": "provider-mini-v2"}}),
		llmProv(t, big, m{"models": l{"gpt-4o"}, "priority": 1}),
	}}, nil)
	postJSON(t, s, "/v1/chat/completions", chat("mini-1", "hi"))
	postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"))
	if small.count() != 1 || big.count() != 1 {
		t.Fatalf("model routing: small %d big %d", small.count(), big.count())
	}
	if got := small.seen()[0].Body["model"]; got != "provider-mini-v2" {
		t.Errorf("modelMap not applied: %v", got)
	}
}

// ---- budgets --------------------------------------------------------------

func budgetServer(t *testing.T, policy m, extra m) (*Server, *syncBuf, *fakeClock, *fakeLLM) {
	t.Helper()
	up := newLLM(t, "oa", "openai")
	clk := &fakeClock{t: time.Date(2030, 1, 15, 12, 30, 10, 0, time.UTC)}
	policy["providers"] = l{llmProv(t, up, nil)}
	s, log := aiServerRule(t, policy, extra, func(o *Options) { o.AI.Clock = clk.now })
	return s, log, clk, up
}

func budgetReq(model string, max int) m {
	r := chat(model, "hello there")
	r["max_tokens"] = max
	return r
}

func TestAITokensPerMinuteReconcilesAndRecovers(t *testing.T) {
	s, _, clk, up := budgetServer(t, m{"identity": "apikey", "budget": m{"default": m{"tokensPerMinute": 100}, "overrides": m{"bob": m{"tokensPerMinute": 1000}}}}, apiKeyAuth("alice", "bob"))
	post := func(who string) reply {
		return postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-"+who)
	}
	// Each request reserves about 66 tokens and is settled to the real 18, so two fit
	// (reserve-only accounting would refuse the second).
	if r := post("alice"); r.Status != 200 {
		t.Fatalf("1st: %d %s", r.Status, r.Body)
	}
	if r := post("alice"); r.Status != 200 {
		t.Fatalf("2nd: %d %s (the reservation was not settled)", r.Status, r.Body)
	}
	r := post("alice")
	if r.Status != 429 {
		t.Fatalf("3rd: %d %s", r.Status, r.Body)
	}
	if ra := r.Header.Get("Retry-After"); ra != "51" { // 12:30:10 -> 12:31:00 plus the second the window needs
		t.Errorf("Retry-After %q", ra)
	}
	var doc struct {
		Error struct {
			Code   string   `json:"code"`
			Type   string   `json:"type"`
			Budget AIDenial `json:"budget"`
		} `json:"error"`
	}
	json.Unmarshal([]byte(r.Body), &doc)
	if doc.Error.Code != "token_budget_exceeded" || doc.Error.Budget.Limit != "tokens_per_minute" || doc.Error.Budget.Max != 100 || doc.Error.Budget.Used != 36 {
		t.Errorf("error body %s", r.Body)
	}
	if up.count() != 2 {
		t.Errorf("a refused request reached the provider: %d calls", up.count())
	}
	// Another identity has its own budget (and a larger override).
	for i := 0; i < 5; i++ {
		if r := post("bob"); r.Status != 200 {
			t.Fatalf("bob %d: %d", i, r.Status)
		}
	}
	// A new minute: alice may call again.
	clk.add(time.Minute)
	if r := post("alice"); r.Status != 200 {
		t.Errorf("after the window: %d %s", r.Status, r.Body)
	}
	if !strings.Contains(metricsText(s), `setura_ai_budget_rejections_total{route="t/r/1",limit="tokens_per_minute"} 1`) {
		t.Error("rejection not counted")
	}
	if !strings.Contains(metricsText(s), `setura_ai_key_tokens_total{route="t/r/1",key="alice",direction="prompt"} 33`) {
		t.Errorf("per key counters:\n%s", metricsText(s))
	}
}

func TestAIDailyAndMonthlyBudgets(t *testing.T) {
	s, _, clk, _ := budgetServer(t, m{"identity": "apikey", "budget": m{"default": m{"tokensPerDay": 80, "monthlyTokens": 150}}}, apiKeyAuth("alice"))
	post := func() reply {
		return postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice")
	}
	if r := post(); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// Day: 18 used, 66 more would pass 80 -> 429 until midnight (11h29m50s -> 41391s).
	r := post()
	if r.Status != 429 || r.Header.Get("Retry-After") != "41391" || !strings.Contains(r.Body, "tokens_per_day") {
		t.Fatalf("daily: %d %v %s", r.Status, r.Header, r.Body)
	}
	clk.add(24 * time.Hour) // 16 Jan 12:30:10
	if r := post(); r.Status != 200 {
		t.Fatalf("next day: %d", r.Status)
	}
	clk.add(24 * time.Hour)
	if r := post(); r.Status != 200 { // monthly used 54
		t.Fatalf("third day: %d", r.Status)
	}
	clk.add(24 * time.Hour)
	for i := 0; i < 3; i++ {
		clk.add(24 * time.Hour)
		post()
	}
	r = post()
	if r.Status != 429 || !strings.Contains(r.Body, "monthly_tokens") {
		t.Fatalf("monthly: %d %s", r.Status, r.Body)
	}
	secs, _ := time.ParseDuration(r.Header.Get("Retry-After") + "s")
	if want := time.Date(2030, 2, 1, 0, 0, 0, 0, time.UTC).Sub(clk.now()); secs < want || secs > want+2*time.Second {
		t.Errorf("monthly Retry-After %v, want about %v", secs, want)
	}
	clk.add(secs)
	if r := post(); r.Status != 200 {
		t.Errorf("new month: %d %s", r.Status, r.Body)
	}
}

func TestAIMonthlyCostBudgetAndRouteBudget(t *testing.T) {
	s, _, _, _ := budgetServer(t, m{"identity": "apikey",
		"prices": m{"gpt-4o": m{"input": 1000000, "output": 1000000}}, // one currency unit per token
		"budget": m{"default": m{"monthlyCost": 100}}}, apiKeyAuth("alice"))
	post := func(s *Server, who string) reply {
		return postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-"+who)
	}
	post(s, "alice")
	post(s, "alice")
	if r := post(s, "alice"); r.Status != 429 || !strings.Contains(r.Body, "monthly_cost") {
		t.Fatalf("cost: %d %s", r.Status, r.Body)
	}

	// The route limit caps everyone together: 5 requests of about 18 tokens, the sixth would pass 150.
	rs, _, _, _ := budgetServer(t, m{"identity": "apikey", "budget": m{"route": m{"tokensPerMinute": 150}}}, apiKeyAuth("alice", "bob"))
	for i := 0; i < 5; i++ {
		if r := post(rs, []string{"alice", "bob"}[i%2]); r.Status != 200 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Body)
		}
	}
	if r := post(rs, "alice"); r.Status != 429 || !strings.Contains(r.Body, `"scope":"route"`) {
		t.Errorf("route budget: %d %s", r.Status, r.Body)
	}
}

func TestAIBudgetByJWTClaimAndHeader(t *testing.T) {
	k := newRSAKey(t, "k1")
	auth := m{"setura.zyvor.dev/auth": m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}}}
	s, _, _, _ := budgetServer(t, m{"identity": "claim:org", "budget": m{"default": m{"tokensPerMinute": 100}}}, auth)
	tok := func(org, sub string) string {
		return "Bearer " + k.sign(t, nil, claims(map[string]any{"org": org, "sub": sub}))
	}
	post := func(org, sub string) reply {
		return postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "Authorization", tok(org, sub))
	}
	post("acme", "u1")
	post("acme", "u2") // another user of the same org shares the budget
	if r := post("acme", "u3"); r.Status != 429 {
		t.Errorf("org budget not shared: %d", r.Status)
	}
	if r := post("globex", "u1"); r.Status != 200 {
		t.Errorf("another org: %d", r.Status)
	}

	// Tenant header: missing identity is refused (fail closed), not pooled.
	s2, _, _, _ := budgetServer(t, m{"identity": "header:X-Tenant", "budget": m{"default": m{"tokensPerMinute": 100}}}, nil)
	if r := postJSON(t, s2, "/v1/chat/completions", budgetReq("gpt-4o", 60)); r.Status != 401 || !strings.Contains(r.Body, "identity_required") {
		t.Errorf("no tenant: %d %s", r.Status, r.Body)
	}
	postJSON(t, s2, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Tenant", "t1")
	postJSON(t, s2, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Tenant", "t1")
	if r := postJSON(t, s2, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Tenant", "t1"); r.Status != 429 {
		t.Errorf("tenant budget: %d", r.Status)
	}
	if r := postJSON(t, s2, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Tenant", "t2"); r.Status != 200 {
		t.Errorf("other tenant: %d", r.Status)
	}
}

func TestAIFailedRequestsReleaseTheirReservation(t *testing.T) {
	s, _, _, up := budgetServer(t, m{"identity": "apikey", "budget": m{"default": m{"tokensPerMinute": 100}}}, apiKeyAuth("alice"))
	up.status = func(n int) int {
		if n <= 5 {
			return 500
		}
		return 0
	}
	for i := 0; i < 5; i++ {
		if r := postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice"); r.Status != 500 {
			t.Fatalf("%d: %d", i, r.Status)
		}
	}
	if r := postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice"); r.Status != 200 {
		t.Errorf("failures consumed the budget: %d %s", r.Status, r.Body)
	}
}

func TestAIUsageEndpoint(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	clk := &fakeClock{t: time.Date(2030, 1, 15, 12, 30, 10, 0, time.UTC)}
	s, _ := aiServerRule(t, m{"providers": l{llmProv(t, up, nil)}, "identity": "apikey", "budget": m{"default": m{"tokensPerMinute": 1000}},
		"cache": m{"enabled": true}}, apiKeyAuth("alice"), func(o *Options) { o.AI.Clock = clk.now; o.Admin = "127.0.0.1:0" })
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice")
	postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice")
	resp, err := http.Get("http://" + s.AdminAddr() + "/ai/usage")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var u AIUsage
	if err := json.Unmarshal(raw, &u); err != nil || len(u.Routes) != 1 {
		t.Fatalf("usage: %v %s", err, raw)
	}
	rt := u.Routes[0]
	if rt.Requests != 2 || rt.TokensIn != 11 || rt.TokensOut != 7 || rt.Cache == nil || rt.Cache.Hits != 1 || rt.Cache.Misses != 1 || rt.Cache.Entries != 1 {
		t.Errorf("route usage %+v cache %+v", rt, rt.Cache)
	}
	if len(rt.Keys) != 1 || rt.Keys[0].Key != "alice" || len(rt.Keys[0].Budget) != 1 || rt.Keys[0].Budget[0].Used != 18 || rt.Keys[0].Budget[0].Max != 1000 {
		t.Errorf("key usage %+v", rt.Keys)
	}
	if len(rt.Providers) != 1 || rt.Providers[0].State != "healthy" || rt.Providers[0].Attempts != 1 {
		t.Errorf("providers %+v", rt.Providers)
	}
}

// ---- cache ----------------------------------------------------------------

func cacheServer(t *testing.T, cache m, extra m, mod func(*Options)) (*Server, *syncBuf, *fakeClock, *fakeLLM) {
	t.Helper()
	up := newLLM(t, "oa", "openai")
	clk := &fakeClock{t: time.Date(2030, 1, 15, 12, 30, 10, 0, time.UTC)}
	cache["enabled"] = true
	s, log := aiServerRule(t, m{"providers": l{llmProv(t, up, nil)}, "cache": cache, "identity": "header:X-Tenant"}, extra, func(o *Options) {
		o.AI.Clock = clk.now
		if mod != nil {
			mod(o)
		}
	})
	return s, log, clk, up
}

func TestAICacheHitMissCanonicalKeyTTL(t *testing.T) {
	s, log, clk, up := cacheServer(t, m{"ttl": "1m"}, nil, nil)
	ask := func(body any, hdr ...string) reply {
		return postJSON(t, s, "/v1/chat/completions", body, append(hdr, "X-Tenant", "t1")...)
	}
	r := ask(`{"model":"gpt-4o","temperature":0,"messages":[{"role":"user","content":"hi"}]}`)
	if r.Status != 200 || r.Header.Get(AICacheHeader) != "MISS" {
		t.Fatalf("first: %d %q", r.Status, r.Header.Get(AICacheHeader))
	}
	// Same request, different key order and whitespace, plus an ignored field: a hit with the same body.
	r2 := ask(`{ "messages": [ {"content":"hi","role":"user"} ], "user":"someone", "temperature": 0, "model":"gpt-4o" }`)
	if r2.Header.Get(AICacheHeader) != "HIT" || r2.Body != r.Body || up.count() != 1 {
		t.Fatalf("second: %q calls %d", r2.Header.Get(AICacheHeader), up.count())
	}
	rec := lastLine(t, s, log)
	if rec["cache_hit"] != true || num(rec, "tokens_in") != 0 || num(rec, "cost_estimate") != 0 {
		t.Errorf("hit record %v", rec)
	}
	// Different parameters or prompt: a miss.
	if r := ask(`{"model":"gpt-4o","temperature":1,"messages":[{"role":"user","content":"hi"}]}`); r.Header.Get(AICacheHeader) != "MISS" {
		t.Error("temperature is part of the key")
	}
	if r := ask(chat("gpt-4o", "other")); r.Header.Get(AICacheHeader) != "MISS" {
		t.Error("the prompt is part of the key")
	}
	// TTL.
	clk.add(61 * time.Second)
	if r := ask(`{"model":"gpt-4o","temperature":0,"messages":[{"role":"user","content":"hi"}]}`); r.Header.Get(AICacheHeader) != "MISS" {
		t.Error("an entry outlived its ttl")
	}
}

func TestAICacheScopeIdentityAndRoute(t *testing.T) {
	s, _, _, up := cacheServer(t, m{}, nil, nil)
	post := func(tenant string) reply {
		return postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "same"), "X-Tenant", tenant)
	}
	post("a")
	if r := post("b"); r.Header.Get(AICacheHeader) != "MISS" || up.count() != 2 {
		t.Errorf("one tenant was served another tenant's cached answer")
	}
	if r := post("a"); r.Header.Get(AICacheHeader) != "HIT" {
		t.Error("same tenant should hit")
	}
	shared, _, _, up2 := cacheServer(t, m{"scope": "route"}, nil, nil)
	postJSON(t, shared, "/v1/chat/completions", chat("gpt-4o", "same"), "X-Tenant", "a")
	if r := postJSON(t, shared, "/v1/chat/completions", chat("gpt-4o", "same"), "X-Tenant", "b"); r.Header.Get(AICacheHeader) != "HIT" || up2.count() != 1 {
		t.Error("route scope should share")
	}
}

func TestAICacheLRUIsBounded(t *testing.T) {
	s, _, _, up := cacheServer(t, m{"maxEntries": 2}, nil, nil)
	ask := func(q string) reply {
		return postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", q), "X-Tenant", "t")
	}
	ask("one")
	ask("two")
	ask("one") // refresh one: two is now the least recently used
	ask("three")
	if r := ask("one"); r.Header.Get(AICacheHeader) != "HIT" {
		t.Error("most recently used entry was evicted")
	}
	if r := ask("two"); r.Header.Get(AICacheHeader) != "MISS" {
		t.Error("least recently used entry survived")
	}
	u := s.Usage().Routes[0]
	if u.Cache.Entries != 2 || u.Cache.Evicted < 2 {
		t.Errorf("cache %+v", u.Cache)
	}
	_ = up
	// Entries above maxEntryBytes are not stored.
	big, _, _, upBig := cacheServer(t, m{"maxEntryBytes": 10}, nil, nil)
	postJSON(t, big, "/v1/chat/completions", chat("gpt-4o", "x"), "X-Tenant", "t")
	if r := postJSON(t, big, "/v1/chat/completions", chat("gpt-4o", "x"), "X-Tenant", "t"); r.Header.Get(AICacheHeader) != "MISS" || upBig.count() != 2 {
		t.Error("an oversized entry was cached")
	}
}

func TestAICacheSkipsStreamingUnlessAsked(t *testing.T) {
	s, _, _, up := cacheServer(t, m{}, nil, nil)
	st := m{"model": "gpt-4o", "stream": true, "messages": l{m{"role": "user", "content": "hi"}}}
	for i := 0; i < 2; i++ {
		r := postJSON(t, s, "/v1/chat/completions", st, "X-Tenant", "t")
		if r.Header.Get(AICacheHeader) != "" {
			t.Errorf("streams are not cached by default: %q", r.Header.Get(AICacheHeader))
		}
	}
	if up.count() != 2 {
		t.Errorf("calls %d", up.count())
	}

	s2, _, _, up2 := cacheServer(t, m{"stream": true}, nil, nil)
	r1 := postJSON(t, s2, "/v1/chat/completions", st, "X-Tenant", "t")
	r2 := postJSON(t, s2, "/v1/chat/completions", st, "X-Tenant", "t")
	if r1.Header.Get(AICacheHeader) != "MISS" || r2.Header.Get(AICacheHeader) != "HIT" || r2.Body != r1.Body || up2.count() != 1 {
		t.Fatalf("stream cache: %q %q calls %d\n%q\n%q", r1.Header.Get(AICacheHeader), r2.Header.Get(AICacheHeader), up2.count(), r1.Body, r2.Body)
	}
	if !strings.HasPrefix(r2.Header.Get("Content-Type"), "text/event-stream") || !strings.Contains(r2.Body, "[DONE]") {
		t.Errorf("replayed stream: %v %q", r2.Header, r2.Body)
	}
}

func TestAICacheHitsAreFreeAndErrorsAreNotCached(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	up.status = func(n int) int {
		if n == 1 {
			return 500
		}
		return 0
	}
	s, _ := aiServerRule(t, m{"providers": l{llmProv(t, up, nil)}, "cache": m{"enabled": true}, "identity": "apikey",
		"budget": m{"default": m{"tokensPerMinute": 100}}}, apiKeyAuth("alice"), nil)
	post := func() reply {
		return postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice")
	}
	if r := post(); r.Status != 500 {
		t.Fatalf("first: %d", r.Status)
	}
	if r := post(); r.Status != 200 || r.Header.Get(AICacheHeader) != "MISS" {
		t.Fatalf("an error must not be cached: %d %q", r.Status, r.Header.Get(AICacheHeader))
	}
	for i := 0; i < 20; i++ {
		if r := post(); r.Status != 200 || r.Header.Get(AICacheHeader) != "HIT" {
			t.Fatalf("hit %d: %d %q (hits must not spend budget)", i, r.Status, r.Header.Get(AICacheHeader))
		}
	}
}

// ---- PII ------------------------------------------------------------------

const piiPrompt = "mail bob@example.com, call (415) 555-2671 or +14155552671, card 4111 1111 1111 1111, " +
	"not a card 4111 1111 1111 1112, ssn 123-45-6789, not ssn 000-12-3456, order EMP-123456"

func TestAIPIIRedactsBeforeTheProviderAndTheCache(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	s, log := aiServer(t, m{"providers": l{llmProv(t, up, nil)}, "cache": m{"enabled": true},
		"pii": m{"mode": "redact", "custom": l{m{"name": "employee", "pattern": `EMP-\d{6}`}}}}, nil)
	body := m{"model": "gpt-4o", "system": "system bob@example.com", "messages": l{
		m{"role": "user", "content": piiPrompt},
		m{"role": "user", "content": l{m{"type": "text", "text": "again alice@example.org"}}},
	}}
	r := postJSON(t, s, "/v1/chat/completions", body)
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	raw := up.seen()[0].Raw
	for _, leaked := range []string{"bob@example.com", "alice@example.org", "555-2671", "4155552671", "4111 1111 1111 1111", "123-45-6789", "EMP-123456"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("provider saw %q", leaked)
		}
	}
	for _, kept := range []string{"[REDACTED:email]", "[REDACTED:phone]", "[REDACTED:card]", "[REDACTED:ssn]", "[REDACTED:employee]", "4111 1111 1111 1112", "000-12-3456"} {
		if !strings.Contains(raw, kept) {
			t.Errorf("provider body lacks %q: %s", kept, raw)
		}
	}
	rec := lastLine(t, s, log)
	// 3 emails, 2 phones, 1 card, 1 ssn, 1 custom.
	if num(rec, "pii_findings") != 8 || rec["pii_action"] != "redacted" {
		t.Errorf("log %v", rec)
	}
	if strings.Contains(log.String(), "example.com") || strings.Contains(log.String(), "4111") {
		t.Error("PII reached the access log")
	}
	mt := metricsText(s)
	if !strings.Contains(mt, `setura_ai_pii_findings_total{route="t/r/1",rule="email",action="redacted"} 3`) || !strings.Contains(mt, `rule="card",action="redacted"} 1`) {
		t.Errorf("pii metrics:\n%s", mt)
	}
	// Two prompts that differ only in the personal data share one cache entry: the cache never held the original.
	a := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "contact x@one.com now"))
	b := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "contact y@two.com now"))
	if a.Header.Get(AICacheHeader) != "MISS" || b.Header.Get(AICacheHeader) != "HIT" {
		t.Errorf("cache keys %q %q", a.Header.Get(AICacheHeader), b.Header.Get(AICacheHeader))
	}
}

func TestAIPIIBlockAndReport(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	s, log := aiServer(t, m{"providers": l{llmProv(t, up, nil)}, "pii": m{"mode": "block", "rules": l{"email", "card"}}}, nil)
	r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "write to bob@example.com, ssn 123-45-6789"))
	if r.Status != 400 || !strings.Contains(r.Body, "pii_detected") || !strings.Contains(r.Body, `"email":1`) {
		t.Fatalf("block: %d %s", r.Status, r.Body)
	}
	if strings.Contains(r.Body, "example.com") || up.count() != 0 {
		t.Errorf("blocked request leaked or was forwarded: %s calls %d", r.Body, up.count())
	}
	if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "ssn 123-45-6789 only")); r.Status != 200 {
		t.Errorf("rules not selected must not block: %d", r.Status)
	}
	if rec := aiLogLines(t, s, log)[0]; rec["pii_action"] != "blocked" || num(rec, "pii_findings") != 1 {
		t.Errorf("block record %v", rec)
	}

	rep, replog := aiServer(t, m{"providers": l{llmProv(t, up, nil)}, "pii": m{"mode": "report"}}, nil)
	r = postJSON(t, rep, "/v1/chat/completions", chat("gpt-4o", "mail bob@example.com"))
	if r.Status != 200 {
		t.Fatal(r.Status)
	}
	if !strings.Contains(up.seen()[len(up.seen())-1].Raw, "bob@example.com") {
		t.Error("report mode must not change the request")
	}
	rec := lastLine(t, rep, replog)
	if rec["pii_action"] != "reported" || num(rec, "pii_findings") != 1 || strings.Contains(replog.String(), "bob@example.com") {
		t.Errorf("report record %v", rec)
	}
}

func TestPIIDetectors(t *testing.T) {
	for s, want := range map[string]bool{"4111 1111 1111 1111": true, "4111-1111-1111-1111": true, "4111111111111111": true, "4111 1111 1111 1112": false,
		"378282246310005": true, "1234": false, "0000 0000 0000 0000 0": false} {
		if got := luhnOK(s); got != want {
			t.Errorf("luhn(%q) = %v", s, got)
		}
	}
	c, err := compilePII(&AIPII{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"call 415-555-2671":       "call [REDACTED:phone]",
		"date 2024-01-15 ok":      "date 2024-01-15 ok",
		"id 000-12-3456":          "id 000-12-3456",
		"id 987-65-4321":          "id 987-65-4321", // 9xx areas are never issued
		"a.b+c@sub.example.co.uk": "[REDACTED:email]",
		"version 1.2.3":           "version 1.2.3",
	}
	for in, want := range cases {
		body := map[string]any{"input": in}
		c.apply(body)
		if body["input"] != want {
			t.Errorf("%q -> %q, want %q", in, body["input"], want)
		}
	}
	// Structure is not text: roles, ids and image data are left alone.
	body := map[string]any{"messages": []any{map[string]any{"role": "user", "name": "bob@example.com", "content": []any{map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,415-555-2671"}}}}}}
	if _, changed := c.apply(body); changed {
		t.Error("non-prompt fields were rewritten")
	}
}

// ---- secrets --------------------------------------------------------------

func TestAIKubernetesSecretKeys(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	mk := func(ns string) []byte {
		pr := m{"name": "oa", "baseURL": up.URL + "/v1", "apiKey": m{"secret": m{"name": "llm", "namespace": ns, "key": "token"}}}
		r := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/"}}}, aiKeyT: m{"providers": l{pr}}}
		return snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, nil)
	}
	apply := func(raw []byte, keys map[string]string) *Server {
		cfg, err := ParseConfig(raw, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cfg.AIKeys = keys
		s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off", Rand: seededRand(1)})
		t.Cleanup(s.Close)
		if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := apply(mk("t"), map[string]string{"t/llm#token": "sk-from-secret-0123456789"})
	if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if got := up.seen()[0].Header.Get("Authorization"); got != "Bearer sk-from-secret-0123456789" {
		t.Errorf("key %q", got)
	}
	dump, _ := json.Marshal(s.Table().Cfg.Dump())
	if strings.Contains(string(dump), "sk-from-secret") {
		t.Error("the secret is in the /config dump")
	}
	// Another namespace needs a ReferenceGrant, as for TLS certificates.
	s = apply(mk("other"), map[string]string{"other/llm#token": "sk-other-0123456789"})
	if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); r.Status == 200 {
		t.Error("a cross namespace Secret was used without a ReferenceGrant")
	}
	// A Secret the source could not read: invalid route.
	s = apply(mk("t"), nil)
	if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); r.Status == 200 {
		t.Error("route served without its key")
	}
}

func TestAIAnnotationEnablesAIRoute(t *testing.T) {
	up := newLLM(t, "oa", "openai")
	pol, _ := json.Marshal(m{"providers": l{llmProv(t, up, nil)}})
	r := route("a.test", m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/"}}}})
	r["setura.zyvor.dev/annotations"] = m{AIKey: string(pol)}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": r}, nil), nil)
	if resp := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); resp.Status != 200 {
		t.Fatalf("annotation route: %d %s", resp.Status, resp.Body)
	}
	// A broken annotation makes the route invalid rather than serving without the policy.
	r["setura.zyvor.dev/annotations"] = m{AIKey: `{"providers":[]}`}
	s = startServer(t, snap(httpGateway(""), map[string]m{"r": r}, nil), nil)
	if resp := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi")); resp.Status == 200 {
		t.Error("a broken annotation was ignored")
	}
}

func TestAIExtractUsage(t *testing.T) {
	for _, c := range []struct {
		name, json string
		in, out    int64
	}{
		{"openai", `{"model":"m","usage":{"prompt_tokens":5,"completion_tokens":6,"total_tokens":11,"prompt_tokens_details":{"cached_tokens":2}}}`, 5, 6},
		{"anthropic", `{"model":"m","usage":{"input_tokens":5,"output_tokens":6,"cache_creation_input_tokens":2,"cache_read_input_tokens":1}}`, 8, 6},
		{"total only", `{"usage":{"total_tokens":10}}`, 0, 10},
		{"none", `{"model":"m"}`, 0, 0},
		{"null", `{"usage":null}`, 0, 0},
	} {
		u := usageFromJSON([]byte(c.json))
		if u.In != c.in || u.Out != c.out {
			t.Errorf("%s: %+v", c.name, u)
		}
	}
	if p, ok := lookupPrice(map[string]AIPrice{"gpt-4o": {1, 2}, "gpt-4o-mini": {3, 4}, "*": {9, 9}}, "gpt-4o-mini-2024"); !ok || p.Input != 3 {
		t.Errorf("longest prefix: %+v", p)
	}
	if p, _ := lookupPrice(map[string]AIPrice{"*": {9, 9}}, "anything"); p.Input != 9 {
		t.Error("wildcard price")
	}
	if n := estimateTokens(map[string]any{"messages": []any{map[string]any{"role": "user", "content": strings.Repeat("a", 400)}}}); n != 104 {
		t.Errorf("estimate %d", n)
	}
}

// ---- why ------------------------------------------------------------------

func TestWhyExplainsProviderChoiceAndFailover(t *testing.T) {
	p1, p2, p3 := newLLM(t, "p1", "openai"), newLLM(t, "p2", "openai"), newLLM(t, "claude", "anthropic")
	p1.status = func(int) int { return 500 }
	clk := &fakeClock{t: time.Date(2030, 1, 15, 12, 30, 10, 0, time.UTC)}
	s, _ := aiServerRule(t, m{"providers": l{llmProv(t, p1, m{"weight": 3}), llmProv(t, p2, m{"weight": 1}), llmProv(t, p3, m{"priority": 1})},
		"identity": "apikey", "budget": m{"default": m{"tokensPerMinute": 5000}}, "cache": m{"enabled": true},
		"pii": m{"mode": "redact"}}, apiKeyAuth("alice"), func(o *Options) {
		o.AI.Clock = clk.now
		o.Rand = func(int) int { return 0 } // always the first provider of the tier
		o.Resilience.OutlierFailures = 1
		o.Resilience.Now = clk.now
	})
	explain := func(path string, live bool, hdr ...string) *TraceAI {
		er, err := ParseExplainRequest("POST", "http://a.test:8080"+path, headerLines(hdr), "", "")
		if err != nil {
			t.Fatal(err)
		}
		er.Now, er.Live = clk.now(), live
		if live {
			er.Server = s.liveServerPolicy()
		}
		tr := Explain(s.Table(), er)
		if tr.Winner == nil || tr.Winner.AI == nil {
			t.Fatalf("no AI explanation: %+v", tr)
		}
		return tr.Winner.AI
	}
	ai := explain("/v1/chat/completions", false, "X-Api-Key", "k-alice")
	if ai.Primary != "p1" || ai.API != "chat" || !strings.Contains(ai.Why, "p1 75%") || !strings.Contains(ai.Why, "p2 25%") {
		t.Errorf("primary %q why %q", ai.Primary, ai.Why)
	}
	if strings.Join(ai.Failover, ",") != "p2,claude" && strings.Join(ai.Failover, ",") != "p2" {
		t.Errorf("failover %v", ai.Failover)
	}
	for _, p := range ai.Providers {
		if p.Name == "claude" && (p.Role != "excluded" || !strings.Contains(p.Reason, "anthropic")) {
			t.Errorf("claude on the chat API: %+v", p)
		}
		if strings.Contains(p.Key, "SECRET") || !strings.HasPrefix(p.Key, "env SETURA_TEST_KEY_") {
			t.Errorf("key description %q", p.Key)
		}
	}
	if !strings.Contains(ai.Identity, "alice") || len(ai.Budget) == 0 || ai.Cache == "" || ai.PII == "" {
		t.Errorf("policies not explained: %+v", ai)
	}
	if m := explain("/v1/messages", false); m.Primary != "claude" {
		t.Errorf("messages API primary %q", m.Primary)
	}

	// Live: after p1 fails once it is ejected and the explanation says so.
	for i := 0; i < 2; i++ {
		if r := postJSON(t, s, "/v1/chat/completions", chat("gpt-4o", "hi"), "X-Api-Key", "k-alice"); r.Status != 200 || r.Header.Get(AIProviderHeader) != "p2" {
			t.Fatalf("live request %d: %d via %q %s", i, r.Status, r.Header.Get(AIProviderHeader), r.Body)
		}
	}
	live := explain("/v1/chat/completions", true, "X-Api-Key", "k-alice")
	if live.Primary != "p2" || !strings.Contains(live.Why, "p2 is the only provider") {
		t.Errorf("live primary %q why %q", live.Primary, live.Why)
	}
	foundEjected := false
	for _, p := range live.Providers {
		if p.Name == "p1" && p.State == "ejected" && p.Until != "" {
			foundEjected = true
		}
	}
	if !foundEjected || !strings.Contains(strings.Join(live.Failover, ","), "p1 (ejected") {
		t.Errorf("ejection not explained: %+v %v", live.Providers, live.Failover)
	}
	if len(live.Usage) != 1 || live.Usage[0].Used == 0 {
		t.Errorf("live budget use: %+v", live.Usage)
	}
}

func TestAIBudgetHoldsUnderConcurrency(t *testing.T) {
	s, _, _, up := budgetServer(t, m{"identity": "apikey", "budget": m{"default": m{"tokensPerMinute": 1000}}}, apiKeyAuth("alice"))
	var wg sync.WaitGroup
	var ok, refused atomic.Int64
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := postJSON(t, s, "/v1/chat/completions", budgetReq("gpt-4o", 60), "X-Api-Key", "k-alice")
			switch r.Status {
			case 200:
				ok.Add(1)
			case 429:
				refused.Add(1)
			default:
				t.Errorf("status %d", r.Status)
			}
		}()
	}
	wg.Wait()
	// Each admitted request settles to 18 tokens and reserves 66 meanwhile: reservations never pass 1000,
	// so at most 55 settle, and at least 15 fit even if every one reserved at once.
	if n := ok.Load(); n < 15 || n*18 > 1000 || int(n) != up.count() || ok.Load()+refused.Load() != 100 {
		t.Errorf("admitted %d refused %d upstream %d", ok.Load(), refused.Load(), up.count())
	}
}
