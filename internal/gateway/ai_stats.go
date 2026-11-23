package gateway

import (
	"fmt"
	"io"
	"sort"
	"time"
)

type aiTok struct {
	in, out int64
	cost    float64
	reqs    int64
}

// aiRouteStat are the counters of one AI rule. The zero cost of a model with
// no price is a zero, not an error: cost_estimate only covers priced models.
type aiRouteStat struct {
	reqs      map[[3]string]int64  // provider, model, outcome
	tokens    map[[2]string]*aiTok // provider, model
	keys      map[string]*aiTok
	cacheHit  int64
	cacheMiss int64
	cacheEvct int64
	denied    map[string]int64    // limit
	attempts  map[[2]string]int64 // provider, result (ok, failover, error)
	failovers map[[2]string]int64 // from, to
	pii       map[[2]string]int64 // rule, action
	models    map[string]bool
}

// aiStat returns the counters of a route. Caller holds ai.mu.
func (s *Server) aiStat(route string) *aiRouteStat {
	st := s.ai.routes[route]
	if st == nil {
		st = &aiRouteStat{reqs: map[[3]string]int64{}, tokens: map[[2]string]*aiTok{}, keys: map[string]*aiTok{}, denied: map[string]int64{},
			attempts: map[[2]string]int64{}, failovers: map[[2]string]int64{}, pii: map[[2]string]int64{}, models: map[string]bool{}}
		s.ai.routes[route] = st
	}
	return st
}

// aiCount applies f to the counters of route under the lock.
func (s *Server) aiCount(route string, f func(st *aiRouteStat)) {
	s.ai.mu.Lock()
	defer s.ai.mu.Unlock()
	f(s.aiStat(route))
}

// modelLabel bounds the model label cardinality of a route.
func (st *aiRouteStat) modelLabel(m string) string {
	if m == "" {
		return "unknown"
	}
	if st.models[m] {
		return m
	}
	if len(st.models) >= 64 {
		return "_other"
	}
	st.models[m] = true
	return m
}

func (st *aiRouteStat) keyEntry(k string, max int) *aiTok {
	if t := st.keys[k]; t != nil {
		return t
	}
	if len(st.keys) >= max {
		k = "_other"
		if t := st.keys[k]; t != nil {
			return t
		}
	}
	t := &aiTok{}
	st.keys[k] = t
	return t
}

// aiRules lists the AI rules of the table, one entry per rule.
func (t *Table) aiRules() []*compiledAI {
	seen := map[string]bool{}
	var out []*compiledAI
	for _, l := range t.Listeners {
		for _, e := range l.Entries {
			if c := e.Rule.AI; c != nil && !seen[c.key] {
				seen[c.key] = true
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// AIUsage is the /ai/usage document.
type AIUsage struct {
	Currency string         `json:"currency,omitempty"`
	Routes   []AIRouteUsage `json:"routes"`
}

// AIRouteUsage is one AI rule.
type AIRouteUsage struct {
	Route        string            `json:"route"`
	Requests     int64             `json:"requests"`
	TokensIn     int64             `json:"tokens_in"`
	TokensOut    int64             `json:"tokens_out"`
	CostEstimate float64           `json:"cost_estimate"`
	Cache        *AICacheUsage     `json:"cache,omitempty"`
	Denied       map[string]int64  `json:"budget_denied,omitempty"`
	PII          map[string]int64  `json:"pii,omitempty"`
	Providers    []AIProviderUsage `json:"providers"`
	Keys         []AIKeyUsage      `json:"keys,omitempty"`
}

// AICacheUsage is the cache state of a route.
type AICacheUsage struct {
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
	Entries int   `json:"entries"`
	Evicted int64 `json:"evicted"`
}

// AIProviderUsage is one provider of a route.
type AIProviderUsage struct {
	Name      string  `json:"name"`
	State     string  `json:"state"` // healthy, ejected or unhealthy
	Priority  int     `json:"priority"`
	Weight    int     `json:"weight"`
	Attempts  int64   `json:"attempts"`
	Failures  int64   `json:"failures"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	Cost      float64 `json:"cost_estimate"`
}

// AIKeyUsage is one identity of a route with its budget state.
type AIKeyUsage struct {
	Key       string           `json:"key"`
	Requests  int64            `json:"requests"`
	TokensIn  int64            `json:"tokens_in"`
	TokensOut int64            `json:"tokens_out"`
	Cost      float64          `json:"cost_estimate"`
	Budget    []AIBudgetWindow `json:"budget,omitempty"`
}

// AIBudgetWindow is the state of one limit.
type AIBudgetWindow struct {
	Limit       string  `json:"limit"`
	Used        float64 `json:"used"`
	Max         float64 `json:"max"`
	ResetsInSec int     `json:"resets_in_seconds"`
}

// windowsOf describes the limits an identity has and how much of each is used.
func windowsOf(w *aiWin, l AILimits, now time.Time) []AIBudgetWindow {
	var out []AIBudgetWindow
	add := func(name string, used, max float64) {
		if max > 0 {
			out = append(out, AIBudgetWindow{Limit: name, Used: used, Max: max, ResetsInSec: retryUntil(now, name)})
		}
	}
	var min, day, mon int64
	var cost float64
	if w != nil {
		min, day, mon, cost = w.min, w.day, w.mon, w.monCost
	}
	add("tokens_per_minute", float64(min), float64(l.TokensPerMinute))
	add("tokens_per_day", float64(day), float64(l.TokensPerDay))
	add("monthly_tokens", float64(mon), float64(l.MonthlyTokens))
	add("monthly_cost", cost, l.MonthlyCost)
	return out
}

// Usage assembles the AI usage document for the admin endpoint.
func (s *Server) Usage() *AIUsage {
	out := &AIUsage{Routes: []AIRouteUsage{}}
	if p := s.ai.prices.get(); p != nil {
		out.Currency = p.Currency
	}
	t := s.Table()
	if t == nil {
		return out
	}
	now := s.aiNow()
	rt := &s.ai
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, c := range t.aiRules() {
		st := rt.routes[c.key]
		u := AIRouteUsage{Route: c.key, Providers: []AIProviderUsage{}}
		if st == nil {
			st = &aiRouteStat{}
		}
		for k, n := range st.reqs {
			_ = k
			u.Requests += n
		}
		if len(st.denied) > 0 {
			u.Denied = map[string]int64{}
			for k, v := range st.denied {
				u.Denied[k] = v
			}
		}
		if len(st.pii) > 0 {
			u.PII = map[string]int64{}
			for k, v := range st.pii {
				u.PII[k[0]+"/"+k[1]] += v
			}
		}
		if c.cache != nil {
			cu := &AICacheUsage{Hits: st.cacheHit, Misses: st.cacheMiss, Evicted: st.cacheEvct}
			if ca := rt.caches[c.key]; ca != nil {
				cu.Entries = ca.len()
			}
			u.Cache = cu
		}
		for _, p := range c.provs {
			pu := AIProviderUsage{Name: p.Name, Priority: p.Priority, Weight: p.weight, State: c.b.state(p.ep, now)}
			for k, n := range st.attempts {
				if k[0] == p.Name {
					pu.Attempts += n
					if k[1] != "ok" {
						pu.Failures += n
					}
				}
			}
			for k, tk := range st.tokens {
				if k[0] == p.Name {
					pu.TokensIn, pu.TokensOut, pu.Cost = pu.TokensIn+tk.in, pu.TokensOut+tk.out, pu.Cost+tk.cost
				}
			}
			u.TokensIn, u.TokensOut, u.CostEstimate = u.TokensIn+pu.TokensIn, u.TokensOut+pu.TokensOut, u.CostEstimate+pu.Cost
			u.Providers = append(u.Providers, pu)
		}
		for _, k := range sortedKeys(st.keys) {
			tk := st.keys[k]
			ku := AIKeyUsage{Key: k, Requests: tk.reqs, TokensIn: tk.in, TokensOut: tk.out, Cost: tk.cost}
			if b := c.p.Budget; b != nil {
				w := rt.budgets[c.key+"|"+k]
				if w != nil {
					w.roll(now)
				}
				ku.Budget = windowsOf(w, b.limitsFor(k), now)
			}
			u.Keys = append(u.Keys, ku)
		}
		if b := c.p.Budget; b != nil && b.Route != nil {
			w := rt.budgets[c.key+"|\x00route"]
			if w != nil {
				w.roll(now)
			}
			u.Keys = append(u.Keys, AIKeyUsage{Key: "(route total)", Budget: windowsOf(w, *b.Route, now)})
		}
		out.Routes = append(out.Routes, u)
	}
	return out
}

// ---- metrics -------------------------------------------------------------

// writeAIMetrics emits the AI route series. HELP and TYPE lines are always
// written so a series is discoverable before its first sample.
func (s *Server) writeAIMetrics(w io.Writer) {
	head := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	rt := &s.ai
	rt.mu.Lock()
	defer rt.mu.Unlock()
	routes := sortedKeys(rt.routes)
	lp := promLabel
	head("setura_ai_requests_total", "counter", "AI requests by outcome (ok, upstream_error, cache_hit, budget_denied, pii_blocked, rejected).")
	for _, r := range routes {
		st := rt.routes[r]
		keys := make([][3]string, 0, len(st.reqs))
		for k := range st.reqs {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			fmt.Fprintf(w, "setura_ai_requests_total{route=\"%s\",provider=\"%s\",model=\"%s\",outcome=\"%s\"} %d\n", lp(r), lp(k[0]), lp(k[1]), lp(k[2]), st.reqs[k])
		}
	}
	head("setura_ai_tokens_total", "counter", "Tokens reported by providers (direction prompt or completion), or estimated when a response carried no usage.")
	for _, r := range routes {
		st := rt.routes[r]
		for _, k := range sortedTokKeys(st.tokens) {
			tk := st.tokens[k]
			fmt.Fprintf(w, "setura_ai_tokens_total{route=\"%s\",provider=\"%s\",model=\"%s\",direction=\"prompt\"} %d\n", lp(r), lp(k[0]), lp(k[1]), tk.in)
			fmt.Fprintf(w, "setura_ai_tokens_total{route=\"%s\",provider=\"%s\",model=\"%s\",direction=\"completion\"} %d\n", lp(r), lp(k[0]), lp(k[1]), tk.out)
		}
	}
	head("setura_ai_cost_estimate_total", "counter", "Estimated spend from the price table, in its currency; models without a price add nothing.")
	for _, r := range routes {
		st := rt.routes[r]
		for _, k := range sortedTokKeys(st.tokens) {
			fmt.Fprintf(w, "setura_ai_cost_estimate_total{route=\"%s\",provider=\"%s\",model=\"%s\"} %g\n", lp(r), lp(k[0]), lp(k[1]), st.tokens[k].cost)
		}
	}
	head("setura_ai_key_tokens_total", "counter", "Tokens per identity (API key name, subject, claim or header value), at most --ai-max-key-labels identities per route.")
	for _, r := range routes {
		st := rt.routes[r]
		for _, k := range sortedKeys(st.keys) {
			tk := st.keys[k]
			fmt.Fprintf(w, "setura_ai_key_tokens_total{route=\"%s\",key=\"%s\",direction=\"prompt\"} %d\n", lp(r), lp(k), tk.in)
			fmt.Fprintf(w, "setura_ai_key_tokens_total{route=\"%s\",key=\"%s\",direction=\"completion\"} %d\n", lp(r), lp(k), tk.out)
		}
	}
	head("setura_ai_key_cost_estimate_total", "counter", "Estimated spend per identity.")
	for _, r := range routes {
		st := rt.routes[r]
		for _, k := range sortedKeys(st.keys) {
			fmt.Fprintf(w, "setura_ai_key_cost_estimate_total{route=\"%s\",key=\"%s\"} %g\n", lp(r), lp(k), st.keys[k].cost)
		}
	}
	head("setura_ai_cache_requests_total", "counter", "Prompt cache lookups by result (hit or miss).")
	for _, r := range routes {
		st := rt.routes[r]
		if st.cacheHit+st.cacheMiss > 0 {
			fmt.Fprintf(w, "setura_ai_cache_requests_total{route=\"%s\",result=\"hit\"} %d\n", lp(r), st.cacheHit)
			fmt.Fprintf(w, "setura_ai_cache_requests_total{route=\"%s\",result=\"miss\"} %d\n", lp(r), st.cacheMiss)
		}
	}
	head("setura_ai_cache_evictions_total", "counter", "Prompt cache entries evicted to stay within the size bounds.")
	for _, r := range routes {
		if v := rt.routes[r].cacheEvct; v > 0 {
			fmt.Fprintf(w, "setura_ai_cache_evictions_total{route=\"%s\"} %d\n", lp(r), v)
		}
	}
	head("setura_ai_budget_rejections_total", "counter", "Requests refused with 429 by a token budget, by the limit that refused.")
	for _, r := range routes {
		st := rt.routes[r]
		for _, k := range sortedKeys(st.denied) {
			fmt.Fprintf(w, "setura_ai_budget_rejections_total{route=\"%s\",limit=\"%s\"} %d\n", lp(r), lp(k), st.denied[k])
		}
	}
	head("setura_ai_provider_attempts_total", "counter", "Upstream attempts per provider by result (ok, failover, error).")
	for _, r := range routes {
		st := rt.routes[r]
		keys := make([][2]string, 0, len(st.attempts))
		for k := range st.attempts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			fmt.Fprintf(w, "setura_ai_provider_attempts_total{route=\"%s\",provider=\"%s\",result=\"%s\"} %d\n", lp(r), lp(k[0]), lp(k[1]), st.attempts[k])
		}
	}
	head("setura_ai_failovers_total", "counter", "Requests moved from one provider to the next.")
	for _, r := range routes {
		st := rt.routes[r]
		keys := make([][2]string, 0, len(st.failovers))
		for k := range st.failovers {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			fmt.Fprintf(w, "setura_ai_failovers_total{route=\"%s\",from=\"%s\",to=\"%s\"} %d\n", lp(r), lp(k[0]), lp(k[1]), st.failovers[k])
		}
	}
	head("setura_ai_pii_findings_total", "counter", "Prompt PII matches per rule and action (redacted, blocked or reported). Counts only, never the data.")
	for _, r := range routes {
		st := rt.routes[r]
		keys := make([][2]string, 0, len(st.pii))
		for k := range st.pii {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		for _, k := range keys {
			fmt.Fprintf(w, "setura_ai_pii_findings_total{route=\"%s\",rule=\"%s\",action=\"%s\"} %d\n", lp(r), lp(k[0]), lp(k[1]), st.pii[k])
		}
	}
	head("setura_ai_provider_up", "gauge", "1 while the provider can take requests, 0 while it is ejected by outlier detection.")
	if t := s.Table(); t != nil {
		now := s.aiNow()
		for _, c := range t.aiRules() {
			for _, p := range c.provs {
				up := 1
				if c.b.state(p.ep, now) != "healthy" {
					up = 0
				}
				fmt.Fprintf(w, "setura_ai_provider_up{route=\"%s\",provider=\"%s\"} %d\n", lp(c.key), lp(p.Name), up)
			}
		}
	}
}

func sortedTokKeys(m map[[2]string]*aiTok) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	return keys
}
