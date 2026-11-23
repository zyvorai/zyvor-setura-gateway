package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// TraceAI explains an AI rule: which provider the request goes to first and
// why, what happens when it fails, and which policies apply. It is computed
// from the same compiled policy and provider state the data path uses.
type TraceAI struct {
	API         string            `json:"api,omitempty"` // chat, completion, embeddings, messages; empty when the path is not an AI API
	Providers   []TraceAIProvider `json:"providers"`
	Primary     string            `json:"primary,omitempty"`
	Why         string            `json:"why"`
	Failover    []string          `json:"failover,omitempty"`
	Credentials string            `json:"credentials"`
	Identity    string            `json:"identity,omitempty"`
	Budget      []string          `json:"budget,omitempty"`
	Usage       []AIBudgetWindow  `json:"budget_used,omitempty"` // live gateways only
	Cache       string            `json:"cache,omitempty"`
	PII         string            `json:"pii,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

// TraceAIProvider is one provider of the rule.
type TraceAIProvider struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Priority int      `json:"priority"`
	Weight   int      `json:"weight"`
	Percent  float64  `json:"percent,omitempty"` // share of first choices among the providers of its tier that can serve the request
	State    string   `json:"state"`             // healthy, ejected or unhealthy ("healthy" offline: health is only known on a live gateway)
	Until    string   `json:"ejected_until,omitempty"`
	Key      string   `json:"key"` // where the credential comes from, never the credential
	Models   []string `json:"models,omitempty"`
	Role     string   `json:"role"` // first-choice, failover or excluded
	Reason   string   `json:"reason,omitempty"`
}

func (tr *Trace) explainAI(w *TraceWinner, e *Entry, q ExplainRequest, r *http.Request) {
	c := e.Rule.AI
	shape, _ := aiShape(q.Path)
	ta := &TraceAI{API: shape, Credentials: "the client's Authorization, X-Api-Key and cookies are dropped; each provider's own key is set on every attempt, so a request moved to the next provider is signed for that provider"}
	w.AI = ta
	typ := shapeProviderType(shape)
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	type cand struct {
		p     *aiProv
		state string
		until time.Time
	}
	var all []cand
	for _, p := range c.provs {
		cd := cand{p: p, state: "healthy"}
		if q.Live {
			c.b.hmu.Lock()
			cd.until = p.ep.st.until
			c.b.hmu.Unlock()
			cd.state = c.b.state(p.ep, now)
		}
		all = append(all, cd)
	}
	var usable, held []cand
	for _, cd := range all {
		switch {
		case shape != "" && cd.p.typ != typ:
		case cd.state == "healthy":
			usable = append(usable, cd)
		default:
			held = append(held, cd)
		}
	}
	tiers := func(cs []cand) [][]cand {
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].p.Priority < cs[j].p.Priority })
		var out [][]cand
		for _, cd := range cs {
			if n := len(out); n > 0 && out[n-1][0].p.Priority == cd.p.Priority {
				out[n-1] = append(out[n-1], cd)
			} else {
				out = append(out, []cand{cd})
			}
		}
		return out
	}
	ut := tiers(usable)
	first := map[string]float64{}
	if len(ut) > 0 {
		total := 0
		for _, cd := range ut[0] {
			total += cd.p.weight
		}
		for _, cd := range ut[0] {
			if total > 0 {
				first[cd.p.Name] = 100 * float64(cd.p.weight) / float64(total)
			}
		}
		best := ut[0][0]
		for _, cd := range ut[0] {
			if cd.p.weight > best.p.weight {
				best = cd
			}
		}
		ta.Primary = best.p.Name
		names := make([]string, 0, len(ut[0]))
		for _, cd := range ut[0] {
			names = append(names, fmt.Sprintf("%s %.0f%%", cd.p.Name, first[cd.p.Name]))
		}
		if len(ut[0]) == 1 {
			ta.Why = fmt.Sprintf("%s is the only provider in the first priority tier (priority %d) that can take the request", best.p.Name, best.p.Priority)
		} else {
			ta.Why = fmt.Sprintf("priority %d is the best tier with a provider that can take traffic; its providers share first choices by weight (%s) and %s has the largest share", best.p.Priority, strings.Join(names, ", "), best.p.Name)
		}
	} else {
		ta.Why = "no provider can take this request right now"
		if shape == "" {
			ta.Why = "the path is not an AI API (the route serves /chat/completions, /completions, /embeddings and /messages)"
		}
	}
	// Failover order: the rest of the first tier, then lower tiers, then providers held back by ejection.
	for i, tier := range ut {
		for _, cd := range tier {
			if i == 0 && cd.p.Name == ta.Primary {
				continue
			}
			ta.Failover = append(ta.Failover, cd.p.Name)
		}
	}
	for _, cd := range held {
		ta.Failover = append(ta.Failover, cd.p.Name+" (ejected: tried last)")
	}
	fs := "429 and every 5xx"
	if len(c.p.Failover.statusList()) > 0 {
		fs = fmt.Sprint(c.p.Failover.statusList())
	}
	ta.Notes = append(ta.Notes, fmt.Sprintf("a transport error, a timeout or %s moves the request to the next provider (at most %d attempts); 4xx answers are the client's and are returned", fs, c.maxAttempts))
	for _, cd := range all {
		tp := TraceAIProvider{Name: cd.p.Name, Type: cd.p.typ, Priority: cd.p.Priority, Weight: cd.p.weight, Percent: first[cd.p.Name],
			State: cd.state, Key: cd.p.describeKey(), Models: cd.p.Models, Role: "failover"}
		if !cd.until.IsZero() && now.Before(cd.until) {
			tp.Until = cd.until.UTC().Format(time.RFC3339)
		}
		switch {
		case shape != "" && cd.p.typ != typ:
			tp.Role, tp.Reason = "excluded", fmt.Sprintf("a %s provider does not serve the %s API", cd.p.typ, shape)
		case cd.p.Name == ta.Primary:
			tp.Role = "first-choice"
		case first[cd.p.Name] > 0:
			tp.Role = "first-choice"
		case cd.state != "healthy":
			tp.Reason = "skipped while " + cd.state + "; tried last"
		}
		ta.Providers = append(ta.Providers, tp)
	}

	ident := ""
	kind := c.identKind
	switch kind {
	case "header":
		ident = strings.TrimSpace(r.Header.Get(c.identName))
		ta.Identity = "header " + c.identName
	case "claim":
		ta.Identity = "JWT claim " + c.identName + " (read from the verified token on a real request)"
	case "apikey":
		ta.Identity = "the name of the API key that matched"
		if a := w.Auth; a != nil && a.Method == "apikey" {
			ident = a.Subject
		}
	default:
		ta.Identity = "the verified subject of the credential"
		if a := w.Auth; a != nil {
			ident = a.Subject
		}
	}
	if ident != "" {
		ta.Identity += ": " + ident
	}
	if b := c.p.Budget; b != nil {
		lim := b.limitsFor(ident)
		ta.Budget = append(ta.Budget, "limits for this identity: "+describeLimits(lim))
		if b.Route != nil {
			ta.Budget = append(ta.Budget, "route wide limits: "+describeLimits(*b.Route))
		}
		ta.Budget = append(ta.Budget, "a request reserves its prompt estimate plus max_tokens (default "+fmt.Sprint(aiDefaultOr(c.defMax))+") before it is forwarded, and is settled with the provider's real usage afterwards; over a limit it gets 429 with Retry-After")
		if q.Live && q.Server.srv != nil && ident != "" {
			ta.Usage = q.Server.srv.aiWindowsFor(c, ident)
		}
	}
	switch {
	case c.cache == nil:
	default:
		scope := "per identity"
		if !c.cache.perIdentity {
			scope = "shared by the whole route"
		}
		st := "streamed responses are not cached"
		if c.cache.stream {
			st = "streamed responses are cached too"
		}
		ta.Cache = fmt.Sprintf("exact-match cache, ttl %s, at most %d entries, %s; %s; a hit costs no tokens and no budget", c.cache.ttl, c.cache.maxEntries, scope, st)
	}
	if c.pii != nil {
		names := make([]string, len(c.pii.rules))
		for i, r := range c.pii.rules {
			names[i] = r.name
		}
		ta.PII = fmt.Sprintf("prompt PII %s for %s (counts only are logged, never the data)", c.pii.mode, strings.Join(names, ", "))
	}
}

func aiDefaultOr(n int) int {
	if n <= 0 {
		return aiDefaultMaxTokens
	}
	return n
}

func (f *AIFailover) statusList() []int {
	if f == nil {
		return nil
	}
	return f.Statuses
}

func describeLimits(l AILimits) string {
	var parts []string
	if l.TokensPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens/minute", l.TokensPerMinute))
	}
	if l.TokensPerDay > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens/day", l.TokensPerDay))
	}
	if l.MonthlyTokens > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens/month", l.MonthlyTokens))
	}
	if l.MonthlyCost > 0 {
		parts = append(parts, fmt.Sprintf("%g/month in cost", l.MonthlyCost))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// aiWindowsFor reports how much of an identity's limits is used right now.
func (s *Server) aiWindowsFor(c *compiledAI, ident string) []AIBudgetWindow {
	b := c.p.Budget
	if b == nil {
		return nil
	}
	now := s.aiNow()
	s.ai.mu.Lock()
	defer s.ai.mu.Unlock()
	w := s.ai.budgets[c.key+"|"+ident]
	if w != nil {
		w.roll(now)
	}
	return windowsOf(w, b.limitsFor(ident), now)
}
