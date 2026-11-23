package gateway

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// AIOptions are the gateway wide settings of AI routes.
type AIOptions struct {
	// PricesFile is a JSON price table (see docs/ai-gateway.md); it is re-read
	// when it changes. A route's own "prices" override it per model.
	PricesFile string
	// MaxKeyLabels bounds the distinct identities a route reports in /metrics
	// (default 500); the rest are folded into "_other".
	MaxKeyLabels int
	// Clock replaces the clock of budget windows and cache expiry (tests).
	Clock func() time.Time
}

// aiRuntime is the state that outlives routing table reloads: budgets, caches,
// counters and the price table.
type aiRuntime struct {
	opts   AIOptions
	prices priceBook

	mu      sync.Mutex
	budgets map[string]*aiWin
	caches  map[string]*aiCache
	routes  map[string]*aiRouteStat
}

func (rt *aiRuntime) init(o AIOptions) {
	rt.opts = o
	rt.prices.path = o.PricesFile
	rt.budgets = map[string]*aiWin{}
	rt.caches = map[string]*aiCache{}
	rt.routes = map[string]*aiRouteStat{}
	if o.MaxKeyLabels <= 0 {
		rt.opts.MaxKeyLabels = 500
	}
}

func (s *Server) aiNow() time.Time {
	if s.ai.opts.Clock != nil {
		return s.ai.opts.Clock()
	}
	return s.res.now()
}

// LoadAIPrices reads the price table file now and reports why it cannot be used.
func (s *Server) LoadAIPrices() error { return s.ai.prices.reload(true) }

// aiPrice finds the price of model: the route's table first, then the gateway's.
func (s *Server) aiPrice(c *compiledAI, model string) (AIPrice, bool) {
	if p, ok := lookupPrice(c.p.Prices, model); ok {
		return p, true
	}
	if t := s.ai.prices.get(); t != nil {
		return lookupPrice(t.Models, model)
	}
	return AIPrice{}, false
}

// ---- budgets -----------------------------------------------------------

// aiWin is one identity's usage in the current minute, day and month.
type aiWin struct {
	minID, dayID, monID int64
	min, day, mon       int64
	monCost             float64
}

func windowIDs(now time.Time) (min, day, mon int64) {
	u := now.UTC()
	return u.Unix() / 60, u.Unix() / 86400, int64(u.Year())*12 + int64(u.Month()) - 1
}

func (w *aiWin) roll(now time.Time) {
	min, day, mon := windowIDs(now)
	if w.minID != min {
		w.minID, w.min = min, 0
	}
	if w.dayID != day {
		w.dayID, w.day = day, 0
	}
	if w.monID != mon {
		w.monID, w.mon, w.monCost = mon, 0, 0
	}
}

// AIDenial says which limit refused a request.
type AIDenial struct {
	Limit      string  `json:"limit"` // tokens_per_minute, tokens_per_day, monthly_tokens or monthly_cost
	Max        float64 `json:"max"`
	Used       float64 `json:"used"`
	Requested  float64 `json:"requested"`
	RetryAfter int     `json:"retry_after_seconds"`
	Scope      string  `json:"scope"` // "identity" or "route"
}

type aiReservation struct {
	key                 string
	minID, dayID, monID int64
	tok                 int64
	cost                float64
}

// retryUntil is the whole seconds until the window of limit ends.
func retryUntil(now time.Time, limit string) int {
	u := now.UTC()
	var next time.Time
	switch limit {
	case "tokens_per_minute":
		next = u.Truncate(time.Minute).Add(time.Minute)
	case "tokens_per_day":
		next = time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	default:
		next = time.Date(u.Year(), u.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	}
	secs := int(next.Sub(u).Seconds()) + 1
	if secs < 1 {
		secs = 1
	}
	return secs
}

// check returns the first limit that tok (and cost) would exceed on w.
func (w *aiWin) check(l AILimits, tok int64, cost float64, now time.Time, scope string) *AIDenial {
	type lim struct {
		name            string
		used, max, want float64
	}
	for _, x := range []lim{
		{"tokens_per_minute", float64(w.min), float64(l.TokensPerMinute), float64(tok)},
		{"tokens_per_day", float64(w.day), float64(l.TokensPerDay), float64(tok)},
		{"monthly_tokens", float64(w.mon), float64(l.MonthlyTokens), float64(tok)},
		{"monthly_cost", w.monCost, l.MonthlyCost, cost},
	} {
		if x.max > 0 && x.used+x.want > x.max {
			return &AIDenial{Limit: x.name, Max: x.max, Used: x.used, Requested: x.want, RetryAfter: retryUntil(now, x.name), Scope: scope}
		}
	}
	return nil
}

// limitsFor picks the limits of an identity: its override, else the default.
func (b *AIBudget) limitsFor(ident string) AILimits {
	if l, ok := b.Overrides[ident]; ok {
		return l
	}
	return b.Default
}

// aiReserve checks the identity limits and the route limits for a request that
// may use tok tokens and cost, and, when both pass, charges the estimate. The
// reservations are settled with the real usage afterwards.
func (s *Server) aiReserve(c *compiledAI, ident string, tok int64, cost float64, now time.Time) ([]*aiReservation, *AIDenial) {
	b := c.p.Budget
	if b == nil {
		return nil, nil
	}
	type target struct {
		key, scope string
		l          AILimits
	}
	var ts []target
	if l := b.limitsFor(ident); !l.none() {
		ts = append(ts, target{c.key + "|" + ident, "identity", l})
	}
	if b.Route != nil && !b.Route.none() {
		ts = append(ts, target{c.key + "|\x00route", "route", *b.Route})
	}
	if len(ts) == 0 {
		return nil, nil
	}
	rt := &s.ai
	rt.mu.Lock()
	defer rt.mu.Unlock()
	wins := make([]*aiWin, len(ts))
	for i, t := range ts {
		w := rt.budgets[t.key]
		if w == nil {
			if len(rt.budgets) >= 200000 {
				rt.sweepBudgets(now)
			}
			w = &aiWin{}
			rt.budgets[t.key] = w
		}
		w.roll(now)
		if d := w.check(t.l, tok, cost, now, t.scope); d != nil {
			return nil, d
		}
		wins[i] = w
	}
	out := make([]*aiReservation, len(ts))
	for i, t := range ts {
		w := wins[i]
		w.min, w.day, w.mon, w.monCost = w.min+tok, w.day+tok, w.mon+tok, w.monCost+cost
		out[i] = &aiReservation{key: t.key, minID: w.minID, dayID: w.dayID, monID: w.monID, tok: tok, cost: cost}
	}
	return out, nil
}

// sweepBudgets drops entries whose month is over. Caller holds mu.
func (rt *aiRuntime) sweepBudgets(now time.Time) {
	_, _, mon := windowIDs(now)
	for k, w := range rt.budgets {
		if w.monID < mon {
			delete(rt.budgets, k)
		}
	}
}

// aiSettle replaces each reservation with what the request really used.
func (s *Server) aiSettle(rs []*aiReservation, tok int64, cost float64) {
	if len(rs) == 0 {
		return
	}
	rt := &s.ai
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, r := range rs {
		w := rt.budgets[r.key]
		if w == nil {
			continue
		}
		d, dc := tok-r.tok, cost-r.cost
		if w.minID == r.minID {
			w.min = max(0, w.min+d)
		}
		if w.dayID == r.dayID {
			w.day = max(0, w.day+d)
		}
		if w.monID == r.monID {
			w.mon = max(0, w.mon+d)
			w.monCost = max(0, w.monCost+dc)
		}
	}
}

// ---- cache -------------------------------------------------------------

type aiCacheEntry struct {
	key      string
	status   int
	ctype    string
	body     []byte
	usage    aiUsage
	provider string
	stream   bool
	exp      time.Time
}

// aiCache is a bounded LRU with a TTL: bounded by entries and by total bytes.
type aiCache struct {
	mu    sync.Mutex
	cfg   aiCacheCfg
	ll    *list.List
	m     map[string]*list.Element
	bytes int64
}

func newAICache(cfg aiCacheCfg) *aiCache {
	return &aiCache{cfg: cfg, ll: list.New(), m: map[string]*list.Element{}}
}

func (c *aiCache) get(key string, now time.Time) *aiCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.m[key]
	if el == nil {
		return nil
	}
	e := el.Value.(*aiCacheEntry)
	if !now.Before(e.exp) {
		c.remove(el)
		return nil
	}
	c.ll.MoveToFront(el)
	return e
}

func (c *aiCache) remove(el *list.Element) {
	e := el.Value.(*aiCacheEntry)
	c.ll.Remove(el)
	delete(c.m, e.key)
	c.bytes -= int64(len(e.body))
}

// put stores e, evicting the least recently used entries to stay in bounds. It
// returns the number evicted; an entry above maxEntryBytes is not stored.
func (c *aiCache) put(e *aiCacheEntry, now time.Time) (evicted int) {
	if int64(len(e.body)) > c.cfg.maxEntryBytes || int64(len(e.body)) > c.cfg.maxBytes {
		return 0
	}
	e.exp = now.Add(c.cfg.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.m[e.key]; old != nil {
		c.remove(old)
	}
	c.m[e.key] = c.ll.PushFront(e)
	c.bytes += int64(len(e.body))
	for c.ll.Len() > c.cfg.maxEntries || c.bytes > c.cfg.maxBytes {
		c.remove(c.ll.Back())
		evicted++
	}
	return evicted
}

func (c *aiCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// aiCacheFor returns the cache of a rule, creating it (or replacing it when
// its settings changed in a reload).
func (s *Server) aiCacheFor(c *compiledAI) *aiCache {
	if c.cache == nil {
		return nil
	}
	rt := &s.ai
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ca := rt.caches[c.key]
	if ca == nil || !sameCacheCfg(ca.cfg, *c.cache) {
		ca = newAICache(*c.cache)
		rt.caches[c.key] = ca
	}
	return ca
}

func sameCacheCfg(a, b aiCacheCfg) bool {
	return a.ttl == b.ttl && a.maxEntries == b.maxEntries && a.maxEntryBytes == b.maxEntryBytes && a.maxBytes == b.maxBytes &&
		a.stream == b.stream && a.perIdentity == b.perIdentity && strings.Join(a.ignore, ",") == strings.Join(b.ignore, ",")
}

// aiCacheKey is the cache key: the rule, the API, the identity (unless the
// scope is the route) and the whole request body, canonicalised so key order
// and whitespace do not matter, minus the ignored fields.
func aiCacheKey(c *compiledAI, shape, ident string, body map[string]any) string {
	cp := make(map[string]any, len(body))
	for k, v := range body {
		cp[k] = v
	}
	for _, k := range c.cache.ignore {
		delete(cp, k)
	}
	canon, _ := json.Marshal(cp) // maps marshal with sorted keys
	h := sha256.New()
	h.Write([]byte(c.key + "\x00" + shape + "\x00"))
	if c.cache.perIdentity {
		h.Write([]byte(ident))
	}
	h.Write([]byte{0})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil))
}
