package gateway

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig is a local (per gateway process) token bucket.
type RateLimitConfig struct {
	Rate  float64       // tokens added per Per; 0 disables limiting
	Per   time.Duration // default one second
	Burst int           // bucket size; default ceil(rate per second), at least 1
	Key   string        // "ip" (default), "route" or "header:NAME"
	// Share divides the rate (and an explicit burst) by the number of gateway
	// replicas, as an approximation of a shared limit: each replica enforces
	// its 1/Share of the budget, which is exact only when traffic is spread
	// evenly. 0 or 1 means a single replica.
	Share int
	// Shared keeps the count in Redis, for every replica (shared.go); Scope
	// (route and rule) is part of its keys. Rate and Per then give requests
	// per window, Burst does not apply, and Share divides only the local fallback.
	Shared *SharedLimit
	Scope  string
}

// ParseRate parses "100/s", "30/m", "5000/h" or a bare number (per second).
func ParseRate(v string) (float64, time.Duration, error) {
	num, unit, _ := strings.Cut(strings.TrimSpace(v), "/")
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n <= 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, 0, fmt.Errorf("rate %q: want N/s, N/m or N/h with N > 0", v)
	}
	switch unit {
	case "", "s", "sec", "second":
		return n, time.Second, nil
	case "m", "min", "minute":
		return n, time.Minute, nil
	case "h", "hour":
		return n, time.Hour, nil
	}
	return 0, 0, fmt.Errorf("rate %q: unit must be s, m or h", v)
}

func (c *RateLimitConfig) validate() error {
	if c.Rate == 0 {
		return nil
	}
	if c.Rate < 0 {
		return errors.New("rate must be positive")
	}
	if c.Burst < 0 {
		return errors.New("burst must not be negative")
	}
	if c.Share < 0 {
		return errors.New("share must not be negative")
	}
	if c.Shared != nil {
		if c.Burst != 0 {
			return errors.New("burst does not apply to a shared limit (it counts requests per window); remove it")
		}
		if err := c.Shared.validate(); err != nil {
			return err
		}
	}
	switch k := c.Key; {
	case k == "" || k == "ip" || k == "route":
	case strings.HasPrefix(k, "header:") && len(k) > len("header:"):
	default:
		return fmt.Errorf("rate key %q: want ip, route or header:NAME", k)
	}
	return nil
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	sweepAbove = 10000  // sweep idle buckets once the table is this big
	maxBuckets = 100000 // hard cap; new keys share nothing and are refused above it
)

type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	key     string
	header  string
	trusted trustedNets
	now     func() time.Time
	buckets map[string]*bucket
	limited map[string]int64 // per route
	allowed int64
	sh      *sharedState // non-nil: the count lives in Redis and the bucket is the outage fallback
}

// sharedFallbackBurstCap bounds the burst of the local fallback of a shared limit.
const sharedFallbackBurstCap = 100

func newLimiter(c RateLimitConfig, now func() time.Time) *limiter {
	if c.Rate <= 0 {
		return nil
	}
	if c.Per <= 0 {
		c.Per = time.Second
	}
	if now == nil {
		now = time.Now
	}
	share := c.Share
	if c.Shared != nil {
		share = c.Shared.FallbackReplicas
	}
	if share < 1 {
		share = 1
	}
	perSec := c.Rate / c.Per.Seconds() / float64(share)
	burst := c.Burst
	if burst > 0 && share > 1 {
		burst = int(math.Ceil(float64(burst) / float64(share)))
	}
	if burst <= 0 {
		burst = int(math.Ceil(perSec))
		if burst < 1 {
			burst = 1
		}
	}
	if c.Shared != nil && c.Burst == 0 {
		// The fallback stands in for a window counter that admits N requests in any
		// pattern within a window, so a bucket of one token (the default for N/m)
		// would refuse a client that is well inside its limit. Hold up to the
		// replica's share of N, capped.
		burst = int(math.Min(math.Ceil(c.Rate/float64(share)), sharedFallbackBurstCap))
		if burst < 1 {
			burst = 1
		}
	}
	l := &limiter{perSec: perSec, burst: float64(burst), key: c.Key, now: now, buckets: map[string]*bucket{}, limited: map[string]int64{}}
	if l.key == "" {
		l.key = "ip"
	}
	if h, ok := strings.CutPrefix(l.key, "header:"); ok {
		l.header = h
	}
	if c.Shared != nil {
		l.sh = newSharedState(c)
	}
	return l
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// bucketKey names the token bucket a request draws from.
func (l *limiter) bucketKey(route string, r *http.Request) string {
	switch {
	case l.key == "route":
		return route
	case l.header != "":
		v := r.Header.Get(l.header)
		if v == "" {
			v = "ip:" + l.trusted.clientIP(r)
		}
		return route + "\x00" + v
	}
	return route + "\x00" + l.trusted.clientIP(r)
}

// allow takes one token for the request. When refused it returns how long
// until a token is available.
func (l *limiter) allow(route string, r *http.Request) (bool, time.Duration) {
	k := l.bucketKey(route, r)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= sweepAbove {
			l.sweep(now)
		}
		if len(l.buckets) >= maxBuckets {
			l.limited[route]++
			return false, time.Second
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.perSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		l.allowed++
		return true, 0
	}
	l.limited[route]++
	return false, time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
}

// sweep drops buckets that have refilled completely (they carry no state).
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, k)
		}
	}
}

func (l *limiter) snapshot() (allowed int64, limited map[string]int64, buckets int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	limited = make(map[string]int64, len(l.limited))
	for k, v := range l.limited {
		limited[k] = v
	}
	return l.allowed, limited, len(l.buckets)
}

func sortedRoutes(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rateLimited answers 429 with Retry-After when the route's bucket is empty.
func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, st *reqState) bool {
	l := s.obs.limiter
	if l == nil {
		return false
	}
	ok, wait := l.allow(st.route, r)
	if ok {
		return false
	}
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	st.errMsg, st.rateLimited = "rate limited", true
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	plain(w, http.StatusTooManyRequests, "rate limit exceeded")
	return true
}

// ruleRateLimited applies the rule's own limiter (setura.zyvor.dev/rate-limit)
// after the gateway-wide one: a request must pass both.
func (s *Server) ruleRateLimited(w http.ResponseWriter, r *http.Request, st *reqState, rule *CRule) bool {
	l := rule.Limit
	if l == nil {
		return false
	}
	if l.sh != nil {
		return s.sharedRateLimited(w, r, st, l)
	}
	ok, wait := l.allow(st.route, r)
	if ok {
		return false
	}
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	st.errMsg, st.rateLimited = "rate limited (route)", true
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	plain(w, http.StatusTooManyRequests, "rate limit exceeded")
	return true
}

type ruleLimiter struct {
	route string
	rule  int // 1-based
	l     *limiter
}

// ruleLimiters lists the per-rule limiters of a table, ordered by route and rule.
func (t *Table) ruleLimiters() []ruleLimiter {
	if t == nil {
		return nil
	}
	seen := map[*CRule]bool{}
	var out []ruleLimiter
	for _, l := range t.Listeners {
		for _, e := range l.Entries {
			if e.Rule.Limit != nil && !seen[e.Rule] {
				seen[e.Rule] = true
				out = append(out, ruleLimiter{e.Rule.RouteKey, e.Rule.Index + 1, e.Rule.Limit})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].route != out[j].route {
			return out[i].route < out[j].route
		}
		return out[i].rule < out[j].rule
	})
	return out
}

// prepareLimiters gives the per-rule limiters of a new table the gateway's
// clock and trusted proxies, and carries the buckets of an unchanged limiter
// over from the table it replaces so a reload does not refill them.
func (s *Server) prepareLimiters(old, next *Table) error {
	prev := map[[2]string]*limiter{}
	for _, rl := range old.ruleLimiters() {
		prev[[2]string{rl.route, strconv.Itoa(rl.rule)}] = rl.l
	}
	for _, rl := range next.ruleLimiters() {
		if o := prev[[2]string{rl.route, strconv.Itoa(rl.rule)}]; o != nil && o.sameAs(rl.l) {
			for _, l := range next.Listeners {
				for _, e := range l.Entries {
					if e.Rule.RouteKey == rl.route && e.Rule.Index+1 == rl.rule {
						e.Rule.Limit = o
					}
				}
			}
			continue
		}
		rl.l.trusted = s.trusted
		if s.opts.Obs.Now != nil {
			rl.l.now = s.opts.Obs.Now
		}
	}
	for _, rl := range next.ruleLimiters() {
		if rl.l.sh == nil || rl.l.sh.cl != nil {
			continue
		}
		cl := s.redis[rl.l.sh.cfg.redisName()]
		if cl == nil {
			return fmt.Errorf("route %s rule %d: %s: shared.redis %q is not configured (start the gateway with --redis %s=HOST:PORT)",
				rl.route, rl.rule, RateLimitKey, rl.l.sh.cfg.redisName(), rl.l.sh.cfg.redisName())
		}
		rl.l.sh.cl = cl
	}
	return nil
}

func (l *limiter) sameAs(o *limiter) bool {
	if (l.sh == nil) != (o.sh == nil) || (l.sh != nil && (l.sh.cfg != o.sh.cfg || l.sh.limit != o.sh.limit || l.sh.windowMs != o.sh.windowMs || l.sh.scope != o.sh.scope)) {
		return false
	}
	return l.perSec == o.perSec && l.burst == o.burst && l.key == o.key && l.header == o.header
}

// grpcRateLimited is rateLimited for a gRPC call: a Trailers-Only
// RESOURCE_EXHAUSTED answer (HTTP 429 in logs and counters) with the wait in
// grpc-retry-pushback-ms.
func (s *Server) grpcRateLimited(rec *recorder, r *http.Request, st *reqState) bool {
	l := s.obs.limiter
	if l == nil {
		return false
	}
	ok, wait := l.allow(st.route, r)
	if ok {
		return false
	}
	ms := wait.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	st.errMsg, st.rateLimited = "rate limited", true
	rec.Header().Set("Grpc-Retry-Pushback-Ms", strconv.FormatInt(ms, 10))
	grpcFail(rec, grpcResourceExhaust, "rate limit exceeded", http.StatusTooManyRequests)
	return true
}
