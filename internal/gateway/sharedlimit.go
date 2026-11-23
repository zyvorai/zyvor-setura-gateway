package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SharedLimit moves a rule's rate limit from per-replica token buckets to a
// counter in Redis that every gateway replica updates, so the limit holds for
// the fleet. It is the "shared" member of the setura.zyvor.dev/rate-limit block.
//
// The algorithm is a sliding window counter: one counter per window per
// client, kept for two windows, and the request count is the current counter
// plus the previous one weighted by how much of it still overlaps the window.
// Each check is one MULTI / INCR / PEXPIRE / GET / EXEC round trip (no Lua).
type SharedLimit struct {
	Redis     string `json:"redis,omitempty"`     // name of a --redis server (default "default")
	KeyPrefix string `json:"keyPrefix,omitempty"` // key namespace in Redis (default "setura:rl")
	FailOpen  *bool  `json:"failOpen,omitempty"`  // when Redis fails: true (default) keeps serving, false answers 503
	// Fallback says what failing open means: "local" (default) enforces the
	// same rate with a per-replica token bucket, "none" lets everything through.
	Fallback string `json:"fallback,omitempty"`
	// FallbackReplicas divides the local fallback rate by the replica count.
	FallbackReplicas int `json:"fallbackReplicas,omitempty"`
}

const (
	defaultSharedPrefix = "setura:rl"
	sharedCooldown      = time.Second // a failed Redis is not tried again for this long
	maxPrefixLen        = 128
)

var sharedNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func (s *SharedLimit) validate() error {
	if s.Redis != "" && !sharedNameRe.MatchString(s.Redis) {
		return fmt.Errorf("shared.redis %q: want a name of letters, digits, _ . - (the NAME of a --redis NAME=ADDR flag)", s.Redis)
	}
	if len(s.KeyPrefix) > maxPrefixLen {
		return fmt.Errorf("shared.keyPrefix is %d bytes, the limit is %d", len(s.KeyPrefix), maxPrefixLen)
	}
	for _, c := range s.KeyPrefix {
		if c <= ' ' || c == 0x7f {
			return fmt.Errorf("shared.keyPrefix %q has a space or control character", s.KeyPrefix)
		}
	}
	switch s.Fallback {
	case "", "local", "none":
	default:
		return fmt.Errorf("shared.fallback %q: want local or none", s.Fallback)
	}
	if s.FallbackReplicas < 0 {
		return fmt.Errorf("shared.fallbackReplicas must not be negative")
	}
	return nil
}

func (s *SharedLimit) redisName() string {
	if s.Redis == "" {
		return DefaultRedisName
	}
	return s.Redis
}

func (s *SharedLimit) failOpen() bool { return s.FailOpen == nil || *s.FailOpen }

// sharedState is the compiled shared part of a limiter.
type sharedState struct {
	cfg      SharedLimit
	scope    string // route and rule, part of every key
	limit    int64  // requests per window
	windowMs int64
	prefix   string
	cl       *RedisClient // set by Server.prepareLimiters

	mu        sync.Mutex
	downUntil time.Time

	allowed, limited, fbAllowed, fbLimited, open, unavailable atomic.Int64
}

func newSharedState(c RateLimitConfig) *sharedState {
	sh := c.Shared
	per := c.Per
	if per <= 0 {
		per = time.Second
	}
	limit := int64(math.Ceil(c.Rate - 1e-9))
	if limit < 1 {
		limit = 1
	}
	// c.Rate requests per c.Per, expressed as limit requests per window.
	win := time.Duration(float64(per) * float64(limit) / c.Rate)
	if win < time.Millisecond {
		win = time.Millisecond
	}
	prefix := sh.KeyPrefix
	if prefix == "" {
		prefix = defaultSharedPrefix
	}
	return &sharedState{cfg: *sh, scope: c.Scope, limit: limit, windowMs: win.Milliseconds(), prefix: prefix}
}

// clientPart names the client a request is counted for.
func (l *limiter) clientPart(r *http.Request) string {
	switch {
	case l.key == "route":
		return "-"
	case l.header != "":
		if v := r.Header.Get(l.header); v != "" {
			return "h:" + v
		}
	}
	return "ip:" + l.trusted.clientIP(r)
}

func (st *sharedState) keyFor(client string, win int64) string {
	sum := sha256.Sum256([]byte(client))
	return st.prefix + ":" + st.scope + ":" + hex.EncodeToString(sum[:8]) + ":" + strconv.FormatInt(win, 10)
}

// sharedDecision is the outcome of one shared check.
type sharedDecision struct {
	ok          bool
	wait        time.Duration // when refused: until the window turns over
	limit       int64
	remaining   int64
	reset       time.Duration // until the current window ends
	source      string        // "shared", "fallback" or "open"
	unavailable bool          // Redis failed and the block says fail closed
	headers     bool          // X-RateLimit-* apply
}

// estimate reads the counters of the current and previous window.
func (st *sharedState) estimate(cur, prev int64, elapsedMs int64) float64 {
	w := float64(st.windowMs)
	return float64(prev)*(w-float64(elapsedMs))/w + float64(cur)
}

func (st *sharedState) check(r *http.Request, l *limiter, now time.Time) (sharedDecision, error) {
	ms := now.UnixMilli()
	win := ms / st.windowMs
	elapsed := ms - win*st.windowMs
	client := l.clientPart(r)
	curKey, prevKey := st.keyFor(client, win), st.keyFor(client, win-1)
	ttl := strconv.FormatInt(2*st.windowMs+1000, 10)
	vals, err := st.cl.Do(r.Context(),
		[]string{"MULTI"},
		[]string{"INCR", curKey},
		[]string{"PEXPIRE", curKey, ttl},
		[]string{"GET", prevKey},
		[]string{"EXEC"})
	if err != nil {
		return sharedDecision{}, err
	}
	if len(vals) != 5 {
		return sharedDecision{}, fmt.Errorf("redis: %d replies for 5 commands", len(vals))
	}
	for _, v := range vals {
		if v.isErr() {
			return sharedDecision{}, fmt.Errorf("redis: %s", v.str)
		}
	}
	ex := vals[4]
	if ex.kind != respArray || ex.nil_ || len(ex.arr) != 3 {
		return sharedDecision{}, fmt.Errorf("redis: transaction aborted")
	}
	cur, ok := ex.arr[0].intValue()
	if !ok {
		return sharedDecision{}, fmt.Errorf("redis: INCR did not return a number")
	}
	var prev int64
	if p := ex.arr[2]; !(p.kind == respBulk && p.nil_) {
		if prev, ok = p.intValue(); !ok {
			return sharedDecision{}, fmt.Errorf("redis: previous window is not a number")
		}
	}
	est := st.estimate(cur, prev, elapsed)
	d := sharedDecision{limit: st.limit, source: "shared", headers: true,
		reset: time.Duration(st.windowMs-elapsed) * time.Millisecond}
	d.ok = est <= float64(st.limit)
	if rem := math.Floor(float64(st.limit) - est); rem > 0 {
		d.remaining = int64(rem)
	}
	if !d.ok {
		d.wait = d.reset
		// A refused request must not count against the client: give the slot back (best effort).
		st.cl.Do(r.Context(), []string{"DECR", curKey})
	}
	return d, nil
}

// sharedAllow decides a request for a limiter with a shared counter.
func (s *Server) sharedAllow(l *limiter, route string, r *http.Request) sharedDecision {
	st := l.sh
	now := l.now()
	var err error
	st.mu.Lock()
	down := now.Before(st.downUntil)
	st.mu.Unlock()
	switch {
	case st.cl == nil:
		err = fmt.Errorf("redis %q is not configured", st.cfg.redisName())
	case down:
		err = fmt.Errorf("redis is marked down")
	default:
		var d sharedDecision
		if d, err = st.check(r, l, now); err == nil {
			l.count(route, d.ok)
			if d.ok {
				st.allowed.Add(1)
			} else {
				st.limited.Add(1)
			}
			return d
		}
		st.mu.Lock()
		st.downUntil = now.Add(sharedCooldown)
		st.mu.Unlock()
	}
	if !st.cfg.failOpen() {
		st.unavailable.Add(1)
		return sharedDecision{unavailable: true, wait: sharedCooldown, source: "unavailable"}
	}
	if st.cfg.Fallback == "none" {
		st.open.Add(1)
		return sharedDecision{ok: true, source: "open"}
	}
	ok, wait := l.allow(route, r)
	d := sharedDecision{ok: ok, wait: wait, source: "fallback", limit: st.limit, headers: true, reset: time.Duration(st.windowMs) * time.Millisecond}
	if ok {
		st.fbAllowed.Add(1)
	} else {
		st.fbLimited.Add(1)
	}
	if tok, _ := l.peek(l.bucketKey(route, r), now); tok >= 1 {
		d.remaining = int64(tok)
	}
	return d
}

// count records the outcome of a request decided by Redis in the limiter's
// totals (a local decision is counted by allow itself).
func (l *limiter) count(route string, ok bool) {
	l.mu.Lock()
	if ok {
		l.allowed++
	} else {
		l.limited[route]++
	}
	l.mu.Unlock()
}

func setRateLimitHeaders(h http.Header, d sharedDecision) {
	if !d.headers {
		return
	}
	h.Set("X-RateLimit-Limit", strconv.FormatInt(d.limit, 10))
	h.Set("X-RateLimit-Remaining", strconv.FormatInt(d.remaining, 10))
	secs := int64(math.Ceil(d.reset.Seconds()))
	if secs < 1 {
		secs = 1
	}
	h.Set("X-RateLimit-Reset", strconv.FormatInt(secs, 10))
}

// sharedPeek reads a client's current window without counting a request.
func (st *sharedState) peek(l *limiter, route string, r *http.Request, now time.Time) (est float64, err error) {
	if st.cl == nil {
		return 0, fmt.Errorf("redis %q is not configured", st.cfg.redisName())
	}
	ms := now.UnixMilli()
	win := ms / st.windowMs
	client := l.clientPart(r)
	vals, err := st.cl.Do(r.Context(), []string{"GET", st.keyFor(client, win)}, []string{"GET", st.keyFor(client, win-1)})
	if err != nil {
		return 0, err
	}
	var n [2]int64
	for i, v := range vals {
		if v.isErr() {
			return 0, fmt.Errorf("redis: %s", v.str)
		}
		if !(v.kind == respBulk && v.nil_) {
			n[i], _ = v.intValue()
		}
	}
	return st.estimate(n[0], n[1], ms-win*st.windowMs), nil
}

// describe is the one line policy text of a shared limit.
func (st *sharedState) describe() string {
	mode := "fails open to a per-replica token bucket"
	switch {
	case !st.cfg.failOpen():
		mode = "fails closed with 503"
	case st.cfg.Fallback == "none":
		mode = "fails open without a fallback"
	}
	return fmt.Sprintf("%d requests per %s, shared through Redis %q (key prefix %s), %s when Redis is down",
		st.limit, (time.Duration(st.windowMs) * time.Millisecond).String(), st.cfg.redisName(), st.prefix, mode)
}

// sharedRateLimited applies a rule's shared limiter: 429 with Retry-After and
// X-RateLimit-* when the window is full, 503 when Redis is down and the block
// fails closed, and the X-RateLimit-* headers on admitted requests.
func (s *Server) sharedRateLimited(w http.ResponseWriter, r *http.Request, st *reqState, l *limiter) bool {
	d := s.sharedAllow(l, st.route, r)
	setRateLimitHeaders(w.Header(), d)
	switch {
	case d.unavailable:
		st.errMsg, st.rateLimited = "rate limit backend unavailable", false
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.wait.Seconds()))))
		plain(w, http.StatusServiceUnavailable, "rate limit service unavailable")
		return true
	case d.ok:
		return false
	}
	secs := int(math.Ceil(d.wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	st.errMsg, st.rateLimited = "rate limited (route, "+d.source+")", true
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	plain(w, http.StatusTooManyRequests, "rate limit exceeded")
	return true
}

// sharedMetrics writes the shared rate limit families. Labels are bounded:
// route and rule come from the configuration, result and redis name from
// fixed sets and the --redis flags.
func (s *Server) sharedMetrics(b *strings.Builder) {
	var rls []ruleLimiter
	for _, rl := range s.table.Load().ruleLimiters() {
		if rl.l.sh != nil {
			rls = append(rls, rl)
		}
	}
	if len(rls) == 0 {
		return
	}
	fmt.Fprint(b, "# HELP setura_gateway_shared_ratelimit_requests_total Requests decided by a shared (Redis) rate limit, by result: allowed, limited, fallback_allowed, fallback_limited (Redis down, local bucket), open (Redis down, no fallback), unavailable (Redis down, failOpen false).\n# TYPE setura_gateway_shared_ratelimit_requests_total counter\n")
	for _, rl := range rls {
		sh := rl.l.sh
		for _, c := range []struct {
			res string
			n   int64
		}{{"allowed", sh.allowed.Load()}, {"limited", sh.limited.Load()}, {"fallback_allowed", sh.fbAllowed.Load()},
			{"fallback_limited", sh.fbLimited.Load()}, {"open", sh.open.Load()}, {"unavailable", sh.unavailable.Load()}} {
			fmt.Fprintf(b, "setura_gateway_shared_ratelimit_requests_total{route=\"%s\",rule=\"%d\",result=\"%s\"} %d\n", esc(rl.route), rl.rule, c.res, c.n)
		}
	}
	names := make([]string, 0, len(s.redis))
	for n := range s.redis {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprint(b, "# HELP setura_gateway_redis_errors_total Failed Redis round trips of the shared rate limiter.\n# TYPE setura_gateway_redis_errors_total counter\n")
	for _, n := range names {
		fmt.Fprintf(b, "setura_gateway_redis_errors_total{redis=\"%s\"} %d\n", esc(n), s.redis[n].errors.Load())
	}
	fmt.Fprint(b, "# HELP setura_gateway_redis_up 1 when the last Redis round trip succeeded, 0 when it failed (absent until one was tried).\n# TYPE setura_gateway_redis_up gauge\n")
	for _, n := range names {
		c := s.redis[n]
		if !c.used.Load() {
			continue
		}
		v := 0
		if c.up.Load() {
			v = 1
		}
		fmt.Fprintf(b, "setura_gateway_redis_up{redis=\"%s\"} %d\n", esc(n), v)
	}
}
