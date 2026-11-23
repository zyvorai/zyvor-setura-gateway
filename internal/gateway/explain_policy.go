package gateway

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// This file models the per-request policy that is not routing: rate limiting,
// retries and mirrors with shadow-diff. Each piece reads the same compiled
// objects (limiter, CRetry, CMirror, CShadow) the data path uses.

// ExplainServer is the gateway-wide policy a route config does not carry.
type ExplainServer struct {
	RateLimit  RateLimitConfig   // --rate-limit/--rate-burst/--rate-key
	Resilience ResilienceOptions // retry budget and body limit
	ShadowDiff int               // --shadow-diff default sample percent
	Path       PathOptions       // --normalize-path, --merge-slashes, --reject-escaped-slashes
	Limits     LimitsOptions     // --max-request-body and the other limits, for the notes
	AuthClock  func() time.Time  // clock of token validation (the running gateway's)
	Plans      *PlanSet          // API plans (--plans); evaluated against fresh counters offline
	Shape      ShapeOptions      // --compress, --bandwidth-*, --request-id: the gateway wide shaping defaults

	chaos   *chaosState // live run-time faults of a running gateway
	limiter *limiter    // live limiter of a running gateway (admin endpoint)
	meter   *meter      // live usage counters of a running gateway
	srv     *Server     // the running gateway (admin endpoint): live AI budget state
}

// liveServerPolicy hands the explainer the running gateway's policy and
// limiter, so the admin endpoint reports the bucket's current state.
func (s *Server) liveServerPolicy() ExplainServer {
	return ExplainServer{RateLimit: s.opts.Obs.RateLimit, Resilience: *s.res.opt(), ShadowDiff: s.opts.ShadowDiff, Path: s.opts.Path, Limits: s.opts.Limits, Shape: s.opts.Shape, AuthClock: s.opts.AuthClock, limiter: s.obs.limiter, chaos: &s.chaos, Plans: s.Plans(), meter: s.meter, srv: s}
}

// TraceMirror is one mirror target of the winning rule.
type TraceMirror struct {
	Backend    string `json:"backend"`
	Percent    int    `json:"percent"`
	ShadowDiff string `json:"shadow_diff"` // "off", or what is compared
}

// TraceRetry is the retry policy of the winning rule.
type TraceRetry struct {
	Codes      []int  `json:"codes,omitempty"`
	Attempts   int    `json:"attempts"`
	Backoff    string `json:"backoff"`
	Budget     string `json:"budget"`
	Idempotent bool   `json:"idempotent"` // the request method may be retried on a status code
}

// TraceRateLimit is the rate-limit bucket this request would draw from.
type TraceRateLimit struct {
	Enabled bool     `json:"enabled"`
	Applies bool     `json:"applies"`          // false for gRPC, TLS passthrough and unlimited gateways
	Policy  string   `json:"policy,omitempty"` // rate, burst and key
	Bucket  string   `json:"bucket,omitempty"` // the key this request resolves to
	Live    bool     `json:"live"`             // Tokens and WouldLimit come from a running gateway
	Source  string   `json:"source,omitempty"` // local (a token bucket in this process) or shared (a counter in Redis)
	Tokens  *float64 `json:"tokens,omitempty"`
	Limited *bool    `json:"would_be_limited,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// peek returns the tokens a bucket would have now without taking one.
func (l *limiter) peek(key string, now time.Time) (tokens float64, exists bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return l.burst, false
	}
	t := b.tokens
	if el := now.Sub(b.last).Seconds(); el > 0 {
		t = math.Min(l.burst, t+el*l.perSec)
	}
	return t, true
}

func (e ExplainServer) describeMirror(m *CMirror) TraceMirror {
	tm := TraceMirror{Backend: m.B.Name, Percent: m.Percent}
	on, sample := m.Shadow.effective(e.ShadowDiff)
	if !on {
		tm.ShadowDiff = "off: copies are fire and forget, responses are not compared"
		return tm
	}
	c := m.Shadow
	hdrs := c.headers
	if len(hdrs) == 0 {
		hdrs = defaultCompareHeaders
	}
	parts := []string{fmt.Sprintf("comparing status, headers [%s] and body for %d%% of mirrored requests", strings.Join(hdrs, ", "), sample)}
	if len(c.ignore) > 0 {
		ig := make([]string, 0, len(c.ignore))
		for k := range c.ignore {
			ig = append(ig, k)
		}
		sort.Strings(ig)
		parts = append(parts, "ignoring headers "+strings.Join(ig, ", "))
	}
	if len(c.paths) > 0 {
		parts = append(parts, fmt.Sprintf("%d ignored JSON path(s)", len(c.paths)))
	}
	parts = append(parts, fmt.Sprintf("bodies up to %d bytes", c.max()))
	if c.latencyMs > 0 {
		parts = append(parts, fmt.Sprintf("latency flagged above +%d ms", c.latencyMs))
	}
	tm.ShadowDiff = strings.Join(parts, "; ")
	return tm
}

// explainPolicy fills mirrors, retry and rate limit of the winner. r is the
// inbound request as the data path sees it.
func (tr *Trace) explainPolicy(w *TraceWinner, e *Entry, q ExplainRequest, r *http.Request) {
	rule := e.Rule
	srv := q.Server
	tr.explainAuth(w, e, q, r)
	if rule.AI != nil {
		tr.explainAI(w, e, q, r)
	}
	if e.GRPC {
		w.RateLimit = srv.rateLimit(w.Route, q, r)
	} else {
		w.RateLimit = srv.rateLimit(w.Route, q, r)
		w.RouteLimit = srv.ruleRateLimit(rule, w.Route, q, r)
		srv.noteLimits(w, rule, tr.chosen)
		w.Plan = tr.explainPlan(e, q, r, w.Route)
		if rule.Redirect == nil && rule.Direct == nil {
			for _, m := range rule.Mirrors {
				tm := srv.describeMirror(m)
				w.MirrorTargets = append(w.MirrorTargets, tm)
				w.Mirrors = append(w.Mirrors, fmt.Sprintf("%d%% of requests are copied to %s (fire and forget, the response is ignored); shadow-diff %s", m.Percent, m.B.Name, tm.ShadowDiff))
			}
			if rule.Retry != nil {
				w.Retry = srv.retry(rule.Retry, r.Method)
			}
		}
	}
}

func (e ExplainServer) retry(c *CRetry, method string) *TraceRetry {
	o := *newResilience(e.Resilience).opt()
	tr := &TraceRetry{Attempts: c.Attempts, Backoff: c.Backoff.String(), Idempotent: isIdempotent(method)}
	for code := range c.Codes {
		tr.Codes = append(tr.Codes, code)
	}
	sort.Ints(tr.Codes)
	tr.Budget = fmt.Sprintf("retries are capped at %d%% of the requests to the backend in the last %s (at least %d always allowed); request bodies over %d bytes are not retried",
		o.RetryBudgetPercent, o.RetryBudgetWindow, o.RetryBudgetMin, o.RetryBodyLimit)
	return tr
}

func (e ExplainServer) rateLimit(route string, q ExplainRequest, r *http.Request) *TraceRateLimit {
	t := &TraceRateLimit{}
	l := e.limiter
	if l == nil {
		l = newLimiter(e.RateLimit, nil)
	}
	if l == nil {
		t.Note = "no rate limit is configured on the gateway (--rate-limit); pass --rate-limit to model one"
		return t
	}
	t.Enabled, t.Applies = true, true
	t.Policy = fmt.Sprintf("%g tokens/s, burst %g, key %s", l.perSec, l.burst, l.key)
	t.Bucket = strings.ReplaceAll(l.bucketKey(route, r), "\x00", " | ")
	if !q.Live || e.limiter == nil {
		t.Note = "policy only: a fresh bucket starts full, so the first request for this key is admitted; live bucket state needs --admin"
		return t
	}
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	tok, exists := l.peek(l.bucketKey(route, r), now)
	limited := tok < 1
	t.Live, t.Tokens, t.Limited = true, &tok, &limited
	if !exists {
		t.Note = "no bucket exists for this key yet, so it starts full"
	}
	return t
}

// ruleRateLimit models the rule's own limiter (setura.zyvor.dev/rate-limit).
// The limiter is the table's, so a running gateway reports its live bucket.
func (e ExplainServer) ruleRateLimit(rule *CRule, route string, q ExplainRequest, r *http.Request) *TraceRateLimit {
	l := rule.Limit
	if l == nil {
		return nil
	}
	t := &TraceRateLimit{Enabled: true, Applies: true, Source: "local"}
	t.Policy = fmt.Sprintf("%g tokens/s, burst %g, key %s (this rule)", l.perSec, l.burst, l.key)
	t.Bucket = strings.ReplaceAll(l.bucketKey(route, r), "\x00", " | ")
	if l.sh != nil {
		return e.sharedRateLimit(t, l, route, q, r)
	}
	if !q.Live {
		t.Note = "policy only: a fresh bucket starts full, so the first request for this key is admitted; live bucket state needs --admin"
		return t
	}
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	tok, exists := l.peek(l.bucketKey(route, r), now)
	limited := tok < 1
	t.Live, t.Tokens, t.Limited = true, &tok, &limited
	if !exists {
		t.Note = "no bucket exists for this key yet, so it starts full"
	}
	return t
}

// noteLimits adds the size and idle limits that apply to the winning rule.
func (e ExplainServer) noteLimits(w *TraceWinner, rule *CRule, l *RTListener) {
	max := e.Limits.MaxBodyBytes
	switch {
	case rule.MaxBody != nil:
		max = *rule.MaxBody
	case l != nil && l.MaxBody != nil:
		max = *l.MaxBody
	}
	if max > 0 {
		w.Notes = append(w.Notes, fmt.Sprintf("request bodies over %d bytes are refused with 413", max))
	}
	idle := e.Limits.StreamIdleTimeout
	if rule.StreamIdle != nil {
		idle = *rule.StreamIdle
	}
	if idle > 0 && rule.Direct == nil {
		w.Notes = append(w.Notes, fmt.Sprintf("a response that sends no byte for %s is cut", idle))
	}
	if pol := e.compressFor(l, rule); pol.enabled {
		src := "gateway --compress"
		switch {
		case rule.Compress != nil && rule.Compress.Enabled != nil:
			src = "the rule's " + CompressKey + " block"
		case l != nil && l.Compress != nil && l.Compress.Enabled != nil:
			src = "the listener's " + CompressKey + " block"
		}
		w.Notes = append(w.Notes, fmt.Sprintf("responses are compressed (%s; %s) when the client accepts it, the content type is on the list and the body is at least %d bytes; source: %s",
			strings.Join(pol.encodings, ", "), "level "+fmt.Sprint(pol.level), pol.min, src))
	} else if rule.Compress != nil && rule.Compress.Enabled != nil && !*rule.Compress.Enabled {
		w.Notes = append(w.Notes, "response compression is switched off for this rule")
	}
	if in, out, _ := e.bandwidthFor(rule); (in > 0 || out > 0) && rule.Direct == nil {
		w.Notes = append(w.Notes, fmt.Sprintf("bandwidth is limited per request to %d bytes/s (request body, 0 = none) and %d bytes/s (response body, 0 = none)", in, out))
	}
	if rule.GRPCWeb != nil {
		w.Notes = append(w.Notes, "gRPC-web calls (application/grpc-web, application/grpc-web-text) are translated to gRPC for the backend")
	}
}

// sharedRateLimit describes a rule limit whose count lives in Redis. A running
// gateway reads the client's counters (a read only, nothing is counted).
func (e ExplainServer) sharedRateLimit(t *TraceRateLimit, l *limiter, route string, q ExplainRequest, r *http.Request) *TraceRateLimit {
	sh := l.sh
	t.Source = "shared"
	t.Policy = sh.describe() + fmt.Sprintf("; key %s (this rule)", l.key)
	t.Bucket = sh.scope + " | " + l.clientPart(r)
	if !q.Live {
		t.Note = "policy only: the count is in Redis and is shared by every gateway replica; live state needs --admin"
		return t
	}
	now := q.Now
	if now.IsZero() {
		now = l.now()
	}
	est, err := sh.peek(l, route, r, now)
	if err != nil {
		t.Note = "Redis could not be read (" + err.Error() + "): requests are served by the " + map[bool]string{true: "per-replica fallback bucket", false: "fail-closed 503 answer"}[sh.cfg.failOpen()]
		return t
	}
	rem := float64(sh.limit) - est
	limited := rem < 1
	t.Live, t.Tokens, t.Limited = true, &rem, &limited
	t.Note = fmt.Sprintf("%.1f of %d requests used in the sliding window", est, sh.limit)
	return t
}

func (e ExplainServer) compressFor(l *RTListener, rule *CRule) compressPolicy {
	var lc *CompressConfig
	if l != nil {
		lc = l.Compress
	}
	var gw *CompressConfig
	if e.Shape.Compress.Enabled {
		gw = e.Shape.Compress.config()
	}
	return resolveCompress(gw, lc, rule.Compress)
}

func (e ExplainServer) bandwidthFor(rule *CRule) (in, out, burst int64) {
	in, out = e.Shape.BandwidthIn, e.Shape.BandwidthOut
	if sp := rule.BW; sp != nil {
		if sp.in != nil {
			in = *sp.in
		}
		if sp.out != nil {
			out = *sp.out
		}
		burst = sp.burst
	}
	return
}
