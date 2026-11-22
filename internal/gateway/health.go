package gateway

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResilienceOptions tunes retries, outlier ejection and default active health
// checks. The zero value gives the documented defaults.
type ResilienceOptions struct {
	// Retries.
	RetryBudgetPercent int           // retries allowed as a percentage of recent requests (default 20)
	RetryBudgetMin     int           // retries always allowed per window, so quiet routes can retry (default 3)
	RetryBudgetWindow  time.Duration // sliding window for the budget (default 10s)
	RetryBodyLimit     int64         // largest request body buffered for replay (default 64 KiB)
	RetryHeader        bool          // add X-Setura-Retries to responses (default off)
	RetryCrossBackend  bool          // retries may move to another weighted backendRef (a rule's retry.crossBackend overrides)
	RetryJitter        float64       // backoff jitter as a fraction, 0-1 (a rule's retry.jitter overrides; default 0 = none)

	// Passive outlier ejection. OutlierFailures < 0 disables it.
	OutlierFailures  int           // consecutive 5xx or connection failures that eject an endpoint (default 5)
	OutlierBaseEject time.Duration // first ejection lasts this long, then doubles (default 30s)
	OutlierMaxEject  time.Duration // ejection cap (default 5m)

	// Defaults for backends that have no healthCheck of their own. An empty
	// HealthPath leaves active checks off for those backends.
	HealthPath     string
	HealthInterval time.Duration
	HealthTimeout  time.Duration

	// Circuit breaking defaults for every backend; a backend's circuitBreaker
	// block overrides them field by field. The zero value disables it.
	Circuit CircuitOptions

	// Test hooks.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// RetryHeaderName is the optional response header carrying the retry count.
const RetryHeaderName = "X-Setura-Retries"

// resilience is the server-wide state shared by retries, ejection and metrics.
type resilience struct {
	raw ResilienceOptions // flags / Options as given (zero = unset)
	cur atomic.Pointer[ResilienceOptions]

	mu             sync.Mutex
	budgets        map[string]*budget
	retries        map[string]int64
	denied         map[string]int64
	ejections      map[string]int64
	crossRetries   map[string]int64
	perTryTimeouts map[string]int64
	breakers       map[string]*breaker
	transports     map[string]*http.Transport // per-backend transports (maxConnections)
}

// opt returns the effective options: flags, then the config file's
// resilience block, then built-in defaults.
func (rs *resilience) opt() *ResilienceOptions { return rs.cur.Load() }

func newResilience(o ResilienceOptions) *resilience {
	rs := &resilience{raw: o, budgets: map[string]*budget{}, retries: map[string]int64{}, denied: map[string]int64{}, ejections: map[string]int64{},
		crossRetries: map[string]int64{}, perTryTimeouts: map[string]int64{}, breakers: map[string]*breaker{}, transports: map[string]*http.Transport{}}
	rs.cur.Store(normalizeResilience(o))
	return rs
}

func normalizeResilience(o ResilienceOptions) *ResilienceOptions {
	if o.RetryBudgetPercent <= 0 {
		o.RetryBudgetPercent = 20
	}
	if o.RetryBudgetMin <= 0 {
		o.RetryBudgetMin = 3
	}
	if o.RetryBudgetWindow <= 0 {
		o.RetryBudgetWindow = 10 * time.Second
	}
	if o.RetryBodyLimit <= 0 {
		o.RetryBodyLimit = 64 << 10
	}
	if o.OutlierFailures == 0 {
		o.OutlierFailures = 5
	}
	if o.OutlierBaseEject <= 0 {
		o.OutlierBaseEject = 30 * time.Second
	}
	if o.OutlierMaxEject <= 0 {
		o.OutlierMaxEject = 5 * time.Minute
	}
	if o.OutlierMaxEject < o.OutlierBaseEject {
		o.OutlierMaxEject = o.OutlierBaseEject
	}
	if o.HealthInterval <= 0 {
		o.HealthInterval = 5 * time.Second
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 2 * time.Second
	}
	return &o
}

func (rs *resilience) now() time.Time {
	if rs.opt().Now != nil {
		return rs.opt().Now()
	}
	return time.Now()
}

func (rs *resilience) sleep(ctx context.Context, d time.Duration) error {
	if rs.opt().Sleep != nil {
		return rs.opt().Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (rs *resilience) bump(m map[string]int64, key string) {
	rs.mu.Lock()
	m[key]++
	rs.mu.Unlock()
}

func (rs *resilience) budgetFor(key string) *budget {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	b := rs.budgets[key]
	if b == nil {
		b = &budget{width: rs.opt().RetryBudgetWindow / budgetBuckets}
		if b.width <= 0 {
			b.width = time.Millisecond
		}
		rs.budgets[key] = b
	}
	return b
}

// epState is the per-endpoint health bookkeeping, guarded by Backend.hmu.
type epState struct {
	fails     int       // consecutive passive failures
	ejections int       // ejection count, drives the backoff
	until     time.Time // ejected until
	actFail   int       // consecutive failed active probes
	actOK     int       // consecutive successful active probes
}

// up reports whether the endpoint may receive traffic. Caller holds hmu.
func (b *Backend) up(e *Endpoint, now time.Time) bool {
	return e.healthy.Load() && !now.Before(e.st.until)
}

// available reports whether any endpoint of the backend can take traffic.
func (b *Backend) available(now time.Time) bool {
	b.hmu.Lock()
	defer b.hmu.Unlock()
	for _, e := range b.Eps {
		if b.up(e, now) {
			return true
		}
	}
	return false
}

// choose returns the next endpoint round-robin, skipping unhealthy and ejected
// ones and, when possible, those in skip. With nothing healthy it still
// returns an endpoint so the request is attempted.
func (b *Backend) choose(now time.Time, skip map[*Endpoint]bool) *Endpoint {
	n := len(b.Eps)
	if n == 0 {
		return nil
	}
	b.hmu.Lock()
	defer b.hmu.Unlock()
	start := int(b.rr.Add(1) - 1)
	var anyUp *Endpoint
	for i := 0; i < n; i++ {
		e := b.Eps[(start+i)%n]
		if !b.up(e, now) {
			continue
		}
		if !skip[e] {
			return e
		}
		if anyUp == nil {
			anyUp = e
		}
	}
	if anyUp != nil {
		return anyUp
	}
	return b.Eps[start%n]
}

// observe feeds one upstream outcome into passive outlier detection.
func (rs *resilience) observe(b *Backend, ep *Endpoint, bad bool, now time.Time) {
	if rs.opt().OutlierFailures < 0 {
		return
	}
	b.hmu.Lock()
	defer b.hmu.Unlock()
	st := &ep.st
	if now.Before(st.until) {
		return // already ejected; late results from in-flight requests do not count
	}
	if !bad {
		st.fails = 0
		if st.ejections > 0 {
			st.ejections-- // a served request after probation earns back one backoff step
		}
		return
	}
	st.fails++
	if st.fails < rs.opt().OutlierFailures {
		return
	}
	others := 0
	for _, e := range b.Eps {
		if e != ep && b.up(e, now) {
			others++
		}
	}
	if others == 0 {
		return // never eject the last healthy endpoint
	}
	d := rs.opt().OutlierBaseEject
	for i := 0; i < st.ejections && d < rs.opt().OutlierMaxEject; i++ {
		d *= 2
	}
	if d > rs.opt().OutlierMaxEject {
		d = rs.opt().OutlierMaxEject
	}
	st.until = now.Add(d)
	st.ejections++
	st.fails = 0
	rs.bump(rs.ejections, b.Key)
}

// pickRef does the weighted backendRef choice over refs that can take
// traffic, so weights renormalise when a backend is fully ejected or down.
// Unresolved refs keep their weight (the spec wants a 500 for that share).
// When nothing is available it falls back to all refs.
func (s *Server) pickRef(rule *CRule) *CRef {
	if rule.Total <= 0 {
		return nil
	}
	now := s.res.now()
	live := func(c *CRef) bool { return c.B == nil || c.B.available(now) }
	total := 0
	for _, c := range rule.Refs {
		if live(c) {
			total += c.Weight
		}
	}
	all := total == 0
	if all {
		total = rule.Total
	}
	n := s.intn(total)
	for _, c := range rule.Refs {
		if !all && !live(c) {
			continue
		}
		if n < c.Weight {
			return c
		}
		n -= c.Weight
	}
	return nil
}

// healthConfig resolves a backend's active check settings; nil means none.
type healthConfig struct {
	path               string
	interval, timeout  time.Duration
	unhealthy, healthy int
	grpc               bool   // probe grpc.health.v1.Health/Check instead of an HTTP GET
	service            string // gRPC health service name ("" = whole server)
}

func (s *Server) healthConfigFor(b *Backend) *healthConfig {
	hc := b.Health
	if hc == nil && s.res.opt().HealthPath == "" {
		return nil
	}
	c := &healthConfig{path: s.res.opt().HealthPath, interval: s.res.opt().HealthInterval, timeout: s.res.opt().HealthTimeout, unhealthy: 1, healthy: 1}
	if hc != nil {
		c.path = hc.Path
		c.grpc, c.service = strings.EqualFold(hc.Protocol, "grpc"), hc.Service
		if d, err := parseDur(hc.Interval); err == nil && d > 0 {
			c.interval = d
		}
		if d, err := parseDur(hc.Timeout); err == nil && d > 0 {
			c.timeout = d
		}
		if hc.UnhealthyThreshold > 0 {
			c.unhealthy = hc.UnhealthyThreshold
		}
		if hc.HealthyThreshold > 0 {
			c.healthy = hc.HealthyThreshold
		}
	}
	if c.path == "" && !c.grpc {
		c.path = "/"
	}
	if c.interval <= 0 {
		c.interval = 5 * time.Second
	}
	if c.timeout <= 0 {
		c.timeout = 2 * time.Second
	}
	return c
}

// startHealth runs active checks for every endpoint of b until ctx ends.
func (s *Server) startHealth(ctx context.Context, b *Backend) {
	c := s.healthConfigFor(b)
	if c == nil {
		return
	}
	client := &http.Client{Transport: s.backendTransport(b), Timeout: c.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, ep := range b.Eps {
		go func(ep *Endpoint) {
			s.checkEndpoint(ctx, client, c, b, ep)
			tk := time.NewTicker(c.interval)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					s.checkEndpoint(ctx, client, c, b, ep)
				}
			}
		}(ep)
	}
}

// checkEndpoint probes one endpoint once and applies the thresholds.
func (s *Server) checkEndpoint(ctx context.Context, client *http.Client, c *healthConfig, b *Backend, ep *Endpoint) {
	ok := false
	if c.grpc {
		ok = s.grpcHealthProbe(ctx, c, b, ep)
	} else if req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL.String()+c.path, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			ok = resp.StatusCode < 400
		}
	}
	if ctx.Err() != nil {
		return
	}
	b.hmu.Lock()
	defer b.hmu.Unlock()
	st := &ep.st
	if ok {
		st.actFail = 0
		if st.actOK++; st.actOK >= c.healthy {
			ep.healthy.Store(true)
		}
		return
	}
	st.actOK = 0
	if st.actFail++; st.actFail >= c.unhealthy {
		ep.healthy.Store(false)
	}
}
