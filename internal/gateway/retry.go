package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// RetryRule is the HTTPRoute rule `retry` field (Gateway API HTTPRouteRetry).
type RetryRule struct {
	Codes    []int  `json:"codes,omitempty"`
	Attempts *int   `json:"attempts,omitempty"`
	Backoff  string `json:"backoff,omitempty"`
	// PerTryTimeout bounds each attempt until response headers arrive.
	PerTryTimeout string `json:"perTryTimeout,omitempty"`
	// Jitter randomises each backoff by +/- this fraction (0-1).
	Jitter *float64 `json:"jitter,omitempty"`
	// CrossBackend lets a retry move to another weighted backendRef
	// (overrides the gateway default).
	CrossBackend *bool `json:"crossBackend,omitempty"`
}

const (
	maxRetryAttempts    = 10
	defaultRetryTries   = 1
	defaultRetryBackoff = 25 * time.Millisecond
)

// CRetry is a compiled retry rule.
type CRetry struct {
	Codes    map[int]bool
	Attempts int // retries after the first attempt
	Backoff  time.Duration

	PerTry       time.Duration
	Jitter       *float64
	CrossBackend *bool
}

func compileRetry(r *RetryRule) (*CRetry, error) {
	c := &CRetry{Codes: map[int]bool{}, Attempts: defaultRetryTries, Backoff: defaultRetryBackoff}
	for _, code := range r.Codes {
		if code < 400 || code > 599 {
			return nil, fmt.Errorf("retry.codes: %d is outside 400-599", code)
		}
		c.Codes[code] = true
	}
	if r.Attempts != nil {
		if *r.Attempts < 0 || *r.Attempts > maxRetryAttempts {
			return nil, fmt.Errorf("retry.attempts: %d is outside 0-%d", *r.Attempts, maxRetryAttempts)
		}
		c.Attempts = *r.Attempts
	}
	if r.Backoff != "" {
		d, err := time.ParseDuration(r.Backoff)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("retry.backoff: %q is not a duration", r.Backoff)
		}
		c.Backoff = d
	}
	if r.PerTryTimeout != "" {
		d, err := time.ParseDuration(r.PerTryTimeout)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("retry.perTryTimeout: %q is not a positive duration", r.PerTryTimeout)
		}
		c.PerTry = d
	}
	if r.Jitter != nil {
		if *r.Jitter < 0 || *r.Jitter > 1 {
			return nil, fmt.Errorf("retry.jitter: %v is outside 0-1", *r.Jitter)
		}
		c.Jitter = r.Jitter
	}
	c.CrossBackend = r.CrossBackend
	return c, nil
}

const budgetBuckets = 10

// budget is a sliding-window retry budget: retries may not exceed a
// percentage of the requests seen in the window (with a small floor).
type budget struct {
	mu      sync.Mutex
	width   time.Duration
	buckets [budgetBuckets]struct {
		slot          int64
		reqs, retries int64
	}
}

func (b *budget) bucket(now time.Time) (cur int64, idx int) {
	cur = now.UnixNano() / int64(b.width)
	idx = int(((cur % budgetBuckets) + budgetBuckets) % budgetBuckets)
	if b.buckets[idx].slot != cur {
		b.buckets[idx].slot, b.buckets[idx].reqs, b.buckets[idx].retries = cur, 0, 0
	}
	return cur, idx
}

func (b *budget) request(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, i := b.bucket(now)
	b.buckets[i].reqs++
}

// tryRetry takes one retry from the budget if the cap allows it.
func (b *budget) tryRetry(now time.Time, percent, floor int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, i := b.bucket(now)
	var reqs, retries int64
	for _, bk := range b.buckets {
		if bk.slot > cur-budgetBuckets {
			reqs += bk.reqs
			retries += bk.retries
		}
	}
	allowed := reqs * int64(percent) / 100
	if allowed < int64(floor) {
		allowed = int64(floor)
	}
	if retries+1 > allowed {
		return false
	}
	b.buckets[i].retries++
	return true
}

type replayBody struct {
	io.Reader
	io.Closer
}

// bufferBody reads r's body into memory when it fits under limit so it can be
// replayed. When it does not fit the body stays readable and ok is false.
func bufferBody(r *http.Request, limit int64) (buf []byte, ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	if r.ContentLength > limit {
		return nil, false
	}
	orig := r.Body
	buf, err := io.ReadAll(io.LimitReader(orig, limit+1))
	switch {
	case err != nil:
		r.Body = replayBody{io.MultiReader(bytes.NewReader(buf), errReader{err}), orig}
		return nil, false
	case int64(len(buf)) > limit:
		r.Body = replayBody{io.MultiReader(bytes.NewReader(buf), orig), orig}
		return nil, false
	}
	orig.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, true
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// isConnectError reports a failure to establish the connection, after which
// nothing of the request was sent and a retry is always safe.
func isConnectError(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// resTransport is the RoundTripper the proxy uses for every request. It
// observes outcomes for outlier ejection and circuit breaking and, when the
// rule has a retry block, retries failed attempts on another endpoint (or,
// when allowed, another backendRef) before any byte reaches the client.
type resTransport struct {
	s     *Server
	rule  *CRule
	ref   *CRef // the ref serving the current attempt
	b     *Backend
	first *Endpoint
	retry *CRetry

	replay    []byte
	canReplay bool
	// rebuild makes the outbound request for another ref from the request as
	// it was before any filter ran: it applies that ref's filters.
	rebuild func(ctx context.Context, ref *CRef) *http.Request

	tried     map[*Endpoint]bool
	triedRefs map[*CRef]bool
	retries   int
}

func (s *Server) newTransport(rule *CRule, ref *CRef, first *Endpoint, retry *CRetry, replay []byte, canReplay bool) *resTransport {
	return &resTransport{s: s, rule: rule, ref: ref, b: ref.B, first: first, retry: retry, replay: replay, canReplay: canReplay,
		tried: map[*Endpoint]bool{}, triedRefs: map[*CRef]bool{ref: true}}
}

// annotate adds the retry-count header when enabled.
func (t *resTransport) annotate(h http.Header) {
	if t.s.res.opt().RetryHeader && t.retry != nil {
		h.Set(RetryHeaderName, strconv.Itoa(t.retries))
	}
}

func (t *resTransport) crossBackend() bool {
	if t.rebuild == nil || t.retry == nil || len(t.rule.Refs) < 2 {
		return false
	}
	if t.retry.CrossBackend != nil {
		return *t.retry.CrossBackend
	}
	return t.s.res.opt().RetryCrossBackend
}

// otherRef picks, by weight, a backendRef not tried yet whose backend can take
// traffic; nil when there is none.
func (t *resTransport) otherRef() *CRef {
	now := t.s.res.now()
	total := 0
	for _, c := range t.rule.Refs {
		if c.B != nil && c.Weight > 0 && !t.triedRefs[c] && c.B.available(now) {
			total += c.Weight
		}
	}
	if total == 0 {
		return nil
	}
	n := t.s.intn(total)
	for _, c := range t.rule.Refs {
		if c.B != nil && c.Weight > 0 && !t.triedRefs[c] && c.B.available(now) {
			if n < c.Weight {
				return c
			}
			n -= c.Weight
		}
	}
	return nil
}

// backoffFor is the wait before retry number n, with jitter applied.
func (t *resTransport) backoffFor() time.Duration {
	d := t.retry.Backoff
	j := t.s.res.opt().RetryJitter
	if t.retry.Jitter != nil {
		j = *t.retry.Jitter
	}
	if d > 0 && j > 0 {
		u := float64(t.s.intn(1001)) / 1000 // 0..1
		d = time.Duration(float64(d) * (1 + j*(2*u-1)))
	}
	return d
}

// tryBody cancels a per-try context when the response body is done.
type tryBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *tryBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

func (t *resTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rs := t.s.res
	ctx := req.Context()
	var bud *budget
	if t.retry != nil {
		bud = rs.budgetFor(t.b.Key)
		bud.request(rs.now())
	}
	bodyless := req.Body == nil || req.Body == http.NoBody
	cross := t.crossBackend()
	switched := false // the current attempt uses a ref other than the first
	for attempt := 0; ; attempt++ {
		ep := t.first
		if attempt > 0 || ep == nil {
			ep = t.b.choose(rs.now(), t.tried)
		}
		t.tried[ep] = true
		var out *http.Request
		if switched {
			out = t.rebuild(ctx, t.ref)
		} else {
			out = req.Clone(ctx)
		}
		out.URL.Scheme, out.URL.Host = ep.URL.Scheme, ep.URL.Host
		if t.retry != nil && t.canReplay && !bodyless {
			out.Body = io.NopCloser(bytes.NewReader(t.replay))
		}

		// Circuit breaker for this attempt's backend.
		lim := t.s.limitsFor(t.b)
		var tk *cbTicket
		var cerr error
		if lim.enabled() {
			tk, cerr = rs.enter(ctx, rs.breakerFor(t.b.Key), lim)
		}
		var resp *http.Response
		var err error
		var cancelTry context.CancelFunc = func() {}
		perTryHit := false
		if cerr != nil {
			err = cerr
		} else {
			actx := ctx
			var timer *time.Timer
			if pt := t.retry; pt != nil && pt.PerTry > 0 {
				actx, cancelTry = context.WithCancel(ctx)
				timer = time.AfterFunc(pt.PerTry, cancelTry)
				out = out.WithContext(actx)
			}
			resp, err = t.s.transportFor(t.b, lim).RoundTrip(out)
			if timer != nil && !timer.Stop() && resp == nil && ctx.Err() == nil {
				perTryHit = true
				err = fmt.Errorf("per-try timeout %s exceeded: %w", t.retry.PerTry, context.DeadlineExceeded)
				rs.bump(rs.perTryTimeouts, t.b.Key)
			}
		}
		_, shed := cerr.(*circuitReject)
		cancelled := err != nil && ctx.Err() != nil && !shed
		bad := !shed && (err != nil || resp.StatusCode >= 500)
		if !cancelled && !shed {
			rs.observe(t.b, ep, bad, rs.now())
		}
		if tk != nil {
			if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
				resp.Body = &cbBody{ReadCloser: resp.Body, tk: tk, bad: bad}
			} else {
				tk.done(bad, cancelled)
			}
		}
		// retry decision
		final := func() (*http.Response, error) {
			if resp != nil && t.retry != nil && t.retry.PerTry > 0 {
				resp.Body = &tryBody{ReadCloser: resp.Body, cancel: cancelTry}
			} else {
				cancelTry()
			}
			return resp, err
		}
		if t.retry == nil || cancelled || attempt >= t.retry.Attempts || !(bodyless || t.canReplay) {
			return final()
		}
		var retryable bool
		switch {
		case shed:
			retryable = cross // another backendRef may still serve it
		case err != nil:
			// Non-idempotent requests are retried only when nothing was sent.
			retryable = isConnectError(err) || isIdempotent(req.Method)
		default:
			retryable = t.retry.Codes[resp.StatusCode] && isIdempotent(req.Method)
		}
		_ = perTryHit
		if !retryable {
			return final()
		}
		// Choose where the retry goes before spending budget or time on it.
		var next *CRef
		if cross {
			next = t.otherRef()
		}
		if shed && next == nil {
			return final()
		}
		wait := t.backoffFor()
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= wait {
			return final() // no time left to wait and try again
		}
		if !bud.tryRetry(rs.now(), rs.opt().RetryBudgetPercent, rs.opt().RetryBudgetMin) {
			rs.bump(rs.denied, t.b.Key)
			return final()
		}
		if wait > 0 && rs.sleep(ctx, wait) != nil {
			return final()
		}
		cancelTry()
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
		t.retries++
		rs.bump(rs.retries, t.b.Key)
		if next != nil {
			rs.bump(rs.crossRetries, t.b.Key)
			t.ref, t.b, t.first, switched = next, next.B, nil, true
			t.triedRefs[next] = true
		}
	}
}
