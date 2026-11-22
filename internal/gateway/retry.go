package gateway

import (
	"bytes"
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
// observes outcomes for outlier ejection and, when the rule has a retry
// block, retries failed attempts on another endpoint before any byte reaches
// the client.
type resTransport struct {
	s     *Server
	base  http.RoundTripper
	b     *Backend
	first *Endpoint
	retry *CRetry

	replay    []byte
	canReplay bool

	tried   map[*Endpoint]bool
	retries int
	st      *reqState // receives upstream details; may be nil
}

func (s *Server) newTransport(b *Backend, first *Endpoint, retry *CRetry, replay []byte, canReplay bool) *resTransport {
	return &resTransport{s: s, base: s.transport(b.Insecure), b: b, first: first, retry: retry, replay: replay, canReplay: canReplay, tried: map[*Endpoint]bool{}}
}

// annotate adds the retry-count header when enabled.
func (t *resTransport) annotate(h http.Header) {
	if t.s.res.o.RetryHeader && t.retry != nil {
		h.Set(RetryHeaderName, strconv.Itoa(t.retries))
	}
}

func (t *resTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rs := t.s.res
	ctx := req.Context()
	var bud *budget
	if t.retry != nil {
		bud = rs.budgetFor(t.b.Key)
		bud.request(rs.now())
	}
	bodyless := req.Body == nil || req.Body == http.NoBody
	for attempt := 0; ; attempt++ {
		ep := t.first
		if attempt > 0 || ep == nil {
			ep = t.b.choose(rs.now(), t.tried)
		}
		t.tried[ep] = true
		rctx, health := ctx, ""
		var tr *attemptTrace
		if t.st != nil {
			rctx, tr = t.st.up.begin(ctx)
			health = t.b.state(ep, rs.now())
		}
		out := req.Clone(rctx)
		out.URL.Scheme, out.URL.Host = ep.URL.Scheme, ep.URL.Host
		if t.retry != nil && t.canReplay && !bodyless {
			out.Body = io.NopCloser(bytes.NewReader(t.replay))
		}
		resp, err := t.base.RoundTrip(out)
		if t.st != nil {
			t.st.up.end(tr, ep, health, resp, err)
			t.st.noteUpstream()
		}
		cancelled := err != nil && ctx.Err() != nil
		if !cancelled {
			rs.observe(t.b, ep, err != nil || resp.StatusCode >= 500, rs.now())
		}
		if t.retry == nil || cancelled || attempt >= t.retry.Attempts || !(bodyless || t.canReplay) {
			return resp, err
		}
		var retryable bool
		if err != nil {
			// Non-idempotent requests are retried only when nothing was sent.
			retryable = isConnectError(err) || isIdempotent(req.Method)
		} else {
			retryable = t.retry.Codes[resp.StatusCode] && isIdempotent(req.Method)
		}
		if !retryable {
			return resp, err
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= t.retry.Backoff {
			return resp, err // no time left to wait and try again
		}
		if !bud.tryRetry(rs.now(), rs.o.RetryBudgetPercent, rs.o.RetryBudgetMin) {
			rs.bump(rs.denied, t.b.Key)
			return resp, err
		}
		if t.retry.Backoff > 0 && rs.sleep(ctx, t.retry.Backoff) != nil {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
		t.retries++
		rs.bump(rs.retries, t.b.Key)
	}
}
