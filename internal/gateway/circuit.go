package gateway

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Circuit breaker states.
const (
	cbClosed = iota
	cbOpen
	cbHalfOpen
)

// Reasons a request is refused by a circuit breaker.
const (
	CircuitOpen        = "open"
	CircuitMaxRequests = "max_requests"
	CircuitMaxPending  = "max_pending"
)

// CircuitHeader names the response header that says why a request was shed.
const CircuitHeader = "X-Setura-Circuit"

// circuitReject is the error a breaker returns instead of sending a request.
type circuitReject struct{ Reason string }

func (e *circuitReject) Error() string { return "circuit breaker " + e.Reason }

// cbLimits are the effective settings of one backend.
type cbLimits struct {
	maxReq, maxPend, maxConn, failures, probes int
	openFor                                    time.Duration
}

func (l cbLimits) enabled() bool { return l.maxReq > 0 || l.failures > 0 }

// limitsFor resolves gateway defaults overlaid with the backend's own block.
func (s *Server) limitsFor(b *Backend) cbLimits {
	o := s.res.opt().Circuit
	if b.CB != nil {
		o = overlayCircuit(o, *b.CB)
	}
	pos := func(v int) int {
		if v < 0 {
			return 0
		}
		return v
	}
	l := cbLimits{maxReq: pos(o.MaxRequests), maxPend: pos(o.MaxPending), maxConn: pos(o.MaxConnections),
		failures: pos(o.FailureThreshold), probes: o.HalfOpenProbes, openFor: o.OpenFor}
	if l.probes <= 0 {
		l.probes = 1
	}
	if l.openFor <= 0 {
		l.openFor = 30 * time.Second
	}
	return l
}

// breaker is one backend's circuit state. It lives in the resilience state,
// keyed by backend, so it survives configuration reloads.
type breaker struct {
	mu        sync.Mutex
	state     int
	fails     int
	openUntil time.Time
	probes    int
	active    int
	waiters   []chan struct{}
	opened    int64
	rejected  map[string]int64
}

func (rs *resilience) breakerFor(key string) *breaker {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	b := rs.breakers[key]
	if b == nil {
		b = &breaker{rejected: map[string]int64{}}
		rs.breakers[key] = b
	}
	return b
}

// cbTicket is the permission to send one request; done must be called once.
type cbTicket struct {
	b     *breaker
	l     cbLimits
	probe bool
	once  sync.Once
	rs    *resilience
}

// enter admits one request or refuses it. Requests above maxRequests wait in a
// queue of up to maxPending; beyond that they are refused.
func (rs *resilience) enter(ctx context.Context, bk *breaker, l cbLimits) (*cbTicket, error) {
	now := rs.now()
	bk.mu.Lock()
	tk := &cbTicket{b: bk, l: l, rs: rs}
	if bk.state == cbOpen && !now.Before(bk.openUntil) {
		bk.state, bk.probes = cbHalfOpen, 0
	}
	switch bk.state {
	case cbOpen:
		bk.rejected[CircuitOpen]++
		bk.mu.Unlock()
		return nil, &circuitReject{CircuitOpen}
	case cbHalfOpen:
		if bk.probes >= l.probes {
			bk.rejected[CircuitOpen]++
			bk.mu.Unlock()
			return nil, &circuitReject{CircuitOpen}
		}
		bk.probes++
		tk.probe = true
	}
	if l.maxReq > 0 && bk.active >= l.maxReq && !tk.probe {
		if len(bk.waiters) >= l.maxPend {
			reason := CircuitMaxRequests
			if l.maxPend > 0 {
				reason = CircuitMaxPending
			}
			bk.rejected[reason]++
			bk.mu.Unlock()
			return nil, &circuitReject{reason}
		}
		w := make(chan struct{})
		bk.waiters = append(bk.waiters, w)
		bk.mu.Unlock()
		select {
		case <-w: // a finishing request handed its slot over
			return tk, nil
		case <-ctx.Done():
			bk.mu.Lock()
			for i, x := range bk.waiters {
				if x == w {
					bk.waiters = append(bk.waiters[:i], bk.waiters[i+1:]...)
					bk.mu.Unlock()
					return nil, ctx.Err()
				}
			}
			bk.mu.Unlock() // already granted: give the slot back
			tk.release(false, true)
			return nil, ctx.Err()
		}
	}
	bk.active++
	bk.mu.Unlock()
	return tk, nil
}

// done releases the slot and records the outcome. bad marks an upstream
// failure; skip leaves the failure count alone (client cancellations).
func (t *cbTicket) done(bad, skip bool) { t.once.Do(func() { t.release(bad, skip) }) }

func (t *cbTicket) release(bad, skip bool) {
	bk := t.b
	now := t.rs.now()
	bk.mu.Lock()
	defer bk.mu.Unlock()
	if n := len(bk.waiters); n > 0 && (t.l.maxReq == 0 || bk.active <= t.l.maxReq) {
		close(bk.waiters[0]) // hand the slot to the next waiter: active stays
		bk.waiters = bk.waiters[1:]
	} else if bk.active > 0 {
		bk.active--
	}
	if skip || t.l.failures <= 0 {
		if t.probe && skip && bk.state == cbHalfOpen && bk.probes > 0 {
			bk.probes--
		}
		return
	}
	switch {
	case t.probe && bk.state == cbHalfOpen:
		if bad {
			bk.state, bk.openUntil = cbOpen, now.Add(t.l.openFor)
			bk.opened++
		} else {
			bk.state, bk.fails = cbClosed, 0
		}
	case bk.state == cbClosed:
		if !bad {
			bk.fails = 0
			return
		}
		if bk.fails++; bk.fails >= t.l.failures {
			bk.state, bk.openUntil, bk.fails = cbOpen, now.Add(t.l.openFor), 0
			bk.opened++
		}
	}
}

// cbBody releases the breaker slot when the response body is closed.
type cbBody struct {
	io.ReadCloser
	tk  *cbTicket
	bad bool
}

func (b *cbBody) Close() error {
	err := b.ReadCloser.Close()
	b.tk.done(b.bad, false)
	return err
}

// transportFor returns the transport for b. A backend with maxConnections
// gets its own transport whose per-endpoint connection cap is the limit
// divided over the endpoints, so excess requests wait for a connection.
func (s *Server) transportFor(b *Backend, l cbLimits) http.RoundTripper {
	if l.maxConn <= 0 {
		return s.backendTransport(b)
	}
	per := (l.maxConn + len(b.Eps) - 1) / len(b.Eps)
	key := b.Key + "|" + strconv.Itoa(per) + "|" + strconv.FormatBool(b.Insecure) + "|" + b.tlsFP()
	s.res.mu.Lock()
	defer s.res.mu.Unlock()
	if t := s.res.transports[key]; t != nil {
		return t
	}
	bt, ok := s.backendTransport(b).(*http.Transport)
	if !ok {
		return s.backendTransport(b)
	}
	t := bt.Clone()
	t.MaxConnsPerHost = per
	s.res.transports[key] = t
	return t
}

func (rs *resilience) closeTransports() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, t := range rs.transports {
		t.CloseIdleConnections()
	}
}
