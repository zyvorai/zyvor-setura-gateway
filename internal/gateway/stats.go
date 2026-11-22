package gateway

import (
	"sync"
	"sync/atomic"
)

// Counter counts requests by status class.
type Counter struct {
	Requests int64            `json:"requests"`
	Status   map[string]int64 `json:"status"`
}

// statCounter is the live form of a Counter: plain atomics indexed by status
// class (status/100), so the request path takes no exclusive lock.
type statCounter struct {
	requests atomic.Int64
	class    [10]atomic.Int64
}

// Stats holds per-route and per-backend counters across reloads. Recording a
// request takes a read lock to find the counter and then only atomic adds; the
// write lock is taken the first time a route or backend is seen.
type Stats struct {
	total     atomic.Int64
	unmatched atomic.Int64

	mu       sync.RWMutex
	routes   map[string]*statCounter
	backends map[string]*statCounter
}

func newStats() *Stats {
	return &Stats{routes: map[string]*statCounter{}, backends: map[string]*statCounter{}}
}

func (s *Stats) counter(m map[string]*statCounter, key string) *statCounter {
	s.mu.RLock()
	c := m[key]
	s.mu.RUnlock()
	if c != nil {
		return c
	}
	s.mu.Lock()
	if c = m[key]; c == nil {
		c = &statCounter{}
		m[key] = c
	}
	s.mu.Unlock()
	return c
}

func (c *statCounter) add(status int) {
	i := status / 100
	if i < 0 {
		i = 0
	} else if i >= len(c.class) {
		i = len(c.class) - 1
	}
	c.requests.Add(1)
	c.class[i].Add(1)
}

func (s *Stats) record(route, backend string, status int) {
	s.total.Add(1)
	if route == "" {
		s.unmatched.Add(1)
	} else {
		s.counter(s.routes, route).add(status)
	}
	if backend != "" {
		s.counter(s.backends, backend).add(status)
	}
}

// Snapshot returns a JSON-ready copy. Counters are read one by one, so a
// snapshot taken during traffic may be a request or two out of step between
// the total and the per-class numbers; each value is exact when read.
func (s *Stats) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := func(in map[string]*statCounter) map[string]Counter {
		out := map[string]Counter{}
		for k, v := range in {
			c := Counter{Requests: v.requests.Load(), Status: map[string]int64{}}
			for i := range v.class {
				if n := v.class[i].Load(); n != 0 {
					c.Status[statusClasses[i]] = n
				}
			}
			out[k] = c
		}
		return out
	}
	return map[string]any{"requests": s.total.Load(), "unmatched": s.unmatched.Load(), "routes": cp(s.routes), "backends": cp(s.backends)}
}
