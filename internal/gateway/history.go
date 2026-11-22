package gateway

import (
	"math"
	"sort"
	"sync"
	"time"
)

const (
	historySize      = 120 // samples kept per route (two minutes at one per second)
	historyMaxRoutes = 3   // routes drawn in the dashboard, busiest first
)

// Latency bucket upper bounds in milliseconds; p95 is read as the upper
// bound of the bucket holding the 95th percentile, so it is a coarse upper
// estimate, not an exact value.
var latencyBoundsMs = [...]float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000}

type histPoint struct {
	req, errs int64
	p95       float64
}

type routeHist struct {
	curReq, curErr int64
	curBuckets     [len(latencyBoundsMs) + 1]int64
	ring           [historySize]histPoint
	next, count    int
}

// history keeps a per-route time series, sampled once per second into a
// fixed ring, for the dashboard's history section.
type history struct {
	mu     sync.Mutex
	routes map[string]*routeHist

	startOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

func newHistory() *history { return &history{routes: map[string]*routeHist{}} }

// observe records one finished request.
func (h *history) observe(route string, status int, d time.Duration) {
	if h == nil || route == "" {
		return
	}
	ms := float64(d.Microseconds()) / 1000
	i := len(latencyBoundsMs)
	for k, b := range latencyBoundsMs {
		if ms <= b {
			i = k
			break
		}
	}
	h.mu.Lock()
	r := h.routes[route]
	if r == nil {
		r = &routeHist{}
		h.routes[route] = r
	}
	r.curReq++
	if status >= 500 {
		r.curErr++
	}
	r.curBuckets[i]++
	h.mu.Unlock()
}

func p95Of(b *[len(latencyBoundsMs) + 1]int64, total int64) float64 {
	if total == 0 {
		return 0
	}
	rank := int64(math.Ceil(float64(total) * 0.95))
	var cum int64
	for i, n := range b {
		if cum += n; cum >= rank {
			if i < len(latencyBoundsMs) {
				return latencyBoundsMs[i]
			}
			return latencyBoundsMs[len(latencyBoundsMs)-1] * 2
		}
	}
	return 0
}

// sample closes the current second for every route.
func (h *history) sample() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name, r := range h.routes {
		r.ring[r.next] = histPoint{req: r.curReq, errs: r.curErr, p95: p95Of(&r.curBuckets, r.curReq)}
		r.next = (r.next + 1) % historySize
		if r.count < historySize {
			r.count++
		}
		r.curReq, r.curErr = 0, 0
		r.curBuckets = [len(latencyBoundsMs) + 1]int64{}
		if r.count == historySize && r.allIdle() {
			delete(h.routes, name) // forget routes that have been silent for the whole window
		}
	}
}

func (r *routeHist) allIdle() bool {
	for _, p := range r.ring {
		if p.req != 0 {
			return false
		}
	}
	return true
}

// points returns the ring oldest first.
func (r *routeHist) points() []histPoint {
	out := make([]histPoint, 0, r.count)
	for i := 0; i < r.count; i++ {
		out = append(out, r.ring[(r.next-r.count+i+historySize)%historySize])
	}
	return out
}

// series renders the busiest routes as the dashboard's history section:
// requests per second, server error rate and p95 latency per route.
func (h *history) series() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	type rt struct {
		name  string
		total int64
		pts   []histPoint
	}
	var rs []rt
	for name, r := range h.routes {
		if r.count == 0 {
			continue
		}
		x := rt{name: name, pts: r.points()}
		for _, p := range x.pts {
			x.total += p.req
		}
		rs = append(rs, x)
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].total != rs[j].total {
			return rs[i].total > rs[j].total
		}
		return rs[i].name < rs[j].name
	})
	if len(rs) > historyMaxRoutes {
		rs = rs[:historyMaxRoutes]
	}
	var out []map[string]any
	for _, x := range rs {
		req, errp, p95 := make([]float64, len(x.pts)), make([]float64, len(x.pts)), make([]float64, len(x.pts))
		for i, p := range x.pts {
			req[i], p95[i] = float64(p.req), p.p95
			if p.req > 0 {
				errp[i] = math.Round(float64(p.errs)/float64(p.req)*1000) / 10
			}
		}
		out = append(out,
			map[string]any{"name": x.name + " requests", "unit": "req/s", "points": req},
			map[string]any{"name": x.name + " error rate", "unit": "%", "points": errp},
			map[string]any{"name": x.name + " p95 latency", "unit": "ms", "points": p95})
	}
	return out
}

// start samples every interval until stopHistory; it runs once. A negative
// interval means the owner calls sample itself (tests).
func (h *history) start(interval time.Duration) {
	h.startOnce.Do(func() {
		if interval < 0 {
			return
		}
		// Counts gathered before sampling began would show up as one huge second.
		h.mu.Lock()
		for _, r := range h.routes {
			r.curReq, r.curErr = 0, 0
			r.curBuckets = [len(latencyBoundsMs) + 1]int64{}
		}
		h.mu.Unlock()
		if interval == 0 {
			interval = time.Second
		}
		h.stop, h.done = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(h.done)
			tk := time.NewTicker(interval)
			defer tk.Stop()
			for {
				select {
				case <-h.stop:
					return
				case <-tk.C:
					h.sample()
				}
			}
		}()
	})
}

func (h *history) close() {
	h.startOnce.Do(func() {}) // a start after close must not launch a goroutine
	if h.stop != nil {
		select {
		case <-h.stop:
		default:
			close(h.stop)
		}
		<-h.done
	}
}
