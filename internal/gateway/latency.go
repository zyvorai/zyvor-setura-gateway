package gateway

import (
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// LatencyBuckets are the upper bounds (seconds) of the request duration
// histograms on /metrics.
var LatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	counts []int64 // one per bucket, non cumulative; the last is +Inf
	sum    float64
	n      int64
	ex     []exemplar // last exemplar per bucket, nil until one is recorded
}

// exemplar links one observation in a bucket to the trace that produced it.
type exemplar struct {
	trace string
	val   float64
	at    time.Time
}

// latencyStats keeps a duration histogram per route and per backend. The zero
// value is ready to use.
type latencyStats struct {
	mu       sync.Mutex
	routes   map[string]*histogram
	backends map[string]*histogram
}

func (l *latencyStats) add(m *map[string]*histogram, key string, sec float64, trace string) {
	if *m == nil {
		*m = map[string]*histogram{}
	}
	h := (*m)[key]
	if h == nil {
		h = &histogram{counts: make([]int64, len(LatencyBuckets)+1)}
		(*m)[key] = h
	}
	i := 0
	for i < len(LatencyBuckets) && sec > LatencyBuckets[i] {
		i++
	}
	h.counts[i]++
	h.sum += sec
	h.n++
	if trace != "" {
		if h.ex == nil {
			h.ex = make([]exemplar, len(LatencyBuckets)+1)
		}
		h.ex[i] = exemplar{trace: trace, val: sec, at: time.Now()}
	}
}

func (l *latencyStats) observe(route, backend string, d time.Duration) {
	l.observeTrace(route, backend, d, "")
}

// observeTrace records a duration and remembers trace as the exemplar of the
// bucket it fell into (shown in the OpenMetrics exposition only).
func (l *latencyStats) observeTrace(route, backend string, d time.Duration, trace string) {
	sec := d.Seconds()
	l.mu.Lock()
	defer l.mu.Unlock()
	if route != "" {
		l.add(&l.routes, route, sec, trace)
	}
	if backend != "" {
		l.add(&l.backends, backend, sec, trace)
	}
}

// write emits the histograms in the Prometheus text format, or with trace_id
// exemplars on the bucket lines when om is set (OpenMetrics).
func (l *latencyStats) write(w io.Writer, om bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	emit := func(name, label, help string, m map[string]*histogram) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
		for _, k := range sortedKeys(m) {
			h := m[k]
			var cum int64
			exm := func(i int) string {
				if !om || h.ex == nil || h.ex[i].trace == "" {
					return ""
				}
				e := h.ex[i]
				return fmt.Sprintf(" # {trace_id=\"%s\"} %s %s", promLabel(e.trace), strconv.FormatFloat(e.val, 'g', -1, 64), strconv.FormatFloat(float64(e.at.UnixMilli())/1000, 'f', 3, 64))
			}
			for i, b := range LatencyBuckets {
				cum += h.counts[i]
				fmt.Fprintf(w, "%s_bucket{%s=\"%s\",le=\"%s\"} %d%s\n", name, label, promLabel(k), strconv.FormatFloat(b, 'g', -1, 64), cum, exm(i))
			}
			cum += h.counts[len(LatencyBuckets)]
			fmt.Fprintf(w, "%s_bucket{%s=\"%s\",le=\"+Inf\"} %d%s\n", name, label, promLabel(k), cum, exm(len(LatencyBuckets)))
			fmt.Fprintf(w, "%s_sum{%s=\"%s\"} %g\n%s_count{%s=\"%s\"} %d\n", name, label, promLabel(k), h.sum, name, label, promLabel(k), h.n)
		}
	}
	emit("setura_gateway_request_duration_seconds", "route", "Request duration per route.", l.routes)
	emit("setura_gateway_backend_request_duration_seconds", "backend", "Request duration per backend.", l.backends)
}
