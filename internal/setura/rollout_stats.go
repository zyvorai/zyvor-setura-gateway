package setura

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// The gateway's own view of traffic: /stats (request and 5xx counters per
// route and backend) and /metrics (request duration histograms per route and
// backend). A rollout snapshots both before a stage's window and reads the
// difference during it.

const (
	routeHistName   = "setura_gateway_request_duration_seconds"
	backendHistName = "setura_gateway_backend_request_duration_seconds"
)

type gwCount struct{ Requests, Errors int64 } // Errors counts 5xx

type gwBucket struct {
	le  float64 // upper bound in seconds; +Inf for the last
	cum int64   // cumulative count
}

// gwSnap is one reading of /stats and /metrics. Keys are "route:KEY" and
// "backend:KEY".
type gwSnap struct {
	counts map[string]gwCount
	hist   map[string][]gwBucket
}

// statsAPI is implemented by admin clients that can read /stats and /metrics.
type statsAPI interface {
	GatewayStats(ctx context.Context) (*gwSnap, error)
}

func (a *httpAdmin) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin %s answered HTTP %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// GatewayStats reads /stats and /metrics.
func (a *httpAdmin) GatewayStats(ctx context.Context) (*gwSnap, error) {
	raw, err := a.get(ctx, "/stats")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Routes map[string]struct {
			Requests int64
			Status   map[string]int64
		} `json:"routes"`
		Backends map[string]struct {
			Requests int64
			Status   map[string]int64
		} `json:"backends"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("admin /stats: %w", err)
	}
	s := &gwSnap{counts: map[string]gwCount{}, hist: map[string][]gwBucket{}}
	for k, v := range doc.Routes {
		s.counts["route:"+k] = gwCount{v.Requests, v.Status["5xx"]}
	}
	for k, v := range doc.Backends {
		s.counts["backend:"+k] = gwCount{v.Requests, v.Status["5xx"]}
	}
	if m, err := a.get(ctx, "/metrics"); err == nil {
		parseHistograms(m, s.hist)
	}
	return s, nil
}

// parseLabels reads `k="v",k2="v2"` into a map.
func parseLabels(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq < 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			break
		}
		k := strings.TrimSpace(strings.TrimPrefix(s[:eq], ","))
		var v strings.Builder
		i := eq + 2
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				if s[i] == 'n' {
					v.WriteByte('\n')
					continue
				}
			}
			v.WriteByte(s[i])
		}
		out[k] = v.String()
		s = strings.TrimPrefix(s[min(i+1, len(s)):], ",")
	}
	return out
}

// parseHistograms extracts the per route and per backend duration buckets
// from a Prometheus text exposition.
func parseHistograms(text []byte, into map[string][]gwBucket) {
	sc := bufio.NewScanner(strings.NewReader(string(text)))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		var prefix, label string
		switch {
		case strings.HasPrefix(line, routeHistName+"_bucket{"):
			prefix, label = "route:", "route"
		case strings.HasPrefix(line, backendHistName+"_bucket{"):
			prefix, label = "backend:", "backend"
		default:
			continue
		}
		open, closeB := strings.IndexByte(line, '{'), strings.LastIndexByte(line, '}')
		if closeB < open {
			continue
		}
		labels := parseLabels(line[open+1 : closeB])
		val, err := strconv.ParseFloat(strings.TrimSpace(line[closeB+1:]), 64)
		if err != nil || labels[label] == "" {
			continue
		}
		le := labels["le"]
		bound := 0.0
		if le == "+Inf" {
			bound = 1e18
		} else if bound, err = strconv.ParseFloat(le, 64); err != nil {
			continue
		}
		k := prefix + labels[label]
		into[k] = append(into[k], gwBucket{bound, int64(val)})
	}
	for k := range into {
		b := into[k]
		sort.Slice(b, func(i, j int) bool { return b[i].le < b[j].le })
	}
}

// gwDelta is the traffic of one route or backend between two readings.
type gwDelta struct {
	Key      string
	Requests int64
	Errors   int64
	P95Ms    float64
	HasP95   bool
}

func (d gwDelta) rate() float64 {
	if d.Requests == 0 {
		return 0
	}
	return float64(d.Errors) / float64(d.Requests)
}

// p95 estimates the 95th percentile of the observations added between two
// cumulative bucket readings, interpolating inside the bucket.
func p95Between(before, after []gwBucket) (ms float64, ok bool) {
	return quantileBetween(before, after, 0.95)
}

// quantileBetween is p95Between for any quantile q in (0, 1).
func quantileBetween(before, after []gwBucket, q float64) (ms float64, ok bool) {
	if len(after) == 0 {
		return 0, false
	}
	prev := map[float64]int64{}
	for _, b := range before {
		prev[b.le] = b.cum
	}
	delta := make([]gwBucket, len(after))
	for i, b := range after {
		delta[i] = gwBucket{b.le, b.cum - prev[b.le]}
	}
	total := delta[len(delta)-1].cum
	if total <= 0 {
		return 0, false
	}
	target := q * float64(total)
	lo, below := 0.0, int64(0)
	for _, b := range delta {
		if float64(b.cum) >= target {
			if b.le >= 1e17 { // beyond the last finite bound
				return lo * 1000, true
			}
			in := b.cum - below
			if in <= 0 {
				return b.le * 1000, true
			}
			return (lo + (b.le-lo)*(target-float64(below))/float64(in)) * 1000, true
		}
		lo, below = b.le, b.cum
	}
	return lo * 1000, true
}

// deltas compares two readings for the keys in scope (nil scope = everything).
func (after *gwSnap) deltas(before *gwSnap, inScope func(key string) bool) []gwDelta {
	var out []gwDelta
	keys := map[string]bool{}
	for k := range after.counts {
		keys[k] = true
	}
	for k := range after.hist {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		if inScope != nil && !inScope(k) {
			continue
		}
		d := gwDelta{Key: k}
		a, b := after.counts[k], before.counts[k]
		if a.Requests >= b.Requests { // a restart resets the counters: no delta then
			d.Requests, d.Errors = a.Requests-b.Requests, a.Errors-b.Errors
		}
		if ms, ok := p95Between(before.hist[k], after.hist[k]); ok && d.Requests > 0 {
			d.P95Ms, d.HasP95 = ms, true
		}
		if d.Requests > 0 {
			out = append(out, d)
		}
	}
	return out
}
