package setura

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// minGatewaySamples is how many requests a series needs in a window before its
// p95 is judged; a handful of requests is not a latency distribution.
const minGatewaySamples = 5

// gwStage summarizes the /stats and /metrics deltas of one window for the
// series in scope.
type gwStage struct {
	Requests   int64   `json:"requests"`
	Errors     int64   `json:"errors"`
	ErrorRate  float64 `json:"errorRate"`
	P95Ms      float64 `json:"p95Ms"`
	WorstRoute string  `json:"worst,omitempty"`
	// Before is the cumulative request count and 5xx rate of the same series
	// when the window opened, for comparison.
	BeforeRequests  int64   `json:"beforeRequests"`
	BeforeErrorRate float64 `json:"beforeErrorRate"`
}

// gwWindow reads the gateway's own counters across one stage's window.
type gwWindow struct {
	api   statsAPI
	base  *gwSnap
	scope func(string) bool
	last  []gwDelta
	err   error
}

// openWindow takes the baseline reading. It returns nil when the admin client
// cannot read /stats, or the reading fails (the rollout then rests on probes).
func (r *rollout) openWindow(ctx context.Context, res *rolloutResult) *gwWindow {
	api, ok := r.admin.(statsAPI)
	if !ok {
		return nil
	}
	snap, err := api.GatewayStats(ctx)
	if err != nil {
		if res.GatewayStats == "" {
			res.GatewayStats = "unavailable: " + err.Error()
			r.logf("gateway /stats and /metrics unavailable (%v); judging on probes only", err)
		}
		return nil
	}
	if res.GatewayStats == "" {
		res.GatewayStats = "used"
	}
	return &gwWindow{api: api, base: snap, scope: r.scope}
}

func (w *gwWindow) refresh(ctx context.Context) {
	snap, err := w.api.GatewayStats(ctx)
	if err != nil {
		w.err = err
		return
	}
	w.err, w.last = nil, snap.deltas(w.base, w.scope)
}

func trimKey(k string) string {
	kind, name, _ := strings.Cut(k, ":")
	return kind + " " + name
}

// gatewayBreach applies --max-error-rate and --max-p95 to the gateway's deltas
// and names the source that tripped.
func (r *rollout) gatewayBreach(w *gwWindow, final bool) (why, source string) {
	if w == nil {
		return "", ""
	}
	for _, d := range w.last {
		switch {
		case r.o.MaxErrorRate <= 0 && d.Errors > 0:
			return fmt.Sprintf("%s answered 5xx for %d of %d requests during the window (no failures tolerated)", trimKey(d.Key), d.Errors, d.Requests), "gateway /stats"
		case final && r.o.MaxErrorRate > 0 && d.rate() > r.o.MaxErrorRate:
			return fmt.Sprintf("%s error rate %.1f%% exceeds the %.1f%% limit (%d of %d requests answered 5xx)", trimKey(d.Key), d.rate()*100, r.o.MaxErrorRate*100, d.Errors, d.Requests), "gateway /stats"
		}
	}
	if r.o.MaxP95 > 0 {
		for _, d := range w.last {
			if d.HasP95 && d.Requests >= minGatewaySamples && d.P95Ms > float64(r.o.MaxP95)/float64(time.Millisecond) {
				return fmt.Sprintf("%s p95 latency %.1f ms exceeds the %s limit (%d requests in the window)", trimKey(d.Key), d.P95Ms, r.o.MaxP95, d.Requests), "gateway /metrics"
			}
		}
	}
	return "", ""
}

// summary aggregates the window for the report. Routes and backends overlap in
// traffic, so the totals use the route series, or the backend series when no
// route saw traffic.
func (w *gwWindow) summary() *gwStage {
	if w == nil {
		return nil
	}
	sum := func(kind string) (n, e int64) {
		for _, d := range w.last {
			if strings.HasPrefix(d.Key, kind) {
				n, e = n+d.Requests, e+d.Errors
			}
		}
		return
	}
	kind := "route:"
	if n, _ := sum(kind); n == 0 {
		kind = "backend:"
	}
	st := &gwStage{}
	st.Requests, st.Errors = sum(kind)
	if st.Requests > 0 {
		st.ErrorRate = math.Round(float64(st.Errors)/float64(st.Requests)*10000) / 10000
	}
	for _, d := range w.last {
		if strings.HasPrefix(d.Key, kind) && d.HasP95 && d.P95Ms >= st.P95Ms {
			st.P95Ms, st.WorstRoute = math.Round(d.P95Ms*10)/10, strings.TrimPrefix(d.Key, kind)
		}
	}
	var errs float64
	for k, c := range w.base.counts {
		if strings.HasPrefix(k, kind) && (w.scope == nil || w.scope(k)) {
			st.BeforeRequests += c.Requests
			errs += float64(c.Errors)
		}
	}
	if st.BeforeRequests > 0 {
		st.BeforeErrorRate = math.Round(errs/float64(st.BeforeRequests)*10000) / 10000
	}
	return st
}

// verdict is why a stage failed and which source said so.
type verdict struct{ why, source string }

// observe runs the checks repeatedly for the observation window and, when the
// admin API provides it, reads the gateway's own counters across the same window.
func (r *rollout) observe(ctx context.Context, gw *gwWindow) (*observeStats, verdict, error) {
	s := &observeStats{}
	start := r.clock.Now()
	for {
		rows, err := r.probe(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return s, verdict{}, ctx.Err()
			}
			return s, verdict{"checks could not run: " + err.Error(), "probes"}, nil
		}
		for _, rep := range rows {
			s.probes++
			s.lat = append(s.lat, rep.ElapsedMS)
			if !rep.OK {
				s.failures++
				if len(s.evidence) < 5 {
					s.evidence = append(s.evidence, failureEvidence(rep))
				}
			}
		}
		done := r.clock.Now().Sub(start) >= r.o.Observe
		if gw != nil {
			gw.refresh(ctx)
		}
		if why := r.breach(s, done); why != "" {
			return s, verdict{why, "probes"}, nil
		}
		if why, src := r.gatewayBreach(gw, done); why != "" {
			return s, verdict{why, src}, nil
		}
		if done {
			return s, verdict{}, nil
		}
		if err := r.clock.Sleep(ctx, r.o.ProbeInterval); err != nil {
			return s, verdict{}, err
		}
	}
}
