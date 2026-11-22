package gateway

import (
	"fmt"
	"io"
)

// writeCircuitMetrics writes the per-backend circuit breaker series. They
// exist only for backends that have a breaker in effect.
func (s *Server) writeCircuitMetrics(w io.Writer) {
	rs := s.res
	rs.mu.Lock()
	keys := make([]string, 0, len(rs.breakers))
	for k := range rs.breakers {
		keys = append(keys, k)
	}
	rs.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	type row struct {
		key                 string
		state, active, pend int
		opened              int64
		rejected            map[string]int64
	}
	var rows []row
	for _, k := range sortedStrings(keys) {
		b := rs.breakerFor(k)
		b.mu.Lock()
		now := rs.now()
		st := b.state
		if st == cbOpen && !now.Before(b.openUntil) {
			st = cbHalfOpen // the next request will probe
		}
		r := row{key: k, state: st, active: b.active, pend: len(b.waiters), opened: b.opened, rejected: map[string]int64{}}
		for rk, rv := range b.rejected {
			r.rejected[rk] = rv
		}
		b.mu.Unlock()
		rows = append(rows, r)
	}
	gauge := func(name, help string, v func(row) int) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, r := range rows {
			fmt.Fprintf(w, "%s{backend=\"%s\"} %d\n", name, promLabel(r.key), v(r))
		}
	}
	gauge("setura_gateway_circuit_state", "Circuit breaker state: 0 closed, 1 open, 2 half-open.", func(r row) int { return r.state })
	gauge("setura_gateway_circuit_active_requests", "Requests in flight through the breaker.", func(r row) int { return r.active })
	gauge("setura_gateway_circuit_pending_requests", "Requests waiting for a free slot.", func(r row) int { return r.pend })
	fmt.Fprintf(w, "# HELP setura_gateway_circuit_opened_total Times the circuit opened.\n# TYPE setura_gateway_circuit_opened_total counter\n")
	for _, r := range rows {
		fmt.Fprintf(w, "setura_gateway_circuit_opened_total{backend=\"%s\"} %d\n", promLabel(r.key), r.opened)
	}
	fmt.Fprintf(w, "# HELP setura_gateway_circuit_rejected_total Requests refused with 503 by a circuit breaker, by reason.\n# TYPE setura_gateway_circuit_rejected_total counter\n")
	for _, r := range rows {
		for _, reason := range sortedKeys(r.rejected) {
			fmt.Fprintf(w, "setura_gateway_circuit_rejected_total{backend=\"%s\",reason=\"%s\"} %d\n", promLabel(r.key), reason, r.rejected[reason])
		}
	}
}

func sortedStrings(in []string) []string {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		m[s] = struct{}{}
	}
	return sortedKeys(m)
}
