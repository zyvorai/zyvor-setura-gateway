package gateway

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

func promLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// WriteMetrics writes resilience counters and endpoint health in the
// Prometheus text exposition format.
func (s *Server) WriteMetrics(w io.Writer) { s.writeMetrics(w, false) }

func (s *Server) writeMetrics(w io.Writer, om bool) {
	rs := s.res
	counter := func(name, help string, m map[string]int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for _, k := range sortedKeys(m) {
			fmt.Fprintf(w, "%s{backend=\"%s\"} %d\n", name, promLabel(k), m[k])
		}
	}
	rs.mu.Lock()
	counter("setura_gateway_retries_total", "Upstream attempts retried after a failure.", rs.retries)
	counter("setura_gateway_retries_denied_total", "Retries refused because the retry budget was spent.", rs.denied)
	counter("setura_gateway_ejections_total", "Endpoints ejected by passive outlier detection.", rs.ejections)
	counter("setura_gateway_retries_cross_backend_total", "Retries that moved to another weighted backendRef.", rs.crossRetries)
	counter("setura_gateway_retry_per_try_timeouts_total", "Attempts abandoned because the per-try timeout expired.", rs.perTryTimeouts)
	rs.mu.Unlock()

	type row struct {
		backend, endpoint string
		healthy, ejected  int
	}
	var rows []row
	if t := s.table.Load(); t != nil {
		now := rs.now()
		for _, k := range sortedKeys(t.Backends) {
			b := t.Backends[k]
			b.hmu.Lock()
			for _, e := range b.Eps {
				r := row{backend: b.Key, endpoint: e.URL.Host}
				if e.healthy.Load() {
					r.healthy = 1
				}
				if now.Before(e.st.until) {
					r.ejected = 1
				}
				rows = append(rows, r)
			}
			b.hmu.Unlock()
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].backend < rows[j].backend })
	gauge := func(name, help string, val func(row) int) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, r := range rows {
			fmt.Fprintf(w, "%s{backend=\"%s\",endpoint=\"%s\"} %d\n", name, promLabel(r.backend), promLabel(r.endpoint), val(r))
		}
	}
	gauge("setura_gateway_endpoint_healthy", "1 when the endpoint passes active health checks.", func(r row) int { return r.healthy })
	gauge("setura_gateway_endpoint_ejected", "1 while the endpoint is ejected by outlier detection.", func(r row) int { return r.ejected })
	s.writeL4Metrics(w)
	s.writeCircuitMetrics(w)
	s.writeShadowMetrics(w)
	s.latency.write(w, om)
	s.writeExtMetrics(w)
	s.writeAIMetrics(w)
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.WriteMetrics(w)
}
