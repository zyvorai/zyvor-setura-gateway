package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// extStats are the counters that are not part of Stats or the resilience
// state: auth outcomes, CORS preflights, session persistence hits and backend
// TLS handshake failures. The zero value is ready to use.
type extStats struct {
	mu   sync.Mutex
	auth map[[3]string]int64 // route, decision, reason
	cors map[string]int64    // route
	sess map[string]int64    // route
	btls map[string]int64    // backend
}

func (e *extStats) bump(m *map[string]int64, key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[key]++
}

// authOutcome counts one decision of an auth policy. decision is "allowed" or
// "denied"; reason is a short fixed word for denials (unauthenticated,
// forbidden, client_cert, external) and empty when allowed.
func (e *extStats) authOutcome(route, decision, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.auth == nil {
		e.auth = map[[3]string]int64{}
	}
	e.auth[[3]string{route, decision, reason}]++
}

// isTLSHandshakeError reports whether err came from the TLS handshake with an
// upstream (certificate verification, protocol mismatch or a TLS alert).
func isTLSHandshakeError(err error) bool {
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &cv) || errors.As(err, &rh) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) {
		return true
	}
	m := err.Error()
	return strings.Contains(m, "tls: ") || strings.Contains(m, "x509: ") || strings.Contains(m, "remote error: tls")
}

func (e *extStats) snapshot() (auth map[[3]string]int64, cors, sess, btls map[string]int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	auth = make(map[[3]string]int64, len(e.auth))
	for k, v := range e.auth {
		auth[k] = v
	}
	cp := func(in map[string]int64) map[string]int64 {
		out := make(map[string]int64, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	return auth, cp(e.cors), cp(e.sess), cp(e.btls)
}

// writeExtMetrics emits the series added after the first release: per-backend
// request counters, auth outcomes, CORS preflights, backend TLS handshake
// failures, session persistence hits, certificate expiry, connection counts
// and the log sinks. HELP and TYPE lines are always written so a series is
// discoverable before its first sample.
func (s *Server) writeExtMetrics(w io.Writer) {
	head := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	// backend requests
	head("setura_gateway_backend_requests_total", "counter", "Requests answered per backend and status class (1xx..5xx).")
	backends := s.stats.Snapshot()["backends"].(map[string]Counter)
	for _, k := range sortedKeys(backends) {
		for _, c := range sortedKeys(backends[k].Status) {
			fmt.Fprintf(w, "setura_gateway_backend_requests_total{backend=\"%s\",code=\"%s\"} %d\n", promLabel(k), c, backends[k].Status[c])
		}
	}
	auth, cors, sess, btls := s.ext.snapshot()
	head("setura_gateway_auth_requests_total", "counter", "Auth policy decisions per route: decision allowed or denied, reason unauthenticated, forbidden, client_cert or external for denials.")
	keys := make([][3]string, 0, len(auth))
	for k := range auth {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		for n := 0; n < 3; n++ {
			if keys[i][n] != keys[j][n] {
				return keys[i][n] < keys[j][n]
			}
		}
		return false
	})
	for _, k := range keys {
		fmt.Fprintf(w, "setura_gateway_auth_requests_total{route=\"%s\",decision=\"%s\",reason=\"%s\"} %d\n", promLabel(k[0]), k[1], k[2], auth[k])
	}
	one := func(name, typ, help, label string, m map[string]int64) {
		head(name, typ, help)
		for _, k := range sortedKeys(m) {
			fmt.Fprintf(w, "%s{%s=\"%s\"} %d\n", name, label, promLabel(k), m[k])
		}
	}
	one("setura_gateway_cors_preflights_total", "counter", "CORS preflight requests answered by the gateway, per route.", "route", cors)
	one("setura_gateway_backend_tls_handshake_failures_total", "counter", "TLS handshakes with a backend that failed (verification, protocol or alert), per backend.", "backend", btls)
	one("setura_gateway_session_persistence_hits_total", "counter", "Requests routed to their pinned endpoint by session persistence, per route.", "route", sess)

	// certificate expiry per HTTPS listener: the soonest NotAfter of its certificates
	head("setura_gateway_cert_expiry_seconds", "gauge", "Seconds until the soonest-expiring serving certificate of the listener expires (negative once expired).")
	if t := s.table.Load(); t != nil {
		now := s.res.now()
		type row struct {
			l string
			v int64
		}
		var rows []row
		for _, pg := range t.Ports {
			for _, l := range pg.Listeners {
				if len(l.Certs) == 0 {
					continue
				}
				first := true
				var soon int64
				for i := range l.Certs {
					leaf := l.Certs[i].Leaf
					if leaf == nil && len(l.Certs[i].Certificate) > 0 {
						leaf, _ = x509.ParseCertificate(l.Certs[i].Certificate[0])
					}
					if leaf == nil {
						continue
					}
					v := int64(leaf.NotAfter.Sub(now).Seconds())
					if first || v < soon {
						soon, first = v, false
					}
				}
				if !first {
					rows = append(rows, row{l.Key, soon})
				}
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].l < rows[j].l })
		for _, r := range rows {
			fmt.Fprintf(w, "setura_gateway_cert_expiry_seconds{listener=\"%s\"} %d\n", promLabel(r.l), r.v)
		}
	}

	head("setura_gateway_requests_in_flight", "gauge", "HTTP requests currently inside the data-plane handler.")
	fmt.Fprintf(w, "setura_gateway_requests_in_flight %d\n", s.inflight.Load())
	if s.conns != nil {
		head("setura_gateway_connections_open", "gauge", "Open long-lived connections tracked by the connection table (WebSocket and similar).")
		s.conns.mu.Lock()
		n := len(s.conns.open)
		s.conns.mu.Unlock()
		fmt.Fprintf(w, "setura_gateway_connections_open %d\n", n)
	}
	s.obs.writeSinkMetrics(w, head)
}

// wantsOpenMetrics reports whether the scraper asked for the OpenMetrics text
// format, which is the only one that carries exemplars.
func wantsOpenMetrics(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "application/openmetrics-text") {
			return true
		}
	}
	return false
}

var omFamily = regexp.MustCompile(`(?m)^(# (?:HELP|TYPE) setura_gateway_\w+?)_total `)

// serveMetrics answers /metrics: the Prometheus text format, or OpenMetrics
// (with trace_id exemplars on the duration histograms) when the client sends
// Accept: application/openmetrics-text.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	om := wantsOpenMetrics(r)
	var b bytes.Buffer
	s.writeObsMetrics(&b)
	s.writeMetrics(&b, om)
	out := b.Bytes()
	if om {
		// OpenMetrics names a counter family without its _total suffix.
		out = omFamily.ReplaceAll(out, []byte("$1 "))
		out = append(out, "# EOF\n"...)
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	}
	w.Write(out)
}

// MetricDef describes one exposed metric family: the stable contract that
// dashboards, alerts and the Netra preset rely on. A golden test keeps the
// exposition and this list in step, so a rename shows up as a test failure.
type MetricDef struct {
	Name   string
	Type   string   // counter, gauge or histogram
	Labels []string // label names, without le
	When   string   // "" always present; otherwise the condition that creates the family
}

// MetricCatalog lists every family on the admin /metrics endpoint.
var MetricCatalog = []MetricDef{
	{"setura_gateway_requests_total", "counter", nil, ""},
	{"setura_gateway_unmatched_requests_total", "counter", nil, ""},
	{"setura_gateway_route_requests_total", "counter", []string{"route", "code"}, ""},
	{"setura_gateway_backend_requests_total", "counter", []string{"backend", "code"}, ""},
	{"setura_gateway_request_duration_seconds", "histogram", []string{"route"}, ""},
	{"setura_gateway_backend_request_duration_seconds", "histogram", []string{"backend"}, ""},
	{"setura_gateway_requests_in_flight", "gauge", nil, ""},
	{"setura_gateway_connections_open", "gauge", nil, "connection history enabled"},
	{"setura_gateway_retries_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_retries_denied_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_retries_cross_backend_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_retry_per_try_timeouts_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_ejections_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_endpoint_healthy", "gauge", []string{"backend", "endpoint"}, ""},
	{"setura_gateway_endpoint_ejected", "gauge", []string{"backend", "endpoint"}, ""},
	{"setura_gateway_circuit_state", "gauge", []string{"backend"}, "a circuit breaker is in effect"},
	{"setura_gateway_circuit_active_requests", "gauge", []string{"backend"}, "a circuit breaker is in effect"},
	{"setura_gateway_circuit_pending_requests", "gauge", []string{"backend"}, "a circuit breaker is in effect"},
	{"setura_gateway_circuit_opened_total", "counter", []string{"backend"}, "a circuit breaker is in effect"},
	{"setura_gateway_circuit_rejected_total", "counter", []string{"backend", "reason"}, "a circuit breaker is in effect"},
	{"setura_gateway_ratelimit_allowed_total", "counter", nil, "rate limiting enabled"},
	{"setura_gateway_ratelimit_limited_total", "counter", []string{"route"}, "rate limiting enabled"},
	{"setura_gateway_ratelimit_buckets", "gauge", nil, "rate limiting enabled"},
	{"setura_gateway_shadow_total", "counter", []string{"route", "result"}, ""},
	{"setura_gateway_auth_requests_total", "counter", []string{"route", "decision", "reason"}, ""},
	{"setura_gateway_cors_preflights_total", "counter", []string{"route"}, ""},
	{"setura_gateway_backend_tls_handshake_failures_total", "counter", []string{"backend"}, ""},
	{"setura_gateway_session_persistence_hits_total", "counter", []string{"route"}, ""},
	{"setura_gateway_cert_expiry_seconds", "gauge", []string{"listener"}, ""},
	{"setura_gateway_l4_connections_total", "counter", []string{"protocol", "route", "backend"}, "TCP or UDP traffic seen"},
	{"setura_gateway_l4_failures_total", "counter", []string{"protocol", "route", "backend"}, "TCP or UDP traffic seen"},
	{"setura_gateway_l4_bytes_in_total", "counter", []string{"protocol", "route", "backend"}, "TCP or UDP traffic seen"},
	{"setura_gateway_l4_bytes_out_total", "counter", []string{"protocol", "route", "backend"}, "TCP or UDP traffic seen"},
	{"setura_gateway_udp_sessions_open", "gauge", nil, ""},
	{"setura_gateway_accesslog_written_total", "counter", nil, "access log enabled"},
	{"setura_gateway_accesslog_dropped_total", "counter", nil, "access log enabled"},
	{"setura_gateway_accesslog_rotations_total", "counter", nil, "access log is a rotating file"},
	{"setura_gateway_accesslog_rotation_errors_total", "counter", nil, "access log is a rotating file"},
	{"setura_gateway_otlp_spans_exported_total", "counter", nil, "OTLP span export enabled"},
	{"setura_gateway_otlp_spans_dropped_total", "counter", nil, "OTLP span export enabled"},
	{"setura_gateway_otlp_export_failures_total", "counter", nil, "OTLP span export enabled"},
	{"setura_gateway_otlp_retries_total", "counter", nil, "OTLP span export enabled"},
	{"setura_gateway_otlp_queue_length", "gauge", nil, "OTLP span export enabled"},
	{"setura_gateway_logsink_sent_total", "counter", []string{"sink"}, "a log sink is configured"},
	{"setura_gateway_logsink_dropped_total", "counter", []string{"sink"}, "a log sink is configured"},
	{"setura_gateway_logsink_failures_total", "counter", []string{"sink"}, "a log sink is configured"},
	{"setura_gateway_logsink_retries_total", "counter", []string{"sink"}, "a log sink is configured"},
	{"setura_gateway_logsink_queue_length", "gauge", []string{"sink"}, "a log sink is configured"},
}
