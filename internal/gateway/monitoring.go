package gateway

import (
	"fmt"
	"strings"

	"github.com/zyvorai/zyvor-setura-gateway/grafana"
)

// RunbookBase is the document the runbook_url annotation of every alert points into.
const RunbookBase = "https://github.com/zyvorai/zyvor-setura-gateway/blob/main/docs/runbooks.md"

// Default alert thresholds. The Helm chart exposes the same values.
const (
	AlertErrorRatio     = "0.05"    // fraction of 5xx responses
	AlertUnmatchedRate  = "1"       // unmatched requests per second
	AlertP95Seconds     = "0.5"     // request duration
	AlertCertExpirySecs = "1209600" // 14 days
	AlertShadowRatio    = "0.05"    // fraction of shadow comparisons that mismatch
)

// AlertRule is one PrometheusRule alert. The expressions are plain YAML
// scalars (no ": " or " #"), so the same text is used by the printed
// manifests and the Helm chart, and a test keeps both in step.
type AlertRule struct {
	Alert, Expr, For, Severity string
	Summary, Description       string
	Anchor                     string // section of docs/runbooks.md
}

// AlertRules returns the gateway alerts for a controller running in ns.
func AlertRules(ns string) []AlertRule {
	return []AlertRule{
		{"SeturaGatewayDown", `sum(up{job="setura-gateway", namespace="` + ns + `"}) == 0 or absent(up{job="setura-gateway", namespace="` + ns + `"})`,
			"5m", "critical", "No Setura gateway replica is being scraped",
			"Prometheus cannot reach any gateway admin endpoint, so every other alert is blind.", "seturagatewaydown"},
		{"SeturaGateway5xxRatio", `sum(rate(setura_gateway_route_requests_total{code="5xx"}[5m])) / sum(rate(setura_gateway_route_requests_total[5m])) > ` + AlertErrorRatio,
			"10m", "warning", "More than 5% of gateway responses are 5xx",
			"The share of 5xx responses over 5 minutes has been above the threshold for 10 minutes.", "seturagateway5xxratio"},
		{"SeturaGatewayLatencyP95", `histogram_quantile(0.95, sum by (le, route) (rate(setura_gateway_request_duration_seconds_bucket[5m]))) > ` + AlertP95Seconds,
			"10m", "warning", "p95 request duration of route {{ $labels.route }} is above 500 ms",
			"The 95th percentile of request duration of the route has exceeded the threshold for 10 minutes.", "seturagatewaylatencyp95"},
		{"SeturaGatewayAllBackendsEjected", `sum by (backend) (setura_gateway_endpoint_ejected) == count by (backend) (setura_gateway_endpoint_ejected)`,
			"2m", "critical", "Every endpoint of backend {{ $labels.backend }} is ejected",
			"Outlier detection has ejected all endpoints of the backend, so requests to it fail or are served from ejected endpoints.", "seturagatewayallbackendsejected"},
		{"SeturaGatewayCertExpiring", `setura_gateway_cert_expiry_seconds < ` + AlertCertExpirySecs,
			"30m", "warning", "The certificate of listener {{ $labels.listener }} expires in less than 14 days",
			"A serving certificate is close to its NotAfter date. Renew the Secret the listener references.", "seturagatewaycertexpiring"},
		{"SeturaGatewayCircuitOpen", `max by (backend) (setura_gateway_circuit_state) == 1`,
			"2m", "warning", "The circuit breaker of backend {{ $labels.backend }} is open",
			"The backend has been shedding load with 503 for two minutes.", "seturagatewaycircuitopen"},
		{"SeturaGatewayShadowMismatchRate", `sum by (route) (rate(setura_gateway_shadow_total{result="mismatched"}[10m])) / sum by (route) (rate(setura_gateway_shadow_total{result=~"matched|mismatched"}[10m])) > ` + AlertShadowRatio,
			"15m", "warning", "More than 5% of shadow comparisons of route {{ $labels.route }} differ",
			"The mirrored backend answers differently from the primary for a meaningful share of requests.", "seturagatewayshadowmismatchrate"},
		{"SeturaGatewayUnmatchedRoutes", `sum(rate(setura_gateway_unmatched_requests_total[5m])) > ` + AlertUnmatchedRate,
			"10m", "warning", "Requests are arriving that match no route",
			"Clients are hitting hosts or paths that no HTTPRoute serves.", "seturagatewayunmatchedroutes"},
		{"SeturaGatewayEndpointEjected", `max(setura_gateway_endpoint_ejected) == 1`,
			"5m", "warning", "A backend endpoint has been ejected by outlier detection for 5 minutes",
			"At least one endpoint is out of rotation because it kept failing.", "seturagatewayendpointejected"},
		{"SeturaGatewayAccessLogDropping", `increase(setura_gateway_accesslog_dropped_total[10m]) > 0`,
			"10m", "info", "Access log lines are being dropped",
			"The access log writer cannot keep up, so lines are dropped instead of slowing requests.", "seturagatewayaccesslogdropping"},
	}
}

func runbookURL(a AlertRule) string { return RunbookBase + "#" + a.Anchor }

func prometheusRuleYAML(ns string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: setura-gateway
  namespace: %s
  labels:
    app.kubernetes.io/name: setura-gateway
spec:
  groups:
    - name: setura-gateway
      rules:
`, ns)
	for _, a := range AlertRules(ns) {
		fmt.Fprintf(&b, `        - alert: %s
          expr: %s
          for: %s
          labels:
            severity: %s
          annotations:
            summary: %s
            description: %s
            runbook_url: %s
`, a.Alert, a.Expr, a.For, a.Severity, a.Summary, a.Description, runbookURL(a))
	}
	return b.String()
}

// MonitoringYAML returns the optional monitoring objects printed by
// `setura gateway install --with-monitoring`: a ServiceMonitor for the admin
// endpoint, the PrometheusRule and the Grafana dashboard as a ConfigMap that
// Grafana's sidecar picks up.
func MonitoringYAML(ns string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: setura-gateway
  namespace: %s
  labels:
    app.kubernetes.io/name: setura-gateway
spec:
  selector:
    matchLabels: {app.kubernetes.io/name: setura-gateway}
  namespaceSelector:
    matchNames: [%s]
  endpoints:
    - port: admin
      path: /metrics
      authorization:
        credentials: {name: setura-gateway-admin, key: token}
      interval: 30s
      scrapeTimeout: 10s
---
`, ns, ns)
	b.WriteString(prometheusRuleYAML(ns))
	fmt.Fprintf(&b, `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: setura-gateway-dashboard
  namespace: %s
  labels:
    app.kubernetes.io/name: setura-gateway
    grafana_dashboard: "1"
data:
  setura-gateway.json: |
`, ns)
	for _, ln := range strings.Split(strings.TrimRight(string(grafana.Dashboard), "\n"), "\n") {
		b.WriteString("    " + ln + "\n")
	}
	return b.String()
}
