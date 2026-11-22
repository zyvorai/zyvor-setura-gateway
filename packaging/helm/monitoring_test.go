package helm

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

type alertDoc struct{ expr, forD, severity, runbook string }

// alertsOf reads the alerts of a PrometheusRule written as block YAML, the
// way both the chart template and `gateway install --with-monitoring` write it.
func alertsOf(t *testing.T, y string) map[string]alertDoc {
	t.Helper()
	out := map[string]alertDoc{}
	parts := strings.Split(y, "- alert: ")
	for _, p := range parts[1:] {
		name := strings.TrimSpace(strings.SplitN(p, "\n", 2)[0])
		get := func(key string) string {
			m := regexp.MustCompile(`(?m)^\s+` + key + `: (.*)$`).FindStringSubmatch(p)
			if m == nil {
				t.Errorf("%s has no %s", name, key)
				return ""
			}
			return strings.TrimSpace(m[1])
		}
		if _, dup := out[name]; dup {
			t.Errorf("duplicate alert %s", name)
		}
		for _, key := range []string{"summary", "description", "runbook_url"} {
			if get(key) == "" {
				t.Errorf("%s: empty %s", name, key)
			}
		}
		out[name] = alertDoc{get("expr"), get("for"), get("severity"), get("runbook_url")}
	}
	return out
}

// renderTemplate substitutes the chart's default values into the PrometheusRule
// template without helm.
func renderTemplate(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("setura/templates/prometheusrule.yaml")
	if err != nil {
		t.Fatal(err)
	}
	vb, _ := os.ReadFile("setura/values.yaml")
	block := regexp.MustCompile(`(?m)^prometheusRule:\n((?:  .*\n|\n)*)`).FindStringSubmatch(string(vb))
	if block == nil {
		t.Fatal("no prometheusRule block in values.yaml")
	}
	vals := map[string]string{"namespace": "setura-system"}
	for _, m := range regexp.MustCompile(`(?m)^  (\w+): (\S+)\s*$`).FindAllStringSubmatch(block[1], -1) {
		vals[m[1]] = m[2]
	}
	s := string(b)
	s = strings.ReplaceAll(s, "{{`{{ $labels.route }}`}}", "{{ $labels.route }}")
	s = strings.ReplaceAll(s, "{{`{{ $labels.backend }}`}}", "{{ $labels.backend }}")
	s = strings.ReplaceAll(s, "{{`{{ $labels.listener }}`}}", "{{ $labels.listener }}")
	s = strings.ReplaceAll(s, "{{ .Values.namespace }}", vals["namespace"])
	s = regexp.MustCompile(`\{\{ \.Values\.prometheusRule\.(\w+)(?: \| int64)? \}\}`).ReplaceAllStringFunc(s, func(m string) string {
		k := regexp.MustCompile(`\.Values\.prometheusRule\.(\w+)`).FindStringSubmatch(m)[1]
		v, ok := vals[k]
		if !ok {
			t.Errorf("values.yaml has no prometheusRule.%s", k)
		}
		return v
	})
	return s
}

// TestAlertRulesMatchChart keeps the chart's alerts, the ones printed by
// `setura gateway install --with-monitoring` and AlertRules identical.
func TestAlertRulesMatchChart(t *testing.T) {
	chart := alertsOf(t, renderTemplate(t))
	printed := alertsOf(t, gateway.MonitoringYAML("setura-system"))
	if len(chart) < 10 {
		t.Fatalf("chart has %d alerts", len(chart))
	}
	for _, name := range []string{"SeturaGateway5xxRatio", "SeturaGatewayLatencyP95", "SeturaGatewayAllBackendsEjected", "SeturaGatewayCertExpiring", "SeturaGatewayCircuitOpen", "SeturaGatewayShadowMismatchRate"} {
		if _, ok := chart[name]; !ok {
			t.Errorf("chart lacks alert %s", name)
		}
	}
	for name, p := range printed {
		c, ok := chart[name]
		if !ok {
			t.Errorf("alert %s is printed by install but missing from the chart", name)
			continue
		}
		if c != p {
			t.Errorf("alert %s differs\nchart:   %+v\ninstall: %+v", name, c, p)
		}
		if !strings.HasPrefix(p.runbook, gateway.RunbookBase+"#") {
			t.Errorf("%s runbook_url %q", name, p.runbook)
		}
	}
	for name := range chart {
		if _, ok := printed[name]; !ok {
			t.Errorf("alert %s is in the chart but not printed by install", name)
		}
	}
	// the Go list is the source of both
	if len(gateway.AlertRules("x")) != len(printed) {
		t.Errorf("AlertRules has %d, install prints %d", len(gateway.AlertRules("x")), len(printed))
	}
}

// TestAlertsOnlyUseExposedMetrics checks every metric in an alert expression
// is a family the gateway exposes.
func TestAlertsOnlyUseExposedMetrics(t *testing.T) {
	known := map[string]bool{}
	for _, d := range gateway.MetricCatalog {
		known[d.Name] = true
	}
	re := regexp.MustCompile(`setura_gateway_[a-z0-9_]+`)
	for _, a := range gateway.AlertRules("setura-system") {
		for _, m := range re.FindAllString(a.Expr, -1) {
			base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(m, "_bucket"), "_sum"), "_count")
			if !known[m] && !known[base] {
				t.Errorf("%s uses %s, which is not in MetricCatalog", a.Alert, m)
			}
		}
		if strings.Contains(a.Expr, ": ") || strings.Contains(a.Expr, " #") {
			t.Errorf("%s: expression is not a safe plain YAML scalar", a.Alert)
		}
	}
}

func TestInstallWithMonitoring(t *testing.T) {
	base := objects(gateway.Install(gateway.InstallOptions{}))
	with := gateway.Install(gateway.InstallOptions{WithMonitoring: true})
	got := objects(with)
	have := map[string]bool{}
	for _, o := range base {
		have[o] = true
	}
	var extra []string
	for _, o := range got {
		if !have[o] {
			extra = append(extra, o)
		}
	}
	want := "ConfigMap/setura-gateway-dashboard PrometheusRule/setura-gateway ServiceMonitor/setura-gateway"
	if strings.Join(extra, " ") != want || len(got) != len(base)+3 {
		t.Fatalf("extra objects %v, want %s", extra, want)
	}
	if !strings.Contains(with, "- {name: admin, port: 19000, targetPort: admin}") {
		t.Error("the Service has no admin port for the ServiceMonitor")
	}
	if n := gateway.Install(gateway.InstallOptions{WithMonitoring: true, Namespace: "mesh"}); strings.Count(n, "namespace: setura-system") != 0 || strings.Count(n, "namespace: mesh") < 8 {
		t.Error("monitoring objects ignore --namespace")
	}
	if strings.Contains(gateway.Install(gateway.InstallOptions{}), "ServiceMonitor") {
		t.Error("monitoring must be opt in")
	}
	// the embedded dashboard is valid JSON once the ConfigMap indentation is removed
	i := strings.Index(with, "  setura-gateway.json: |\n")
	var js []string
	for _, ln := range strings.Split(with[i+len("  setura-gateway.json: |\n"):], "\n") {
		js = append(js, strings.TrimPrefix(ln, "    "))
	}
	src, _ := os.ReadFile("../../grafana/setura-gateway.json")
	if strings.TrimSpace(strings.Join(js, "\n")) != strings.TrimSpace(string(src)) {
		t.Error("the printed dashboard differs from grafana/setura-gateway.json")
	}
}

// TestChartDashboardIsACopy keeps the chart's copy of the dashboard (helm cannot
// read files outside the chart) in step with grafana/setura-gateway.json.
func TestChartDashboardIsACopy(t *testing.T) {
	a, err := os.ReadFile("setura/dashboards/setura-gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../grafana/setura-gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("packaging/helm/setura/dashboards/setura-gateway.json differs from grafana/setura-gateway.json; copy it over")
	}
	tpl, _ := os.ReadFile("setura/templates/grafana-dashboard.yaml")
	if !strings.Contains(string(tpl), `.Files.Get "dashboards/setura-gateway.json"`) || !strings.HasPrefix(string(tpl), "{{- if .Values.grafanaDashboard.enabled }}") {
		t.Error("grafana-dashboard.yaml must be gated on grafanaDashboard.enabled and read the chart's copy")
	}
}

func TestHelmTemplateMonitoring(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command(helm, "template", "setura", "setura", "--set", "prometheusRule.enabled=true,grafanaDashboard.enabled=true").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	alerts := alertsOf(t, string(out))
	if len(alerts) != len(gateway.AlertRules("setura-system")) {
		t.Errorf("rendered %d alerts", len(alerts))
	}
	if !strings.Contains(string(out), "ConfigMap") || !strings.Contains(string(out), `"uid": "setura-gateway"`) {
		t.Error("dashboard ConfigMap not rendered")
	}
}

// TestPromtoolChecksRules validates the printed rules with promtool when it is installed.
func TestPromtoolChecksRules(t *testing.T) {
	promtool, err := exec.LookPath("promtool")
	if err != nil {
		t.Skip("promtool not installed")
	}
	y := gateway.MonitoringYAML("setura-system")
	i := strings.Index(y, "kind: PrometheusRule")
	spec := y[strings.Index(y[i:], "spec:\n")+i+len("spec:\n"):]
	spec = spec[:strings.Index(spec, "\n---\n")]
	var b strings.Builder
	for _, ln := range strings.Split(spec, "\n") {
		b.WriteString(strings.TrimPrefix(ln, "  ") + "\n")
	}
	f := t.TempDir() + "/rules.yaml"
	os.WriteFile(f, []byte(b.String()), 0o644)
	if out, err := exec.Command(promtool, "check", "rules", f).CombinedOutput(); err != nil {
		t.Fatalf("promtool: %v\n%s", err, out)
	}
}
