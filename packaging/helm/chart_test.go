package helm

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

var (
	kindRe = regexp.MustCompile(`(?m)^kind: (\w+)\s*$`)
	nameRe = regexp.MustCompile(`(?m)^  name: (\S+)\s*$`)
)

// objects returns "Kind/name" for every document in a YAML stream. Only
// top-level kinds and the first metadata name of each document are read, so
// it works on the printed install manifest and on a rendered chart.
func objects(yaml string) []string {
	var out []string
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(yaml, -1) {
		k := kindRe.FindStringSubmatch(doc)
		n := nameRe.FindStringSubmatch(doc)
		if k != nil && n != nil {
			out = append(out, k[1]+"/"+n[1])
		}
	}
	sort.Strings(out)
	return out
}

// templateObjects reads the chart templates without helm: unconditional
// objects only. Templates that start with {{- if .Values.X.enabled }} are the
// optional monitoring objects and must default to off.
func templateObjects(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob("setura/templates/*.yaml")
	values, err := os.ReadFile("setura/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		s := string(b)
		if m := regexp.MustCompile(`^\{\{- if \.Values\.(\w+)\.enabled \}\}`).FindStringSubmatch(s); m != nil {
			if !regexp.MustCompile(`(?m)^` + m[1] + `:\n(?:  .*\n|\n)*?  enabled: false`).Match(values) {
				t.Errorf("%s: %s.enabled must default to false", f, m[1])
			}
			continue
		}
		// Drop the conditional Namespace wrapper: it defaults on.
		s = strings.ReplaceAll(s, "{{- if .Values.createNamespace }}\n", "")
		s = strings.ReplaceAll(s, "{{- end }}\n", "")
		s = regexp.MustCompile(`\{\{[^}]*\}\}`).ReplaceAllString(s, "X")
		for _, o := range objects(s) {
			// namespace and class names come from values; map back to the defaults.
			o = strings.NewReplacer("Namespace/X", "Namespace/setura-system", "GatewayClass/X", "GatewayClass/setura").Replace(o)
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}

func TestChartMatchesGatewayInstall(t *testing.T) {
	want := objects(gateway.Install(gateway.InstallOptions{}))
	got := templateObjects(t)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("chart objects differ from `setura gateway install`\nchart:\n%s\ninstall:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(want) < 9 {
		t.Fatalf("install printed only %d objects", len(want))
	}
}

// TestChartHasEveryInstallOption keeps values.yaml in step with the flags of
// `setura gateway install`.
func TestChartHasEveryInstallOption(t *testing.T) {
	b, err := os.ReadFile("setura/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	values := string(b)
	for flag, key := range map[string]string{
		"namespace":            "namespace:",
		"image":                "image:",
		"class":                "className:",
		"replicas":             "replicas:",
		"expose-gateway-ports": "exposeGatewayPorts:",
	} {
		if !strings.Contains(values, "\n"+key) {
			t.Errorf("values.yaml has no key for install flag --%s (%s)", flag, key)
		}
	}
	chart, _ := os.ReadFile("setura/Chart.yaml")
	if !strings.Contains(string(chart), "apiVersion: v2") {
		t.Error("Chart.yaml is not a v2 chart")
	}
}

// TestHelmTemplate additionally renders with helm when it is installed.
func TestHelmTemplate(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command(helm, "template", "setura", "setura").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	got := objects(string(out))
	want := objects(gateway.Install(gateway.InstallOptions{}))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rendered chart differs from install\nchart:\n%s\ninstall:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	out, err = exec.Command(helm, "template", "setura", "setura", "--set", "serviceMonitor.enabled=true,prometheusRule.enabled=true,exposeGatewayPorts=true,replicas=3").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template (all on): %v\n%s", err, out)
	}
	all := strings.Join(objects(string(out)), " ")
	for _, k := range []string{"ServiceMonitor/setura-gateway", "PrometheusRule/setura-gateway"} {
		if !strings.Contains(all, k) {
			t.Errorf("missing %s when enabled", k)
		}
	}
	if !strings.Contains(string(out), "--expose-gateway-ports") || !strings.Contains(string(out), "replicas: 3") {
		t.Error("options not applied")
	}
}
