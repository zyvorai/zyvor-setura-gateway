package gateway

import (
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestNetraDocsListEveryMetric keeps docs/netra.md in step with MetricCatalog.
func TestNetraDocsListEveryMetric(t *testing.T) {
	doc := readDoc(t, "docs/netra.md")
	for _, d := range MetricCatalog {
		if !strings.Contains(doc, "`"+d.Name+"`") {
			t.Errorf("docs/netra.md does not list %s", d.Name)
		}
	}
}

// TestNetraAppsSnippetGlobs checks the ready-made Netra config only names
// series the gateway exposes: the include glob matches, and every exclude
// glob matches something (so a rename cannot leave a dead exclude behind).
func TestNetraAppsSnippetGlobs(t *testing.T) {
	y := readDoc(t, "docs/netra/apps.yaml")
	list := func(key string) []string {
		var out []string
		if m := regexp.MustCompile(`(?m)^    ` + key + `: \[(.*)\]\s*$`).FindStringSubmatch(y); m != nil {
			for _, g := range strings.Split(m[1], ",") {
				out = append(out, strings.Trim(strings.TrimSpace(g), `"`))
			}
			return out
		}
		block := regexp.MustCompile(`(?m)^    ` + key + `:\n((?:      - .*\n)+)`).FindStringSubmatch(y)
		if block != nil {
			for _, ln := range strings.Split(strings.TrimSpace(block[1]), "\n") {
				out = append(out, strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "- ")), `"`))
			}
		}
		return out
	}
	inc, exc := list("include"), list("exclude")
	if len(inc) == 0 || len(exc) == 0 {
		t.Fatalf("include %v exclude %v", inc, exc)
	}
	matches := func(glob string) bool {
		for _, d := range MetricCatalog {
			if ok, _ := path.Match(glob, d.Name); ok {
				return true
			}
		}
		return false
	}
	for _, g := range append(inc, exc...) {
		if !matches(g) {
			t.Errorf("glob %q matches no exposed metric", g)
		}
	}
	for _, want := range []string{"kind: prometheus", "bearer_env: SETURA_ADMIN_TOKEN", "url: http://127.0.0.1:19000/metrics"} {
		if !strings.Contains(y, want) {
			t.Errorf("snippet lacks %q", want)
		}
	}
	if doc := readDoc(t, "docs/netra.md"); !strings.Contains(doc, strings.TrimSpace(strings.SplitN(y, "apps:\n", 2)[1])[:40]) {
		t.Error("the snippet in docs/netra.md drifted from docs/netra/apps.yaml")
	}
}

func TestRunbookHasASectionPerAlert(t *testing.T) {
	doc := readDoc(t, "docs/runbooks.md")
	for _, a := range AlertRules("x") {
		if !strings.Contains(doc, "\n## "+a.Alert+"\n") {
			t.Errorf("docs/runbooks.md has no section for %s", a.Alert)
		}
		if a.Anchor != strings.ToLower(a.Alert) {
			t.Errorf("%s: anchor %q must be the lower case alert name (GitHub heading anchor)", a.Alert, a.Anchor)
		}
	}
}
