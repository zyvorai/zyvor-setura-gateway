package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ciSnapshot(t *testing.T) string {
	t.Helper()
	snap := lintSnap(t, goodGateway(), obj{"parentRefs": []any{obj{"name": "dev"}},
		"rules": []any{
			obj{"backendRefs": []any{obj{"name": "c", "port": 80, "namespace": "other"}}},
			obj{"backendRefs": []any{obj{"name": "z", "port": 80, "weight": 0}}}}})
	raw, _ := json.Marshal(snap)
	p := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(p, raw, 0o600)
	return p
}

func TestLintSARIFStructure(t *testing.T) {
	snap := ciSnapshot(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("apiVersion: v1\nkind: Gateway\nmetadata:\n  name: dev\n---\n# c\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata:\n  labels:\n    name: nope\n  name: \"orders\"\n  namespace: demo\nspec: {}\n"), 0o600)
	code, out, errs := cli(t, nil, "lint", "--snapshot", snap, "--format", "sarif", "--manifest-dir", dir, "--severity-override", "SET004=error")
	is(t, code, 1)
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string         `json:"id"`
						Help                 map[string]any `json:"help"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string            `json:"ruleId"`
				RuleIndex int               `json:"ruleIndex"`
				Level     string            `json:"level"`
				Message   map[string]string `json:"message"`
				Locations []struct {
					Logical  []map[string]string `json:"logicalLocations"`
					Physical *struct {
						Art    map[string]string `json:"artifactLocation"`
						Region map[string]int    `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Fingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v: %s %s", err, out, errs)
	}
	is(t, doc.Version, "2.1.0")
	contains(t, doc.Schema, "sarif-2.1.0")
	is(t, len(doc.Runs), 1)
	run := doc.Runs[0]
	is(t, run.Tool.Driver.Name, "setura")
	is(t, len(run.Tool.Driver.Rules), len(Rules))
	for i, r := range run.Tool.Driver.Rules {
		is(t, r.ID, Rules[i].ID)
		is(t, r.DefaultConfiguration.Level, Rules[i].Severity)
		if r.Help["text"] == nil {
			t.Errorf("rule %s has no help", r.ID)
		}
	}
	is(t, len(run.Results), 2)
	for _, r := range run.Results {
		is(t, run.Tool.Driver.Rules[r.RuleIndex].ID, r.RuleID)
		is(t, r.Locations[0].Logical[0]["fullyQualifiedName"], "HTTPRoute/demo/orders")
		if r.Fingerprints["setura/v1"] == "" {
			t.Error("missing fingerprint")
		}
		if r.RuleID == "SET004" {
			is(t, r.Level, "error") // override applied
		}
		p := r.Locations[0].Physical
		if p == nil || !strings.HasSuffix(p.Art["uri"], "r.yaml") || p.Region["startLine"] != 12 {
			t.Errorf("physical location wrong: %+v", p)
		}
	}
}

func TestCheckSARIFAndGithub(t *testing.T) {
	url := fixture(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	body := `[{"url":"` + url + `","address":"127.0.0.1","headers":{"X-Env":"prod"}}]`
	os.WriteFile(path, []byte(body), 0o600)
	sarif := filepath.Join(dir, "out.sarif")
	code, out, _ := cli(t, nil, "check", path, "--sarif", sarif, "--format", "github")
	is(t, code, 1)
	if !strings.HasPrefix(out, "::error title=setura assert,file=") && !strings.HasPrefix(out, "::error file=") {
		t.Errorf("annotation: %q", out)
	}
	contains(t, out, "assert failed")
	raw, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	is(t, doc["version"], "2.1.0")
	res := asList(asMap(asList(doc["runs"])[0])["results"])
	is(t, len(res), 1)
	is(t, asMap(res[0])["ruleId"], "SETCHK-ASSERT")
	// passing check yields empty results
	os.WriteFile(path, []byte(`[{"url":"`+url+`","address":"127.0.0.1"}]`), 0o600)
	code, out, _ = cli(t, nil, "check", path, "--sarif", sarif, "--format", "github")
	is(t, code, 0)
	is(t, out, "")
	if code, _, _ := cli(t, nil, "check", path, "--format", "xml"); code != 2 {
		t.Error("bad format accepted")
	}
}

func TestGithubEscaping(t *testing.T) {
	is(t, escapeData("a%b\r\nc"), "a%25b%0D%0Ac")
	is(t, escapeProperty("a:b,c%\n"), "a%3Ab%2Cc%25%0A")
	is(t, annotation("error", "SET002", "", 0, "x\ny"), "::error title=SET002::x%0Ay\n")
	is(t, annotation("warning", "T", "dir/a:b.yaml", 3, "m"), "::warning file=dir/a%3Ab.yaml,line=3,title=T::m\n")
}

func TestLintGithubFormat(t *testing.T) {
	snap := ciSnapshot(t)
	code, out, _ := cli(t, nil, "lint", "--snapshot", snap, "--format", "github")
	is(t, code, 1)
	contains(t, out, "::warning title=SET004::HTTPRoute/demo/orders: rule 1")
	contains(t, out, "::error title=SET002::")
}

func TestBaselineRoundTripAndOptions(t *testing.T) {
	snap := ciSnapshot(t)
	base := filepath.Join(t.TempDir(), "base.json")
	code, out, _ := cli(t, nil, "lint", "--snapshot", snap, "--write-baseline", base)
	is(t, code, 0) // everything baselined
	contains(t, out, "suppressed by baseline")
	code, out, _ = cli(t, nil, "lint", "--snapshot", snap, "--baseline", base)
	is(t, code, 0)
	contains(t, out, "0 error(s), 0 warning(s)")
	// a new finding is not covered by the baseline
	code, _, _ = cli(t, nil, "lint", "--snapshot", snap, "--baseline", base, "--severity-override", "SET004=error")
	is(t, code, 0) // same message, same fingerprint: severity is not part of identity
	code, out, _ = cli(t, nil, "lint", "--snapshot", snap)
	is(t, code, 1)
	// disable + override
	code, _, _ = cli(t, nil, "lint", "--snapshot", snap, "--disable", "SET002")
	is(t, code, 0)
	code, _, _ = cli(t, nil, "lint", "--snapshot", snap, "--disable", "SET002", "--severity-override", "SET004=error")
	is(t, code, 1)
	// stale baseline: changed message produces a new finding
	raw, _ := os.ReadFile(base)
	os.WriteFile(base, []byte(strings.ReplaceAll(string(raw), "SET002", "SET099")), 0o600)
	code, _, _ = cli(t, nil, "lint", "--snapshot", snap, "--baseline", base)
	is(t, code, 1)
	for _, bad := range [][]string{{"--disable", "NOPE"}, {"--severity-override", "SET004"}, {"--severity-override", "SET004=fatal"}, {"--baseline", filepath.Join(t.TempDir(), "missing")}} {
		if code, _, _ := cli(t, nil, append([]string{"lint", "--snapshot", snap}, bad...)...); code != 2 {
			t.Errorf("%v: exit %d, want 2", bad, code)
		}
	}
}

func TestManifestScanners(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte("{\n \"kind\": \"List\",\n \"items\": [\n  {\"kind\":\"Gateway\",\n \"metadata\": {\"name\": \"gw\", \"namespace\": \"x\"}}]}"), 0o600)
	idx, err := ScanManifests(dir)
	if err != nil {
		t.Fatal(err)
	}
	l := idx.Find("Gateway/x/gw", "x")
	if l.Line != 5 && l.Line != 4 || !strings.HasSuffix(l.File, "a.json") {
		t.Errorf("json location %+v", l)
	}
	if idx.Find("Gateway/y/none", "y").File != "" {
		t.Error("unexpected match")
	}
}
