package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeaderBodyAndLatencyAssertions(t *testing.T) {
	url := fixture(t, nil)
	cases := []struct {
		name string
		mod  func(*ProbeOptions)
		ok   bool
		msg  string
	}{
		{"header exact", func(o *ProbeOptions) { o.Headers = map[string]string{"x-env": "staging"} }, true, ""},
		{"header presence", func(o *ProbeOptions) { o.Headers = map[string]string{"X-Env": "*"} }, true, ""},
		{"header wrong", func(o *ProbeOptions) { o.Headers = map[string]string{"X-Env": "prod"} }, false, "expected 'prod', received 'staging'"},
		{"header missing", func(o *ProbeOptions) { o.Headers = map[string]string{"X-Nope": "*"} }, false, "X-Nope is missing"},
		{"body found", func(o *ProbeOptions) { o.BodyContains = "service ready" }, true, ""},
		{"body missing", func(o *ProbeOptions) { o.BodyContains = "maintenance" }, false, "does not contain 'maintenance'"},
		{"latency ok", func(o *ProbeOptions) { o.MaxMS = 5000 }, true, ""},
		{"latency blown", func(o *ProbeOptions) { o.MaxMS = 0.0001 }, false, "budget is"},
	}
	for _, c := range cases {
		o := probeOpts(url)
		c.mod(&o)
		r, err := Probe(o)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if r.OK != c.ok {
			t.Errorf("%s: ok=%v want %v (%v)", c.name, r.OK, c.ok, r.Steps["assert"])
		}
		if c.msg != "" {
			contains(t, asStr(r.Step("assert").Get("reason")), c.msg)
		}
	}
	if r, _ := Probe(probeOpts(url)); r.Step("assert").State() != "unused" {
		t.Error("assert step should be unused without assertions")
	}
}

func TestCheckFileAssertionsAndExplainFlags(t *testing.T) {
	url := fixture(t, nil)
	path := filepath.Join(t.TempDir(), "c.json")
	body := `[{"url":"` + url + `","address":"127.0.0.1","headers":{"X-Env":"staging"},"body_contains":"ready","max_ms":5000}]`
	os.WriteFile(path, []byte(body), 0o600)
	if code, _, errs := cli(t, nil, "check", path); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	os.WriteFile(path, []byte(`[{"url":"`+url+`","headers":{"X-Env":7}}]`), 0o600)
	if code, _, _ := cli(t, nil, "check", path); code != 2 {
		t.Fatalf("non-string header accepted, exit %d", code)
	}
	code, out, _ := cli(t, nil, "explain", url, "--address", "127.0.0.1", "--header", "X-Env: staging", "--body-contains", "ready")
	if code != 0 || !strings.Contains(out, "assert   ok") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if code, _, _ := cli(t, nil, "explain", url, "--header", "malformed"); code != 2 {
		t.Fatalf("bad --header accepted")
	}
}

func lintSnap(t *testing.T, gw, rt obj) obj {
	t.Helper()
	return obj{"schema": snapshotSchema, "namespace": "demo", "resources": obj{gateway + "/dev": gw, route + "/orders": rt}}
}

func ids(report obj) string {
	var out []string
	for _, f := range asList(report["findings"]) {
		out = append(out, asStr(asMap(f)["id"]))
	}
	return strings.Join(out, ",")
}

func goodGateway() obj {
	return obj{"listeners": []any{obj{"name": "web", "port": 8080, "protocol": "HTTP", "hostname": "*.mactra.test"}}}
}

func TestLintCleanSnapshot(t *testing.T) {
	rt := obj{"hostnames": []any{"orders.mactra.test"}, "parentRefs": []any{obj{"name": "dev", "sectionName": "web"}},
		"rules": []any{obj{"backendRefs": []any{obj{"name": "orders", "port": 80}}}}}
	r, err := Lint(lintSnap(t, goodGateway(), rt))
	if err != nil {
		t.Fatal(err)
	}
	is(t, r["ok"], true)
	is(t, ids(r), "")
}

func TestLintRules(t *testing.T) {
	gw := obj{"listeners": []any{
		obj{"name": "web", "port": 8080, "protocol": "HTTP", "hostname": "orders.mactra.test"},
		obj{"name": "secure", "port": 8443, "protocol": "HTTPS"},
		obj{"name": "web", "port": 9090, "protocol": "HTTP", "hostname": "orders.mactra.test"}}}
	rt := obj{"hostnames": []any{"shop.example.org"},
		"parentRefs": []any{obj{"name": "dev", "sectionName": "web"}, obj{"name": "dev", "sectionName": "missing"}},
		"rules": []any{
			obj{"backendRefs": []any{obj{"name": "a", "port": 80, "weight": 0}, obj{"name": "b", "port": 80, "weight": 0}}},
			obj{},
			obj{"backendRefs": []any{obj{"name": "c", "port": 80, "namespace": "other"}}}}}
	r, _ := Lint(lintSnap(t, gw, rt))
	is(t, r["ok"], false)
	for _, want := range []string{"SET002", "SET003", "SET004", "SET005", "SET006", "SET007", "SET008"} {
		contains(t, ids(r), want)
	}
	// no parentRefs
	r, _ = Lint(lintSnap(t, goodGateway(), obj{"rules": []any{obj{"backendRefs": []any{obj{"name": "a", "port": 1}}}}}))
	contains(t, ids(r), "SET001")
	is(t, r["ok"], false)
}

func TestLintShadowedRoutes(t *testing.T) {
	mk := func() obj {
		return obj{"hostnames": []any{"orders.mactra.test"}, "parentRefs": []any{obj{"name": "dev"}},
			"rules": []any{obj{"matches": []any{obj{"path": obj{"type": "PathPrefix", "value": "/checkout"}}},
				"backendRefs": []any{obj{"name": "a", "port": 80}}}}}
	}
	snap := obj{"schema": snapshotSchema, "namespace": "demo", "resources": obj{
		gateway + "/dev": goodGateway(), route + "/a": mk(), route + "/b": mk()}}
	r, _ := Lint(snap)
	is(t, ids(r), "SET009")
	is(t, r["ok"], true) // warning only
	is(t, asMap(asList(r["findings"])[0])["resource"], "HTTPRoute/demo/b")
}

func TestLintCLIExitCodesAndFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	warn := lintSnap(t, goodGateway(), obj{"parentRefs": []any{obj{"name": "dev"}},
		"rules": []any{obj{"backendRefs": []any{obj{"name": "c", "port": 80, "namespace": "other"}}}}})
	raw, _ := json.Marshal(warn)
	os.WriteFile(path, raw, 0o600)
	code, out, _ := cli(t, nil, "lint", "--snapshot", path)
	is(t, code, 0)
	contains(t, out, "SET004")
	contains(t, out, "1 warning")
	is(t, func() int { c, _, _ := cli(t, nil, "lint", "--snapshot", path, "--strict"); return c }(), 1)
	code, out, _ = cli(t, nil, "lint", "--snapshot", path, "--format", "json")
	var rep obj
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 {
		t.Fatalf("%d %v %s", code, err, out)
	}
	if code, out, _ := cli(t, nil, "lint", "--rules"); code != 0 || !strings.Contains(out, "SET009") {
		t.Fatalf("--rules: %d %q", code, out)
	}
	// lint output feeds the AI evidence extractor
	var generic any
	json.Unmarshal([]byte(mustLintJSON(t, path)), &generic)
	facts, err := Evidence(generic)
	if err != nil || len(facts) == 0 {
		t.Fatalf("lint evidence: %v %v", err, facts)
	}
}

func mustLintJSON(t *testing.T, path string) string {
	_, out, _ := cli(t, nil, "lint", "--snapshot", path, "--format", "json")
	return out
}

func TestExampleTopologyLintsClean(t *testing.T) {
	r, err := Lint(loadSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if r["ok"] != true {
		t.Fatalf("examples/topology.json has lint errors: %v", r["findings"])
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, _ := cli(t, nil, "completion", shell)
		if code != 0 || !strings.Contains(out, "lint") || !strings.Contains(out, "setura") {
			t.Errorf("%s: %d %q", shell, code, out)
		}
	}
	if code, _, _ := cli(t, nil, "completion", "powershell"); code != 2 {
		t.Error("unsupported shell accepted")
	}
}
