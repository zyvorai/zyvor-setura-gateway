package setura

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func TestInitFromPairs(t *testing.T) {
	cases := []struct {
		name    string
		pairs   []string
		wantErr string
		routes  int
		bks     int
	}{
		{"two hosts", []string{"a.example.test=127.0.0.1:9001", "b.example.test=http://127.0.0.1:9002"}, "", 2, 2},
		{"shared upstream", []string{"a.test=127.0.0.1:9001", "b.test=127.0.0.1:9001"}, "", 2, 1},
		{"path prefixes", []string{"a.test/api=127.0.0.1:9001", "a.test/web=127.0.0.1:9002"}, "", 1, 2},
		{"https default port", []string{"a.test=https://api.internal"}, "", 1, 1},
		{"missing equals", []string{"a.test"}, "want host=upstream", 0, 0},
		{"empty host", []string{"=127.0.0.1:1"}, "host before", 0, 0},
		{"bad upstream", []string{"a.test=nonsense"}, "want host:port", 0, 0},
		{"bad port", []string{"a.test=h:99999"}, "invalid port", 0, 0},
		{"upstream with path", []string{"a.test=http://h:1/x"}, "put paths on the host", 0, 0},
		{"duplicate", []string{"a.test=h:1", "a.test=h:2"}, "listed twice", 0, 0},
		{"none", nil, "no routes", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := fromPairs(c.pairs, "gateway", 8080)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(spec.Routes) != c.routes || len(spec.Backends) != c.bks {
				t.Fatalf("routes=%d backends=%d", len(spec.Routes), len(spec.Backends))
			}
			assertAccepted(t, spec)
		})
	}
}

// assertAccepted round-trips the snapshot through the gateway parser and lint.
func assertAccepted(t *testing.T, spec initSpec) {
	t.Helper()
	raw, _ := json.Marshal(buildSnapshot(spec))
	if _, err := builtin.ParseConfig(raw, t.TempDir()); err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	var snap obj
	_ = json.Unmarshal(raw, &snap)
	rep, err := Lint(snap)
	if err != nil {
		t.Fatal(err)
	}
	if rep["errors"] != 0 || rep["warnings"] != 0 {
		t.Fatalf("lint not clean: %v", rep["findings"])
	}
}

const petsV3 = `{"openapi":"3.0.3","servers":[{"url":"https://api.pets.test/v1"},{"url":"https://api2.pets.test/v1"},{"url":"https://api.pets.test/v1"}],
"paths":{"/pets":{"get":{},"post":{}},"/pets/{id}":{"get":{},"delete":{}},"/health":{}}}`

func TestInitFromOpenAPI(t *testing.T) {
	spec, err := fromOpenAPI([]byte(petsV3), "pets", "", "", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Backends) != 1 || len(spec.Backends[0].Endpoints) != 2 {
		t.Fatalf("backends = %+v", spec.Backends)
	}
	if spec.Backends[0].Endpoints[0] != "https://api.pets.test:443" || spec.Backends[0].Port != 443 {
		t.Fatalf("primary = %+v", spec.Backends[0])
	}
	r := spec.Routes[0]
	if r.Host != "api.pets.test" {
		t.Fatalf("host = %q", r.Host)
	}
	got := map[string]bool{}
	for _, ru := range r.Rules {
		for _, m := range ru.Matches {
			got[m.Type+" "+m.Path+" "+m.Method] = true
		}
	}
	for _, w := range []string{"Exact /v1/health ", "Exact /v1/pets GET", "Exact /v1/pets POST", "PathPrefix /v1/pets GET", "PathPrefix /v1/pets DELETE"} {
		if !got[w] {
			t.Errorf("missing match %q in %v", w, got)
		}
	}
	if r.Sample != "/v1/health" {
		t.Errorf("sample = %q", r.Sample)
	}
	assertAccepted(t, spec)
}

func TestInitFromSwagger2(t *testing.T) {
	doc := `{"swagger":"2.0","host":"shop.test:8443","basePath":"/api","schemes":["https","http"],"paths":{"/items/{id}":{"get":{}}}}`
	spec, err := fromOpenAPI([]byte(doc), "shop", "front.test", "", 80)
	if err != nil {
		t.Fatal(err)
	}
	b := spec.Backends[0]
	if b.Port != 8443 || len(b.Endpoints) != 2 || b.Endpoints[0] != "https://shop.test:8443" || b.Endpoints[1] != "shop.test:8443" {
		t.Fatalf("backend %+v", b)
	}
	if spec.Routes[0].Host != "front.test" || spec.Routes[0].Rules[0].Matches[0].Path != "/api/items" {
		t.Fatalf("route %+v", spec.Routes[0])
	}
	assertAccepted(t, spec)
}

func TestInitOpenAPIErrors(t *testing.T) {
	cases := []struct{ name, in, upstream, want string }{
		{"yaml", "openapi: 3.0.0\npaths: {}\n", "", "JSON only"},
		{"not openapi", `{"a":1}`, "", "does not look like an OpenAPI"},
		{"no paths", `{"openapi":"3.0.0","paths":{}}`, "", "no paths"},
		{"no server", `{"openapi":"3.0.0","servers":[{"url":"/v1"}],"paths":{"/a":{}}}`, "", "--upstream"},
		{"bad json", `{"openapi":`, "", "not valid JSON"},
	}
	for _, c := range cases {
		_, err := fromOpenAPI([]byte(c.in), "x", "", c.upstream, 8080)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	spec, err := fromOpenAPI([]byte(`{"openapi":"3.0.0","servers":[{"url":"/v1"}],"paths":{"/a":{"get":{}}}}`), "x", "", "127.0.0.1:9000", 8080)
	if err != nil || len(spec.Backends) != 1 {
		t.Fatalf("upstream override: %v", err)
	}
}

func runInitCLI(t *testing.T, stdin string, tty bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	fs := newFlagSet("init", &errb)
	code, err := runInit(fs, args, strings.NewReader(stdin), tty, &out, &errb, plainUI, tty)
	if err != nil && code == 0 {
		code = 2
	}
	return code, out.String(), errb.String()
}

func TestInitWritesAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	code, out, errs := runInitCLI(t, "", false, "--route", "orders.example.test=127.0.0.1:9001", "--route", "shop.example.test=127.0.0.1:9002", "--out", dir, "--format", "pretty")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	for _, w := range []string{"Created setura.json and checks.json: 2 routes, 2 backends, lint clean", "Next: setura gateway run --config " + filepath.Join(dir, "setura.json"), "setura check "} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
	if ansi.MatchString(out) {
		t.Error("plain output has escapes")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var checks []map[string]any
	if json.Unmarshal(raw, &checks) != nil || len(checks) != 2 || checks[0]["address"] != "127.0.0.1" {
		t.Fatalf("checks.json = %s", raw)
	}
	code, _, errs = runInitCLI(t, "", false, "--route", "a.test=h:1", "--out", dir)
	if code != 2 || !strings.Contains(errs, "already exists") || !strings.Contains(errs, "--force") {
		t.Fatalf("overwrite: code %d, %s", code, errs)
	}
	if code, _, errs = runInitCLI(t, "", false, "--route", "a.test=h:1", "--out", dir, "--force"); code != 0 {
		t.Fatalf("force: %d %s", code, errs)
	}
}

func TestInitJSONAndErrors(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := runInitCLI(t, "", false, "--route", "a.test=127.0.0.1:1", "--out", dir)
	if code != 0 {
		t.Fatal(code)
	}
	var doc struct {
		Schema   string
		Routes   int
		Backends int
		Files    []string
		Next     []string
		Lint     map[string]any
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Schema != "setura.init/v1" || doc.Routes != 1 || len(doc.Files) != 2 || len(doc.Next) != 2 || doc.Lint["ok"] != true {
		t.Fatalf("json: %v %s", err, out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "Nothing to scaffold"},
		{[]string{"--route", "x", "--out", dir}, "want host=upstream"},
		{[]string{"--route", "a=h:1", "--openapi", "x.json"}, "not both"},
		{[]string{"--openapi", filepath.Join(dir, "missing.json")}, "Cannot read"},
		{[]string{"--route", "a=h:1", "--listen-port", "0"}, "not a valid listen port"},
	} {
		code, _, errs := runInitCLI(t, "", false, c.args...)
		if code != 2 || !strings.Contains(errs, c.want) || !strings.Contains(errs, "Next:") {
			t.Errorf("%v: code %d %q", c.args, code, errs)
		}
	}
}

func TestInitInteractive(t *testing.T) {
	dir := t.TempDir()
	in := "orders.test=127.0.0.1:9001\nshop.test=127.0.0.1:9002\n\n9090\n" + dir + "\n"
	code, out, errs := runInitCLI(t, in, true, "--format", "pretty")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	if !strings.Contains(errs, "Listen port [8080]") || !strings.Contains(out, "port 9090") {
		t.Fatalf("prompts/summary missing:\n%s\n%s", errs, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "setura.json")); err != nil {
		t.Fatal(err)
	}
}

func TestInitPrettyGolden(t *testing.T) {
	spec, _ := fromPairs([]string{"orders.example.test=127.0.0.1:9001"}, "gateway", 8080)
	res := &initResult{Dir: "gw", Routes: 1, Backends: 1, spec: spec, Lint: obj{"errors": 0, "warnings": 0},
		Files: []string{"gw/setura.json", "gw/checks.json"}, Next: []string{"setura gateway run --config gw/setura.json --ui 127.0.0.1:9090", "setura check gw/checks.json"}}
	want := `
  ✓ Created setura.json and checks.json: 1 route, 1 backend, lint clean

    Folder     gw
    Gateway    gateway, HTTP on port 8080
    Routes     orders.example.test → 127-0-0-1:9001

  Next: setura gateway run --config gw/setura.json --ui 127.0.0.1:9090
        setura check gw/checks.json

`
	golden(t, plainUI.InitPretty(res), want)
	ascii := newUI(false, termOptions{Color: "never", ASCII: true}, func(string) string { return "" })
	if s := ascii.InitPretty(res); strings.Contains(s, "✓") || strings.Contains(s, "→") {
		t.Errorf("ascii output has unicode:\n%s", s)
	}
}
