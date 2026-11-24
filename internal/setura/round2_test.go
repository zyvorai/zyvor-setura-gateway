package setura

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func jsonServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestJSONAssertEval(t *testing.T) {
	doc := `{"status":"ok","n":7,"ratio":0.5,"flag":true,"nil":null,"items":[{"id":"a1"},{"id":"b2"}],"obj":{"x":1}}`
	cases := []struct {
		path, want string
		fail       string // substring of the failure; "" passes
	}{
		{"$.status", "ok", ""},
		{"status", "ok", ""},
		{"$.status", "bad", `expected 'bad'`},
		{"$.n", "7", ""},
		{"$.n", ">5", ""},
		{"$.n", ">7", "expected >7"},
		{"$.n", ">=7", ""},
		{"$.n", "<=6", "expected <=6"},
		{"$.n", "<8", ""},
		{"$.ratio", "0.5", ""},
		{"$.flag", "true", ""},
		{"$.nil", "null", ""},
		{"$.items[1].id", "b2", ""},
		{"$.items[2].id", "*", "is missing"},
		{"$.items[0].id", "!=a1", "must not be"},
		{"$.items[0].id", "!=zz", ""},
		{"$.items[0].id", "~^a\\d$", ""},
		{"$.items[1].id", "~^a", "does not match"},
		{"$.missing", "*", "is missing"},
		{"$.obj", "*", ""},
		{"$.obj", "x", "expected 'x', received 'object'"},
		{"$.items", "*", ""},
		{"$.status", ">3", "needs numbers"},
		{"$.status.deeper", "*", "no object"},
		{"$.status", "==>weird", `expected '>weird'`},
	}
	for _, c := range cases {
		body := strings.NewReader(doc)
		o := ProbeOptions{JSON: []JSONAssert{{c.path, c.want}}}
		_ = body
		_, err := o.checkBody([]byte(doc))
		switch {
		case c.fail == "" && err != nil:
			t.Errorf("%s %s: unexpected %v", c.path, c.want, err)
		case c.fail != "" && (err == nil || !strings.Contains(err.Error(), c.fail)):
			t.Errorf("%s %s: want %q, got %v", c.path, c.want, c.fail, err)
		}
	}
	if _, err := (ProbeOptions{JSON: []JSONAssert{{"$.a", "*"}}}).checkBody([]byte("<html>")); err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("non-JSON body: %v", err)
	}
	for _, p := range []string{"", "$", "$.", "$.a[", "$.a[x]", "$.a[-1]"} {
		if _, err := parseJSONPath(p); err == nil {
			t.Errorf("path %q should be rejected", p)
		}
	}
}

func TestExplainJSONPathAndBodyMatches(t *testing.T) {
	srv := jsonServer(t, `{"status":"ok","count":3,"version":"v1.2.3"}`)
	code, m := cliJSON(t, "explain", srv.URL+"/", "--json", "--json-path", "$.status=ok", "--json-path", "$.count=>2", "--json-path", "$.version=~^v1\\.", "--body-matches", `"count":\d`)
	if code != 0 || m["ok"] != true {
		t.Fatalf("expected pass: %d %v", code, m)
	}
	if got := asMap(asMap(m["steps"])["assert"])["checks"]; got != float64(4) {
		t.Errorf("checks = %v", got)
	}
	code, m = cliJSON(t, "explain", srv.URL+"/", "--json", "--json-path", "$.status=down")
	reason := str(asMap(asMap(m["steps"])["assert"]), "reason", "")
	if code != 1 || !strings.Contains(reason, "JSON $.status") {
		t.Errorf("mismatch: %d %v", code, m)
	}
	code, _ = cliJSON(t, "explain", srv.URL+"/", "--json", "--body-matches", "^nomatch$")
	if code != 1 {
		t.Errorf("body-matches mismatch should fail, got %d", code)
	}
	for _, args := range [][]string{
		{"explain", srv.URL, "--json-path", "$.a[x]=1"},
		{"explain", srv.URL, "--json-path", "$.a=~("},
		{"explain", srv.URL, "--body-matches", "("},
	} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: want usage error, got %d", args, code)
		}
	}
}

func writeChecks(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "checks.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckFileJSONAssertions(t *testing.T) {
	srv := jsonServer(t, `{"status":"ok","count":3,"ready":true}`)
	f := writeChecks(t, `[{"url":"`+srv.URL+`/","json":{"$.status":"ok","$.count":">=3","$.ready":true},"body_matches":"status"},
	  {"url":"`+srv.URL+`/","json":{"$.status":"down"}}]`)
	rows, err := Check(f)
	if err != nil {
		t.Fatal(err)
	}
	if !rows[0].OK || rows[1].OK {
		t.Fatalf("rows: %v %v", rows[0].OK, rows[1].OK)
	}
	for _, bad := range []string{
		`[{"url":"` + srv.URL + `","json":["x"]}]`,
		`[{"url":"` + srv.URL + `","json":{"$.a":[1]}}]`,
		`[{"url":"` + srv.URL + `","json":{"$.a[":"1"}}]`,
		`[{"url":"` + srv.URL + `","body_matches":"("}]`,
	} {
		if _, err := Check(writeChecks(t, bad)); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
	// watch accepts the same keys
	if _, err := parseWatchFile(f); err != nil {
		t.Errorf("watch file: %v", err)
	}
}

func TestCheckRetries(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	f := writeChecks(t, `[{"url":"`+srv.URL+`/","retries":3,"retry_interval_ms":5}]`)
	rows, err := Check(f)
	if err != nil || !rows[0].OK || rows[0].Attempts != 3 {
		t.Fatalf("want pass on attempt 3: %v %+v", err, rows)
	}
	b, _ := rows[0].MarshalJSON()
	if !strings.Contains(string(b), `"attempts":3`) {
		t.Errorf("json: %s", b)
	}
	// No retries: fails once and the JSON carries no attempts field.
	n.Store(0)
	code, out, _ := cli(t, nil, "check", writeChecks(t, `[{"url":"`+srv.URL+`/"}]`), "--format", "json")
	if code != 1 || strings.Contains(out, "attempts") || n.Load() != 1 {
		t.Errorf("no retry: %d calls=%d %s", code, n.Load(), out)
	}
	// CLI default applies to cases without their own value.
	n.Store(0)
	code, _, _ = cli(t, nil, "check", writeChecks(t, `[{"url":"`+srv.URL+`/"}]`), "--format", "json", "--retries", "4", "--retry-interval", "1ms")
	if code != 0 || n.Load() != 3 {
		t.Errorf("--retries: %d calls=%d", code, n.Load())
	}
	// A retrying case that never recovers reports its last attempt.
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	t.Cleanup(always.Close)
	rows, _ = Check(writeChecks(t, `[{"url":"`+always.URL+`/","retries":2,"retry_interval_ms":1}]`))
	if rows[0].OK || rows[0].Attempts != 3 {
		t.Errorf("exhausted: %+v", rows[0])
	}
	for _, bad := range []string{`"retries":-1`, `"retries":21`, `"retries":1.5`, `"retries":"x"`, `"retry_interval_ms":-5`, `"retry_interval_ms":999999`} {
		if _, err := Check(writeChecks(t, `[{"url":"`+srv.URL+`/",`+bad+`}]`)); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
	if code, _, _ := cli(t, nil, "check", f, "--retries", "99"); code != 2 {
		t.Errorf("--retries 99: %d", code)
	}
}

func TestCORSExpectRefused(t *testing.T) {
	good, _ := corsServer(t, true) // reflects every origin: a permissive server
	code, out, _ := cli(t, nil, "cors", good.URL+"/", "--origin", "https://evil.example", "--expect-refused")
	if code != 1 || !strings.Contains(out, "FAIL origin https://evil.example is allowed") {
		t.Errorf("reflecting server must fail the refusal check: %d %s", code, out)
	}
	strict, _ := corsServer(t, false) // sends no CORS headers: every origin refused
	code, out, _ = cli(t, nil, "cors", strict.URL+"/", "--origin", "https://evil.example", "--expect-refused")
	if code != 0 || !strings.Contains(out, "PASS origin https://evil.example is refused") {
		t.Errorf("strict server: %d %s", code, out)
	}
	code, m := cliJSON(t, "cors", strict.URL+"/", "--origin", "https://evil.example", "--expect-refused", "--json")
	if code != 0 || m["ok"] != true || m["expect_refused"] != true || m["allowed"] != false {
		t.Errorf("json: %d %v", code, m)
	}
	code, m = cliJSON(t, "cors", good.URL+"/", "--origin", "https://evil.example", "--expect-refused", "--json")
	if code != 1 || m["ok"] != false || m["allowed"] != true {
		t.Errorf("json allowed: %d %v", code, m)
	}
	// An unreachable server is still a failure, not a refusal.
	if code, out, _ = cli(t, nil, "cors", "http://127.0.0.1:1/", "--origin", "https://a.example", "--timeout", "1", "--expect-refused"); code != 1 || !strings.Contains(out, "no preflight answer") {
		t.Errorf("unreachable: %d %s", code, out)
	}
}

func certServer(t *testing.T) (addr, ca string) {
	t.Helper()
	cfg, caPath := selfSigned(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), caPath
}

func TestCertsListMode(t *testing.T) {
	a, ca := certServer(t)
	targets := []string{a, "127.0.0.1:1", a} // duplicate collapses; a dead port is an error row
	code, out, _ := cli(t, nil, append([]string{"certs", "--ca", ca, "--sni", "orders.mactra.test", "--timeout", "1", "--json"}, targets...)...)
	if code != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	m := mustJSONMap(t, out)
	rows := asList(m["targets"])
	if len(rows) != 2 || m["ok"] != false {
		t.Fatalf("rows: %v", m)
	}
	first, second := asMap(rows[0]), asMap(rows[1])
	if first["status"] != "error" || first["target"] != "127.0.0.1:1" || second["status"] != "ok" || second["verified"] != true {
		t.Errorf("errors sort first: %v / %v", first, second)
	}
	// Healthy list, from a file with comments, exits 0 in text mode.
	f := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(f, []byte("# prod\n"+a+"  # api\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = cli(t, nil, "certs", "--file", f, "--ca", ca, "--sni", "orders.mactra.test")
	if code != 0 || !strings.Contains(out, "all 1 certificates ok") || !strings.Contains(out, "TARGET") {
		t.Errorf("file mode: %d %s", code, out)
	}
	// Expiry threshold turns it red (the fixture certificate lives one hour).
	code, out, _ = cli(t, nil, "certs", a, "--file", f, "--ca", ca, "--sni", "orders.mactra.test", "--warn-expiry-days", "30")
	if code != 1 || !strings.Contains(out, "EXPIRING") || !strings.Contains(out, "1 of 1 need attention") {
		t.Errorf("expiring: %d %s", code, out)
	}
	// Untrusted chain is reported per row.
	code, out, _ = cli(t, nil, "certs", "--file", f, "--sni", "orders.mactra.test")
	if code != 1 || !strings.Contains(out, "UNVERIFIED") {
		t.Errorf("unverified: %d %s", code, out)
	}
	// Bad input is a usage error, before any connection.
	if code, _, _ = cli(t, nil, "certs", a, "nocolon"); code != 2 && code != 1 {
		t.Errorf("bad target: %d", code)
	}
	if code, _, errs := cli(t, nil, "certs", "--file", filepath.Join(t.TempDir(), "missing")); code == 0 {
		t.Errorf("missing file should fail: %s", errs)
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if code, _, _ = cli(t, nil, "certs", "--file", empty); code == 0 {
		t.Error("empty list should fail")
	}
}

func TestReadCertTargetsStdin(t *testing.T) {
	got, err := readCertTargets("-", strings.NewReader("a:1\n  \n#c\nb:2 # x\n"))
	if err != nil || len(got) != 2 || got[0] != "a:1" || got[1] != "b:2" {
		t.Errorf("%v %v", got, err)
	}
}

func mustJSONMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%v: %s", err, s)
	}
	return m
}
