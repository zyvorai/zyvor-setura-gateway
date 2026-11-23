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

func limitsFindings(t *testing.T, listener obj, rules []any, ann obj) (set030, set003 []string) {
	t.Helper()
	rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": rules}
	if ann != nil {
		rt[builtin.SeturaAnnotationsKey] = ann
	}
	l := obj{"name": "web", "protocol": "HTTP", "port": 80}
	for k, v := range listener {
		l[k] = v
	}
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{l}}, route + "/r": rt}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range asList(rep["findings"]) {
		m := asMap(f)
		switch asStr(m["id"]) {
		case "SET030":
			set030 = append(set030, asStr(m["message"]))
		case "SET003":
			set003 = append(set003, asStr(m["message"]))
		}
	}
	return
}

func TestLintLimitsRule(t *testing.T) {
	back := []any{obj{"name": "a", "port": 80}}
	direct := obj{builtin.DirectResponseKey: obj{"status": 404}}
	if got, no := limitsFindings(t, nil, []any{direct}, nil); len(got) != 0 || len(no) != 0 {
		t.Errorf("a direct-response rule is clean and needs no backend: %v %v", got, no)
	}
	if got, no := limitsFindings(t, nil, []any{obj{}}, obj{builtin.DirectResponseKey + ".rule-1": `{"status":403}`}); len(got) != 0 || len(no) != 0 {
		t.Errorf("annotation direct response: %v %v", got, no)
	}
	if _, no := limitsFindings(t, nil, []any{obj{}}, nil); len(no) != 1 {
		t.Errorf("SET003 must still fire for an empty rule: %v", no)
	}
	cases := map[string]struct {
		rules []any
		ann   obj
		want  string
	}{
		"bad status":     {[]any{obj{builtin.DirectResponseKey: obj{"status": 99}}}, nil, "status 99"},
		"backend clash":  {[]any{obj{builtin.DirectResponseKey: obj{"status": 404}, "backendRefs": back}}, nil, "no backendRefs"},
		"redirect clash": {[]any{obj{builtin.DirectResponseKey: obj{"status": 404}, "filters": []any{obj{"type": "RequestRedirect"}}}}, nil, "RequestRedirect"},
		"bad rate":       {[]any{obj{builtin.RateLimitKey: obj{"rate": "fast"}, "backendRefs": back}}, nil, "rate"},
		"bad key":        {[]any{obj{builtin.RateLimitKey: obj{"rate": "1/s", "key": "cookie"}, "backendRefs": back}}, nil, "key"},
		"bad limits":     {[]any{obj{builtin.LimitsKey: obj{"maxRequestBody": "lots"}, "backendRefs": back}}, nil, "maxRequestBody"},
		"bad annotation": {[]any{obj{"backendRefs": back}}, obj{builtin.RateLimitKey: "{"}, "annotation"},
		"orphan":         {[]any{obj{"backendRefs": back}}, obj{builtin.LimitsKey + ".rule-5": `{"maxRequestBody":"1"}`}, "names no rule"},
	}
	for name, c := range cases {
		got, _ := limitsFindings(t, nil, c.rules, c.ann)
		if len(got) == 0 || !strings.Contains(strings.Join(got, "|"), c.want) {
			t.Errorf("%s: want a SET030 finding with %q, got %v", name, c.want, got)
		}
	}
	good := []any{obj{builtin.RateLimitKey: obj{"rate": "10/s", "burst": 5, "key": "header:X-Id"}, builtin.LimitsKey: obj{"maxRequestBody": "1MB", "streamIdleTimeout": "30s"}, "backendRefs": back}}
	if got, _ := limitsFindings(t, nil, good, nil); len(got) != 0 {
		t.Errorf("valid blocks: %v", got)
	}
	for name, l := range map[string]obj{
		"tls order":    {"protocol": "HTTPS", "tls": obj{"options": obj{builtin.TLSMinVersionOption: "1.3", builtin.TLSMaxVersionOption: "1.2"}}},
		"tls version":  {"protocol": "HTTPS", "tls": obj{"options": obj{builtin.TLSMinVersionOption: "1.1"}}},
		"listener lim": {builtin.LimitsKey: obj{"maxRequestBody": "x"}},
	} {
		if got, _ := limitsFindings(t, l, []any{obj{"backendRefs": back}}, nil); len(got) == 0 {
			t.Errorf("%s: no SET030 finding", name)
		}
	}
}

func TestWhyDirectResponseCLI(t *testing.T) {
	cfg := `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
	 "gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"x","listeners":[{"name":"web","protocol":"HTTP","port":8080}]},
	 "httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["a.test"],"rules":[
	  {"matches":[{"path":{"type":"PathPrefix","value":"/internal"}}],"setura.zyvor.dev/direct-response":{"status":403,"body":"blocked","headers":{"X-Blocked":"1"}}},
	  {"backendRefs":[{"name":"v1","port":80}]}]}},
	 "backends":{"v1":"127.0.0.1:1"}}`
	path := filepath.Join(t.TempDir(), "gw.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Main(args, &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, errs := run("why", "GET", "http://a.test:8080/internal/x", "--config", path, "--ascii")
	if code != 0 || !strings.Contains(out, "Direct response") || !strings.Contains(out, "403") || !strings.Contains(out, "X-Blocked") || !strings.Contains(out, "Answered directly") {
		t.Fatalf("pretty (code %d, %s)\n%s", code, errs, out)
	}
	code, out, _ = run("why", "GET", "http://a.test:8080/internal/x", "--config", path, "--format", "json")
	var tr builtin.Trace
	if err := json.Unmarshal([]byte(out), &tr); err != nil || code != 0 || tr.Verdict != builtin.VerdictDirect || tr.Winner.Direct.Status != 403 {
		t.Fatalf("json: %v code %d verdict %q", err, code, tr.Verdict)
	}
	code, out, _ = run("why", "GET", "http://a.test:8080/x/../internal", "--config", path, "--normalize-path", "--format", "json")
	json.Unmarshal([]byte(out), &tr)
	if code != 0 || tr.Verdict != builtin.VerdictDirect || tr.NormalizedPath != "/internal" {
		t.Errorf("--normalize-path: code %d verdict %q path %q", code, tr.Verdict, tr.NormalizedPath)
	}
	if code, _, _ = run("why", "GET", "http://a.test:8080/a%2Fb", "--config", path, "--reject-escaped-slashes"); code != 1 {
		t.Errorf("--reject-escaped-slashes: code %d, want 1", code)
	}
}
