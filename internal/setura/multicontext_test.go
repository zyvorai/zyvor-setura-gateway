package setura

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ctxCluster fakes kubectl per context. Contexts listed in broken fail;
// routes maps a context to the HTTPRoute specs it serves.
func ctxCluster(routes map[string][]obj, broken ...string) *Cluster {
	var mu sync.Mutex
	return &Cluster{Exec: func(args []string) (string, string, int, error) {
		mu.Lock()
		defer mu.Unlock()
		cmd := strings.Join(args, " ")
		if strings.Contains(cmd, "config get-contexts") {
			return "alpha\nbeta\n", "", 0, nil
		}
		ctx := ""
		for i, a := range args {
			if a == "--context" && i+1 < len(args) {
				ctx = args[i+1]
			}
		}
		for _, b := range broken {
			if ctx == b {
				return "", "Unable to connect to the server", 1, nil
			}
		}
		items := []any{}
		if strings.Contains(cmd, "get httproutes") {
			for i, spec := range routes[ctx] {
				items = append(items, obj{"metadata": obj{"name": "r" + string(rune('0'+i))}, "spec": spec})
			}
		}
		return mustJSON(obj{"items": items}), "", 0, nil
	}}
}

func decodeOut(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return v
}

func TestMultiContextSnapshotMergesPerContext(t *testing.T) {
	code, out, errs := cli(t, ctxCluster(nil), "--context", "alpha,beta", "snapshot", "-n", "demo")
	is(t, code, 0)
	list := asList(asMap(decodeOut(t, out))["contexts"])
	is(t, len(list), 2)
	is(t, asMap(list[0])["context"], "alpha")
	is(t, asMap(list[1])["context"], "beta")
	is(t, asMap(asMap(list[0])["snapshot"])["schema"], snapshotSchema)
	is(t, errs, "")
}

func TestMultiContextOneUnreachableExits2(t *testing.T) {
	code, out, errs := cli(t, ctxCluster(nil, "beta"), "snapshot", "--context", "alpha,beta")
	is(t, code, 2)
	list := asList(asMap(decodeOut(t, out))["contexts"])
	is(t, asMap(list[0])["context"], "alpha")
	is(t, asMap(list[1])["error"], "Unable to connect to the server")
	contains(t, errs, "context beta")
}

func TestAllContextsListsFromKubectl(t *testing.T) {
	code, out, _ := cli(t, ctxCluster(nil), "--all-contexts", "snapshot")
	is(t, code, 0)
	is(t, len(asList(asMap(decodeOut(t, out))["contexts"])), 2)
}

func TestMultiContextLintFindingsCarryContext(t *testing.T) {
	// A route with no parentRefs is a finding
	// in the context that has it, and only there.
	bad := obj{"parentRefs": []any{}, "rules": []any{}}
	c := ctxCluster(map[string][]obj{"beta": {bad}})
	code, out, _ := cli(t, c, "--context", "alpha,beta", "lint", "-n", "demo", "--format", "json")
	m := asMap(decodeOut(t, out))
	findings := asList(m["findings"])
	if len(findings) == 0 {
		t.Fatalf("expected findings: %s", out)
	}
	for _, f := range findings {
		is(t, asMap(f)["context"], "beta")
	}
	ctxs := asList(m["contexts"])
	is(t, len(ctxs), 2)
	is(t, asMap(ctxs[0])["context"], "alpha")
	is(t, asMap(ctxs[0])["ok"], true)
	want := 0
	if m["ok"] != true {
		want = 1
	}
	is(t, code, want)
}

func TestMultiContextLintTextHasContextColumn(t *testing.T) {
	bad := obj{"parentRefs": []any{}, "rules": []any{}}
	_, out, _ := cli(t, ctxCluster(map[string][]obj{"beta": {bad}}), "lint", "--context", "alpha,beta")
	contains(t, out, "alpha")
	contains(t, out, "beta")
	contains(t, out, "error(s)")
}

func TestMultiContextCheckSubstitutesContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/alpha" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "checks.json")
	os.WriteFile(file, []byte(`[{"url":"`+srv.URL+`/{context}"}]`), 0o600)

	code, out, _ := cli(t, ctxCluster(nil), "check", file, "--context", "alpha,beta", "--format", "json")
	is(t, code, 1)
	rows := asList(decodeOut(t, out))
	is(t, len(rows), 2)
	is(t, asMap(rows[0])["context"], "alpha")
	is(t, asMap(rows[0])["ok"], true)
	is(t, asMap(rows[1])["context"], "beta")
	is(t, asMap(rows[1])["ok"], false)
	contains(t, asMap(rows[1])["url"].(string), "/beta")

	_, out, _ = cli(t, ctxCluster(nil), "check", file, "--context", "alpha,beta", "--format", "pretty")
	contains(t, out, "CONTEXT")
	contains(t, out, "fail")
}

func TestSingleContextOutputUnchanged(t *testing.T) {
	code, out, _ := cli(t, ctxCluster(nil), "--context", "alpha", "snapshot")
	is(t, code, 0)
	m := asMap(decodeOut(t, out))
	is(t, m["schema"], snapshotSchema)
	_, has := m["contexts"]
	is(t, has, false)
}

func TestMultiContextRejections(t *testing.T) {
	c := ctxCluster(nil)
	for _, args := range [][]string{
		{"--context", "a,b", "doctor"},
		{"--context", "a,b", "inspect", "orders"},
		{"--all-contexts", "--context", "a", "snapshot"},
		{"--context", "a,,b", "snapshot"},
		{"check", "x.json", "--context", "a,b", "--junit", "o.xml"},
		{"lint", "--context", "a,b", "--format", "sarif"},
		{"lint", "--context", "a,b", "--snapshot", "s.json"},
	} {
		code, _, _ := cli(t, c, args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestMultiContextGateMerges(t *testing.T) {
	url := fixture(t, nil)
	var mu sync.Mutex
	c := &Cluster{Exec: func(args []string) (string, string, int, error) {
		mu.Lock()
		defer mu.Unlock()
		for i, a := range args {
			if a == "--context" && args[i+1] == "beta" {
				return "", "boom", 1, nil
			}
		}
		return mustJSON(routeObj(1, 1)), "", 0, nil
	}}
	code, out, _ := cli(t, c, "gate", "orders", url, "--context", "alpha,beta", "-n", "demo", "--gateway", "dev",
		"--listener", "web", "--backend", "orders-v1", "--address", "127.0.0.1", "--interval", "0")
	is(t, code, 2)
	m := asMap(decodeOut(t, out))
	is(t, m["ok"], false)
	list := asList(m["contexts"])
	is(t, asMap(list[0])["context"], "alpha")
	is(t, asMap(list[0])["ok"], true)
	is(t, asMap(list[1])["error"], "boom")
}
