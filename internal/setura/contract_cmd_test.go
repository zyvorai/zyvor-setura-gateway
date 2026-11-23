package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-setura-gateway/internal/contract"
)

func runContractCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(append([]string{"--color", "never", "--ascii", "contract"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

const cliSpec = `openapi: 3.0.3
info:
  title: Orders
  version: "1"
paths:
  /orders:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json: {}
  /orders/{orderId}:
    get:
      responses:
        "200":
          description: ok
  /legacy:
    get:
      responses:
        "200":
          description: ok
`

func accessLog(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	line := func(ts, method, path string, status int, route string, prot bool) {
		fmt.Fprintf(&b, `{"time":%q,"method":%q,"path":%q,"status":%d,"route":%q,"backend":"t/a:80","duration_ms":12.5,"response_bytes":300,"auth_protected":%v}`+"\n", ts, method, path, status, route, prot)
	}
	line("2026-03-01T10:00:00Z", "GET", "/orders", 200, "orders", true)
	line("2026-03-01T10:00:01Z", "GET", "/orders/17?expand=items", 200, "orders", true)
	line("2026-03-02T10:00:01Z", "GET", "/orders/18", 500, "orders", true)
	line("2026-03-02T10:00:02Z", "GET", "/orders/export", 200, "orders", false)
	line("2026-03-03T10:00:03Z", "GET", "/admin/debug", 200, "admin", false)
	b.WriteString(`{"time":"2026-03-03T10:00:04Z","method":"GET","path":"/nope","status":404}` + "\n") // no route: skipped
	b.WriteString("not a log line\n")
	p := filepath.Join(t.TempDir(), "access.jsonl")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestContractCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.json")
	spec := filepath.Join(dir, "spec.yaml")
	os.WriteFile(spec, []byte(cliSpec), 0o600)

	code, out, errs := runContractCLI(t, "learn", "--log", accessLog(t), "--out", inv)
	if code != 0 || !strings.Contains(out, "Learned 4 endpoints from 5 of 7 log lines") {
		t.Fatalf("learn: %d %q %q", code, out, errs)
	}
	d, err := contract.ReadDoc(inv)
	if err != nil || len(d.Endpoints) != 4 {
		t.Fatalf("inventory: %v %+v", err, d)
	}
	if e := d.Endpoints[3]; e.Key() != "GET /orders/{id}" || e.Query[0] != "expand" || e.Count != 2 || e.Latency.P50 != 12.5 {
		t.Fatalf("endpoint %+v", e)
	}
	// learning again resumes the file
	if code, _, _ = runContractCLI(t, "learn", "--log", accessLog(t), "--out", inv); code != 0 {
		t.Fatal(code)
	}
	if d2, _ := contract.ReadDoc(inv); d2.Requests != 10 {
		t.Errorf("merged requests %d", d2.Requests)
	}

	code, out, _ = runContractCLI(t, "show", "--learned", inv)
	if code != 0 || !strings.Contains(out, "GET /orders/{id}") || !strings.Contains(out, "4 endpoints") {
		t.Fatalf("show: %d %s", code, out)
	}

	code, out, _ = runContractCLI(t, "export", "--learned", inv, "--title", "Orders", "--server", "https://x.test")
	var doc map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc["openapi"] != "3.1.0" || !strings.Contains(out, "/orders/{orderId}") || !strings.Contains(out, "x-setura-observed") {
		t.Fatalf("export: %d %s", code, out)
	}
	exp := filepath.Join(dir, "observed.json")
	if code, _, _ = runContractCLI(t, "export", "--learned", inv, "--out", exp); code != 0 {
		t.Fatal(code)
	}
	if _, err := contract.LoadSpecFile(exp); err != nil {
		t.Errorf("exported document is not loadable: %v", err)
	}

	// diff: table, exit 0 without --fail-on
	code, out, _ = runContractCLI(t, "diff", "--spec", spec, "--learned", inv, "--limit", "0")
	if code != 0 {
		t.Fatalf("diff exit %d", code)
	}
	for _, w := range []string{"Shadow APIs", "GET /admin/debug", "Zombie APIs", "GET /legacy", "Drift", "500 (", "Auth gaps", "GET /orders/export"} {
		if !strings.Contains(out, w) {
			t.Errorf("diff table missing %q:\n%s", w, out)
		}
	}
	for fo, want := range map[string]int{"shadow": 1, "zombie": 1, "drift": 1, "auth": 1, "any": 1, "": 0} {
		args := []string{"diff", "--spec", spec, "--learned", inv}
		if fo != "" {
			args = append(args, "--fail-on", fo)
		}
		if code, _, _ := runContractCLI(t, args...); code != want {
			t.Errorf("--fail-on %q: exit %d", fo, code)
		}
	}
	// drift only: ignoring the one undocumented status makes drift exit 0
	if code, _, _ := runContractCLI(t, "diff", "--spec", spec, "--learned", inv, "--fail-on", "drift", "--ignore-status", "500"); code != 0 {
		t.Errorf("ignored status still fails: %d", code)
	}
	code, out, _ = runContractCLI(t, "diff", "--spec", spec, "--learned", inv, "--format", "json")
	var rep contract.Report
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.Schema != contract.DiffSchema || rep.Counts["shadow"] != 1 {
		t.Fatalf("json: %d %s", code, out)
	}
	code, out, _ = runContractCLI(t, "diff", "--spec", spec, "--learned", inv, "--format", "markdown", "--fail-on", "shadow")
	if code != 1 || !strings.Contains(out, "## API contract check") || !strings.Contains(out, "| `GET /admin/debug` |") {
		t.Fatalf("markdown: %d %s", code, out)
	}
}

func TestContractCLIUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no subcommand":   {},
		"unknown":         {"frobnicate"},
		"diff needs spec": {"diff", "--learned", "x"},
		"bad fail-on":     {"diff", "--spec", "s", "--fail-on", "bogus"},
		"bad format":      {"show", "--format", "xml"},
		"markdown show":   {"show", "--format", "markdown"},
		"both sources":    {"show", "--learned", "a", "--admin", "b"},
		"learn needs out": {"learn", "--log", "x"},
		"enable+log":      {"learn", "--log", "x", "--enable"},
	} {
		if code, _, errs := runContractCLI(t, args...); code != 2 || !strings.Contains(errs, "setura contract") {
			t.Errorf("%s: exit %d %q", name, code, errs)
		}
	}
	if code, _, errs := runContractCLI(t, "diff", "--spec", filepath.Join(t.TempDir(), "none.json"), "--learned", "none"); code != 2 {
		t.Errorf("missing files: %d %s", code, errs)
	}
}

func TestContractCLIAdmin(t *testing.T) {
	l := contract.NewLearner(0)
	l.Enable(true)
	l.Record(contract.Obs{Method: "GET", Path: "/a/1", Status: 200, ReqBytes: -1, RespBytes: 1, Latency: -1})
	var toggled string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/contract":
			json.NewEncoder(w).Encode(l.Snapshot())
		case "/contract/learn":
			toggled = r.Method + " " + r.URL.RawQuery
			fmt.Fprint(w, `{"enabled":true,"endpoints":1,"requests":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if code, out, _ := runContractCLI(t, "show", "--admin", addr, "--format", "json"); code != 0 || !strings.Contains(out, "/a/{id}") {
		t.Fatalf("show --admin: %d %s", code, out)
	}
	if code, out, _ := runContractCLI(t, "learn", "--admin", addr, "--enable"); code != 0 || toggled != "POST enabled=true" || !strings.Contains(out, "learning is on") {
		t.Fatalf("enable: %d %q %q", code, toggled, out)
	}
	out := filepath.Join(t.TempDir(), "saved.json")
	if code, _, _ := runContractCLI(t, "learn", "--admin", addr, "--out", out); code != 0 {
		t.Fatal(code)
	}
	if d, err := contract.ReadDoc(out); err != nil || len(d.Endpoints) != 1 {
		t.Fatalf("saved: %v", err)
	}
	if code, _, errs := runContractCLI(t, "show", "--admin", "127.0.0.1:1"); code == 0 || !strings.Contains(errs, "cannot reach") {
		t.Errorf("unreachable: %d %s", code, errs)
	}
}

func TestContractCompletionAndHelp(t *testing.T) {
	var b bytes.Buffer
	for _, sh := range []string{"bash", "zsh", "fish"} {
		b.Reset()
		if err := Completion(sh, &b); err != nil || !strings.Contains(b.String(), "contract") || !strings.Contains(b.String(), "fail-on") && sh == "fish" {
			t.Errorf("%s completion: %v", sh, err)
		}
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"contract", "-h"}, &out, &errb); code != 0 || !strings.Contains(errb.String()+out.String(), "--fail-on") {
		t.Errorf("help: %d %q", code, errb.String())
	}
	for _, f := range []string{"--learn", "--contract-spec", "--contract-enforce"} {
		found := false
		for _, g := range gatewayFlags {
			found = found || g == f
		}
		if !found {
			t.Errorf("gateway completion lacks %s", f)
		}
	}
}
