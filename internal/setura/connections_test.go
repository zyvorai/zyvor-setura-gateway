package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func connFixture(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	rec := func(id int, status int, route, ip string) map[string]any {
		return map[string]any{"id": id, "client_ip": ip, "client_port": 50000 + id, "listener_port": 8080, "protocol": "HTTP/1.1", "route": "HTTPRoute/t/" + route,
			"upstream_addr": "10.0.0.7:9000", "status": status, "duration_ms": 12.5, "path": "/x"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" {
			http.NotFound(w, r)
			return
		}
		n := 0
		if calls != nil {
			n = int(calls.Add(1))
		}
		doc := map[string]any{"enabled": true, "capacity": 500, "latest": 3,
			"history": []any{rec(3, 502, "orders", "10.1.1.1"), rec(2, 200, "orders", "10.1.1.2"), rec(1, 404, "web", "10.1.1.1")},
			"open":    []any{map[string]any{"id": 1, "age_ms": 65000, "client_ip": "10.1.1.9", "client_port": 4000, "listener_port": 8443, "protocol": "TLS-passthrough", "route": "TLSRoute/t/db", "upstream_addr": "10.0.0.8:5432", "bytes_in": 2048, "bytes_out": 1 << 20}}}
		if r.URL.Query().Get("since") != "" { // follow polls: one new record on the first call
			doc["history"] = []any{}
			if n == 2 {
				doc["history"] = []any{rec(4, 500, "orders", "10.1.1.3")}
				doc["latest"] = 4
			}
		}
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectionsJSONWhenPiped(t *testing.T) {
	srv := connFixture(t, nil)
	code, out, errs := cli(t, nil, "connections", "--admin", strings.TrimPrefix(srv.URL, "http://"))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var d connDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil || len(d.History) != 3 || len(d.Open) != 1 {
		t.Fatalf("not the connections document: %v %s", err, out)
	}
}

func TestConnectionsTableAndFilters(t *testing.T) {
	srv := connFixture(t, nil)
	admin := strings.TrimPrefix(srv.URL, "http://")
	code, out, errs := cli(t, nil, "--color", "never", "connections", "--admin", admin, "--format", "table")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"CLIENT", "LISTENER", "PROTO", "ROUTE", "UPSTREAM", "STATUS", "MS", "10.1.1.1:50003", ":8080", "t/orders", "10.0.0.7:9000", "502", "13 ms",
		"open 1m05s", "TLS-passthrough", "2.0K/1.0M", ":8443"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour with --color never")
	}
	// Oldest first, so the newest row is last.
	if strings.Index(out, "50001") > strings.Index(out, "50003") {
		t.Errorf("rows not oldest first:\n%s", out)
	}
	for _, tc := range []struct {
		filter  string
		want    []string
		missing []string
	}{
		{"status=5xx", []string{"502"}, []string{" 200 ", " 404 "}},
		{"status=404", []string{"404"}, []string{"502"}},
		{"route=orders", []string{"502", "200"}, []string{"404"}},
		{"client=10.1.1.2", []string{"200"}, []string{"502", "404"}},
		{"protocol=passthrough", []string{"TLS-passthrough"}, []string{"502"}},
	} {
		_, out, _ := cli(t, nil, "--color", "never", "connections", "--admin", admin, "--format", "table", "--filter", tc.filter)
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("--filter %s lacks %q:\n%s", tc.filter, w, out)
			}
		}
		for _, w := range tc.missing {
			if strings.Contains(out, w) {
				t.Errorf("--filter %s still has %q:\n%s", tc.filter, w, out)
			}
		}
	}
}

func TestConnectionsErrors(t *testing.T) {
	srv := connFixture(t, nil)
	admin := strings.TrimPrefix(srv.URL, "http://")
	for _, args := range [][]string{
		{"connections", "--format", "xml"},
		{"connections", "--filter", "nonsense"},
		{"connections", "--admin", "not-an-address"},
		{"connections", "--limit", "0"},
		{"connections", "extra"},
	} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v -> %d, want 2", args, code)
		}
	}
	srv.Close()
	if code, _, errs := cli(t, nil, "connections", "--admin", admin); code == 0 || !strings.Contains(errs, "cannot reach") {
		t.Errorf("closed server -> %d %q", code, errs)
	}
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"enabled":false,"history":[],"open":[]}`)
	}))
	defer off.Close()
	if code, _, errs := cli(t, nil, "connections", "--admin", strings.TrimPrefix(off.URL, "http://")); code == 0 || !strings.Contains(errs, "--conn-history") {
		t.Errorf("disabled history -> %d %q", code, errs)
	}
}

func TestConnectionsFollow(t *testing.T) {
	var calls atomic.Int32
	srv := connFixture(t, &calls)
	for _, table := range []bool{false, true} {
		calls.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		var out bytes.Buffer
		code, err := connectionsRun(ctx, srv.Client(), strings.TrimPrefix(srv.URL, "http://"), 50, true, table, nil, 100*time.Millisecond, &out, newUI(false, termOptions{Color: "never"}, func(string) string { return "" }))
		cancel()
		if code != 0 || err != nil {
			t.Fatalf("follow: %d %v", code, err)
		}
		s := out.String()
		if table {
			if strings.Count(s, "CLIENT") != 1 || !strings.Contains(s, "500") || !strings.Contains(s, "50004") {
				t.Errorf("table follow:\n%s", s)
			}
		} else {
			if !strings.Contains(s, `"id":4`) || strings.Count(s, `"id":3`) != 1 || !strings.Contains(s, `"open":`) {
				t.Errorf("json follow (one object per line):\n%s", s)
			}
			for _, ln := range strings.Split(strings.TrimSpace(s), "\n") {
				var v map[string]any
				if err := json.Unmarshal([]byte(ln), &v); err != nil {
					t.Errorf("line is not JSON: %q", ln)
				}
			}
		}
	}
}

func TestConnectionsInHelpManAndCompletion(t *testing.T) {
	if _, ok := commandSummary("connections"); !ok {
		t.Fatal("not in help")
	}
	var man, comp bytes.Buffer
	Man(&man)
	if !strings.Contains(man.String(), "connections") {
		t.Error("man page lacks connections")
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		comp.Reset()
		Completion(sh, &comp)
		if !strings.Contains(comp.String(), "connections") || !strings.Contains(comp.String(), "follow") {
			t.Errorf("%s completion lacks connections flags", sh)
		}
	}
	code, _, errs := cli(t, nil, "connections", "-h")
	if code != 0 || !strings.Contains(errs, "--filter") && !strings.Contains(errs, "-filter") {
		t.Errorf("help: %d %q", code, errs)
	}
}
