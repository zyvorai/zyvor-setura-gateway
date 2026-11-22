package setura

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakeShadowAdmin(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/shadow" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

const shadowDoc = `{"schema":"setura.shadow/v1","sampled":1000,"compared":1000,"matched":992,"mismatched":8,"errors":0,"dropped":3,
 "byCategory":{"status":1,"header":2,"body":5,"latency":0},"matchRate":99.2,"p50DeltaMs":1.5,"p95DeltaMs":9,
 "routes":{"t/r":{"sampled":1000,"compared":1000,"matched":992,"mismatched":8,"errors":0,"dropped":3,"byCategory":{},"matchRate":99.2,"p50DeltaMs":1.5,"p95DeltaMs":9}},
 "recent":[{"time":"2026-11-22T10:00:00Z","route":"t/r","category":"body","method":"GET","path":"/a","detail":{"where":"$.a.b","primary":"1","shadow":"2"},
 "primary":{"backend":"a","status":200,"ms":1},"shadow":{"backend":"b","status":200,"ms":2},"deltaMs":1}]}`

func TestShadowCommand(t *testing.T) {
	addr := fakeShadowAdmin(t, shadowDoc)
	code, out, errs := cli(t, nil, "shadow", "--admin", addr)
	if code != 0 || !strings.Contains(out, "99.2% match over 1000 requests") || !strings.Contains(out, "$.a.b") || !strings.Contains(out, "t/r") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, out, _ = cli(t, nil, "shadow", "--admin", "http://"+addr, "--format", "json")
	if code != 0 || !strings.Contains(out, `"matchRate": 99.2`) {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errs = cli(t, nil, "shadow", "--admin", addr, "--fail-under", "99.5"); code != 1 || !strings.Contains(errs, "under --fail-under") {
		t.Fatalf("gate: %d %q", code, errs)
	}
	if code, _, _ = cli(t, nil, "shadow", "--admin", addr, "--fail-under", "99"); code != 0 {
		t.Fatalf("gate should pass: %d", code)
	}
}

func TestShadowCommandNoData(t *testing.T) {
	addr := fakeShadowAdmin(t, `{"schema":"setura.shadow/v1","compared":0,"byCategory":{},"routes":{},"recent":[]}`)
	if code, out, _ := cli(t, nil, "shadow", "--admin", addr); code != 0 || !strings.Contains(out, "no compared requests") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errs := cli(t, nil, "shadow", "--admin", addr, "--fail-under", "99"); code != 1 || !strings.Contains(errs, "no compared requests") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestShadowCommandErrors(t *testing.T) {
	for _, args := range [][]string{{"shadow", "extra"}, {"shadow", "--format", "xml"}, {"shadow", "--fail-under", "101"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if code, _, errs := cli(t, nil, "shadow", "--admin", "127.0.0.1:1"); code != 2 || !strings.Contains(errs, "cannot reach") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestShadowFollow(t *testing.T) {
	addr := fakeShadowAdmin(t, shadowDoc)
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	code := shadowRun(ctx, addr, true, "table", 99, 100*time.Millisecond, &out, &errb, newUI(false, termOptions{}, func(string) string { return "" }))
	if code != 0 || !strings.Contains(out.String(), "99.2% match") {
		t.Fatalf("%d %q %q", code, out.String(), errb.String())
	}
}
