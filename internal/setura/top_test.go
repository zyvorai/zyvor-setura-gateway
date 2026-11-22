package setura

import (
	"bytes"
	"context"
	"flag"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

var updateTop = flag.Bool("update-top", false, "rewrite testdata/top golden frames")

var asciiUI = newUI(false, termOptions{Color: "never", ASCII: true}, func(string) string { return "" })

func topGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "top", name+".txt")
	if *updateTop {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(got+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update-top): %v", p, err)
	}
	if got+"\n" != string(want) {
		t.Fatalf("golden %s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func fixtureHist(counts ...float64) topHist {
	le := append(append([]float64{}, builtin.LatencyBuckets...), math.Inf(1))
	h := topHist{le: le, cum: make([]float64, len(le))}
	run := 0.0
	for i := range le {
		if i < len(counts) {
			run += counts[i]
		}
		h.cum[i] = run
	}
	return h
}

func fixtureScrapes() (*topScrape, *topScrape) {
	t0 := time.Unix(1000, 0)
	prev := &topScrape{at: t0, total: 100, routes: map[string]topCounter{
		"HTTPRoute/demo/orders":  {Requests: 80, Status: map[string]int64{"2xx": 80}},
		"HTTPRoute/demo/billing": {Requests: 20, Status: map[string]int64{"2xx": 20}},
	}, backends: map[string]topCounter{
		"orders-v1:80":  {Requests: 80, Status: map[string]int64{"2xx": 80}},
		"billing-v1:80": {Requests: 20, Status: map[string]int64{"2xx": 20}},
	}, routeH: map[string]topHist{
		"HTTPRoute/demo/orders":  fixtureHist(80),
		"HTTPRoute/demo/billing": fixtureHist(20),
	}, backendH: map[string]topHist{
		"orders-v1:80":  fixtureHist(80),
		"billing-v1:80": fixtureHist(20),
	}}
	cur := &topScrape{at: t0.Add(2 * time.Second), total: 140, gen: 3, open: 2,
		routes: map[string]topCounter{
			"HTTPRoute/demo/orders":  {Requests: 110, Status: map[string]int64{"2xx": 100, "5xx": 10}},
			"HTTPRoute/demo/billing": {Requests: 30, Status: map[string]int64{"2xx": 30}},
		}, backends: map[string]topCounter{
			"orders-v1:80":  {Requests: 110, Status: map[string]int64{"2xx": 100, "5xx": 10}},
			"billing-v1:80": {Requests: 30, Status: map[string]int64{"2xx": 30}},
		}, routeH: map[string]topHist{
			"HTTPRoute/demo/orders":  fixtureHist(80, 0, 0, 20, 10),
			"HTTPRoute/demo/billing": fixtureHist(20, 0, 10),
		}, backendH: map[string]topHist{
			"orders-v1:80":  fixtureHist(80, 0, 0, 20, 10),
			"billing-v1:80": fixtureHist(20, 0, 10),
		},
		eps:  []topEP{{"orders-v1:80", "127.0.0.1:19101", true, false}, {"orders-v1:80", "127.0.0.1:19102", false, true}},
		errs: []topErr{{Time: "2026-01-02T03:04:05Z", Status: 502, Method: "GET", Path: "/checkout", Route: "HTTPRoute/demo/orders", Backend: "orders-v1:80", Error: "connection refused"}},
	}
	return prev, cur
}

func TestTopQuantile(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    topHist
		q    float64
		want float64
	}{
		{"empty", topHist{}, .5, -1},
		{"zero total", fixtureHist(), .5, -1},
		{"all in first bucket", fixtureHist(10), .5, 2.5},
		{"p95 of two buckets", fixtureHist(50, 50), .95, 9.5},
		{"midpoint second bucket", fixtureHist(0, 10), .5, 7.5},
		{"overflow clamps to last finite bound", fixtureHist(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10), .5, 10000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := quantile(tc.h, tc.q); math.Abs(got-tc.want) > 1e-6 {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestTopWindowPercentiles(t *testing.T) {
	prev, cur := fixtureScrapes()
	m := buildTopModel("x:1", prev, cur)
	if !m.HaveRate || math.Abs(m.Rate-20) > 1e-9 {
		t.Fatalf("rate %v have %v", m.Rate, m.HaveRate)
	}
	if m.Routes[0].Name != "HTTPRoute/demo/orders" || math.Abs(m.Routes[0].Rate-15) > 1e-9 {
		t.Fatalf("routes %+v", m.Routes)
	}
	if got := m.Routes[0].ErrPct; math.Abs(got-100.0/3) > 1e-6 {
		t.Fatalf("window error %% %v", got)
	}
	// the window holds 20 requests in (0.025,0.05] and 10 in (0.05,0.1]; lifetime would differ
	if p := m.Routes[0].P50; p < 25 || p > 50 {
		t.Fatalf("windowed p50 %v", p)
	}
	// no new samples: fall back to lifetime
	same := *cur
	same.at = cur.at.Add(time.Second)
	m2 := buildTopModel("x:1", cur, &same)
	if m2.Rate != 0 || m2.Routes[0].P95 < 0 {
		t.Fatalf("expected lifetime fallback, got %+v", m2.Routes[0])
	}
	// one sample: totals only
	m3 := buildTopModel("x:1", nil, cur)
	if m3.HaveRate || m3.Routes[0].Rate != -1 || m3.Routes[0].ErrPct < 9 {
		t.Fatalf("single sample %+v", m3.Routes[0])
	}
}

func TestTopParseProm(t *testing.T) {
	text := `# HELP x
setura_gateway_request_duration_seconds_bucket{route="HTTPRoute/demo/orders",le="0.005"} 3
setura_gateway_request_duration_seconds_bucket{route="HTTPRoute/demo/orders",le="+Inf"} 5
setura_gateway_backend_request_duration_seconds_bucket{backend="b\"q:80",le="0.005"} 1
setura_gateway_backend_request_duration_seconds_bucket{backend="b\"q:80",le="+Inf"} 2
setura_gateway_endpoint_healthy{backend="a:80",endpoint="h:1"} 0
setura_gateway_endpoint_ejected{backend="a:80",endpoint="h:1"} 1
unrelated 1
`
	r, b, eps := parseProm(text)
	if h := r["HTTPRoute/demo/orders"]; len(h.cum) != 2 || h.cum[1] != 5 || !math.IsInf(h.le[1], 1) {
		t.Fatalf("route hist %+v", h)
	}
	if _, ok := b[`b"q:80`]; !ok {
		t.Fatalf("escaped label lost: %v", b)
	}
	if len(eps) != 1 || eps[0].Healthy || !eps[0].Ejected {
		t.Fatalf("eps %+v", eps)
	}
}

func TestTopKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		n    int
		want topState
	}{
		{"down stops at end", []string{"j", "j", "j", "down"}, 3, topState{Sel: 2}},
		{"up stops at 0", []string{"k", "up"}, 3, topState{}},
		{"enter then esc", []string{"enter", "esc"}, 2, topState{}},
		{"enter opens", []string{"j", "enter"}, 2, topState{Sel: 1, Detail: true}},
		{"enter toggles", []string{"enter", "enter"}, 2, topState{}},
		{"pause", []string{"p"}, 2, topState{Paused: true}},
		{"quit", []string{"q"}, 2, topState{Quit: true}},
		{"ctrl-c", []string{"ctrl-c"}, 2, topState{Quit: true}},
		{"no rows no detail", []string{"enter"}, 0, topState{}},
		{"backspace leaves detail", []string{"enter", "backspace"}, 2, topState{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var st topState
			for _, k := range tc.in {
				st = topKey(st, k, tc.n)
			}
			if st != tc.want {
				t.Fatalf("got %+v want %+v", st, tc.want)
			}
		})
	}
	for in, want := range map[string]string{"\x1b": "esc", "\x1b[A": "up", "\x1b[B": "down", "q": "q", "\r": "enter", "\x7f": "backspace", "\x03": "ctrl-c"} {
		if got := topKeys([]byte(in)); len(got) != 1 || got[0] != want {
			t.Fatalf("keys(%q)=%v want %s", in, got, want)
		}
	}
}

func TestTopFrames(t *testing.T) {
	prev, cur := fixtureScrapes()
	live := buildTopModel("127.0.0.1:19000", prev, cur)
	live.Interval = time.Second
	quiet := buildTopModel("127.0.0.1:19000", &topScrape{at: prev.at, routes: map[string]topCounter{}}, &topScrape{at: cur.at, routes: map[string]topCounter{}})
	quiet.Interval = time.Second
	down := &topModel{Admin: "127.0.0.1:19000", Err: "Cannot reach the gateway admin endpoint at 127.0.0.1:19000", Hint: "start the gateway."}
	single := buildTopModel("127.0.0.1:19000", nil, cur)
	for _, tc := range []struct {
		name string
		m    *topModel
		st   topState
		u    *ui
		w, h int
	}{
		{"plain", live, topState{Sel: 1}, plainUI, 100, 40},
		{"ascii", live, topState{}, asciiUI, 100, 40},
		{"narrow", live, topState{}, plainUI, 60, 40},
		{"short", live, topState{}, plainUI, 100, 12},
		{"empty", quiet, topState{}, plainUI, 100, 30},
		{"error", down, topState{}, plainUI, 100, 30},
		{"detail_route", live, topState{Sel: 0, Detail: true}, plainUI, 100, 40},
		{"detail_backend", live, topState{Sel: 2, Detail: true}, plainUI, 100, 40},
		{"paused", live, topState{Paused: true}, plainUI, 100, 40},
		{"once", single, topState{Once: true}, plainUI, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderTop(tc.m, tc.st, tc.w, tc.h, tc.u)
			for i, l := range strings.Split(got, "\n") {
				if tc.w > 0 && len([]rune(l)) > tc.w {
					t.Fatalf("line %d wider than %d: %q", i, tc.w, l)
				}
			}
			if tc.h > 0 && strings.Count(got, "\n")+1 > tc.h {
				t.Fatalf("taller than %d", tc.h)
			}
			if tc.u.ascii && strings.IndexFunc(got, func(r rune) bool { return r > 126 }) >= 0 {
				t.Fatalf("non-ASCII in --ascii frame:\n%s", got)
			}
			topGolden(t, tc.name, got)
		})
	}
	colored := newUI(true, termOptions{Color: "always"}, func(string) string { return "" })
	if f := renderTop(live, topState{}, 100, 40, colored); !strings.Contains(f, "\x1b[7m") {
		t.Fatalf("selected row should be reverse video")
	}
	if f := renderTop(live, topState{}, 100, 40, plainUI); strings.Contains(f, "\x1b") {
		t.Fatal("plain frame must carry no escape codes")
	}
}

// fakeAdmin serves scripted documents; each /stats call advances the script.
type fakeAdmin struct {
	srv     *httptest.Server
	token   string
	calls   atomic.Int32
	stats   []string
	metrics string
	conns   string
	status  string
}

func newFakeAdmin(t *testing.T) *fakeAdmin {
	f := &fakeAdmin{
		stats: []string{`{"requests":10,"unmatched":1,"routes":{"HTTPRoute/demo/orders":{"requests":10,"status":{"2xx":8,"5xx":2}}},"backends":{"orders-v1:80":{"requests":10,"status":{"2xx":8,"5xx":2}}}}`},
		metrics: `setura_gateway_request_duration_seconds_bucket{route="HTTPRoute/demo/orders",le="0.005"} 5
setura_gateway_request_duration_seconds_bucket{route="HTTPRoute/demo/orders",le="0.01"} 10
setura_gateway_request_duration_seconds_bucket{route="HTTPRoute/demo/orders",le="+Inf"} 10
setura_gateway_endpoint_healthy{backend="orders-v1:80",endpoint="127.0.0.1:1"} 1
setura_gateway_endpoint_ejected{backend="orders-v1:80",endpoint="127.0.0.1:1"} 0
setura_gateway_endpoint_healthy{backend="orders-v1:80",endpoint="127.0.0.1:2"} 0
setura_gateway_endpoint_ejected{backend="orders-v1:80",endpoint="127.0.0.1:2"} 1
`,
		conns:  `{"enabled":true,"open":[{"id":1}],"history":[{"status":200,"method":"GET","path":"/"},{"status":502,"method":"GET","path":"/x","route":"HTTPRoute/demo/orders","backend":"orders-v1:80","time":"2026-01-02T03:04:05Z"}]}`,
		status: `{"generation":7}`,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if f.token != "" && r.Header.Get("Authorization") != "Bearer "+f.token {
			http.Error(w, "token required", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/stats":
			i := int(f.calls.Add(1)) - 1
			if i >= len(f.stats) {
				i = len(f.stats) - 1
			}
			io.WriteString(w, f.stats[i])
		case "/metrics":
			io.WriteString(w, f.metrics)
		case "/connections":
			io.WriteString(w, f.conns)
		case "/status":
			io.WriteString(w, f.status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAdmin) addr() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func TestTopFetchFake(t *testing.T) {
	f := newFakeAdmin(t)
	f.stats = []string{
		`{"requests":10,"routes":{"r":{"requests":10,"status":{"2xx":10}}},"backends":{}}`,
		`{"requests":30,"routes":{"r":{"requests":30,"status":{"2xx":30}}},"backends":{}}`,
	}
	base, _ := topBase(f.addr())
	a, err := topFetch(context.Background(), f.srv.Client(), base, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := topFetch(context.Background(), f.srv.Client(), base, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	m := buildTopModel(f.addr(), a, b)
	if m.Rate != 10 || m.Generation != 7 || m.Open != 1 || len(m.Errors) != 1 || len(m.ejected()) != 1 {
		t.Fatalf("model %+v", m)
	}
}

func TestTopOneShotCLI(t *testing.T) {
	f := newFakeAdmin(t)
	for _, tc := range []struct {
		name    string
		token   string
		env     string
		args    []string
		code    int
		stdout  []string
		stderr  []string
		noColor bool
	}{
		{name: "table", args: []string{"--admin", f.addr()}, stdout: []string{"setura top", "generation 7", "Single sample", "ROUTES", "HTTPRoute/demo/orders", "EJECTED ENDPOINTS", "127.0.0.1:2", "Open connections  1", "502 GET /x"}},
		{name: "once", args: []string{"--admin", f.addr(), "--once"}, stdout: []string{"ROUTES"}},
		{name: "json", args: []string{"--admin", f.addr(), "--format", "json"}, stdout: []string{`"admin"`, `"routes"`, `"p95_ms"`}},
		{name: "needs token", token: "s3cret", args: []string{"--admin", f.addr()}, code: 1, stderr: []string{"needs a token", "Next:", "SETURA_ADMIN_TOKEN"}},
		{name: "with token", token: "s3cret", env: "s3cret", args: []string{"--admin", f.addr()}, stdout: []string{"ROUTES"}},
		{name: "bad format", args: []string{"--format", "yaml"}, code: 2, stderr: []string{"--format must be"}},
		{name: "bad interval", args: []string{"--interval", "10ms"}, code: 2, stderr: []string{"at least 200ms"}},
		{name: "bad admin", args: []string{"--admin", "nope"}, code: 2, stderr: []string{"--admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.token = tc.token
			t.Setenv("SETURA_ADMIN_TOKEN", tc.env)
			var out, errb bytes.Buffer
			code := runWith(nil, append([]string{"top"}, tc.args...), &out, &errb)
			if code != tc.code {
				t.Fatalf("exit %d want %d\nout=%s\nerr=%s", code, tc.code, out.String(), errb.String())
			}
			for _, s := range tc.stdout {
				if !strings.Contains(out.String(), s) {
					t.Errorf("stdout missing %q:\n%s", s, out.String())
				}
			}
			for _, s := range tc.stderr {
				if !strings.Contains(errb.String(), s) {
					t.Errorf("stderr missing %q:\n%s", s, errb.String())
				}
			}
			if strings.Contains(out.String(), "\x1b") {
				t.Errorf("one-shot output has escape codes")
			}
		})
	}
	f.token = ""
}

func TestTopUnreachable(t *testing.T) {
	f := newFakeAdmin(t)
	addr := f.addr()
	f.srv.Close()
	var out, errb bytes.Buffer
	if code := runWith(nil, []string{"top", "--admin", addr}, &out, &errb); code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{"Cannot reach the gateway admin endpoint", "Next:", "--admin"} {
		if !strings.Contains(errb.String(), s) {
			t.Errorf("missing %q in %s", s, errb.String())
		}
	}
}
