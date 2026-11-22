package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shadowRig struct {
	s       *Server
	primary *httptest.Server
	shadow  *httptest.Server
	hits    atomic.Int64 // shadow requests served
}

// newShadowRig serves one rule on / with a RequestMirror carrying block.
func newShadowRig(t *testing.T, primary, shadow http.HandlerFunc, block m, mod func(*Options)) *shadowRig {
	t.Helper()
	rig := &shadowRig{}
	rig.primary = httptest.NewServer(primary)
	t.Cleanup(rig.primary.Close)
	rig.shadow = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.hits.Add(1)
		shadow(w, r)
	}))
	t.Cleanup(rig.shadow.Close)
	rig.s = rig.start(t, rig.shadow.Listener.Addr().String(), block, mod)
	return rig
}

func (rig *shadowRig) start(t *testing.T, shadowAddr string, block m, mod func(*Options)) *Server {
	mir := m{"backendRef": ref("shadow", -1)}
	if block != nil {
		mir[ShadowDiffKey] = block
	}
	r := rule("/", ref("app", 1))
	r["filters"] = l{m{"type": "RequestMirror", "requestMirror": mir}}
	be := map[string]any{"app": strings.TrimPrefix(rig.primary.URL, "http://"), "shadow": shadowAddr}
	return startServer(t, snap(httpGateway(""), map[string]m{"r": route("", r)}, be), mod)
}

func (rig *shadowRig) do(t *testing.T, path string) (int, string, time.Duration) {
	t.Helper()
	t0 := time.Now()
	r := get(t, rig.s, "x.test", path)
	return r.Status, r.Body, time.Since(t0)
}

// settle waits for every comparison to finish.
func (rig *shadowRig) settle() ShadowSummary {
	rig.s.mirrorWG.Wait()
	return rig.s.shadow.Summary()
}

func same(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Date", time.Now().String())
		io.WriteString(w, body)
	}
}

func TestShadowIdentical(t *testing.T) {
	rig := newShadowRig(t, same("hello"), same("hello"), m{"compare": true}, nil)
	for i := 0; i < 20; i++ {
		if code, body, _ := rig.do(t, "/p"); code != 200 || body != "hello" {
			t.Fatalf("client got %d %q", code, body)
		}
	}
	sum := rig.settle()
	if sum.Compared != 20 || sum.Matched != 20 || sum.Mismatched != 0 || sum.MatchRate == nil || *sum.MatchRate != 100 || len(sum.Recent) != 0 {
		t.Fatalf("summary %+v", sum)
	}
	if rs := sum.Routes["t/r"]; rs.Compared != 20 {
		t.Fatalf("routes %+v", sum.Routes)
	}
}

func TestShadowNotComparedByDefault(t *testing.T) {
	rig := newShadowRig(t, same("a"), same("b"), nil, nil)
	rig.do(t, "/")
	if sum := rig.settle(); sum.Sampled != 0 || sum.Compared != 0 {
		t.Fatalf("plain mirror was compared: %+v", sum)
	}
	if rig.hits.Load() != 1 {
		t.Fatalf("plain mirror still has to fire, hits=%d", rig.hits.Load())
	}
}

func TestShadowGlobalDefault(t *testing.T) {
	rig := newShadowRig(t, same("a"), same("b"), nil, func(o *Options) { o.ShadowDiff = 100 })
	rig.do(t, "/")
	if sum := rig.settle(); sum.Mismatched != 1 || sum.ByCategory["body"] != 1 {
		t.Fatalf("global default did not compare: %+v", sum)
	}
	off := newShadowRig(t, same("a"), same("b"), m{"compare": false}, func(o *Options) { o.ShadowDiff = 100 })
	off.do(t, "/")
	if sum := off.settle(); sum.Sampled != 0 {
		t.Fatalf("compare:false must win over the global default: %+v", sum)
	}
}

func TestShadowMismatches(t *testing.T) {
	jsonH := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		}
	}
	cases := []struct {
		name           string
		p, s           http.HandlerFunc
		block          m
		path           string
		cat, wantWhere string
		wantMatch      bool
		wantP, wantSh  string
		notInExcerpt   string
	}{
		{name: "status", p: same("x"), s: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); io.WriteString(w, "x") },
			cat: "status", wantWhere: "status", wantP: "200", wantSh: "500"},
		{name: "header", p: same("x"), s: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "x")
		}, cat: "header", wantWhere: "Content-Type", wantP: "text/plain", wantSh: "text/html"},
		{name: "custom header", p: func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Version", "1") },
			s:     func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Version", "2") },
			block: m{"compare": true, "headers": l{"X-Version"}}, cat: "header", wantWhere: "X-Version", wantP: "1", wantSh: "2"},
		{name: "custom header ignored", p: func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Cache-Control", "a") },
			s:     func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Cache-Control", "b") },
			block: m{"compare": true, "ignoreHeaders": l{"cache-control"}}, wantMatch: true},
		{name: "body bytes", p: same("hello world, this is the primary"), s: same("hello world, this is the shadow!"),
			cat: "body", wantWhere: "offset 25", wantP: "this is the primary", wantSh: "this is the shadow!"},
		{name: "json path", p: jsonH(`{"a":{"b":[1,2,3]},"ts":1}`), s: jsonH(`{"a":{"b":[1,9,3]},"ts":2}`),
			block: m{"compare": true, "ignoreJSONPaths": l{"$.ts"}}, cat: "body", wantWhere: "$.a.b[1]", wantP: "2", wantSh: "9"},
		{name: "json ignored", p: jsonH(`{"a":1,"ts":1,"x":{"id":5},"l":[{"n":1},{"n":2}]}`), s: jsonH(`{ "l":[{"n":1},{"n":7}], "x":{"id":6}, "a":1, "ts":99 }`),
			block: m{"compare": true, "ignoreJSONPaths": l{"$.ts", "$..id", "$.l[1]"}}, wantMatch: true},
		{name: "json reformatted is equal", p: jsonH(`{"a":1,"b":[true]}`), s: jsonH("{\n \"b\": [true],\n \"a\": 1.0\n}"), wantMatch: true},
		{name: "secret redacted", p: jsonH(`{"user":"u","password":"hunter2hunter2"}`), s: jsonH(`{"user":"v","password":"hunter3hunter3"}`),
			cat: "body", wantWhere: "$.password", wantP: "[redacted]", wantSh: "[redacted]"},
		{name: "secret path redacted", p: jsonH(`{"apiToken":"AAAA"}`), s: jsonH(`{"apiToken":"BBBB"}`),
			cat: "body", wantWhere: "$.apiToken", wantP: "[redacted]", wantSh: "[redacted]"},
		{name: "text secret redacted", p: same("ok key=sk-abcdefghijklmnop1234 password=hunter2 end A"), s: same("ok key=sk-abcdefghijklmnop1234 password=hunter2 end B"),
			cat: "body", wantWhere: "offset 52", notInExcerpt: "hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := tc.block
			if block == nil {
				block = m{"compare": true}
			}
			rig := newShadowRig(t, tc.p, tc.s, block, nil)
			if code, _, _ := rig.do(t, "/q/r?token=sekrit&x=1"); code != 200 && tc.name != "status" {
				t.Fatalf("client code %d", code)
			}
			sum := rig.settle()
			if tc.wantMatch {
				if sum.Matched != 1 || sum.Mismatched != 0 {
					t.Fatalf("want match, got %+v recent=%+v", sum, sum.Recent)
				}
				return
			}
			if sum.Mismatched != 1 || sum.ByCategory[tc.cat] < 1 || len(sum.Recent) == 0 {
				t.Fatalf("want %s mismatch, got %+v", tc.cat, sum)
			}
			e := sum.Recent[0]
			for _, x := range sum.Recent {
				if x.Category == tc.cat {
					e = x
				}
			}
			if e.Path != "/q/r" || e.Method != "GET" || e.Route != "t/r" || strings.Contains(fmt.Sprint(e), "sekrit") {
				t.Fatalf("entry %+v (query must be stripped)", e)
			}
			if !strings.HasPrefix(e.Detail.Where, tc.wantWhere) {
				t.Fatalf("where %q, want prefix %q", e.Detail.Where, tc.wantWhere)
			}
			if tc.wantP != "" && !strings.Contains(e.Detail.Primary, tc.wantP) || tc.wantSh != "" && !strings.Contains(e.Detail.Shadow, tc.wantSh) {
				t.Fatalf("detail %+v", e.Detail)
			}
			if tc.notInExcerpt != "" && strings.Contains(e.Detail.Primary+e.Detail.Shadow, tc.notInExcerpt) {
				t.Fatalf("secret leaked: %+v", e.Detail)
			}
			if strings.Contains(e.Detail.Primary, "hunter") || strings.Contains(e.Detail.Shadow, "hunter") {
				t.Fatalf("secret leaked: %+v", e.Detail)
			}
			if !strings.Contains(e.Primary.Backend, "app") || !strings.Contains(e.Shadow.Backend, "shadow") || e.Primary.Status == 0 || e.Shadow.Status == 0 {
				t.Fatalf("sides %+v %+v", e.Primary, e.Shadow)
			}
			if len(e.Detail.Primary) > 100 || len(e.Detail.Shadow) > 100 {
				t.Fatalf("excerpt too long: %+v", e.Detail)
			}
		})
	}
}

func TestShadowLatencyCategory(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "x")
	}
	rig := newShadowRig(t, same("x"), slow, m{"compare": true, "latencyThresholdMs": 50}, nil)
	rig.do(t, "/")
	sum := rig.settle()
	if sum.ByCategory["latency"] != 1 || sum.P50DeltaMs < 100 {
		t.Fatalf("%+v", sum)
	}
	// Without a threshold the delta is recorded but not flagged.
	rig2 := newShadowRig(t, same("x"), slow, m{"compare": true}, nil)
	rig2.do(t, "/")
	if sum := rig2.settle(); sum.Mismatched != 0 || sum.Routes["t/r"].P95DeltaMs < 100 {
		t.Fatalf("%+v", sum)
	}
}

func TestShadowSlowDoesNotSlowClient(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1200 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "x")
	}
	rig := newShadowRig(t, same("x"), slow, m{"compare": true}, nil)
	for i := 0; i < 5; i++ {
		code, body, d := rig.do(t, "/")
		if code != 200 || body != "x" {
			t.Fatalf("client got %d %q", code, body)
		}
		if d > 500*time.Millisecond {
			t.Fatalf("client waited %v for a slow shadow", d)
		}
	}
	if sum := rig.s.shadow.Summary(); sum.Compared != 0 {
		t.Fatalf("comparison cannot have finished yet: %+v", sum)
	}
	if sum := rig.settle(); sum.Compared != 5 || sum.Routes["t/r"].P50DeltaMs < 1000 {
		t.Fatalf("%+v", sum)
	}
}

func TestShadowDownDoesNotAffectClient(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	rig := &shadowRig{}
	rig.primary = httptest.NewServer(same("ok"))
	t.Cleanup(rig.primary.Close)
	rig.s = rig.start(t, dead, m{"compare": true}, nil)
	for i := 0; i < 3; i++ {
		if code, body, d := rig.do(t, "/"); code != 200 || body != "ok" || d > time.Second {
			t.Fatalf("client got %d %q in %v", code, body, d)
		}
	}
	sum := rig.settle()
	if sum.Errors != 3 || sum.Compared != 0 || sum.Mismatched != 0 || sum.LastError == "" {
		t.Fatalf("%+v", sum)
	}
}

func TestShadowSampling(t *testing.T) {
	rig := newShadowRig(t, same("x"), same("x"), m{"compare": true, "sample": 50}, nil)
	for i := 0; i < 300; i++ {
		rig.do(t, "/")
	}
	sum := rig.settle()
	if sum.Compared < 90 || sum.Compared > 210 {
		t.Fatalf("sample 50 of 300 compared %d", sum.Compared)
	}
	if int(rig.hits.Load()) != 300 {
		t.Fatalf("every request is still mirrored, got %d", rig.hits.Load())
	}
	none := newShadowRig(t, same("x"), same("x"), m{"compare": true, "sample": 0}, nil)
	none.do(t, "/")
	if sum := none.settle(); sum.Sampled != 0 {
		t.Fatalf("%+v", sum)
	}
}

func TestShadowDropCounterUnderLoad(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "x")
	}
	rig := newShadowRig(t, same("x"), slow, m{"compare": true}, nil)
	rig.s.shadow.limit = 2
	var wg sync.WaitGroup
	var bad atomic.Int64
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, _, d := rig.do(t, "/"); code != 200 || d > 250*time.Millisecond {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d clients were slowed or failed", bad.Load())
	}
	sum := rig.settle()
	if sum.Dropped == 0 || sum.Sampled+sum.Dropped != 30 || sum.Sampled > 30-sum.Dropped {
		t.Fatalf("%+v", sum)
	}
	if int(rig.hits.Load()) != 30 {
		t.Fatalf("dropped comparisons must still be mirrored, got %d", rig.hits.Load())
	}
	var out strings.Builder
	rig.s.WriteMetrics(&out)
	if !strings.Contains(out.String(), fmt.Sprintf(`setura_gateway_shadow_total{route="t/r",result="dropped"} %d`, sum.Dropped)) {
		t.Fatalf("metrics:\n%s", out.String())
	}
}

func TestShadowRingBounds(t *testing.T) {
	var st shadowState
	p := &respCapture{status: 200, hdr: http.Header{}, backend: "a"}
	sh := &respCapture{status: 500, hdr: http.Header{}, backend: "b", dur: time.Millisecond}
	for i := 0; i < shadowRingSize*3; i++ {
		st.record("r", "GET", fmt.Sprintf("/%d", i), p, sh, []shadowMismatch{{Category: "status", Where: "status"}}, time.Now())
	}
	sum := st.Summary()
	if len(sum.Recent) != shadowRingSize || sum.Recent[0].Path != fmt.Sprintf("/%d", shadowRingSize*3-1) || sum.Recent[shadowRingSize-1].Path != fmt.Sprintf("/%d", shadowRingSize*2) {
		t.Fatalf("ring %d first %s last %s", len(sum.Recent), sum.Recent[0].Path, sum.Recent[len(sum.Recent)-1].Path)
	}
	if sum.Mismatched != int64(shadowRingSize*3) || len(st.routes["r"].deltas) != shadowDeltaWindow && len(st.routes["r"].deltas) > shadowDeltaWindow {
		t.Fatalf("%+v", sum.ShadowRouteSummary)
	}
}

func TestShadowAdminMetricsAndUI(t *testing.T) {
	old := UIStateBuilder
	UIStateBuilder = func(UIInput) (any, error) { return map[string]any{"routes": []any{}}, nil }
	t.Cleanup(func() { UIStateBuilder = old })
	rig := newShadowRig(t, same("a"), same("b"), m{"compare": true}, func(o *Options) { o.Admin = "127.0.0.1:0" })
	if err := rig.s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	if st, _ := rig.s.UIState().(map[string]any); st["shadow"] != nil {
		t.Fatalf("shadow section must be absent before any comparison: %v", st)
	}
	rig.do(t, "/")
	rig.settle()

	resp, err := http.Get("http://" + rig.s.AdminAddr() + "/shadow")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["schema"] != shadowSchema || doc["mismatched"].(float64) != 1 || len(doc["recent"].([]any)) != 1 || doc["routes"].(map[string]any)["t/r"] == nil {
		t.Fatalf("/shadow: %v", doc)
	}
	resp, _ = http.Get("http://" + rig.s.AdminAddr() + "/metrics")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{`setura_gateway_shadow_total{route="t/r",result="mismatched"} 1`, `result="body"} 1`, `result="matched"} 0`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %q in\n%s", want, b)
		}
	}
	st, _ := rig.s.UIState().(map[string]any)
	if st["shadow"] == nil {
		t.Fatalf("ui state lacks shadow: %v", st)
	}
}

func TestShadowConfigValidation(t *testing.T) {
	bad := []string{`{"compare":true,"sample":101}`, `{"ignoreJSONPaths":["a.b"]}`, `{"maxBody":-1}`}
	for _, blk := range bad {
		var d ShadowDiff
		if err := json.Unmarshal([]byte(blk), &d); err != nil {
			t.Fatal(err)
		}
		if _, err := compileShadow(&d); err == nil {
			t.Errorf("block %s was accepted", blk)
		}
	}
	// An invalid block makes the route invalid instead of silently comparing nothing.
	mir := m{"backendRef": ref("shadow", -1), ShadowDiffKey: m{"compare": true, "sample": 500}}
	r := rule("/", ref("app", 1))
	r["filters"] = l{m{"type": "RequestMirror", "requestMirror": mir}}
	raw := snap(httpGateway(""), map[string]m{"r": route("", r)}, map[string]any{"app": "127.0.0.1:1", "shadow": "127.0.0.1:2"})
	s := startServer(t, raw, nil)
	if got := get(t, s, "x.test", "/"); got.Status == 200 {
		t.Fatalf("invalid shadow block served traffic: %d", got.Status)
	}
}

func TestJSONPathPrune(t *testing.T) {
	doc := `{"a":{"b":1,"c":[{"id":1,"k":2},{"id":3}]},"id":4,"list":[10,20,30]}`
	for path, want := range map[string]string{
		"$.a.b":       `{"a":{"c":[{"id":1,"k":2},{"id":3}]},"id":4,"list":[10,20,30]}`,
		"$.list[1]":   `{"a":{"b":1,"c":[{"id":1,"k":2},{"id":3}]},"id":4,"list":[10,30]}`,
		"$..id":       `{"a":{"b":1,"c":[{"k":2},{}]},"list":[10,20,30]}`,
		"$.a.c[0].k":  `{"a":{"b":1,"c":[{"id":1},{"id":3}]},"id":4,"list":[10,20,30]}`,
		"$['a']['b']": `{"a":{"c":[{"id":1,"k":2},{"id":3}]},"id":4,"list":[10,20,30]}`,
		"$.nope.deep": doc,
		"$.list[9]":   doc,
		"$..c..k":     `{"a":{"b":1,"c":[{"id":1},{"id":3}]},"id":4,"list":[10,20,30]}`,
	} {
		jp, err := parseJSONPath(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var v any
		json.Unmarshal([]byte(doc), &v)
		got, _ := json.Marshal(jp.prune(v))
		if string(got) != want {
			t.Errorf("%s:\n got %s\nwant %s", path, got, want)
		}
	}
	for _, bad := range []string{"", "a.b", "$", "$.", "$..", "$[x]", "$.a[", "$.a[-1]", "$.*"} {
		if _, err := parseJSONPath(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	for _, in := range []string{`password: "hunter2"`, `Authorization: Bearer abc.def.ghi`, `token=abcdef123456`, `AKIAABCDEFGHIJKLMNOP`,
		`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig`, strings.Repeat("ab12", 12)} {
		out := redactSecrets(in)
		if out == in || strings.Contains(out, "hunter2") || strings.Contains(out, "abcdef123456") || strings.Contains(out, "abc.def.ghi") {
			t.Errorf("%q -> %q", in, out)
		}
	}
	if got := redactSecrets("hello world"); got != "hello world" {
		t.Fatal(got)
	}
}

func TestShadowCaptureLargeBodyTruncated(t *testing.T) {
	big := strings.Repeat("a", 5000)
	rig := newShadowRig(t, same(big+"P"), same(big+"S"), m{"compare": true, "maxBody": 1000}, nil)
	rig.do(t, "/")
	if sum := rig.settle(); sum.Matched != 1 {
		t.Fatalf("equal prefixes under maxBody must match: %+v", sum)
	}
}
