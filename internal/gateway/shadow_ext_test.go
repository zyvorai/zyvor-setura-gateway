package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sizedBody(n int, tail string) string { return strings.Repeat("0123456789abcdef", n/16) + tail }

func TestShadowLargeResponseComparedBySHA(t *testing.T) {
	big := sizedBody(3<<20, "")
	rig := newShadowRig(t, same(big), same(big), m{"compare": true}, nil)
	if _, body, _ := rig.do(t, "/"); len(body) != len(big) {
		t.Fatalf("client got %d bytes", len(body))
	}
	if sum := rig.settle(); sum.Matched != 1 || sum.Skipped != 0 {
		t.Fatalf("identical large bodies must match: %+v", sum)
	}

	rig2 := newShadowRig(t, same(big+"P"), same(big+"S"), m{"compare": true}, nil)
	rig2.do(t, "/")
	sum := rig2.settle()
	if sum.Mismatched != 1 || len(sum.Recent) != 1 || sum.Recent[0].Category != "body" || !strings.Contains(sum.Recent[0].Detail.Where, "sha256") {
		t.Fatalf("a differing large body must mismatch by length/sha256: %+v", sum.Recent)
	}
}

func TestShadowResponseOverCeilingSkipped(t *testing.T) {
	big := strings.Repeat("a", 5000)
	rig := newShadowRig(t, same(big+"P"), same(big+"S"), m{"compare": true, "maxBody": 1000}, nil)
	rig.do(t, "/")
	sum := rig.settle()
	if sum.Skipped != 1 || sum.Matched != 1 {
		t.Fatalf("over the ceiling the body is skipped and the rest still compared: %+v", sum)
	}
	if sum.Routes["t/r"].Skipped != 1 {
		t.Fatalf("per route skipped: %+v", sum.Routes)
	}
}

// draining answers "ok" after reading the whole request body, as a real upload
// handler does.
func draining(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	same("ok")(w, r)
}

func postBody(t *testing.T, rig *shadowRig, body string) {
	t.Helper()
	r := req(t, client(rig.s.Addr(8080), nil), "http", "POST", "x.test", "/up", body)
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
}

func TestShadowLargeRequestBodyMirrored(t *testing.T) {
	var got atomic.Int64
	var sumShadow atomic.Value
	shadow := func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(int64(len(b)))
		sumShadow.Store(string(b[len(b)-4:]))
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}
	rig := newShadowRig(t, draining, shadow, m{"compare": true}, nil)
	body := sizedBody(3<<20, "TAIL")
	postBody(t, rig, body)
	sum := rig.settle()
	if got.Load() != int64(len(body)) || sumShadow.Load() != "TAIL" {
		t.Fatalf("shadow received %d bytes (want %d)", got.Load(), len(body))
	}
	if sum.Compared != 1 || sum.Matched != 1 {
		t.Fatalf("%+v", sum)
	}
	left, _ := filepath.Glob(filepath.Join(os.TempDir(), "setura-spool-*"))
	if len(left) != 0 {
		t.Fatalf("spool files leaked: %v", left)
	}
}

func TestShadowRequestBodyOverCeilingSkipped(t *testing.T) {
	rig := newShadowRig(t, draining, same("ok"), m{"compare": true, "maxBody": 1500000}, nil)
	postBody(t, rig, sizedBody(3<<20, ""))
	sum := rig.settle()
	if sum.Skipped != 1 || rig.hits.Load() != 0 {
		t.Fatalf("a body over the ceiling is skipped and not mirrored: skipped %d hits %d", sum.Skipped, rig.hits.Load())
	}
}

func TestShadowLargeBodyWithoutCompareKeepsOldPath(t *testing.T) {
	rig := newShadowRig(t, same("ok"), same("ok"), nil, nil)
	postBody(t, rig, sizedBody(2<<20, ""))
	rig.s.mirrorWG.Wait()
	if rig.hits.Load() != 0 {
		t.Fatalf("a large body without comparison is not mirrored (old behaviour), hits %d", rig.hits.Load())
	}
}

func TestShadowStatePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	rig := newShadowRig(t, same("a"), same("b"), m{"compare": true, "latencyThresholdMs": 0}, func(o *Options) { o.ShadowState = path })
	for i := 0; i < 5; i++ {
		rig.do(t, "/p")
	}
	before := rig.settle()
	if before.Mismatched != 5 {
		t.Fatalf("%+v", before)
	}
	rig.s.Close() // final snapshot

	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(raw, []byte(shadowStateSchema)) {
		t.Fatalf("no state file: %v %s", err, raw)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".shadow-state-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}

	s2 := New(Options{Admin: "off", ShadowState: path})
	defer s2.Close()
	after := s2.shadow.Summary()
	if after.Compared != before.Compared || after.Mismatched != 5 || len(after.Recent) != len(before.Recent) || after.Routes["t/r"].Compared != 5 {
		t.Fatalf("restored %+v, want %+v", after, before)
	}
	if after.Recent[0] != before.Recent[0] {
		t.Fatalf("ring order changed: %+v vs %+v", after.Recent[0], before.Recent[0])
	}
	if after.ByCategory["body"] != 5 {
		t.Fatalf("categories %+v", after.ByCategory)
	}

	// A corrupt file starts empty instead of failing.
	os.WriteFile(path, []byte("{nope"), 0o600)
	var diag syncBuf
	s3 := New(Options{Admin: "off", ShadowState: path, Diag: &diag})
	defer s3.Close()
	if s3.shadow.Summary().Compared != 0 || !strings.Contains(diag.String(), "starting empty") {
		t.Fatalf("corrupt state: %q", diag.String())
	}
}

func TestShadowStatePeriodicSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	rig := newShadowRig(t, same("a"), same("a"), m{"compare": true}, func(o *Options) {
		o.ShadowState, o.ShadowStateInterval = path, 20*time.Millisecond
	})
	rig.do(t, "/")
	rig.settle()
	waitFor(t, "periodic snapshot", func() bool {
		f, err := loadShadowState(path)
		return err == nil && f != nil && f.Total.Compared == 1
	})
}

func TestShadowLatencyHistogramOnMetrics(t *testing.T) {
	rig := newShadowRig(t, same("a"), same("a"), m{"compare": true}, nil)
	rig.do(t, "/")
	rig.settle()
	var b strings.Builder
	rig.s.WriteMetrics(&b)
	for _, want := range []string{`setura_gateway_request_duration_seconds_bucket{route="t/r",le="+Inf"} 1`,
		`setura_gateway_backend_request_duration_seconds_count{backend="t/app:80"} 1`, `result="skipped"`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// --- annotations -------------------------------------------------------------

func TestShadowAnnotationMapping(t *testing.T) {
	mk := func() []Rule {
		mirror := func() Filter {
			return Filter{Type: "RequestMirror", RequestMirror: &Mirror{BackendRef: BackendRef{Name: "s"}}}
		}
		return []Rule{{Filters: []Filter{mirror()}}, {Filters: []Filter{mirror()}}, {}}
	}
	rules := mk()
	annotateHTTP(rules, map[string]string{
		ShadowDiffKey:               `{"sample":10}`,
		ShadowRuleAnnotation(2):     `{"sample":50,"ignoreJSONPaths":["$.ts"]}`,
		ShadowDiffKey + ".rule-9":   `{}`,
		ShadowDiffKey + ".rule-x":   `{}`,
		"example.com/unrelated-key": "x",
	})
	if s := *rules[0].Filters[0].RequestMirror.ShadowDiff.Sample; s != 10 {
		t.Fatalf("rule 1 takes the route wide block, got %d", s)
	}
	if d := rules[1].Filters[0].RequestMirror.ShadowDiff; *d.Sample != 50 || d.IgnoreJSONPaths[0] != "$.ts" {
		t.Fatalf("rule 2 takes its own block: %+v", d)
	}
	if got := OrphanShadowAnnotations(map[string]string{ShadowDiffKey: "{}", ShadowDiffKey + ".rule-9": "{}", ShadowDiffKey + ".rule-x": "{}", ShadowDiffKey + ".rule-1": "{}"}, 3); len(got) != 2 {
		t.Fatalf("orphans %v", got)
	}

	// An inline block is more specific than an annotation.
	inline := mk()
	five := 5
	inline[0].Filters[0].RequestMirror.ShadowDiff = &ShadowDiff{Sample: &five}
	annotateHTTP(inline, map[string]string{ShadowDiffKey: `{"sample":10}`})
	if *inline[0].Filters[0].RequestMirror.ShadowDiff.Sample != 5 {
		t.Fatal("inline block must win")
	}

	// Garbage makes compilation fail rather than comparing nothing.
	bad := mk()
	annotateHTTP(bad, map[string]string{ShadowDiffKey: `{"sampel":10}`})
	if _, err := compileShadow(bad[0].Filters[0].RequestMirror.ShadowDiff); err == nil || !strings.Contains(err.Error(), "annotation") {
		t.Fatalf("typo in an annotation must be an error, got %v", err)
	}
	for _, v := range []string{`{"sample":101}`, `{"ignoreJSONPaths":["a.b"]}`, `{"frameFormat":"xml"}`, `{"ignoreFrames":[-1]}`, `[]`, `{} {}`} {
		if _, err := ParseShadowBlock([]byte(v)); err == nil {
			t.Errorf("%s should be rejected", v)
		}
	}
	if _, err := ParseShadowBlock([]byte(`{"compare":true,"sample":5,"maxBody":20000000,"ignoreFrames":[0],"frameFormat":"json"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestShadowAnnotationInSnapshotFile(t *testing.T) {
	rig := &shadowRig{}
	rig.primary = httptest.NewServer(same("one"))
	rig.shadow = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rig.hits.Add(1); same("two")(w, r) }))
	t.Cleanup(rig.primary.Close)
	t.Cleanup(rig.shadow.Close)
	r := rule("/", ref("app", 1))
	r["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("shadow", -1)}}}
	rt := route("", r)
	rt[SeturaAnnotationsKey] = m{ShadowDiffKey + ".rule-1": `{"compare":true}`}
	be := map[string]any{"app": strings.TrimPrefix(rig.primary.URL, "http://"), "shadow": strings.TrimPrefix(rig.shadow.URL, "http://")}
	rig.s = startServer(t, snap(httpGateway(""), map[string]m{"r": rt}, be), nil)
	rig.do(t, "/")
	if sum := rig.settle(); sum.Compared != 1 || sum.Mismatched != 1 {
		t.Fatalf("the annotation must switch comparison on: %+v", sum)
	}
}

func TestShadowAnnotationOnKubernetesHTTPRoute(t *testing.T) {
	up1, up2 := newUpstream(t, "primary"), newUpstream(t, "mirror")
	api := newFakeAPI(t)
	api.seed(up1.addr())
	api.put("services", "shop", "orders-v2", m{"spec": m{"ports": l{m{"name": "http", "port": 80, "targetPort": 8080}}}})
	api.put("endpointslices", "shop", "orders-v2-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders-v2"}},
		"endpoints": l{m{"addresses": l{hostOf(up2.addr())}, "conditions": m{"ready": true}}},
		"ports":     l{m{"name": "http", "port": portOf(up2.addr())}}})
	api.put("httproutes", "shop", "orders", m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z", "generation": 3,
		"annotations": m{ShadowRuleAnnotation(1): `{"compare":true,"sample":100,"ignoreHeaders":["X-Upstream"]}`}},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}},
			"rules": l{m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/orders"}}},
				"filters":     l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": m{"name": "orders-v2", "port": 80}}}},
				"backendRefs": l{m{"name": "orders", "port": 80}}}}}})
	s, _, _ := kubeServer(t, api, nil)
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders/1", ""); r.Status != 200 {
		t.Fatalf("status %d %s", r.Status, r.Body)
	}
	s.mirrorWG.Wait()
	waitFor(t, "shadow comparison from the annotation", func() bool { s.mirrorWG.Wait(); return s.shadow.Summary().Compared == 1 })
	sum := s.shadow.Summary()
	// The two upstreams echo their own name, so the bodies differ.
	if sum.Mismatched != 1 || sum.Routes["shop/orders"].Compared != 1 {
		t.Fatalf("%+v", sum)
	}
}

// --- gRPC --------------------------------------------------------------------

// grpcShadowBackend answers with fixed frames, status and message.
func grpcShadowBackend(t *testing.T, frames []string, status, message string) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		for _, f := range frames {
			w.Write(grpcFrame(f))
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", status)
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", message)
	}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func grpcShadowRig(t *testing.T, block m, primary, shadow *httptest.Server) (*Server, *http.Client) {
	t.Helper()
	mir := m{"backendRef": gref("shadow", -1)}
	if block != nil {
		mir[ShadowDiffKey] = block
	}
	rl := grule(nil, gref("app", 1))
	rl["filters"] = l{m{"type": "RequestMirror", "requestMirror": mir}}
	be := map[string]any{"app": strings.TrimPrefix(primary.URL, "http://"), "shadow": strings.TrimPrefix(shadow.URL, "http://")}
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": grpcRoute("", rl)}, be, nil), nil)
	return s, h2cClient(s.Addr(8080))
}

func TestShadowGRPC(t *testing.T) {
	const wantMsg = "done"
	cases := []struct {
		name     string
		block    m
		p, s     []string
		ps, ss   string
		pm, sm   string
		category string // "" means a match
		where    string
	}{
		{name: "identical", block: m{"compare": true}, p: []string{"a", "b"}, s: []string{"a", "b"}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg},
		{name: "status", block: m{"compare": true}, p: []string{"a"}, s: []string{"a"}, ps: "0", ss: "13", pm: wantMsg, sm: wantMsg, category: "grpc-status"},
		{name: "message", block: m{"compare": true}, p: []string{"a"}, s: []string{"a"}, ps: "0", ss: "0", pm: "x", sm: "y", category: "grpc-message"},
		{name: "frame bytes", block: m{"compare": true}, p: []string{"a", "bbb"}, s: []string{"a", "bXb"}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg, category: "body", where: "frame 1"},
		{name: "frame count", block: m{"compare": true}, p: []string{"a", "b"}, s: []string{"a"}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg, category: "body", where: "frames"},
		{name: "ignored frame", block: m{"compare": true, "ignoreFrames": l{1}}, p: []string{"a", "b"}, s: []string{"a", "z"}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg},
		{name: "json frames", block: m{"compare": true, "frameFormat": "json", "ignoreJSONPaths": l{"$.ts"}}, p: []string{`{"id":1,"ts":5}`}, s: []string{`{"ts":9, "id":1.0}`}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg},
		{name: "json frames differ", block: m{"compare": true, "frameFormat": "json"}, p: []string{`{"id":1}`}, s: []string{`{"id":2}`}, ps: "0", ss: "0", pm: wantMsg, sm: wantMsg, category: "body", where: "$.id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prim := grpcShadowBackend(t, tc.p, tc.ps, tc.pm)
			shad := grpcShadowBackend(t, tc.s, tc.ss, tc.sm)
			s, c := grpcShadowRig(t, tc.block, prim, shad)
			r := grpcCall(t, c, "http", "svc.test", "/pkg.Svc/Do", []string{"ping"})
			if r.HTTP != 200 || len(r.Msgs) != len(tc.p) || r.Status != tc.ps {
				t.Fatalf("the client must see the primary answer unchanged: %+v", r)
			}
			s.mirrorWG.Wait()
			sum := s.shadow.Summary()
			if sum.Compared != 1 {
				t.Fatalf("not compared: %+v", sum)
			}
			if tc.category == "" {
				if sum.Matched != 1 {
					t.Fatalf("want a match, got %+v", sum.Recent)
				}
				return
			}
			if sum.Mismatched != 1 || sum.ByCategory[tc.category] != 1 {
				t.Fatalf("want a %s mismatch, got %+v / %+v", tc.category, sum.ByCategory, sum.Recent)
			}
			var found bool
			for _, e := range sum.Recent {
				if e.Category == tc.category && strings.Contains(e.Detail.Where, tc.where) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s entry with %q: %+v", tc.category, tc.where, sum.Recent)
			}
		})
	}
}

func TestShadowGRPCTrailersOnlyStatus(t *testing.T) {
	prim := newGRPCBackend(t, "p")
	shad := newGRPCBackend(t, "s")
	s, c := grpcShadowRig(t, m{"compare": true}, prim.Server, shad.Server)
	r := grpcCall(t, c, "http", "svc.test", "/pkg.Svc/Fail", []string{"x"})
	if r.Status != "5" {
		t.Fatalf("%+v", r)
	}
	s.mirrorWG.Wait()
	if sum := s.shadow.Summary(); sum.Compared != 1 || sum.Matched != 1 {
		t.Fatalf("both sides answered Trailers-Only status 5: %+v", sum.Recent)
	}
}

func TestShadowGRPCRoutePrometheusCategories(t *testing.T) {
	prim := grpcShadowBackend(t, []string{"a"}, "0", "m")
	shad := grpcShadowBackend(t, []string{"a"}, "2", "m")
	s, c := grpcShadowRig(t, m{"compare": true}, prim, shad)
	grpcCall(t, c, "http", "svc.test", "/pkg.Svc/Do", []string{"ping"})
	s.mirrorWG.Wait()
	var b strings.Builder
	s.WriteMetrics(&b)
	if !strings.Contains(b.String(), `result="grpc-status"} 1`) {
		t.Fatalf("metrics lack the grpc-status category:\n%s", b.String())
	}
}

func TestShadowSummaryJSONHasSkipped(t *testing.T) {
	var st shadowState
	st.skip("r")
	raw, _ := json.Marshal(st.Summary())
	if !strings.Contains(string(raw), `"skipped":1`) {
		t.Fatalf("%s", raw)
	}
	if !st.active() {
		t.Fatal("skipped alone must activate the dashboard card")
	}
}
