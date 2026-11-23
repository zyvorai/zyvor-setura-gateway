package contract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"/":                   "/",
		"":                    "/",
		"/users/42":           "/users/{id}",
		"/users/42/orders/7/": "/users/{id}/orders/{id}",
		"//a//b":              "/a/b",
		"/v1/health":          "/v1/health",
		"/users/me":           "/users/me",
		"/o/123e4567-e89b-12d3-a456-426614174000": "/o/{id}",
		"/blob/d41d8cd98f00b204e9800998ecf8427e":  "/blob/{id}",
		"/cal/2026-03-01":                         "/cal/{id}",
		"/ulid/01ARZ3NDEKTSV4RRFFQ69G5FAV":        "/ulid/{id}",
		"/u/usr_8f3k2m9x1q7z":                     "/u/{id}",
		"/t/" + strings.Repeat("aB3", 8):          "/t/{id}",
		"/price/12.50":                            "/price/{id}",
		"/x/{evil}":                               "/x/{id}",
		"/files/report.pdf":                       "/files/report.pdf",
		"/orders/history-items":                   "/orders/history-items",
		"/a/b/c/d/e/f/g/h/i/j/k/l/m/n":            "/a/b/c/d/e/f/g/h/i/j/k/l/**",
		"/s/" + strings.Repeat("x", 80):           "/s/{id}",
	} {
		if got := Template(in); got != want {
			t.Errorf("Template(%q) = %q, want %q", in, got, want)
		}
	}
}

func obs(method, path string, status int, at time.Time) Obs {
	return Obs{Method: method, Path: path, Status: status, ReqBytes: -1, RespBytes: 100, Latency: 20 * time.Millisecond, At: at}
}

func TestLearnerRecordsNamesOnly(t *testing.T) {
	l := NewLearner(0)
	l.Record(obs("GET", "/users/1", 200, t0)) // disabled: ignored
	if n, _, _ := l.Stats(); n != 0 {
		t.Fatal("recorded while disabled")
	}
	l.Enable(true)
	for i := 1; i <= 50; i++ {
		o := obs("get", fmt.Sprintf("/users/%d", i), 200, t0.Add(time.Duration(i)*time.Second))
		o.QueryNames, o.HeaderNames, o.Route, o.Backend = []string{"limit", "q"}, []string{"X-Api-Key", "Accept"}, "r1", "b1"
		o.RespType, o.Protected = "Application/JSON; charset=utf-8", i%2 == 0
		l.Record(o)
	}
	l.Record(obs("GET", "/users/1", 404, t0))
	d := l.Snapshot()
	if len(d.Endpoints) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(d.Endpoints))
	}
	e := d.Endpoints[0]
	if e.Key() != "GET /users/{id}" || e.Count != 51 || e.Status["200"] != 50 || e.Status["404"] != 1 {
		t.Fatalf("bad endpoint %+v", e)
	}
	if e.ResponseTypes["application/json"] != 50 || !reflect.DeepEqual(e.Query, []string{"limit", "q"}) || !reflect.DeepEqual(e.Headers, []string{"accept", "x-api-key"}) {
		t.Fatalf("names/types wrong %+v", e)
	}
	if e.Auth.Protected != 25 || e.Auth.Open != 26 || e.Latency.P50 != 20 || e.ResponseBytes.P99 != 100 {
		t.Fatalf("auth/latency wrong %+v", e)
	}
	if !d.First.Equal(t0) || e.LastSeen != t0.Add(50*time.Second) {
		t.Fatalf("window wrong %v %v", d.First, e.LastSeen)
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), "secret") {
		t.Fatal("unexpected content")
	}
}

func TestLearnerBounds(t *testing.T) {
	l := NewLearner(10)
	l.Enable(true)
	for i := 0; i < 100; i++ { // literal fan-out beyond 64 collapses to {id}
		l.Record(obs("GET", fmt.Sprintf("/tags/word%c%c", 'a'+i/26, 'a'+i%26), 200, t0))
	}
	d := l.Snapshot()
	if len(d.Endpoints) > 10 {
		t.Fatalf("cap exceeded: %d", len(d.Endpoints))
	}
	if d.DroppedRequests == 0 {
		t.Fatal("expected dropped requests past the cap")
	}
	l2 := NewLearner(5000)
	l2.Enable(true)
	for i := 0; i < 200; i++ {
		l2.Record(obs("GET", fmt.Sprintf("/tags/w%c%c", 'a'+i/26, 'a'+i%26), 200, t0))
	}
	got := l2.Snapshot()
	if len(got.Endpoints) != maxFanout+1 {
		t.Fatalf("want %d literal tags plus {id}, got %d", maxFanout, len(got.Endpoints))
	}
	// per-endpoint maps stay bounded
	l3 := NewLearner(0)
	l3.Enable(true)
	for i := 0; i < 100; i++ {
		o := obs("GET", "/p", 200+i, t0)
		o.Route, o.QueryNames = fmt.Sprint("route", i), []string{fmt.Sprint("q", i)}
		l3.Record(o)
	}
	e := l3.Snapshot().Endpoints[0]
	if len(e.Status) > maxStatus+1 || len(e.Routes) > maxKeys+1 || len(e.Query) > maxNames {
		t.Fatalf("unbounded: %d %d %d", len(e.Status), len(e.Routes), len(e.Query))
	}
}

func TestPersistAndMerge(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "inv.json")
	l := NewLearner(0)
	l.Enable(true)
	l.Record(obs("GET", "/a/1", 200, t0))
	l.Record(obs("POST", "/a", 201, t0.Add(time.Hour)))
	if err := l.SaveFile(f); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if l.Dirty() {
		t.Fatal("still dirty")
	}
	l2 := NewLearner(0)
	if n, err := l2.LoadFile(f); err != nil || n != 2 {
		t.Fatalf("load %d %v", n, err)
	}
	l2.Enable(true)
	l2.Record(obs("GET", "/a/9", 500, t0.Add(2*time.Hour)))
	d := l2.Snapshot()
	if d.Requests != 3 || len(d.Endpoints) != 2 || d.Endpoints[1].Count != 2 || d.Endpoints[1].Status["500"] != 1 || d.Endpoints[1].Latency.N != 2 {
		t.Fatalf("merge wrong: %+v", d.Endpoints[1])
	}
	if n, err := NewLearner(0).LoadFile(filepath.Join(dir, "nope.json")); err != nil || n != 0 {
		t.Fatalf("missing file: %d %v", n, err)
	}
	os.WriteFile(f, []byte(`{"schema":"x"}`), 0o600)
	if _, err := NewLearner(0).LoadFile(f); err == nil {
		t.Fatal("bad schema accepted")
	}
}

const specJSON = `{"openapi":"3.0.3","info":{"title":"Orders"},"servers":[{"url":"https://x.test/api"}],
"security":[{"key":[]}],
"paths":{
 "/orders":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{}}},"4XX":{"description":"e"}}},
            "post":{"requestBody":{"content":{"application/json":{}}},"responses":{"201":{"description":"c"},"default":{"description":"d"}}}},
 "/orders/{orderId}":{"get":{"responses":{"200":{"description":"ok","content":{"application/json":{}}},"404":{"$ref":"#/components/responses/NF"}}},
                      "delete":{"security":[],"responses":{"204":{"description":"gone"}}}},
 "/orders/export":{"get":{"deprecated":true,"responses":{"200":{"description":"csv","content":{"text/csv":{}}}}}},
 "/legacy":{"get":{"responses":{"200":{"description":"x"}}}}
},
"components":{"responses":{"NF":{"description":"nf","content":{"application/problem+json":{}}}}}}`

func TestSpecLookupAndCheck(t *testing.T) {
	s, err := ParseSpec([]byte(specJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Ops) != 6 {
		t.Fatalf("ops %d", len(s.Ops))
	}
	for _, c := range []struct {
		m, p, reason string
	}{
		{"GET", "/orders", ""}, {"get", "/orders/", ""}, {"GET", "/orders/123", ""}, {"HEAD", "/orders/123", ""},
		{"GET", "/api/orders/123", ""}, {"DELETE", "/orders/abc", ""},
		{"DELETE", "/orders", "unknown_method"}, {"PUT", "/orders/1", "unknown_method"},
		{"GET", "/users", "unknown_endpoint"}, {"GET", "/orders/1/items", "unknown_endpoint"}, {"GET", "/", "unknown_endpoint"},
	} {
		v := s.Check(c.m, c.p)
		if (c.reason == "") != v.OK || v.Reason != c.reason {
			t.Errorf("%s %s: %+v want %q", c.m, c.p, v, c.reason)
		}
	}
	if v := s.Check("PUT", "/orders/1"); strings.Join(v.Allow, ",") != "DELETE,GET" {
		t.Errorf("allow %v", v.Allow)
	}
	op, _, _ := s.Lookup("GET", "/orders/export", false) // literal wins over {orderId}
	if op.Path != "/orders/export" || !op.Deprecated {
		t.Errorf("specificity: %+v", op)
	}
	get, _, _ := s.Lookup("GET", "/orders/1", false)
	if types, ok := get.StatusDocumented("404"); !ok || types[0] != "application/problem+json" {
		t.Errorf("ref not resolved: %v", types)
	}
	if !get.Secured {
		t.Error("global security not inherited")
	}
	del, _, _ := s.Lookup("DELETE", "/orders/1", false)
	if del.Secured {
		t.Error("security: [] must clear")
	}
}

func TestSpecErrors(t *testing.T) {
	for name, in := range map[string]string{
		"swagger": `{"swagger":"2.0","paths":{}}`, "v4": `{"openapi":"4.0.0","paths":{"/a":{"get":{}}}}`,
		"nopaths": `{"openapi":"3.0.0"}`, "noops": `{"openapi":"3.0.0","paths":{"/a":{}}}`,
		"badjson": `{"openapi":`, "array": `[1]`, "anchor": "openapi: 3.0.0\npaths:\n  /a: &x\n    get: {}\n",
	} {
		if _, err := ParseSpec([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const specYAML = `# orders
openapi: "3.0.3"
info:
  title: Orders  # api
  version: '1.0'
servers:
  - url: https://x.test/api
paths:
  /orders:
    get:
      summary: List: all
      parameters:
        - name: limit
          in: query
      responses:
        '200':
          description: |
            ok
            # not a comment
          content:
            application/json: {}
        "4XX": {description: err}
    post:
      requestBody:
        content: {"application/json": {}, text/plain: {}}
      responses:
        201:
          description: created
  /orders/{orderId}:
    delete:
      security: []
      deprecated: true
      responses:
        default:
          description: any
security:
- key: []
tags: [a, 'b', "c"]
`

func TestYAMLSpec(t *testing.T) {
	s, err := ParseSpec([]byte(specYAML))
	if err != nil {
		t.Fatal(err)
	}
	if s.Title != "Orders" || len(s.Ops) != 3 {
		t.Fatalf("%+v", s)
	}
	get, _, _ := s.Lookup("GET", "/orders", false)
	if _, ok := get.StatusDocumented("418"); !ok {
		t.Error("4XX range lost")
	}
	post, _, _ := s.Lookup("POST", "/api/orders", false)
	if !post.HasBody || len(post.RequestTypes) != 2 || !post.Secured {
		t.Errorf("post %+v", post)
	}
	if _, ok := post.StatusDocumented("201"); !ok {
		t.Error("unquoted numeric key lost")
	}
	del, _, _ := s.Lookup("DELETE", "/orders/9", false)
	if !del.Deprecated || del.Secured {
		t.Errorf("del %+v", del)
	}
	for _, bad := range []string{"a: b\n\tc: d", "a: *x", "a: 1\n---\nb: 2\n", "a: [1,"} {
		if _, err := parseYAML([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if v, err := parseYAML([]byte("a:\n- b\n- c: 1\n  d: 2\n")); err != nil || fmt.Sprint(v) != "map[a:[b map[c:1 d:2]]]" {
		t.Errorf("%v %v", v, err)
	}
}

func learned(t *testing.T) *Doc {
	l := NewLearner(0)
	l.Enable(true)
	rec := func(m, p string, st int, ct string, prot bool, n int) {
		for i := 0; i < n; i++ {
			o := obs(m, p, st, t0.Add(time.Duration(i)*time.Hour))
			o.RespType, o.Protected, o.Route = ct, prot, firstSegment(p)
			l.Record(o)
		}
	}
	rec("GET", "/orders", 200, "application/json", true, 5)
	rec("GET", "/orders/17", 200, "application/json", true, 5)
	rec("GET", "/orders/17", 500, "application/json", true, 2)
	rec("GET", "/orders/18", 200, "text/html", true, 1)
	rec("PUT", "/orders/17", 200, "application/json", true, 2)
	rec("GET", "/admin/debug", 200, "text/plain", false, 3) // shadow
	rec("GET", "/orders/export", 200, "text/csv", false, 2) // open, sibling protected
	rec("POST", "/orders", 201, "application/json", true, 2)
	rec("GET", "/exports/9", 200, "application/json", false, 1)
	d := l.Snapshot()
	d.Source = "inv.json"
	return d
}

func TestDiff(t *testing.T) {
	s, _ := ParseSpec([]byte(specJSON))
	s.Source = "orders.json"
	r := Diff(s, learned(t), DiffOptions{})
	by := map[string][]string{}
	for _, f := range r.Findings {
		by[f.Kind] = append(by[f.Kind], f.Method+" "+f.Path+" "+f.Sub)
	}
	if !reflect.DeepEqual(by["shadow"], []string{"GET /admin/debug ", "GET /exports/{id} "}) {
		t.Errorf("shadow %v", by["shadow"])
	}
	z := strings.Join(by["zombie"], ";")
	if !strings.Contains(z, "DELETE /orders/{orderId}") || !strings.Contains(z, "GET /legacy") || strings.Contains(z, "/orders/export") {
		t.Errorf("zombie %v", by["zombie"])
	}
	d := strings.Join(by["drift"], ";")
	for _, w := range []string{"PUT /orders/{id} method", "GET /orders/{id} content-type", "GET /orders/{id} status"} {
		if !strings.Contains(d, w) {
			t.Errorf("drift missing %q in %v", w, by["drift"])
		}
	}
	if !reflect.DeepEqual(by["auth"], []string{"GET /orders/export siblings"}) {
		t.Errorf("auth %v", by["auth"])
	}
	// the {id} 500 is undocumented for GET /orders/{orderId}; 200 and 404 are fine
	if !strings.Contains(fmt.Sprint(r.Findings), "500 (2 requests)") {
		t.Errorf("status finding missing: %v", r.Findings)
	}
	ign := Diff(s, learned(t), DiffOptions{IgnoreStatus: map[string]bool{"500": true}})
	if strings.Contains(fmt.Sprint(ign.Findings), "500 (") {
		t.Error("ignored status still reported")
	}
	min := Diff(s, learned(t), DiffOptions{MinRequests: 3})
	for _, f := range min.Findings {
		if f.Kind == KindShadow && f.Path == "/exports/{id}" {
			t.Error("min-requests ignored")
		}
	}
	if len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "observation window") && r.Window.Last.Sub(r.Window.First) < 24*time.Hour {
		t.Errorf("notes %v", r.Notes)
	}
}

func TestSpecSecuredAuthGap(t *testing.T) {
	s, _ := ParseSpec([]byte(specJSON))
	l := NewLearner(0)
	l.Enable(true)
	o := obs("GET", "/orders", 200, t0)
	l.Record(o) // open, no protected sibling anywhere, spec secured globally
	r := Diff(s, l.Snapshot(), DiffOptions{})
	found := false
	for _, f := range r.Findings {
		if f.Kind == KindAuth && f.Sub == "spec" {
			found = true
		}
	}
	if !found {
		t.Errorf("spec auth gap missing: %v", r.Findings)
	}
}

func TestFailOnAndMarkdown(t *testing.T) {
	s, _ := ParseSpec([]byte(specJSON))
	r := Diff(s, learned(t), DiffOptions{})
	fo, err := ParseFailOn("shadow,zombie")
	if err != nil {
		t.Fatal(err)
	}
	r.ApplyFailOn(fo)
	if !r.Failed {
		t.Error("not failed")
	}
	clean := &Report{Counts: map[string]int{}}
	clean.ApplyFailOn([]string{"drift"})
	if clean.Failed {
		t.Error("failed with no findings")
	}
	if _, err := ParseFailOn("nope"); err == nil {
		t.Error("bad fail-on accepted")
	}
	if a, _ := ParseFailOn("any"); len(a) != 4 {
		t.Errorf("any = %v", a)
	}
	md := r.Markdown()
	for _, w := range []string{"## API contract check", "### Shadow APIs", "`GET /admin/debug`", "### Zombie APIs", "| Kind | Count |"} {
		if !strings.Contains(md, w) {
			t.Errorf("markdown missing %q:\n%s", w, md)
		}
	}
}

func TestExportOpenAPI(t *testing.T) {
	d := learned(t)
	doc := ExportOpenAPI(d, ExportOptions{Title: "T", Server: "https://x.test"})
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSpec(b) // the export is itself a valid document
	if err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.1.0" || len(s.Ops) != len(d.Endpoints) {
		t.Fatalf("ops %d vs %d", len(s.Ops), len(d.Endpoints))
	}
	if got := strings.Join(PathKeys(doc), " "); !strings.Contains(got, "/orders/{orderId}") || !strings.Contains(got, "/exports/{exportId}") {
		t.Errorf("paths %s", got)
	}
	if !strings.Contains(string(b), "x-setura-observed") {
		t.Error("no observed stats")
	}
	// the exported document sees no difference from the traffic it came from
	r := Diff(s, d, DiffOptions{})
	if len(r.Findings) != 0 && r.Counts[KindShadow]+r.Counts[KindZombie]+r.Counts[KindDrift] != 0 {
		t.Errorf("round trip not clean: %v", r.Findings)
	}
	if n, names := pathParamNames("/a/{id}/b-items/{id}/{id}"); n != "/a/{aId}/b-items/{b-itemId}/{id}" && n != "/a/{aId}/b-items/{bItemId}/{id}" || len(names) != 3 {
		t.Errorf("names %s %v", n, names)
	}
}
