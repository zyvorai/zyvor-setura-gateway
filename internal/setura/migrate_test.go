package setura

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const migIngress = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: demo
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: "/$1"   # quoted
    nginx.ingress.kubernetes.io/server-snippet: |
      location /x { return 404; }
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - path: /api/
        pathType: Prefix
        backend: {service: {name: api, port: {number: 80}}}
      - path: /exact
        pathType: Exact
        backend:
          service:
            name: ex
            port:
              name: http
`

const migRoutes = `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: web-a-example-test, namespace: demo}
spec:
  hostnames: [a.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /api}}]
    filters: [{type: URLRewrite, urlRewrite: {hostname: x}}]
    backendRefs: [{name: api, port: 80}]
  - matches: [{path: {type: PathPrefix, value: /exact}}]
    backendRefs: [{name: ex, port: 80}]
  - matches: [{path: {type: PathPrefix, value: /extra}}]
    backendRefs: [{name: other, port: 80}]
`

const migIngressSimple = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: demo}
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /api, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}
`

const migRouteSimple = `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: custom-name, namespace: demo}
spec:
  hostnames: [a.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /api}}]
    backendRefs: [{name: api, port: 80}]
`

func writeTmp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestYAMLSubset(t *testing.T) {
	docs, err := decodeManifests([]byte("---\na: 1\nb: [x, 'y z', {k: v}]\nc:\n- p: true\n  q: ~\n- \"s: t\"\nd: >\n  one\n  two\ne:\n  - - 1\n    - 2\n---\n# only comment\n---\nx: z # c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("docs: %v", docs)
	}
	got, _ := json.Marshal(docs)
	want := `[{"a":1,"b":["x","y z",{"k":"v"}],"c":[{"p":true,"q":null},"s: t"],"d":"one two\n","e":[[1,2]]},{"x":"z"}]`
	if string(got) != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if _, err := decodeManifests([]byte("a:\n\tb: 1\n")); err == nil {
		t.Error("tab indentation accepted")
	}
	docs, err = decodeManifests([]byte(`{"kind":"List","items":[]}`))
	if err != nil || len(docs) != 1 {
		t.Fatalf("json: %v %v", docs, err)
	}
}

func TestMigrateStaticDifferences(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", migIngress)
	rts := writeTmp(t, "rt.yaml", migRoutes)
	code, out, errs := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--format", "json")
	is(t, code, 1)
	var rep migrateReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v %q %q", err, out, errs)
	}
	byPath := map[string]*ruleResult{}
	for _, r := range rep.Rules {
		byPath[r.Path] = r
	}
	is(t, byPath["/api/"].Status, statusEquivalent) // trailing slash normalised
	is(t, byPath["/api/"].Route, "web-a-example-test")
	is(t, byPath["/exact"].Status, statusDifferent)
	contains(t, strings.Join(byPath["/exact"].Details, "|"), "path type Exact in Ingress, PathPrefix in HTTPRoute")
	is(t, byPath["/extra"].Status, statusExtra)
	is(t, rep.Summary["annotations_flagged"], 1) // rewrite-target handled, ssl-redirect false skipped
	is(t, len(rep.Annotations), 2)
	for _, a := range rep.Annotations {
		if strings.HasSuffix(a.Annotation, "rewrite-target") && !a.Handled {
			t.Error("rewrite-target should be handled by URLRewrite filter")
		}
		if strings.HasSuffix(a.Annotation, "server-snippet") && a.Support != supportNone {
			t.Errorf("server-snippet support = %s", a.Support)
		}
	}
}

func TestMigrateEquivalentAndFormats(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", migIngressSimple)
	rts := writeTmp(t, "rt.yaml", migRouteSimple)
	code, out, _ := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--format", "json")
	is(t, code, 0)
	contains(t, out, `"ok": true`)
	contains(t, out, "ingress2gateway convention") // naming note on an equivalent rule
	code, out, _ = cli(t, nil, "--color", "never", "--ascii", "migrate", "check", "--ingress", ing, "--routes", rts, "--format", "pretty")
	is(t, code, 0)
	contains(t, out, "equivalent")
	code, out, _ = cli(t, nil, "migrate", "check", "--ingress", writeTmp(t, "i.yaml", migIngress), "--routes", rts, "--format", "github")
	is(t, code, 1)
	contains(t, out, "::error")
	contains(t, out, "missing-in-gateway")
}

func TestMigrateUsageErrors(t *testing.T) {
	empty := &Cluster{Exec: func([]string) (string, string, int, error) { return `{"items":[]}`, "", 0, nil }}
	for _, args := range [][]string{
		{"migrate"}, {"migrate", "bogus"}, {"migrate", "check", "--ingress-url", "http://127.0.0.1:1"},
		{"migrate", "check", "--address", "127.0.0.1"}, {"migrate", "check", "--format", "xml"},
	} {
		code, _, errs := cli(t, empty, args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s)", args, code, errs)
		}
	}
	if code, _, _ := cli(t, nil, "migrate", "check", "--ingress", "/nonexistent/x.yaml", "--routes", "/nonexistent/y.yaml"); code != 2 {
		t.Error("missing file should exit 2")
	}
}

func TestMigrateFromClusterFake(t *testing.T) {
	ing := map[string]any{"items": []any{map[string]any{
		"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": map[string]any{"name": "web", "namespace": "demo"},
		"spec": map[string]any{
			"tls": []any{map[string]any{"hosts": []any{"a.example.test"}, "secretName": "s"}},
			"rules": []any{map[string]any{"host": "a.example.test", "http": map[string]any{"paths": []any{map[string]any{
				"path": "/", "pathType": "Prefix", "backend": map[string]any{"service": map[string]any{"name": "api", "port": map[string]any{"number": 80}}}}}}}}}}}}
	rt := map[string]any{"items": []any{map[string]any{
		"kind": "HTTPRoute", "metadata": map[string]any{"name": "web-a-example-test", "namespace": "demo"},
		"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "hostnames": []any{"a.example.test"}, "rules": []any{map[string]any{
			"backendRefs": []any{map[string]any{"name": "api", "port": 80}}}}}}}}
	gw := map[string]any{"items": []any{map[string]any{
		"kind": "Gateway", "metadata": map[string]any{"name": "gw", "namespace": "demo"},
		"spec": map[string]any{"listeners": []any{map[string]any{"name": "http", "protocol": "HTTP", "port": 80}}}}}}
	c, seen := keyedCluster(map[string]any{"ingresses.networking.k8s.io": ing, "httproutes.gateway.networking.k8s.io": rt, "gateways.gateway.networking.k8s.io": gw})
	code, out, errs := cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	is(t, code, 1) // TLS host but only an HTTP listener
	contains(t, out, "no HTTPS listener")
	if len(*seen) < 5 || !strings.Contains(strings.Join((*seen)[0], " "), "ingresses.networking.k8s.io") {
		t.Fatalf("kubectl calls: %v (%s)", *seen, errs)
	}
}

func TestMigrateLiveProbe(t *testing.T) {
	mk := func(status int, backend, loc string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Setura-Backend", backend)
			w.Header().Set("Content-Type", "text/plain")
			if loc != "" {
				w.Header().Set("Location", loc)
			}
			w.WriteHeader(status)
		}))
		t.Cleanup(s.Close)
		return s
	}
	ing := writeTmp(t, "ing.yaml", migIngressSimple)
	rts := writeTmp(t, "rt.yaml", strings.Replace(migRouteSimple, "custom-name", "web-a-example-test", 1))
	run := func(a, b string) (int, string) {
		code, out, _ := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--ingress-url", a, "--gateway-url", b, "--address", "127.0.0.1", "--format", "json")
		return code, out
	}
	s1, s2 := mk(200, "api-v1", ""), mk(200, "api-v1", "")
	code, out := run(s1.URL, s2.URL)
	is(t, code, 0)
	contains(t, out, `"probe"`)
	a, b := mk(301, "api-v1", "https://x/"), mk(200, "api-v2", "")
	code, out = run(a.URL, b.URL)
	is(t, code, 1)
	for _, want := range []string{"status 301 via Ingress, 200 via Gateway", "redirect target", "backend identity"} {
		contains(t, out, want)
	}
	dead := mk(200, "x", "")
	dead.Close()
	code, out = run(a.URL, dead.URL)
	is(t, code, 1)
	contains(t, out, "gateway probe failed")
}

func TestMigrateHelp(t *testing.T) {
	code, _, errs := cli(t, nil, "migrate", "-h")
	is(t, code, 0)
	contains(t, errs, "-ingress-url")
	contains(t, errs, "Examples")
	if len(annotationHintTable()) < 30 {
		t.Error("annotation table unexpectedly small")
	}
}

func TestMigrateExamplesDiffer(t *testing.T) {
	code, out, errs := cli(t, nil, "migrate", "check", "--ingress", "../../examples/migrate/ingress.yaml", "--routes", "../../examples/migrate/routes.yaml", "--services", "../../examples/migrate/services.yaml", "--format", "json")
	is(t, code, 1)
	for _, want := range []string{statusMissing, statusExtra, "backend port differs", "configuration-snippet", "web:http(8080)", "GRPCRoute", `"ingress_class": "internal"`} {
		contains(t, out, want)
	}
	_ = errs
}
