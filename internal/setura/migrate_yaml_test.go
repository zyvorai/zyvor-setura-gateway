package setura

import (
	"encoding/json"
	"strings"
	"testing"
)

func yamlJSON(t *testing.T, src string) string {
	t.Helper()
	docs, err := decodeManifests([]byte(src))
	if err != nil {
		t.Fatalf("%v\n%s", err, src)
	}
	var v any = docs
	if len(docs) == 1 {
		v = docs[0]
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestYAMLAdvanced(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"anchor and alias", "a: &x {k: v}\nb: *x\n", `{"a":{"k":"v"},"b":{"k":"v"}}`},
		{"anchor on block map", "base: &base\n  port: 80\n  name: web\nuse: *base\n", `{"base":{"name":"web","port":80},"use":{"name":"web","port":80}}`},
		{"anchor scalar", "a: &n 8080\nb: *n\n", `{"a":8080,"b":8080}`},
		{"merge key", "base: &b {x: 1, y: 2}\nm:\n  <<: *b\n  y: 3\n", `{"base":{"x":1,"y":2},"m":{"x":1,"y":3}}`},
		{"merge list earlier wins", "a: &a {k: 1}\nb: &b {k: 2, j: 3}\nm:\n  <<: [*a, *b]\n", `{"a":{"k":1},"b":{"j":3,"k":2},"m":{"j":3,"k":1}}`},
		{"merge in seq item", "d: &d {proto: TCP}\nports:\n- <<: *d\n  port: 80\n", `{"d":{"proto":"TCP"},"ports":[{"port":80,"proto":"TCP"}]}`},
		{"anchor in sequence", "l:\n- &i {a: 1}\n- *i\n", `{"l":[{"a":1},{"a":1}]}`},
		{"anchor on seq item block", "l:\n- &i\n  a: 1\n- *i\n", `{"l":[{"a":1},{"a":1}]}`},
		{"tag str", "a: !!str 123\nb: !!str true\nc: !!str\n", `{"a":"123","b":"true","c":""}`},
		{"tag int float bool", "a: !!int \"7\"\nb: !!float 1\nc: !!bool \"true\"\nd: !!null x\n", `{"a":7,"b":1,"c":true,"d":null}`},
		{"unknown tag ignored", "a: !Ref foo\nb: !!binary aGk=\nc: !custom\n  k: v\n", `{"a":"foo","b":"aGk=","c":{"k":"v"}}`},
		{"tag in flow", "a: [!!str 1, !!str true]\n", `{"a":["1","true"]}`},
		{"directive", "%YAML 1.2\n---\na: 1\n", `{"a":1}`},
		{"doc start with content", "--- !!map\na: 1\n", `{"a":1}`},
		{"multi-line plain", "a: one\n  two\n  three\nb: x\n", `{"a":"one two three","b":"x"}`},
		{"multi-line plain with blank", "a: one\n\n  two\nb: x\n", `{"a":"one\ntwo","b":"x"}`},
		{"plain on next line", "a:\n  one\n  two\nb: x\n", `{"a":"one two","b":"x"}`},
		{"plain in seq", "l:\n- one\n  two\n- three\n", `{"l":["one two","three"]}`},
		{"plain with url colon", "a: http://x:80/p\n", `{"a":"http://x:80/p"}`},
		{"multi-line double", "a: \"one\n  two\\n\n  three\"\nb: 1\n", `{"a":"one two\n three","b":1}`},
		{"double line continuation", "a: \"foo \\\n   bar\"\n", `{"a":"foo bar"}`},
		{"multi-line single", "a: 'it''s\n  here\n\n  there'\nb: 1\n", `{"a":"it's here\nthere","b":1}`},
		{"quoted with hash", "a: \"x # y\n  z\" # tail\nb: 1\n", `{"a":"x # y z","b":1}`},
		{"double escapes", "a: \"\\u00e9\\x41\\t\\\"\"\n", `{"a":"éA\t\""}`},
		{"multi-line flow seq", "a: [one,\n  two,   # c\n  \"three\nfour\"]\nb: 1\n", `{"a":["one","two","three four"],"b":1}`},
		{"multi-line flow map", "a: {\n  k: v,\n  n: [1,\n 2]\n}\nb: 1\n", `{"a":{"k":"v","n":[1,2]},"b":1}`},
		{"flow in seq item", "l:\n- [a,\n  b]\n- {k:\n  v}\n", `{"l":[["a","b"],{"k":"v"}]}`},
		{"flow plain scalar multi-line", "a: [one\n  two, three]\n", `{"a":["one two","three"]}`},
		{"folded blank lines", "a: >\n  one\n  two\n\n  three\n", `{"a":"one two\nthree\n"}`},
		{"folded more indented", "a: >\n  one\n    two\n  three\n", `{"a":"one\n  two\nthree\n"}`},
		{"literal strip keep", "a: |-\n  x\n  y\nb: |+\n  z\n\nc: 1\n", `{"a":"x\ny","b":"z\n\n","c":1}`},
		{"indentation indicator", "a: |2\n    x\n   y\nb: 1\n", `{"a":"  x\n y\n","b":1}`},
		{"block scalar in seq", "l:\n- |\n  a\n  b\n- c\n", `{"l":["a\nb\n","c"]}`},
		{"wildcard host unquoted", "host: *.example.com\n", `{"host":"*.example.com"}`},
		{"comment after key", "a: # c\n  b: 1\n", `{"a":{"b":1}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := yamlJSON(t, c.src); got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestYAMLErrors(t *testing.T) {
	for name, src := range map[string]string{
		"unknown alias":    "a: *nope\n",
		"unterminated dq":  "a: \"abc\nb: 1\n",
		"unterminated sq":  "a: 'abc\n",
		"unterminated seq": "a: [1, 2\nb: 3\n",
		"bad merge":        "a: 1\nm:\n  <<: *x\n",
		"tab indent":       "a:\n\tb: 1\n",
	} {
		if _, err := decodeManifests([]byte(src)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// Ingress manifests as emitted by helm charts and kubectl, with the YAML
// features that used to defeat the built-in reader.
var helmIngresses = []struct{ name, src string }{
	{"anchors and merge keys", `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: demo
  annotations: &ann
    nginx.ingress.kubernetes.io/proxy-body-size: 8m
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - &p
        path: /api
        pathType: Prefix
        backend: &be
          service:
            name: api
            port: {number: 80}
      - <<: *p
        path: /v2
        backend: *be
`},
	{"multi-line quoted annotation and folded host", `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: demo
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "8m"
    meta.helm.sh/release-note: "first line
      second line"
spec:
  rules:
    - host: a.example.test
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
          - path: /v2
            pathType: Prefix
            backend: {service: {name: api,
                                port: {number: 80}}}
`},
	{"tags and comments", `
# Source: chart/templates/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: !!str web
  namespace: demo
  labels:
    helm.sh/chart: chart-1.2.3
spec:
  rules:
    - host: !!str a.example.test   # primary
      http:
        paths:
          - {path: /api, pathType: Prefix, backend: {service: {name: api, port: {number: !!int "80"}}}}
          - path: /v2
            pathType: Prefix
            backend:
              service:
                name: api
                port: {number: 80}
`},
	{"document markers, crlf and list wrapper", "---\r\n# Source: x\r\napiVersion: v1\r\nkind: List\r\nitems:\r\n- apiVersion: networking.k8s.io/v1\r\n  kind: Ingress\r\n  metadata: {name: web, namespace: demo}\r\n  spec:\r\n    rules:\r\n    - host: a.example.test\r\n      http:\r\n        paths:\r\n        - {path: /api, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}\r\n        - {path: /v2, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}\r\n...\r\n"},
}

func TestYAMLHelmIngresses(t *testing.T) {
	for _, c := range helmIngresses {
		t.Run(c.name, func(t *testing.T) {
			docs, err := decodeManifests([]byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			var ings []obj
			for _, d := range docs {
				for _, o := range flattenList(d) {
					if kindOf(o, "Ingress") {
						ings = append(ings, o)
					}
				}
			}
			if len(ings) != 1 {
				t.Fatalf("ingresses: %d (%v)", len(ings), docs)
			}
			rules := extractIngressRules(ings[0], nil)
			if len(rules) != 2 {
				t.Fatalf("rules: %d", len(rules))
			}
			for i, want := range []string{"/api", "/v2"} {
				r := rules[i]
				if r.Path != want || r.Svc != "api" || r.Port != "80" || r.Host != "a.example.test" || r.PathType != "Prefix" {
					t.Errorf("rule %d = %+v", i, r)
				}
			}
			if n, _ := metaOf(ings[0]); n != "web" {
				t.Errorf("name = %q", n)
			}
		})
	}
	// The multi-line annotation survives with folding.
	docs, _ := decodeManifests([]byte(helmIngresses[1].src))
	if got := annotationsOf(asMap(docs[0]))["meta.helm.sh/release-note"]; got != "first line second line" {
		t.Errorf("annotation = %q", got)
	}
	if got := annotationsOf(asMap(mustDoc(t, helmIngresses[0].src)))[nginxPrefix+"proxy-body-size"]; got != "8m" {
		t.Errorf("anchored annotation = %q", got)
	}
	if !strings.Contains(helmIngresses[3].src, "\r\n") {
		t.Error("crlf case lost its carriage returns")
	}
}

func mustDoc(t *testing.T, src string) any {
	t.Helper()
	docs, err := decodeManifests([]byte(src))
	if err != nil || len(docs) == 0 {
		t.Fatalf("%v %v", docs, err)
	}
	return docs[0]
}
