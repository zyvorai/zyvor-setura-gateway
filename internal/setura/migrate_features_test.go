package setura

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func migJSON(t *testing.T, args ...string) (int, *migrateReport) {
	t.Helper()
	code, out, errs := cli(t, nil, append(append([]string{"migrate", "check"}, args...), "--format", "json")...)
	var rep migrateReport
	if code != 2 {
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%v: %q %q", err, out, errs)
		}
	}
	return code, &rep
}

func ruleAt(t *testing.T, rep *migrateReport, host, path string) *ruleResult {
	t.Helper()
	for _, r := range rep.Rules {
		if r.Host == host && r.Path == path {
			return r
		}
	}
	t.Fatalf("no rule %s%s in %+v", host, path, rep.Rules)
	return nil
}

const namedIngress = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: demo}
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /web, pathType: Prefix, backend: {service: {name: web, port: {name: http}}}}
`

func namedRoute(port int) string {
	return `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: web-a-example-test, namespace: demo}
spec:
  hostnames: [a.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /web}}]
    backendRefs: [{name: web, port: ` + itoa(port) + `}]
`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

const webService = `apiVersion: v1
kind: Service
metadata: {name: web, namespace: demo}
spec:
  ports:
  - {name: metrics, port: 9090}
  - {name: http, port: 8080, targetPort: 80}
`

func TestMigrateNamedPorts(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", namedIngress)
	svc := writeTmp(t, "svc.yaml", webService)

	// Equivalent once the name resolves to 8080.
	code, rep := migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt.yaml", namedRoute(8080)), "--services", svc)
	is(t, code, 0)
	r := ruleAt(t, rep, "a.example.test", "/web")
	is(t, r.Status, statusEquivalent)
	is(t, r.Backend, "web:http(8080)")

	// The targetPort (80) is not the Service port.
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt2.yaml", namedRoute(80)), "--services", svc)
	is(t, code, 1)
	r = ruleAt(t, rep, "a.example.test", "/web")
	is(t, r.Status, statusDifferent)
	contains(t, strings.Join(r.Details, "|"), "backend port differs: Ingress web:http(8080)")

	// Without any Service the port is reported unresolved, not ignored.
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt3.yaml", namedRoute(8080)))
	is(t, code, 1)
	r = ruleAt(t, rep, "a.example.test", "/web")
	is(t, r.Status, statusUnresolved)
	contains(t, strings.Join(r.Details, "|"), `named port "http" unresolved`)
	is(t, rep.Summary[statusUnresolved], 1)

	// A Service that lacks the name.
	other := writeTmp(t, "other.yaml", "apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: demo}\nspec:\n  ports:\n  - {name: grpc, port: 50051}\n")
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt4.yaml", namedRoute(8080)), "--services", other)
	is(t, code, 1)
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "|"), `has no port named "http"`)

	// Services for other workloads do not help: unresolved and says so.
	elsewhere := writeTmp(t, "else.yaml", strings.Replace(webService, "name: web,", "name: nope,", 1))
	_, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt5.yaml", namedRoute(8080)), "--services", elsewhere)
	r = ruleAt(t, rep, "a.example.test", "/web")
	is(t, r.Status, statusUnresolved)
	contains(t, strings.Join(r.Details, "|"), "was not found in the loaded Services")

	// Service objects inside the --routes input are picked up, in a directory too.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(namedRoute(8080)+"---\n"+webService), 0o600)
	code, rep = migJSON(t, "--ingress", ing, "--routes", dir)
	is(t, code, 0)
	is(t, ruleAt(t, rep, "a.example.test", "/web").Status, statusEquivalent)
}

// clusterOf answers kubectl get calls by resource name.
func clusterOf(byResource map[string]any) (*Cluster, *[]string) {
	var asked []string
	return &Cluster{Exec: func(args []string) (string, string, int, error) {
		for i, a := range args {
			if a == "get" && i+1 < len(args) {
				asked = append(asked, args[i+1])
				if v, ok := byResource[args[i+1]]; ok {
					b, _ := json.Marshal(v)
					return string(b), "", 0, nil
				}
				return "", "error: the server doesn't have a resource type", 1, nil
			}
		}
		return `{"items":[]}`, "", 0, nil
	}}, &asked
}

func TestMigrateNamedPortsFromCluster(t *testing.T) {
	var ing, rt, svc any
	for _, p := range []struct {
		v   *any
		src string
	}{{&ing, namedIngress}, {&rt, namedRoute(8080)}, {&svc, webService}} {
		*p.v = map[string]any{"items": []any{mustDoc(t, p.src)}}
	}
	c, asked := clusterOf(map[string]any{
		"ingresses.networking.k8s.io":          ing,
		"httproutes.gateway.networking.k8s.io": rt,
		"services":                             svc,
	})
	code, out, errs := cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	is(t, code, 0)
	contains(t, out, "web:http(8080)")
	contains(t, strings.Join(*asked, " "), "services")
	_ = errs
}

const grpcIngress = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rpc
  namespace: demo
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
spec:
  ingressClassName: nginx
  rules:
  - host: rpc.example.test
    http:
      paths:
      - {path: /helloworld.Greeter, pathType: Prefix, backend: {service: {name: greeter, port: {number: 50051}}}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pass
  namespace: demo
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: db.example.test
    http:
      paths:
      - {path: /, pathType: Prefix, backend: {service: {name: db, port: {number: 5432}}}}
`

const grpcRoutes = `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gw, namespace: demo}
spec:
  listeners:
  - {name: https, protocol: HTTPS, port: 443, hostname: rpc.example.test, tls: {certificateRefs: [{name: rpc-tls}]}}
  - {name: tls, protocol: TLS, port: 8443, hostname: db.example.test, tls: {mode: Passthrough}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata: {name: rpc-rpc-example-test, namespace: demo}
spec:
  parentRefs: [{name: gw}]
  hostnames: [rpc.example.test]
  rules:
  - matches: [{method: {service: helloworld.Greeter}}]
    backendRefs: [{name: greeter, port: 50051}]
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata: {name: pass-db-example-test, namespace: demo}
spec:
  parentRefs: [{name: gw, sectionName: tls}]
  hostnames: [db.example.test]
  rules:
  - backendRefs: [{name: db, port: 5432}]
`

func TestMigrateGRPCAndTLSRoutes(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", grpcIngress)
	code, rep := migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt.yaml", grpcRoutes))
	is(t, code, 0)
	g := ruleAt(t, rep, "rpc.example.test", "/helloworld.Greeter")
	is(t, g.Status, statusEquivalent)
	is(t, g.Kind, kindGRPCRoute)
	is(t, g.RouteKind, kindGRPCRoute)
	is(t, g.IngressClass, "nginx")
	d := ruleAt(t, rep, "db.example.test", "/")
	is(t, d.Status, statusEquivalent)
	is(t, d.RouteKind, kindTLSRoute)
	// The annotations are handled by the route kinds, not flagged.
	is(t, rep.Summary["annotations_flagged"], 0)

	// GRPC rule converted to an HTTPRoute, TLS passthrough missing its TLSRoute.
	bad := strings.Replace(grpcRoutes, "kind: GRPCRoute", "kind: HTTPRoute", 1)
	bad = strings.Replace(bad, "matches: [{method: {service: helloworld.Greeter}}]", "matches: [{path: {type: PathPrefix, value: /helloworld.Greeter}}]", 1)
	i := strings.Index(bad, "---\napiVersion: gateway.networking.k8s.io/v1alpha2")
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "bad.yaml", bad[:i]))
	is(t, code, 1)
	g = ruleAt(t, rep, "rpc.example.test", "/helloworld.Greeter")
	is(t, g.Status, statusDifferent)
	contains(t, strings.Join(g.Details, "|"), "converts to a GRPCRoute (backend-protocol GRPC) but the matching rule is in a HTTPRoute")
	is(t, ruleAt(t, rep, "db.example.test", "/").Status, statusMissing)
	is(t, rep.Summary["annotations_flagged"], 2)

	// Passthrough needs a TLS listener in Passthrough mode.
	term := strings.Replace(grpcRoutes, "tls: {mode: Passthrough}", "tls: {mode: Terminate, certificateRefs: [{name: x}]}", 1)
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "term.yaml", term))
	is(t, code, 1)
	contains(t, strings.Join(ruleAt(t, rep, "db.example.test", "/").Details, "|"), "tls.mode Passthrough")

	// Wrong backend port in a GRPCRoute.
	wrong := strings.Replace(grpcRoutes, "port: 50051", "port: 50052", 1)
	_, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "wrong.yaml", wrong))
	contains(t, strings.Join(ruleAt(t, rep, "rpc.example.test", "/helloworld.Greeter").Details, "|"), "backend port differs")

	// Extra gRPC route.
	extra := grpcRoutes + "---\napiVersion: gateway.networking.k8s.io/v1\nkind: GRPCRoute\nmetadata: {name: x, namespace: demo}\nspec:\n  hostnames: [rpc.example.test]\n  rules:\n  - matches: [{method: {service: other.Svc, method: Do}}]\n    backendRefs: [{name: o, port: 1}]\n"
	_, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "extra.yaml", extra))
	e := ruleAt(t, rep, "rpc.example.test", "/other.Svc/Do")
	is(t, e.Status, statusExtra)
	is(t, e.RouteKind, kindGRPCRoute)
}

const classIngresses = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: a, namespace: demo}
spec:
  ingressClassName: nginx
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /, pathType: Prefix, backend: {service: {name: a, port: {number: 80}}}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: b
  namespace: demo
  annotations: {kubernetes.io/ingress.class: internal}
spec:
  rules:
  - host: b.example.test
    http:
      paths:
      - {path: /, pathType: Prefix, backend: {service: {name: b, port: {number: 80}}}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: c, namespace: demo}
spec:
  rules:
  - host: c.example.test
    http:
      paths:
      - {path: /, pathType: Prefix, backend: {service: {name: c, port: {number: 80}}}}
`

const classRoutes = `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: a-a-example-test, namespace: demo}
spec:
  hostnames: [a.example.test]
  rules: [{backendRefs: [{name: a, port: 80}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: b-b-example-test, namespace: demo}
spec:
  hostnames: [b.example.test]
  rules: [{backendRefs: [{name: b, port: 80}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: c-c-example-test, namespace: demo}
spec:
  hostnames: [c.example.test]
  rules: [{backendRefs: [{name: c, port: 80}]}]
`

func TestMigrateIngressClass(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", classIngresses)
	rts := writeTmp(t, "rt.yaml", classRoutes)

	// All classes by default, each rule reports its class.
	code, rep := migJSON(t, "--ingress", ing, "--routes", rts)
	is(t, code, 0)
	is(t, ruleAt(t, rep, "a.example.test", "/").IngressClass, "nginx")
	is(t, ruleAt(t, rep, "b.example.test", "/").IngressClass, "internal") // legacy annotation
	is(t, ruleAt(t, rep, "c.example.test", "/").IngressClass, "")

	// Only nginx: the routes of the other classes are not "extra".
	code, rep = migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-class", "nginx")
	is(t, code, 0)
	is(t, len(rep.Rules), 1)
	is(t, rep.Rules[0].IngressClass, "nginx")
	contains(t, strings.Join(rep.Notes, "|"), "skipped 2 Ingress objects not of class")
	contains(t, strings.Join(rep.Notes, "|"), "2 route rules belong to Ingresses of other classes")

	// The legacy annotation selects too.
	_, rep = migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-class", "internal")
	is(t, len(rep.Rules), 1)
	is(t, rep.Rules[0].Host, "b.example.test")

	// A class-less Ingress belongs to the default IngressClass when it is loaded.
	dflt := "apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata:\n  name: nginx\n  annotations:\n    ingressclass.kubernetes.io/is-default-class: \"true\"\nspec: {controller: k8s.io/ingress-nginx}\n"
	_, rep = migJSON(t, "--ingress", writeTmp(t, "ing2.yaml", classIngresses+"---\n"+dflt), "--routes", rts, "--ingress-class", "nginx")
	is(t, len(rep.Rules), 2)

	// Unknown class: setup error.
	if code, _, errs := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--ingress-class", "nope"); code != 2 {
		t.Errorf("unknown class: exit %d (%s)", code, errs)
	}

	// Pretty output shows the class.
	_, out, _ := cli(t, nil, "--color", "never", "--ascii", "migrate", "check", "--ingress", ing, "--routes", rts, "--format", "pretty")
	contains(t, out, "CLASS")
	contains(t, out, "internal")
}

func TestMigrateTLSSecrets(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: demo}
spec:
  tls:
  - {hosts: [a.example.test], secretName: web-tls}
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}
`)
	routes := func(secret string) string {
		return `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gw, namespace: demo}
spec:
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    tls:
      certificateRefs:
      - name: ` + secret + `
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: web-a-example-test, namespace: demo}
spec:
  parentRefs: [{name: gw}]
  hostnames: [a.example.test]
  rules: [{backendRefs: [{name: web, port: 80}]}]
`
	}
	code, rep := migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "ok.yaml", routes("web-tls")))
	is(t, code, 0)
	is(t, ruleAt(t, rep, "a.example.test", "/").Status, statusEquivalent)
	code, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "bad.yaml", routes("other-tls")))
	is(t, code, 1)
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/").Details, "|"), `TLS secret "web-tls" in Ingress is not in the certificateRefs`)
}

func TestMigrateProbeExtra(t *testing.T) {
	var hits atomic.Int64
	srv := func(body string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/extra" {
				hits.Add(1)
			}
			w.Header().Set("X-Setura-Backend", body)
			w.WriteHeader(200)
		}))
		t.Cleanup(s.Close)
		return s
	}
	a, b := srv("one"), srv("two")
	ing := writeTmp(t, "ing.yaml", migIngressSimple)
	rts := writeTmp(t, "rt.yaml", strings.Replace(migRouteSimple, "custom-name", "web-a-example-test", 1)+
		"---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\nmetadata: {name: x, namespace: demo}\nspec:\n  hostnames: [a.example.test]\n  rules:\n  - matches: [{path: {type: PathPrefix, value: /extra}}]\n    backendRefs: [{name: x, port: 80}]\n")
	args := []string{"--ingress", ing, "--routes", rts, "--ingress-url", a.URL, "--gateway-url", b.URL, "--address", "127.0.0.1"}
	_, rep := migJSON(t, args...)
	is(t, hits.Load(), int64(0))
	if ruleAt(t, rep, "a.example.test", "/extra").Probe != nil {
		t.Error("extra route probed without --probe-extra")
	}
	_, rep = migJSON(t, append(args, "--probe-extra")...)
	if hits.Load() != 2 {
		t.Errorf("extra route hits = %d, want 2 (one per target)", hits.Load())
	}
	e := ruleAt(t, rep, "a.example.test", "/extra")
	if e.Probe == nil {
		t.Fatal("extra route not probed")
	}
	is(t, e.Status, statusExtra)
	contains(t, strings.Join(e.Details, "|"), "backend identity")
	// --probe-extra without live URLs is a usage error.
	if code, _, _ := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--probe-extra"); code != 2 {
		t.Error("--probe-extra without URLs should exit 2")
	}
}
