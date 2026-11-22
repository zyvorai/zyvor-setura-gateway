package setura

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// keyedCluster answers `kubectl get RESOURCE` by resource name; anything not in
// the map is a NotFound error.
func keyedCluster(res map[string]any) (*Cluster, *[][]string) {
	var mu sync.Mutex
	var seen [][]string
	return &Cluster{Exec: func(args []string) (string, string, int, error) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, args)
		for i, a := range args {
			if a == "get" && i+1 < len(args) {
				if v, ok := res[args[i+1]]; ok {
					return js(v).stdout, "", 0, nil
				}
				return "", "the server doesn't have a resource type " + args[i+1], 1, nil
			}
		}
		return "", "unexpected", 1, nil
	}}, &seen
}

func items(objs ...string) map[string]any {
	var out []any
	for _, o := range objs {
		docs, err := decodeManifests([]byte(o))
		if err != nil {
			panic(err)
		}
		out = append(out, docs...)
	}
	return map[string]any{"items": out}
}

const namedService = `apiVersion: v1
kind: Service
metadata: {name: web, namespace: demo}
spec:
  ports:
  - {name: http, port: 8080, targetPort: 80}
  - {name: alt, port: 9090, targetPort: 8081}
`

func slice(ready bool, port int, name string) string {
	return `apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: web-abc, namespace: demo, labels: {kubernetes.io/service-name: web}}
endpoints:
- {addresses: ["10.0.0.1"], conditions: {ready: ` + map[bool]string{true: "true", false: "false"}[ready] + `}}
ports:
- {name: ` + name + `, port: ` + itoa(port) + `}
`
}

func TestMigrateNamedPortEndpoints(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", namedIngress)
	rts := writeTmp(t, "rt.yaml", namedRoute(8080))
	run := func(objects string) (int, *migrateReport) {
		return migJSON(t, "--ingress", ing, "--routes", rts, "--objects", writeTmp(t, "o.yaml", objects))
	}
	code, rep := run(namedService + "---\n" + slice(true, 80, "http"))
	is(t, code, 0)
	is(t, ruleAt(t, rep, "a.example.test", "/web").Status, statusEquivalent)

	code, rep = run(namedService + "---\n" + slice(false, 80, "http"))
	is(t, code, 1)
	r := ruleAt(t, rep, "a.example.test", "/web")
	is(t, r.Status, statusUnresolved)
	contains(t, strings.Join(r.Details, "\n"), `named port "http" (Service port 8080, targetPort 80) has no ready endpoints (1 not ready)`)

	// Endpoints that do not list the port by name, and a Service without any.
	_, rep = run(namedService + "---\n" + slice(true, 80, "other"))
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n"), "list no port with that name")
	_, rep = run(namedService + "---\n" + strings.Replace(slice(true, 80, "http"), "service-name: web", "service-name: elsewhere", 1))
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n"), "no EndpointSlice or Endpoints found for Service web")

	// The endpoints serve another port than the Service targetPort.
	_, rep = run(namedService + "---\n" + slice(true, 9999, "http"))
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n"), "the endpoints serve port 9999")

	// Legacy Endpoints objects work too.
	legacy := `apiVersion: v1
kind: Endpoints
metadata: {name: web, namespace: demo}
subsets:
- addresses: [{ip: 10.0.0.1}]
  notReadyAddresses: [{ip: 10.0.0.2}]
  ports: [{name: http, port: 80}]
`
	code, _ = run(namedService + "---\n" + legacy)
	is(t, code, 0)
	code, rep = run(namedService + "---\n" + strings.Replace(legacy, "addresses: [{ip: 10.0.0.1}]", "addresses: []", 1))
	is(t, code, 1)
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n"), "(1 not ready)")

	// Without any endpoint source the report says so and stays equivalent.
	code, rep = migJSON(t, "--ingress", ing, "--routes", rts, "--services", writeTmp(t, "s.yaml", namedService))
	is(t, code, 0)
	contains(t, strings.Join(rep.Notes, "\n"), "endpoints were not inspected")
}

func TestMigrateNamedPortTargetDiffers(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", namedIngress)
	svc := writeTmp(t, "s.yaml", namedService)
	code, rep := migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt.yaml", namedRoute(9090)), "--services", svc)
	is(t, code, 1)
	d := strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n")
	contains(t, d, "backend port differs")
	contains(t, d, "Ingress port http reaches targetPort 80, HTTPRoute port 9090 reaches targetPort 8081")
	_, rep = migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt.yaml", namedRoute(7777)), "--services", svc)
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/web").Details, "\n"), "port 7777 is not a port of Service web (ports: http=8080, alt=9090)")
}

func TestMigrateExternalName(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: ext, namespace: demo}
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /one, pathType: Prefix, backend: {service: {name: ext, port: {number: 80}}}}
      - {path: /two, pathType: Prefix, backend: {service: {name: local, port: {number: 80}}}}
      - {path: /three, pathType: Prefix, backend: {service: {name: ext, port: {name: http}}}}
`)
	route := writeTmp(t, "rt.yaml", `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: ext-a-example-test, namespace: demo}
spec:
  hostnames: [a.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /one}}]
    backendRefs: [{name: ext, port: 80}]
  - matches: [{path: {type: PathPrefix, value: /two}}]
    backendRefs: [{name: local, port: 80}]
  - matches: [{path: {type: PathPrefix, value: /three}}]
    backendRefs: [{name: ext, port: 80}]
`)
	svcs := writeTmp(t, "s.yaml", `apiVersion: v1
kind: Service
metadata: {name: ext, namespace: demo}
spec: {type: ExternalName, externalName: db.data.svc.cluster.local}
---
apiVersion: v1
kind: Service
metadata: {name: local, namespace: demo}
spec: {type: ExternalName, externalName: api.example.com}
---
apiVersion: v1
kind: Service
metadata: {name: db, namespace: data}
spec: {ports: [{name: sql, port: 5432}]}
`)
	code, rep := migJSON(t, "--ingress", ing, "--routes", route, "--services", svcs)
	is(t, code, 1) // the named port on an ExternalName Service cannot be resolved
	one := strings.Join(ruleAt(t, rep, "a.example.test", "/one").Details, "\n")
	contains(t, one, "ExternalName Service pointing at db.data.svc.cluster.local (the in-cluster Service data/db, ports sql=5432)")
	is(t, ruleAt(t, rep, "a.example.test", "/one").Status, statusEquivalent)
	contains(t, strings.Join(ruleAt(t, rep, "a.example.test", "/two").Details, "\n"), "pointing at api.example.com; it has no endpoints to inspect")
	three := ruleAt(t, rep, "a.example.test", "/three")
	is(t, three.Status, statusUnresolved)
	contains(t, strings.Join(three.Details, "\n"), "ExternalName Service (db.data.svc.cluster.local) and defines no ports")
}

const classIngress = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: demo}
spec:
  rules:
  - host: a.example.test
    http:
      paths:
      - {path: /api, pathType: Prefix, backend: {service: {name: api, port: {number: 80}}}}
`

func TestMigrateDefaultClassFromCluster(t *testing.T) {
	classes := map[string]any{"items": []any{
		map[string]any{"kind": "IngressClass", "metadata": map[string]any{"name": "other"}},
		map[string]any{"kind": "IngressClass", "metadata": map[string]any{"name": "nginx", "annotations": map[string]any{"ingressclass.kubernetes.io/is-default-class": "true"}}},
	}}
	res := map[string]any{
		"ingresses.networking.k8s.io":          items(classIngress),
		"ingressclasses.networking.k8s.io":     classes,
		"httproutes.gateway.networking.k8s.io": items(strings.Replace(migRouteSimple, "custom-name", "web-a-example-test", 1)),
	}
	c, seen := keyedCluster(res)
	code, out, errs := cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	is(t, code, 0)
	contains(t, out, `"ingress_class": "nginx"`)
	contains(t, out, `"ingress_class_default": true`)
	contains(t, out, "is the default IngressClass")
	if !strings.Contains(strings.Join(joinCalls(*seen), "\n"), "ingressclasses.networking.k8s.io") {
		t.Fatalf("IngressClasses were not read: %v (%s)", *seen, errs)
	}
	// An Ingress without a class belongs to --ingress-class nginx (the default) but not to other.
	code, out, _ = cli(t, c, "migrate", "check", "-n", "demo", "--ingress-class", "nginx", "--format", "json")
	is(t, code, 0)
	contains(t, out, `"ingress_class": "nginx"`)
	code, _, errs = cli(t, c, "migrate", "check", "-n", "demo", "--ingress-class", "other", "--format", "json")
	is(t, code, 2)
	contains(t, errs, "no Ingress objects of class")

	// Two defaults are called out.
	classes["items"] = append(classes["items"].([]any), map[string]any{"kind": "IngressClass", "metadata": map[string]any{"name": "aaa", "annotations": map[string]any{"ingressclass.kubernetes.io/is-default-class": "true"}}})
	c, _ = keyedCluster(res)
	_, out, _ = cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	contains(t, out, "several IngressClasses are marked default (aaa, nginx)")
}

func joinCalls(calls [][]string) []string {
	var out []string
	for _, c := range calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestMigrateDefaultClassFromFiles(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", classIngress)
	rts := writeTmp(t, "rt.yaml", strings.Replace(migRouteSimple, "custom-name", "web-a-example-test", 1))
	obj := writeTmp(t, "o.yaml", "apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata:\n  name: nginx\n  annotations:\n    ingressclass.kubernetes.io/is-default-class: \"true\"\nspec: {controller: k8s.io/ingress-nginx}\n")
	_, rep := migJSON(t, "--ingress", ing, "--routes", rts, "--objects", obj)
	is(t, rep.Rules[0].IngressClass, "nginx")
	is(t, rep.Rules[0].ClassDefault, true)
	_, rep = migJSON(t, "--ingress", ing, "--routes", rts)
	is(t, rep.Rules[0].IngressClass, "")
}

const crossRoutes = `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: web-a-example-test, namespace: demo}
spec:
  parentRefs: [{name: gw}]
  hostnames: [a.example.test]
  rules:
  - matches: [{path: {type: PathPrefix, value: /api}}]
    backendRefs: [{name: api, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: shared, namespace: demo}
spec:
  hostnames: [b.example.test]
  rules:
  - backendRefs: [{name: store, namespace: data, port: 80}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: gw, namespace: demo}
spec:
  listeners:
  - name: https
    protocol: HTTPS
    port: 443
    hostname: a.example.test
    tls:
      certificateRefs: [{name: wild, namespace: certs}]
`

func grant(ns, fromKind, fromNS, toKind, toName string) string {
	to := "{group: \"\", kind: " + toKind + "}"
	if toName != "" {
		to = "{group: \"\", kind: " + toKind + ", name: " + toName + "}"
	}
	return `apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: {name: g-` + strings.ToLower(toKind) + `, namespace: ` + ns + `}
spec:
  from: [{group: gateway.networking.k8s.io, kind: ` + fromKind + `, namespace: ` + fromNS + `}]
  to: [` + to + `]
`
}

func TestMigrateReferenceGrants(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", migIngressSimple)
	rts := writeTmp(t, "rt.yaml", crossRoutes)
	run := func(grants ...string) (int, *migrateReport, string) {
		args := []string{"--ingress", ing, "--routes", rts}
		if len(grants) > 0 {
			args = append(args, "--objects", writeTmp(t, "g.yaml", strings.Join(grants, "---\n")))
		}
		code, out, _ := cli(t, nil, append([]string{"migrate", "check"}, append(args, "--format", "json")...)...)
		rep := &migrateReport{}
		if err := json.Unmarshal([]byte(out), rep); err != nil {
			t.Fatal(err, out)
		}
		return code, rep, out
	}
	// A grant for something else: both references are missing.
	code, rep, out := run(grant("data", "HTTPRoute", "demo", "Service", "other"))
	is(t, code, 1)
	is(t, len(rep.Grants), 2)
	is(t, rep.Summary["grants_missing"], 2)
	g := rep.Grants[0] // sorted by namespace: certs before data
	is(t, g.Namespace, "certs")
	is(t, g.From, "Gateway demo/gw")
	is(t, g.To, "Secret certs/wild")
	for _, want := range []string{"kind: ReferenceGrant", "namespace: certs", "kind: Gateway", `group: ""`, "kind: Secret", "name: wild"} {
		contains(t, g.Fix, want)
	}
	is(t, rep.Grants[1].To, "Service data/store")
	contains(t, rep.Grants[1].Fix, "kind: HTTPRoute")
	contains(t, rep.Grants[1].Fix, "namespace: demo")
	contains(t, out, `"reference_grants"`)

	// Matching grants (one by name, one for every Secret) fix both.
	code, rep, _ = run(grant("data", "HTTPRoute", "demo", "Service", "store"), grant("certs", "Gateway", "demo", "Secret", ""))
	is(t, len(rep.Grants), 0)
	_ = rep

	// A grant from the wrong namespace or kind does not count.
	_, rep, _ = run(grant("data", "HTTPRoute", "elsewhere", "Service", "store"), grant("certs", "TLSRoute", "demo", "Secret", ""))
	is(t, len(rep.Grants), 2)

	// Without any ReferenceGrant source the references are not judged.
	code, rep, _ = run()
	is(t, len(rep.Grants), 0)
	contains(t, strings.Join(rep.Notes, "\n"), "cross-namespace references into certs, data were not checked")

	// A pretty report names the grant.
	_, pretty, _ := cli(t, nil, "--color", "never", "--ascii", "migrate", "check", "--ingress", ing, "--routes", rts, "--objects", writeTmp(t, "g.yaml", grant("x", "HTTPRoute", "y", "Service", "z")), "--format", "pretty")
	contains(t, pretty, "ReferenceGrants")
	contains(t, pretty, "kind: ReferenceGrant")
	_, gh, _ := cli(t, nil, "migrate", "check", "--ingress", ing, "--routes", rts, "--objects", writeTmp(t, "g.yaml", grant("x", "HTTPRoute", "y", "Service", "z")), "--format", "github")
	contains(t, gh, "needs a ReferenceGrant in namespace data")
}

func TestMigrateReferenceGrantsFromCluster(t *testing.T) {
	res := map[string]any{
		"ingresses.networking.k8s.io":               items(migIngressSimple),
		"httproutes.gateway.networking.k8s.io":      items(crossRoutes),
		"gateways.gateway.networking.k8s.io":        items(crossRoutes),
		"referencegrants.gateway.networking.k8s.io": items(grant("data", "HTTPRoute", "demo", "Service", "store")),
	}
	c, seen := keyedCluster(res)
	code, out, _ := cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	is(t, code, 1)
	contains(t, out, `"namespace": "certs"`)
	if strings.Contains(out, `"to": "Service data/store"`) {
		t.Error("the data grant was read from the cluster but not honoured")
	}
	calls := strings.Join(joinCalls(*seen), "\n")
	contains(t, calls, "-n certs get referencegrants.gateway.networking.k8s.io")
	contains(t, calls, "-n data get referencegrants.gateway.networking.k8s.io")

	// An unreadable namespace is noted, not reported as missing.
	delete(res, "referencegrants.gateway.networking.k8s.io")
	c, _ = keyedCluster(res)
	_, out, _ = cli(t, c, "migrate", "check", "-n", "demo", "--format", "json")
	contains(t, out, "could not read ReferenceGrants in namespace certs")
	if strings.Contains(out, `"reference_grants"`) {
		t.Error("unverifiable references must not be reported as missing")
	}
}

// ---- gRPC ----------------------------------------------------------------

const grpcMigIngress = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rpc
  namespace: demo
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
spec:
  rules:
  - host: rpc.example.test
    http:
      paths:
      - {path: /hello.Greeter/SayHello, pathType: Exact, backend: {service: {name: greeter, port: {number: 50051}}}}
`

func grpcMigRoute(match string) string {
	return `apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata: {name: rpc-rpc-example-test, namespace: demo}
spec:
  hostnames: [rpc.example.test]
  rules:
  - matches: [` + match + `]
    backendRefs: [{name: greeter, port: 50051}]
`
}

func TestMigrateGRPCMatches(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", grpcMigIngress)
	check := func(match string) (int, string) {
		code, rep := migJSON(t, "--ingress", ing, "--routes", writeTmp(t, "rt.yaml", grpcMigRoute(match)))
		return code, strings.Join(ruleAt(t, rep, "rpc.example.test", "/hello.Greeter/SayHello").Details, "\n")
	}
	code, _ := check("{method: {service: hello.Greeter, method: SayHello}}")
	is(t, code, 0)
	code, d := check("{method: {service: hello.Greeter, method: SayHello}, headers: [{name: x-tenant, value: a}]}")
	is(t, code, 1)
	contains(t, d, "requires header match x-tenant=a that the Ingress rule does not")
	code, d = check("{method: {service: hello.Greeter, method: SayHello, type: RegularExpression}}")
	is(t, code, 1)
	contains(t, d, "literal gRPC service/method but the GRPCRoute method match is a RegularExpression")
	// A route for the service only does not cover the method rule.
	code, _ = check("{method: {service: hello.Greeter}}")
	is(t, code, 1)

	// canary-by-header on a gRPC Ingress expects the header match.
	canary := strings.Replace(grpcMigIngress, `"GRPC"`, `"GRPC"
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-by-header: X-Canary
    nginx.ingress.kubernetes.io/canary-by-header-value: beta`, 1)
	cing := writeTmp(t, "c.yaml", canary)
	run := func(match string) (int, string) {
		_, rep := migJSON(t, "--ingress", cing, "--routes", writeTmp(t, "rt.yaml", grpcMigRoute(match)))
		r := ruleAt(t, rep, "rpc.example.test", "/hello.Greeter/SayHello")
		return map[bool]int{true: 0, false: 1}[r.Status == statusEquivalent], strings.Join(r.Details, "\n")
	}
	code, d = run("{method: {service: hello.Greeter, method: SayHello}}")
	is(t, code, 1)
	contains(t, d, "canary-by-header expects a GRPCRoute header match X-Canary=beta")
	code, _ = run("{method: {service: hello.Greeter, method: SayHello}, headers: [{name: x-canary, value: beta}]}")
	is(t, code, 0)
	code, d = run("{method: {service: hello.Greeter, method: SayHello}, headers: [{name: X-Canary, value: gamma}]}")
	is(t, code, 1)
	contains(t, d, "X-Canary=gamma differs from the Ingress canary header X-Canary=beta")
	// Not exact: a regular expression header cannot be the same as an Exact one.
	code, _ = run("{method: {service: hello.Greeter, method: SayHello}, headers: [{type: RegularExpression, name: X-Canary, value: be.*}]}")
	is(t, code, 1)
}

func TestGRPCMethodPath(t *testing.T) {
	for path, want := range map[string]string{"/a.B/C": "method", "/a.B": "service", "/a.B/": "", "/": "", "a.B/C": "", "/a.*/C": "", "/a/b/c": ""} {
		if _, _, k := grpcMethodPath(path); k != want {
			t.Errorf("%s: %q, want %q", path, k, want)
		}
	}
}

// grpcServer answers every call with the given grpc-status, as trailers-only
// or with a body and real trailers, and records the requests it saw.
type grpcServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
	body  []string
	hosts []string
	proto []int
}

func newGRPCServer(t *testing.T, status string, trailers bool, backend string, tlsCfg bool) *grpcServer {
	t.Helper()
	g := &grpcServer{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.paths, g.body, g.hosts, g.proto = append(g.paths, r.URL.Path+" "+r.Header.Get("Content-Type")), append(g.body, string(b)), append(g.hosts, r.Host), append(g.proto, r.ProtoMajor)
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		if backend != "" {
			w.Header().Set("X-Setura-Backend", backend)
		}
		if !trailers {
			w.Header().Set("Grpc-Status", status)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("\x00\x00\x00\x00\x00"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", status)
	})
	g.Server = httptest.NewUnstartedServer(h)
	if tlsCfg {
		cfg, _ := selfSigned(t)
		cfg.NextProtos = []string{"h2", "http/1.1"}
		g.Server.TLS = cfg
		g.Server.EnableHTTP2 = true
		g.Server.StartTLS()
	} else {
		var p http.Protocols
		p.SetHTTP1(true)
		p.SetUnencryptedHTTP2(true)
		g.Server.Config.Protocols = &p
		g.Server.Start()
	}
	t.Cleanup(g.Close)
	return g
}

func TestMigrateGRPCLiveProbe(t *testing.T) {
	ing := writeTmp(t, "ing.yaml", grpcMigIngress)
	rts := writeTmp(t, "rt.yaml", grpcMigRoute("{method: {service: hello.Greeter, method: SayHello}}"))
	run := func(a, b *grpcServer, extra ...string) (int, *migrateReport) {
		args := append([]string{"--ingress", ing, "--routes", rts, "--ingress-url", a.URL, "--gateway-url", b.URL, "--address", "127.0.0.1"}, extra...)
		return migJSON(t, args...)
	}
	rule := func(rep *migrateReport) *ruleResult {
		return ruleAt(t, rep, "rpc.example.test", "/hello.Greeter/SayHello")
	}

	// Same status, once as trailers-only and once as real trailers: equivalent.
	a, b := newGRPCServer(t, "3", false, "v1", false), newGRPCServer(t, "3", true, "v1", false)
	code, rep := run(a, b)
	is(t, code, 0)
	r := rule(rep)
	if r.Probe == nil || r.Probe.Ingress.GRPCStatus == nil || *r.Probe.Gateway.GRPCStatus != 3 {
		t.Fatalf("probe: %+v", r.Probe)
	}
	for _, s := range []*grpcServer{a, b} {
		is(t, s.paths[0], "/hello.Greeter/SayHello application/grpc")
		is(t, s.body[0], "\x00\x00\x00\x00\x00")
		is(t, s.proto[0], 2)
		is(t, s.hosts[0], "rpc.example.test:"+portOf2(t, s.URL))
	}

	// UNIMPLEMENTED on one side only: the method is not routed there.
	c := newGRPCServer(t, "12", false, "v1", false)
	code, rep = run(a, c)
	is(t, code, 1)
	is(t, rule(rep).Status, statusDifferent)
	contains(t, strings.Join(rule(rep).Details, "\n"), "UNIMPLEMENTED means the route or method is not served there")

	// UNIMPLEMENTED on both: no difference, but the probe says it is blind.
	c2 := newGRPCServer(t, "12", false, "v1", false)
	code, rep = run(c, c2)
	is(t, code, 0)
	contains(t, strings.Join(rule(rep).Details, "\n"), "both targets answer UNIMPLEMENTED")

	// Different application-level codes, UNAVAILABLE, backend identity.
	d := newGRPCServer(t, "0", false, "v1", false)
	code, rep = run(a, d)
	is(t, code, 1)
	contains(t, strings.Join(rule(rep).Details, "\n"), "both targets reached a backend but answered differently: grpc-status 3 INVALID_ARGUMENT via Ingress, 0 OK via Gateway")
	u := newGRPCServer(t, "14", false, "v1", false)
	_, rep = run(a, u)
	contains(t, strings.Join(rule(rep).Details, "\n"), "UNAVAILABLE means no reachable backend")
	v2 := newGRPCServer(t, "3", false, "v2", false)
	_, rep = run(a, v2)
	contains(t, strings.Join(rule(rep).Details, "\n"), `backend identity "v1" via Ingress, "v2" via Gateway`)

	// A target that is not a gRPC server at all.
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	_, rep = migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-url", a.URL, "--gateway-url", plain.URL, "--address", "127.0.0.1")
	d2 := strings.Join(rule(rep).Details, "\n")
	if !strings.Contains(d2, "gateway probe failed") && !strings.Contains(d2, "HTTP status") {
		t.Errorf("a non-gRPC target should differ: %s", d2)
	}

	// A dead target.
	dead := newGRPCServer(t, "3", false, "", false)
	dead.Close()
	_, rep = run(a, dead)
	contains(t, strings.Join(rule(rep).Details, "\n"), "gateway probe failed")
}

func portOf2(t *testing.T, raw string) string {
	t.Helper()
	i := strings.LastIndex(raw, ":")
	return raw[i+1:]
}

func TestMigrateGRPCLiveProbeTLS(t *testing.T) {
	cfgSrv := newGRPCServerCA(t)
	ing := writeTmp(t, "ing.yaml", strings.Replace(grpcMigIngress, "rpc.example.test", "orders.mactra.test", 1))
	rts := writeTmp(t, "rt.yaml", strings.Replace(grpcMigRoute("{method: {service: hello.Greeter, method: SayHello}}"), "rpc.example.test", "orders.mactra.test", 1))
	_, rep := migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-url", cfgSrv.Server.URL, "--gateway-url", cfgSrv.Server.URL, "--address", "127.0.0.1", "--ca", cfgSrv.ca)
	r := ruleAt(t, rep, "orders.mactra.test", "/hello.Greeter/SayHello")
	if r.Probe == nil || r.Probe.Gateway.Error != "" || r.Probe.Gateway.GRPCStatus == nil || *r.Probe.Gateway.GRPCStatus != 7 {
		t.Fatalf("TLS gRPC probe: %+v / %v", r.Probe, r.Details)
	}
	is(t, r.Status, statusEquivalent)
	is(t, cfgSrv.proto[0], 2)

	// Wrong CA: the TLS failure is reported.
	_, ca2 := selfSigned(t)
	_, rep = migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-url", cfgSrv.Server.URL, "--gateway-url", cfgSrv.Server.URL, "--address", "127.0.0.1", "--ca", ca2)
	contains(t, strings.Join(ruleAt(t, rep, "orders.mactra.test", "/hello.Greeter/SayHello").Details, "\n"), "probe failed")
}

type grpcTLSServer struct {
	*grpcServer
	ca string
}

func newGRPCServerCA(t *testing.T) *grpcTLSServer {
	t.Helper()
	g := &grpcServer{}
	g.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.proto = append(g.proto, r.ProtoMajor)
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "7")
		w.WriteHeader(http.StatusOK)
	}))
	cfg, ca := selfSigned(t)
	cfg.NextProtos = []string{"h2", "http/1.1"}
	g.Server.TLS = cfg
	g.Server.EnableHTTP2 = true
	g.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	g.Server.StartTLS()
	t.Cleanup(g.Close)
	return &grpcTLSServer{g, ca}
}

func TestMigrateGRPCProbeSkips(t *testing.T) {
	// A service-prefix path cannot be probed; a plain HTTP rule still is.
	ing := writeTmp(t, "ing.yaml", strings.Replace(grpcMigIngress, "/hello.Greeter/SayHello", "/hello.Greeter", 1))
	rts := writeTmp(t, "rt.yaml", grpcMigRoute("{method: {service: hello.Greeter}}"))
	a := newGRPCServer(t, "3", false, "", false)
	code, rep := migJSON(t, "--ingress", ing, "--routes", rts, "--ingress-url", a.URL, "--gateway-url", a.URL, "--address", "127.0.0.1")
	is(t, code, 0)
	contains(t, strings.Join(ruleAt(t, rep, "rpc.example.test", "/hello.Greeter").Details, "\n"), "live probe skipped: the path is not a /service/method")
	is(t, len(a.paths), 0)
}

func TestMigrateExamplesObjects(t *testing.T) {
	code, out, _ := cli(t, nil, "migrate", "check", "--ingress", "../../examples/migrate/ingress.yaml", "--routes", "../../examples/migrate/routes.yaml",
		"--services", "../../examples/migrate/services.yaml", "--objects", "../../examples/migrate/objects.yaml", "--format", "json")
	is(t, code, 1)
	for _, want := range []string{"has no ready endpoints (1 not ready)", `"reference_grants"`, "Service data/reports", "/helloworld.Greeter/SayHello"} {
		contains(t, out, want)
	}
}

func TestCompareGRPC(t *testing.T) {
	st := func(n int) *int { return &n }
	diffs, notes := compareGRPC(&probeObs{Status: 200, GRPCStatus: st(3)}, &probeObs{Status: 404})
	is(t, len(diffs), 2) // HTTP status and presence
	is(t, len(notes), 0)
	diffs, notes = compareGRPC(&probeObs{Status: 404}, &probeObs{Status: 404})
	is(t, len(diffs), 0)
	is(t, len(notes), 1)
}
