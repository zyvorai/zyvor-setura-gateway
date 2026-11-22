package setura

import (
	"strings"
	"testing"
)

func snapOf(extra obj, res obj) obj {
	s := obj{"schema": snapshotSchema, "namespace": "demo", "resources": res}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func findingsFor(r obj, id string) []obj {
	var out []obj
	for _, f := range asList(r["findings"]) {
		if m := asMap(f); m["id"] == id {
			out = append(out, m)
		}
	}
	return out
}

func grpcRT(parents, rules any, hosts ...any) obj {
	return obj{"parentRefs": parents, "rules": rules, "hostnames": hosts}
}

func TestLintSET010GRPCRoute(t *testing.T) {
	gw := goodGateway()
	r, _ := Lint(snapOf(nil, obj{gateway + "/dev": gw, grpcRoute + "/g": obj{}}))
	f := findingsFor(r, "SET010")
	is(t, len(f), 2)
	is(t, f[0]["resource"], "GRPCRoute/demo/g")
	is(t, r["ok"], false)
	ok := grpcRT([]any{obj{"name": "dev"}}, []any{obj{"backendRefs": []any{obj{"name": "s", "port": 1}}}})
	r, _ = Lint(snapOf(nil, obj{gateway + "/dev": gw, grpcRoute + "/g": ok}))
	is(t, ids(r), "")
}

func TestLintSET011HostnameIntersection(t *testing.T) {
	gw := goodGateway() // *.mactra.test
	rules := []any{obj{"backendRefs": []any{obj{"name": "s", "port": 1}}}}
	for _, res := range []string{grpcRoute, tlsRoute} {
		bad := grpcRT([]any{obj{"name": "dev"}}, rules, "svc.example.org")
		r, _ := Lint(snapOf(nil, obj{gateway + "/dev": gw, res + "/x": bad}))
		is(t, ids(r), "SET011")
		is(t, r["ok"], true) // warning
		good := grpcRT([]any{obj{"name": "dev"}}, rules, "svc.mactra.test")
		r, _ = Lint(snapOf(nil, obj{gateway + "/dev": gw, res + "/x": good}))
		is(t, ids(r), "")
	}
}

func TestLintSET004ReferenceGrants(t *testing.T) {
	rt := obj{"parentRefs": []any{obj{"name": "dev"}}, "rules": []any{obj{"backendRefs": []any{obj{"name": "db", "port": 1, "namespace": "data"}}}}}
	base := func() obj { return obj{gateway + "/dev": goodGateway(), route + "/orders": rt} }

	// grants not captured: warning
	r, _ := Lint(snapOf(nil, base()))
	f := findingsFor(r, "SET004")
	is(t, len(f), 1)
	is(t, f[0]["severity"], "warning")
	is(t, r["ok"], true)

	// grants captured, none present: error
	r, _ = Lint(snapOf(obj{"captured": []any{"referencegrants"}}, base()))
	is(t, findingsFor(r, "SET004")[0]["severity"], "error")
	is(t, r["ok"], false)

	grant := func(from, kind, name string) obj {
		to := obj{"group": "", "kind": kind}
		if name != "" {
			to["name"] = name
		}
		return obj{"from": []any{obj{"group": group, "kind": "HTTPRoute", "namespace": from}}, "to": []any{to}}
	}
	// matching grant (any name) in data namespace: no finding
	res := base()
	res[refGrant+"/data/allow"] = grant("demo", "Service", "")
	r, _ = Lint(snapOf(obj{"captured": []any{"referencegrants"}}, res))
	is(t, ids(r), "")
	// named grant for another Service, wrong from-namespace, wrong kind, grant in wrong namespace: still errors
	for name, g := range map[string]obj{"other-name": grant("demo", "Service", "cache"), "other-ns": grant("elsewhere", "Service", ""), "kind": grant("demo", "Secret", "")} {
		res = base()
		res[refGrant+"/data/"+name] = g
		r, _ = Lint(snapOf(obj{"captured": []any{"referencegrants"}}, res))
		if ids(r) != "SET004" || findingsFor(r, "SET004")[0]["severity"] != "error" {
			t.Fatalf("%s: %v", name, ids(r))
		}
	}
	res = base()
	res[refGrant+"/demo/allow"] = grant("demo", "Service", "")
	r, _ = Lint(snapOf(obj{"captured": []any{"referencegrants"}}, res))
	is(t, ids(r), "SET004")

	// GRPCRoute backendRefs are checked too, with its own from kind
	g := grpcRT([]any{obj{"name": "dev"}}, []any{obj{"backendRefs": []any{obj{"name": "db", "port": 1, "namespace": "data"}}}})
	res = obj{gateway + "/dev": goodGateway(), grpcRoute + "/g": g, refGrant + "/data/allow": grant("demo", "Service", "")}
	r, _ = Lint(snapOf(obj{"captured": []any{"referencegrants"}}, res))
	is(t, ids(r), "SET004") // grant is for HTTPRoute, not GRPCRoute

	// SET012: empty grant
	r, _ = Lint(snapOf(nil, obj{gateway + "/dev": goodGateway(), refGrant + "/data/empty": obj{}}))
	is(t, ids(r), "SET012")
	is(t, r["ok"], true)
}

func TestLintSET013AllowedRoutes(t *testing.T) {
	rules := []any{obj{"backendRefs": []any{obj{"name": "s", "port": 1}}}}
	listener := func(allowed obj) obj {
		l := obj{"name": "web", "port": 80, "protocol": "HTTP"}
		if allowed != nil {
			l["allowedRoutes"] = allowed
		}
		return obj{"listeners": []any{l}}
	}
	rt := obj{"parentRefs": []any{obj{"name": "shared", "namespace": "infra"}}, "rules": rules}
	run := func(spec obj) obj {
		r, err := Lint(snapOf(obj{"foreign": obj{gateway + "/infra/shared": spec}}, obj{route + "/orders": rt}))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// default (Same) rejects a route from another namespace
	r := run(listener(nil))
	is(t, ids(r), "") // no allowedRoutes block: defaults not judged
	r = run(listener(obj{"namespaces": obj{"from": "Same"}}))
	is(t, ids(r), "SET013")
	is(t, r["ok"], false)
	contains(t, asStr(findingsFor(r, "SET013")[0]["message"]), "infra/shared")
	is(t, ids(run(listener(obj{"namespaces": obj{"from": "All"}}))), "")
	is(t, ids(run(listener(obj{"namespaces": obj{"from": "Selector"}}))), "")
	// kinds restriction
	is(t, ids(run(listener(obj{"namespaces": obj{"from": "All"}, "kinds": []any{obj{"kind": "GRPCRoute"}}}))), "SET013")
	is(t, ids(run(listener(obj{"namespaces": obj{"from": "All"}, "kinds": []any{obj{"kind": "HTTPRoute"}}}))), "")
	// same-namespace gateway admits the route
	r, _ = Lint(snapOf(nil, obj{gateway + "/dev": listener(obj{"namespaces": obj{"from": "Same"}}),
		route + "/orders": obj{"parentRefs": []any{obj{"name": "dev"}}, "rules": rules}}))
	is(t, ids(r), "")
	// one admitting listener among several is enough when no sectionName is given
	two := obj{"listeners": []any{
		obj{"name": "a", "port": 80, "protocol": "HTTP", "allowedRoutes": obj{"namespaces": obj{"from": "Same"}}},
		obj{"name": "b", "port": 81, "protocol": "HTTP", "allowedRoutes": obj{"namespaces": obj{"from": "All"}}}}}
	is(t, ids(run(two)), "")
}

func TestLintSET014Weights(t *testing.T) {
	mk := func(refs ...any) obj {
		return obj{"parentRefs": []any{obj{"name": "dev"}}, "rules": []any{obj{"backendRefs": refs}}}
	}
	lint := func(rt obj) string {
		r, _ := Lint(snapOf(nil, obj{gateway + "/dev": goodGateway(), route + "/orders": rt}))
		return ids(r)
	}
	is(t, lint(mk(obj{"name": "a", "port": 1, "weight": 1}, obj{"name": "b", "port": 1, "weight": 5})), "")
	is(t, lint(mk(obj{"name": "a", "port": 1, "weight": -1}, obj{"name": "b", "port": 1, "weight": 5})), "SET014")
	is(t, lint(mk(obj{"name": "a", "port": 1, "weight": 2000000})), "SET014")
	var many []any
	for i := 0; i < 2200; i++ { // 2200 * 1e6 overflows int32
		many = append(many, obj{"name": "b", "port": 1, "weight": 1000000})
	}
	r, _ := Lint(snapOf(nil, obj{gateway + "/dev": goodGateway(), route + "/orders": mk(many...)}))
	is(t, ids(r), "SET014")
	contains(t, asStr(asMap(asList(r["findings"])[0])["message"]), "overflows")
	// mixed kinds in one rule
	mixed := mk(obj{"name": "a", "port": 1}, obj{"name": "b", "group": "example.io", "kind": "Backend"})
	is(t, lint(mixed), "SET014")
	is(t, lint(mk(obj{"name": "a", "port": 1}, obj{"name": "b", "port": 2, "kind": "Service"})), "")
	// applies to GRPCRoute
	g := grpcRT([]any{obj{"name": "dev"}}, []any{obj{"backendRefs": []any{obj{"name": "a", "port": 1, "weight": -3}}}})
	r, _ = Lint(snapOf(nil, obj{gateway + "/dev": goodGateway(), grpcRoute + "/g": g}))
	is(t, ids(r), "SET014")
	is(t, r["ok"], false)
}

func TestSnapshotCapturesExtras(t *testing.T) {
	item := func(name string, spec obj) obj { return obj{"metadata": obj{"name": name}, "spec": spec} }
	rt := item("orders", obj{"parentRefs": []any{obj{"name": "shared", "namespace": "infra"}},
		"rules": []any{obj{"backendRefs": []any{obj{"name": "db", "namespace": "data"}}}}})
	var asked []string
	c := &Cluster{Exec: func(args []string) (string, string, int, error) {
		cmd := strings.Join(args, " ")
		asked = append(asked, cmd)
		switch {
		case strings.Contains(cmd, "referencegrants") && strings.Contains(cmd, "-n data"):
			return mustJSON(obj{"items": []any{item("allow", obj{"from": []any{}, "to": []any{}})}}), "", 0, nil
		case strings.Contains(cmd, "referencegrants"):
			return mustJSON(obj{"items": []any{}}), "", 0, nil
		case strings.Contains(cmd, "tlsroutes"):
			return "", "the server doesn't have a resource type", 1, nil
		case strings.Contains(cmd, "grpcroutes"):
			return mustJSON(obj{"items": []any{item("g", obj{})}}), "", 0, nil
		case strings.Contains(cmd, "gateways.gateway.networking.k8s.io/shared"):
			return mustJSON(item("shared", obj{"listeners": []any{}})), "", 0, nil
		case strings.Contains(cmd, "httproutes"):
			return mustJSON(obj{"items": []any{rt}}), "", 0, nil
		}
		return mustJSON(obj{"items": []any{}}), "", 0, nil
	}}
	snap, err := Snapshot(c, "demo")
	if err != nil {
		t.Fatal(err)
	}
	res := asMap(snap["resources"])
	for _, k := range []string{route + "/orders", grpcRoute + "/g", refGrant + "/data/allow"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("missing %s in %v", k, sortedKeys(res))
		}
	}
	is(t, snap["schema"], snapshotSchema)
	is(t, grantsCaptured(snap), true)
	if _, ok := asMap(snap["foreign"])[gateway+"/infra/shared"]; !ok {
		t.Fatalf("foreign gateway missing: %v", snap["foreign"])
	}
	r, _ := Lint(snap)
	contains(t, ids(r), "SET012")
	contains(t, ids(r), "SET004")
	is(t, findingsFor(r, "SET004")[0]["severity"], "error")
}

func TestOldSnapshotStillLints(t *testing.T) {
	// no captured/foreign keys: SET004 stays a warning
	rt := obj{"parentRefs": []any{obj{"name": "dev"}}, "rules": []any{obj{"backendRefs": []any{obj{"name": "db", "namespace": "x"}}}}}
	r, err := Lint(snapOf(nil, obj{gateway + "/dev": goodGateway(), route + "/o": rt}))
	if err != nil {
		t.Fatal(err)
	}
	is(t, findingsFor(r, "SET004")[0]["severity"], "warning")
}

func TestTopologyGRPCRoute(t *testing.T) {
	g := grpcRT([]any{obj{"name": "dev"}}, []any{obj{"backendRefs": []any{obj{"name": "svc", "port": 1}}}})
	graph, err := BuildTopology(snapOf(nil, obj{gateway + "/dev": goodGateway(), grpcRoute + "/g": g}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range asList(graph["nodes"]) {
		found = found || asMap(n)["id"] == "GRPCRoute/demo/g"
	}
	if !found {
		t.Fatalf("no GRPCRoute node: %v", graph["nodes"])
	}
	imp, err := Impact(graph, "Service/demo/svc")
	if err != nil {
		t.Fatal(err)
	}
	is(t, imp["dependent_routes"], "[GRPCRoute/demo/g]")
}

func mustJSON(v any) string { return js(v).stdout }
