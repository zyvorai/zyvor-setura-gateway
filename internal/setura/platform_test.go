package setura

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func routeObj(generation, observed int) obj {
	conds := []any{}
	for _, c := range []string{"Accepted", "ResolvedRefs"} {
		conds = append(conds, obj{"type": c, "status": "True", "observedGeneration": observed})
	}
	return obj{"metadata": obj{"uid": "route-id", "generation": generation, "namespace": "demo"},
		"status": obj{"parents": []any{obj{"parentRef": obj{"name": "dev", "sectionName": "web"},
			"controllerName": "example/controller", "conditions": conds}}}}
}

func TestGateRealRequest(t *testing.T) {
	url := fixture(t, nil)
	c, _ := fakeCluster(js(routeObj(1, 1)))
	code, out, errs := cli(t, c, "gate", "orders", url, "-n", "demo", "--gateway", "dev", "--listener", "web",
		"--backend", "orders-v1", "--address", "127.0.0.1", "--interval", "0")
	if code != 0 {
		t.Fatalf("exit %d %s %s", code, out, errs)
	}
	var data obj
	json.Unmarshal([]byte(out), &data)
	a := asList(data["attempts"])
	is(t, asMap(a[0])["streak"], 1)
	is(t, asMap(a[1])["streak"], 2)
}

func TestGateResetsOnUpdateDuringProbe(t *testing.T) {
	url := fixture(t, nil)
	c, _ := fakeCluster(js(routeObj(1, 1)), js(routeObj(1, 1)), js(routeObj(1, 1)), js(routeObj(2, 2)))
	code, out, _ := cli(t, c, "gate", "orders", url, "--gateway", "dev", "-n", "demo", "--backend", "orders-v1",
		"--address", "127.0.0.1", "--attempts", "2", "--interval", "0")
	is(t, code, 1)
	var data obj
	json.Unmarshal([]byte(out), &data)
	a := asList(data["attempts"])
	is(t, asMap(a[len(a)-1])["streak"], 0)
}

func TestParentAmbiguityAndStaleness(t *testing.T) {
	if RouteState(routeObj(2, 1), "dev", "demo", "", "")["ok"] == true {
		t.Fatal("stale generation passed")
	}
	o := routeObj(1, 1)
	parents := asList(dig(o, "status", "parents"))
	o["status"] = obj{"parents": []any{parents[0], parents[0]}}
	contains(t, RouteState(o, "dev", "demo", "", "")["reason"].(string), "2 matching")
	if RouteState(routeObj(1, 1), "dev", "elsewhere", "", "")["ok"] == true {
		t.Fatal("wrong namespace passed")
	}
}

func TestCompareTargetsWithBackend(t *testing.T) {
	url := fixture(t, nil)
	code, out, _ := cli(t, nil, "compare", url, "--target", "127.0.0.1", "--target", "127.0.0.2", "--backend", "orders-v1")
	is(t, code, 1)
	var res obj
	json.Unmarshal([]byte(out), &res)
	targets := asMap(res["targets"])
	is(t, asMap(targets["127.0.0.1"])["ok"], true)
	is(t, asMap(targets["127.0.0.2"])["ok"], false)
}

func TestDoctorDeniedAndUnknown(t *testing.T) {
	yes := call{stdout: "yes\n"}
	c, seen := fakeCluster(yes, yes, yes, yes, yes, yes, yes, call{stdout: "no\n", code: 1}, call{stderr: "offline", code: 1})
	res, err := Doctor(c, "demo", "envoy")
	if err != nil {
		t.Fatal(err)
	}
	is(t, res["ok"], false)
	checks := asList(res["checks"])
	is(t, asMap(checks[7])["state"], "denied")
	is(t, asMap(checks[8])["state"], "unknown")
	contains(t, strings.Join((*seen)[8], " "), "--subresource portforward")
}

func TestExposureDistinguishesProtocolAndPending(t *testing.T) {
	item := func(name, proto string, ingress []any) obj {
		return obj{"metadata": obj{"name": name}, "spec": obj{"type": "LoadBalancer", "ports": []any{obj{"port": 443, "protocol": proto}}},
			"status": obj{"loadBalancer": obj{"ingress": ingress}}}
	}
	c, _ := fakeCluster(js(obj{"items": []any{item("one", "TCP", nil), item("two", "TCP", []any{obj{"hostname": "edge"}}), item("three", "UDP", nil)}}))
	data, err := Exposure(c, "demo")
	if err != nil {
		t.Fatal(err)
	}
	is(t, data["overlapping_lb_ports"], "map[443/TCP:[one two]]")
	var pending []any
	for _, s := range data["services"].([]any) {
		pending = append(pending, s.(obj)["awaiting_ingress"])
	}
	is(t, pending, "[true false true]")
}

func TestListenerStatusAbsentAndZero(t *testing.T) {
	c, _ := fakeCluster(js(obj{"metadata": obj{"generation": 2}, "spec": obj{"listeners": []any{obj{"name": "a"}, obj{"name": "b"}}},
		"status": obj{"listeners": []any{obj{"name": "b", "attachedRoutes": 0}}}}))
	res, err := Listeners(c, "demo", "dev")
	if err != nil {
		t.Fatal(err)
	}
	l := res["listeners"].([]any)
	is(t, asMap(l[0])["attached_routes"], "<nil>")
	is(t, asMap(l[1])["attached_routes"], 0)
}

func TestClassPreservesUnknownFeatures(t *testing.T) {
	c, _ := fakeCluster(js(obj{"items": []any{obj{"metadata": obj{"name": "test"}, "spec": obj{"controllerName": "c"}}}}))
	rows, err := Capabilities(c, "default")
	if err != nil || rows[0]["reported_features"] != nil {
		t.Fatalf("%v %v", err, rows)
	}
}

func TestServiceDiscovery(t *testing.T) {
	gw := obj{"spec": obj{"listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 8080}}}}
	svc := obj{"metadata": obj{"name": "generated-envoy"}, "spec": obj{"ports": []any{obj{"port": 8080}}}}
	c, seen := fakeCluster(js(gw), js(obj{"items": []any{svc}}))
	c.Context = "mactra"
	cmd, err := c.Publication("demo", "dev", "web", "envoy", 9080, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	is(t, strings.Join(cmd, " "), "kubectl --context mactra -n envoy port-forward --address 127.0.0.1 service/generated-envoy 9080:8080")
	contains(t, strings.Join((*seen)[1], " "), "owning-gateway-namespace=demo")
	for _, items := range [][]any{{}, {svc, svc}} {
		c, _ := fakeCluster(js(gw), js(obj{"items": items}))
		if _, err := c.Publication("demo", "dev", "web", "envoy", 8080, "", -1); err == nil {
			t.Fatalf("%d matches accepted", len(items))
		}
	}
}

func TestExplicitProxyService(t *testing.T) {
	gw := obj{"spec": obj{"listeners": []any{obj{"name": "web", "protocol": "HTTPS", "port": 443}}}}
	svc := obj{"metadata": obj{"name": "traefik"}, "spec": obj{"ports": []any{obj{"port": 443}}}}
	c, seen := fakeCluster(js(gw), js(svc))
	cmd, err := c.Publication("demo", "dev", "web", "kube-system", 8443, "traefik", -1)
	if err != nil {
		t.Fatal(err)
	}
	is(t, cmd[len(cmd)-2:], "[service/traefik 8443:443]")
	contains(t, strings.Join((*seen)[1], " "), "-n kube-system get service/traefik")
}

func TestInspectStaleAndUnknown(t *testing.T) {
	rt := obj{"metadata": obj{"generation": 2}, "spec": obj{"rules": []any{obj{"backendRefs": []any{obj{"name": "orders", "port": 80}}}}},
		"status": obj{"parents": []any{obj{"parentRef": obj{"name": "dev"}, "controllerName": "envoy",
			"conditions": []any{obj{"type": "Accepted", "status": "True", "observedGeneration": 1}}}}}}
	c, _ := fakeCluster(js(rt), js(obj{"spec": obj{"ports": []any{obj{"port": 80}}}}),
		js(obj{"items": []any{obj{"endpoints": []any{obj{}, obj{"conditions": obj{"ready": false}}}}}}))
	row, err := c.Inspect("demo", "orders")
	if err != nil {
		t.Fatal(err)
	}
	cond := asMap(asList(asMap(asList(row["parents"])[0])["conditions"])[0])
	is(t, cond["current"], false)
	is(t, asMap(asMap(asList(row["backends"])[0])["endpoint_records_by_ready_condition"]), "map[false:1 true:0 unknown:1]")
}

func TestSnapshotDiffExitCodes(t *testing.T) {
	item := obj{"metadata": obj{"name": "orders"}, "spec": obj{"hostnames": []any{"a.test"}}}
	c, _ := fakeCluster(js(obj{"items": []any{}}), js(obj{"items": []any{item}}))
	code, out, _ := cli(t, c, "snapshot", "-n", "demo")
	is(t, code, 0)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.WriteFile(a, []byte(out), 0o600)
	if code, _, _ := cli(t, nil, "diff", a, a); code != 0 {
		t.Fatalf("identical snapshots exit %d", code)
	}
	os.WriteFile(b, []byte(strings.Replace(out, "a.test", "b.test", 1)), 0o600)
	code, diff, _ := cli(t, nil, "diff", a, b)
	is(t, code, 1)
	var res obj
	json.Unmarshal([]byte(diff), &res)
	is(t, len(asMap(res["changed"])), 1)
}

func TestJUnitMixedAssertions(t *testing.T) {
	url := fixture(t, nil)
	dir := t.TempDir()
	suite, xmlPath := filepath.Join(dir, "suite.json"), filepath.Join(dir, "report.xml")
	cases := `[{"url":"` + url + `","address":"127.0.0.1","backend":"orders-v1"},{"url":"` + url + `","address":"127.0.0.1","backend":"wrong"}]`
	os.WriteFile(suite, []byte(cases), 0o600)
	code, _, errs := cli(t, nil, "check", suite, "--junit", xmlPath)
	if code != 1 {
		t.Fatalf("exit %d %s", code, errs)
	}
	raw, _ := os.ReadFile(xmlPath)
	var parsed junitSuite
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	is(t, parsed.Failures, 1)
	is(t, parsed.Cases[1].Failure.Type, "backend")
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"publish", "dev"}, {"explain"}, {"compare", "http://x"}, {"gate", "r", "http://x"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, out, _ := cli(t, nil, "version"); code != 0 || !strings.HasPrefix(out, "setura ") {
		t.Errorf("version: %d %q", code, out)
	}
}
