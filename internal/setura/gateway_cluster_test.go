package setura

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// crdObj builds one CRD item; fields are paths below openAPIV3Schema.
func crdObj(plural, bundle, channel string, filterFields ...string) obj {
	filters := obj{}
	for _, f := range filterFields {
		filters[f] = obj{"type": "object"}
	}
	schema := obj{"properties": obj{"spec": obj{"properties": obj{"rules": obj{"type": "array", "items": obj{"properties": obj{
		"filters": obj{"type": "array", "items": obj{"properties": filters}}}}}}}}}
	return obj{"metadata": obj{"name": plural + ".gateway.networking.k8s.io", "annotations": obj{annBundle: bundle, annChannel: channel}},
		"spec": obj{"versions": []any{obj{"name": "v1", "served": true, "schema": obj{"openAPIV3Schema": schema}}}}}
}

func crdSet(bundle string, httpFilters ...string) []any {
	return []any{crdObj("gatewayclasses", bundle, "standard"), crdObj("gateways", bundle, "standard"),
		crdObj("httproutes", bundle, "standard", httpFilters...), crdObj("grpcroutes", bundle, "standard"),
		crdObj("referencegrants", bundle, "standard"), crdObj("backendtlspolicies", bundle, "standard")}
}

func findCRD(r *crdReport, feature string) crdFinding {
	for _, f := range r.Findings {
		if strings.Contains(f.Feature, feature) {
			return f
		}
	}
	return crdFinding{}
}

func TestCRDCheckOldBundleLacksExternalAuth(t *testing.T) {
	// The field report: v1.6.3 standard CRDs reject "externalAuth".
	r := checkCRDs(crdSet("v1.6.3", "cors", "requestHeaderModifier"), "")
	f := findCRD(r, "ExternalAuth")
	if f.State != "warn" || !strings.Contains(f.Message, "unknown field") || !strings.Contains(f.Message, "v1.7.0") || !strings.Contains(f.Message, "v1.6.3") {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Fix, "kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml") {
		t.Errorf("fix: %q", f.Fix)
	}
	if findCRD(r, "CORS").State != "ok" {
		t.Errorf("CORS is in the schema: %+v", findCRD(r, "CORS"))
	}
	if !r.OK || !strings.Contains(r.Verdict, "unavailable") || r.Version != "v1.6.3" || r.Channel != "standard" {
		t.Errorf("%+v", r)
	}
	if r.Findings[0].State != "warn" {
		t.Error("problems sort first")
	}
}

func TestCRDCheckCompleteMissingAndAncient(t *testing.T) {
	ok := checkCRDs(crdSet("v1.7.0", "cors", "externalAuth"), "v1.7.0")
	if !ok.OK || strings.Contains(ok.Verdict, "unavailable") || findCRD(ok, "ExternalAuth").State != "ok" {
		t.Errorf("%+v", ok)
	}
	if f := findCRD(ok, "TCPRoute"); f.State != "info" || !strings.Contains(f.Fix, "experimental-install.yaml") {
		t.Errorf("TCPRoute is optional: %+v", f)
	}
	none := checkCRDs(nil, "v1.7.0")
	if none.OK || none.Findings[0].State != "fail" || !strings.Contains(none.Next, "standard-install.yaml") {
		t.Errorf("%+v", none)
	}
	partial := checkCRDs([]any{crdObj("gateways", "v1.7.0", "standard"), crdObj("gatewayclasses", "v1.7.0", "standard")}, "")
	if f := findCRD(partial, "HTTPRoute"); partial.OK || f.State != "fail" || !strings.Contains(f.Message, "httproutes is not installed") {
		t.Errorf("%+v", f)
	}
	old := checkCRDs(crdSet("v1.0.0"), "")
	if old.OK {
		t.Error("v1.0.0 is below the supported minimum")
	}
	mixed := checkCRDs([]any{crdObj("gatewayclasses", "v1.5.0", "standard"), crdObj("gateways", "v1.7.0", "standard"), crdObj("httproutes", "v1.7.0", "standard", "cors", "externalAuth")}, "")
	if findCRD(mixed, "CRD bundle").State != "warn" {
		t.Error("mixed bundles should warn")
	}
}

func TestCRDCheckWithoutSchemaFallsBackToVersion(t *testing.T) {
	strip := func(items []any) []any {
		for _, it := range items {
			delete(asMap(it)["spec"].(obj), "versions")
		}
		return items
	}
	r := checkCRDs(strip(crdSet("v1.6.3")), "")
	if f := findCRD(r, "ExternalAuth"); f.State != "warn" || !strings.Contains(f.Message, "older") {
		t.Errorf("%+v", f)
	}
	if f := findCRD(checkCRDs(strip(crdSet("v1.7.0")), ""), "ExternalAuth"); f.State != "ok" {
		t.Errorf("%+v", f)
	}
}

// kubectlFake answers "kubectl get RESOURCE ..." by resource name.
func kubectlFake(t *testing.T, answers map[string]any) *Cluster {
	return &Cluster{Exec: func(args []string) (string, string, int, error) {
		for i, a := range args {
			if a == "get" && i+1 < len(args) {
				v, ok := answers[args[i+1]]
				if !ok {
					return "", "error: the server doesn't have a resource type \"" + args[i+1] + "\"", 1, nil
				}
				b, _ := json.Marshal(v)
				return string(b), "", 0, nil
			}
		}
		t.Fatalf("unexpected kubectl call %v", args)
		return "", "", 1, nil
	}}
}

func conds(kv ...string) []any {
	var out []any
	for i := 0; i+3 < len(kv); i += 4 {
		out = append(out, obj{"type": kv[i], "status": kv[i+1], "reason": kv[i+2], "message": kv[i+3]})
	}
	return out
}

func statusFixtures() map[string]any {
	const class = "zyvor.dev/setura-gateway"
	list := func(items ...any) obj { return obj{"items": items} }
	gw := func(ns, name, class string, status obj) obj {
		return obj{"metadata": obj{"namespace": ns, "name": name}, "spec": obj{"gatewayClassName": class,
			"listeners": []any{obj{"name": "web", "port": 8080, "protocol": "HTTP"}}}, "status": status}
	}
	return map[string]any{
		"gatewayclasses." + "gateway.networking.k8s.io": list(
			obj{"metadata": obj{"name": "setura"}, "spec": obj{"controllerName": class}},
			obj{"metadata": obj{"name": "envoy"}, "spec": obj{"controllerName": "gateway.envoyproxy.io/gatewayclass-controller"}}),
		"gateways.gateway.networking.k8s.io": list(
			gw("infra", "edge", "setura", obj{"conditions": conds("Accepted", "True", "Accepted", "", "Programmed", "True", "Programmed", ""),
				"listeners": []any{obj{"name": "web", "attachedRoutes": 1, "conditions": conds("Accepted", "True", "Accepted", "", "Programmed", "True", "Programmed", "", "Conflicted", "False", "NoConflicts", "")}}}),
			gw("team-b", "edge", "setura", obj{"conditions": conds("Accepted", "True", "Accepted", "", "Programmed", "False", "ListenersNotValid", "one or more listeners are not programmed: listener \"web\": HostnameConflict: listener \"web\" of Gateway infra/edge already serves port 8080"),
				"listeners": []any{obj{"name": "web", "conditions": conds("Accepted", "True", "Accepted", "", "Programmed", "False", "Invalid", "x", "Conflicted", "True", "HostnameConflict", "listener \"web\" of Gateway infra/edge already serves port 8080, protocol HTTP and hostname \"x.test\"")}}}),
			gw("other", "envoy-gw", "envoy", obj{})),
		"httproutes.gateway.networking.k8s.io": list(
			obj{"metadata": obj{"namespace": "team-b", "name": "shop"}, "spec": obj{"hostnames": []any{"x.test"}, "parentRefs": []any{obj{"name": "edge"}}},
				"status": obj{"parents": []any{obj{"controllerName": class, "parentRef": obj{"name": "edge"}, "conditions": conds("Accepted", "False", "NotAllowedByListeners", "listener does not allow this route: listener team-b/edge/web is not serving: HostnameConflict: ...Gateway infra/edge...", "ResolvedRefs", "True", "ResolvedRefs", "")}}}},
			obj{"metadata": obj{"namespace": "infra", "name": "ok"}, "spec": obj{"parentRefs": []any{obj{"name": "edge"}}},
				"status": obj{"parents": []any{obj{"controllerName": class, "parentRef": obj{"name": "edge"}, "conditions": conds("Accepted", "True", "Accepted", "", "ResolvedRefs", "True", "ResolvedRefs", "")}}}},
			obj{"metadata": obj{"namespace": "other", "name": "foreign"}, "spec": obj{"parentRefs": []any{obj{"name": "envoy-gw"}}}}),
	}
}

func TestGatewayStatusNamesTheConflict(t *testing.T) {
	rep, err := clusterStatus(kubectlFake(t, statusFixtures()), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || len(rep.Gateways) != 2 || len(rep.Routes) != 2 {
		t.Fatalf("other controllers must be left out: %+v", rep)
	}
	var bad stItem
	for _, g := range rep.Gateways {
		if g.Namespace == "team-b" {
			bad = g
		}
	}
	if bad.OK || len(bad.Problems) < 2 || !strings.Contains(strings.Join(bad.Problems, "\n"), "HostnameConflict") || !strings.Contains(strings.Join(bad.Problems, "\n"), "Gateway infra/edge") {
		t.Errorf("%+v", bad)
	}
	for _, r := range rep.Routes {
		if r.Name == "shop" && (r.OK || !strings.Contains(r.Problems[0], "NotAllowedByListeners") || !strings.Contains(r.Problems[0], "infra/edge")) {
			t.Errorf("%+v", r)
		}
		if r.Name == "foreign" {
			t.Error("a route of another controller's Gateway was listed")
		}
	}
	all, _ := clusterStatus(kubectlFake(t, statusFixtures()), "", true)
	if len(all.Gateways) != 3 {
		t.Errorf("--all-controllers: %d gateways", len(all.Gateways))
	}
}

func TestGatewayStatusCommand(t *testing.T) {
	c := kubectlFake(t, statusFixtures())
	code, out, errs := cli(t, c, "gateway", "status", "--format", "json")
	if code != 1 || errs != "" {
		t.Fatalf("exit %d %s", code, errs)
	}
	var rep statusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Schema != gatewayStatusSchema || rep.OK {
		t.Fatalf("%v %s", err, out)
	}
	code, out, _ = cli(t, c, "gateway", "status", "--format", "pretty")
	for _, want := range []string{"team-b/edge", "HostnameConflict", "NotAllowedByListeners", "2 objects need attention"} {
		if !strings.Contains(out, want) {
			t.Errorf("pretty output lacks %q:\n%s", want, out)
		}
	}
	if code, _, e := cli(t, c, "gateway", "status", "-A", "-n", "x"); code != 2 || !strings.Contains(e, "either") {
		t.Errorf("-A with -n: %d %s", code, e)
	}
	healthy := statusFixtures()
	healthy["gateways.gateway.networking.k8s.io"] = obj{"items": []any{statusFixtures()["gateways.gateway.networking.k8s.io"].(obj)["items"].([]any)[0]}}
	healthy["httproutes.gateway.networking.k8s.io"] = obj{"items": []any{statusFixtures()["httproutes.gateway.networking.k8s.io"].(obj)["items"].([]any)[1]}}
	if code, out, _ := cli(t, kubectlFake(t, healthy), "gateway", "status", "--format", "pretty"); code != 0 || !strings.Contains(out, "accepted and programmed") {
		t.Errorf("healthy: %d %s", code, out)
	}
	if code, _, e := cli(t, &Cluster{Exec: func([]string) (string, string, int, error) { return "", "Unable to connect to the server", 1, nil }}, "gateway", "status"); code != 1 || !strings.Contains(e, "Unable to connect") {
		t.Errorf("unreachable cluster: %d %s", code, e)
	}
}

func TestInstallCheckCommand(t *testing.T) {
	old := kubectlFake(t, map[string]any{"customresourcedefinitions.apiextensions.k8s.io": obj{"items": crdSet("v1.6.3", "cors")}})
	code, out, _ := cli(t, old, "gateway", "install", "--check", "--format", "pretty")
	if code != 1 || !strings.Contains(out, "unknown field") || !strings.Contains(out, "standard-install.yaml") {
		t.Errorf("old CRDs: %d\n%s", code, out)
	}
	good := kubectlFake(t, map[string]any{"customresourcedefinitions.apiextensions.k8s.io": obj{"items": crdSet("v1.7.0", "cors", "externalAuth")}})
	code, out, _ = cli(t, good, "gateway", "install", "--check", "--format", "json", "--gateway-api-version", "v1.7.0")
	var rep crdReport
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || !rep.OK || rep.Schema != crdReportSchema {
		t.Errorf("good CRDs: %d %s", code, out)
	}
	if code, _, e := cli(t, good, "gateway", "install", "--check", "--gateway-api-version", "latest"); code != 2 || !strings.Contains(e, "Gateway API version") {
		t.Errorf("bad version: %d %s", code, e)
	}
	// Without --check the install command still only prints YAML.
	if code, out, _ := cli(t, good, "gateway", "install"); code != 0 || !strings.Contains(out, "kind: Deployment") {
		t.Errorf("install: %d", code)
	}
}

func TestDoctorGatewayKube(t *testing.T) {
	answers := statusFixtures()
	answers["customresourcedefinitions.apiextensions.k8s.io"] = obj{"items": crdSet("v1.6.3", "cors")}
	var out, errb bytes.Buffer
	code, err := runDoctorGatewayWith(kubectlFake(t, answers), []string{"--kube", "--admin", "127.0.0.1:1", "--format", "json", "--timeout", "1s"}, &out, &errb, plainUI, false)
	if err != nil || code != 1 {
		t.Fatalf("%d %v %s", code, err, errb.String())
	}
	var rep dgReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	crds, gws := dgFind(&rep, "crds"), dgFind(&rep, "gateways")
	if crds.State != "warn" || !strings.Contains(strings.Join(crds.Details, " "), "ExternalAuth") {
		t.Errorf("crds: %+v", crds)
	}
	if gws.State != "fail" || !strings.Contains(strings.Join(gws.Details, " "), "HostnameConflict") {
		t.Errorf("gateways: %+v", gws)
	}
	out.Reset()
	if code, _ := runDoctorGatewayWith(kubectlFake(t, answers), []string{"--admin", "127.0.0.1:1", "--format", "json", "--timeout", "1s"}, &out, &errb, plainUI, false); code == 2 {
		t.Fatal("usage error")
	}
	if strings.Contains(out.String(), `"id": "crds"`) || strings.Contains(out.String(), `"id":"crds"`) {
		t.Error("crds check ran without --kube")
	}
}

func TestInstallFlagsAreCompletedAndPrinted(t *testing.T) {
	var gw []string
	for _, fs := range flagSets {
		if fs.cmd == "gateway" {
			gw = fs.flags
		}
	}
	have := map[string]bool{}
	for _, f := range gw {
		have[f] = true
	}
	for _, f := range []string{"--service-type", "--node-port", "--listener-port", "--external-traffic-policy", "--host-network", "--replicas", "--arg",
		"--resources", "--node-selector", "--admin-token-secret", "--create-admin-secret", "--crds", "--gateway-api-version", "--check", "status"} {
		if !have[f] {
			t.Errorf("gatewayFlags lacks %s", f)
		}
	}
	code, out, errs := gwxRun("gateway", "install", "--service-type", "LoadBalancer", "--external-traffic-policy", "Local", "--listener-port", "7443",
		"--arg", "--rate-limit=50", "--replicas", "3", "--node-selector", "role=edge", "--resources", "limits.memory=128Mi", "--crds", "--gateway-api-version", "v1.7.0")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"type: LoadBalancer", "externalTrafficPolicy: Local", "name: listener-7443", "- --rate-limit=50", "replicas: 3", "role: edge", "memory: 128Mi", "standard-install.yaml"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(errs, "not printed") || strings.Contains(out, "kind: Secret") {
		t.Errorf("admin Secret handling: %q", errs)
	}
	for _, bad := range [][]string{{"--service-type", "Bogus"}, {"--node-port", "HTTP=30080"}, {"--listener-port", "x"}, {"--resources", "cpu=1"}, {"--arg", "nodash"}} {
		if code, _, e := gwxRun(append([]string{"gateway", "install"}, bad...)...); code != 2 || e == "" {
			t.Errorf("%v: exit %d %q", bad, code, e)
		}
	}
	if code, out, errs := gwxRun("gateway", "install", "--create-admin-secret"); code != 0 || !strings.Contains(out, "kind: Secret") || strings.Contains(errs, "not printed") {
		t.Errorf("--create-admin-secret: %d %q", code, errs)
	}
}
