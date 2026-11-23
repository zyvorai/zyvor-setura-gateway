package setura

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// envoyFixtures is statusFixtures plus Envoy Gateway policies: one the
// controller reported on (with ignored fields), one rejected, one of nobody's
// Gateways.
func envoyFixtures() map[string]any {
	const ctl = "zyvor.dev/setura-gateway"
	fx := statusFixtures()
	policy := func(kind, ns, name string, spec obj, anc []any) obj {
		return obj{"kind": kind, "metadata": obj{"namespace": ns, "name": name}, "spec": spec, "status": obj{"ancestors": anc}}
	}
	ref := func(kind, name string) obj {
		return obj{"group": "gateway.networking.k8s.io", "kind": kind, "name": name}
	}
	ancestor := func(conds []any) []any {
		return []any{obj{"controllerName": ctl, "ancestorRef": obj{"kind": "Gateway", "name": "edge"}, "conditions": conds}}
	}
	fx["backendtrafficpolicies."+builtin.EnvoyGroup] = obj{"items": []any{
		policy("BackendTrafficPolicy", "infra", "slow", obj{"targetRefs": []any{ref("HTTPRoute", "ok")}, "retry": obj{"numRetries": 2}, "dns": obj{"lookupFamily": "IPv4"}},
			ancestor(conds("Accepted", "True", "Unsupported", "translated; Setura ignores these fields: dns"))),
		policy("BackendTrafficPolicy", "other", "theirs", obj{"targetRefs": []any{ref("HTTPRoute", "foreign")}, "retry": obj{"numRetries": 1}}, nil),
	}}
	fx["securitypolicies."+builtin.EnvoyGroup] = obj{"items": []any{
		policy("SecurityPolicy", "infra", "basic", obj{"targetRefs": []any{ref("HTTPRoute", "ok")}, "basicAuth": obj{"users": obj{"name": "u"}}},
			ancestor(conds("Accepted", "False", "Unsupported", "Setura cannot enforce basicAuth"))),
	}}
	return fx
}

func TestGatewayStatusListsEnvoyPolicies(t *testing.T) {
	rep, err := clusterStatus(kubectlFake(t, envoyFixtures()), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Policies) != 2 {
		t.Fatalf("policies of other controllers' routes must be left out: %+v", rep.Policies)
	}
	byName := map[string]stPolicy{}
	for _, p := range rep.Policies {
		byName[p.Name] = p
	}
	slow, basic := byName["slow"], byName["basic"]
	if !slow.OK || slow.Accepted != "True" || len(slow.Unsupported) != 1 || slow.Unsupported[0] != "dns" {
		t.Errorf("slow: %+v", slow)
	}
	if basic.OK || basic.Accepted != "False" || len(basic.FailClosed) != 1 || basic.FailClosed[0] != "basicAuth" || len(basic.Unsupported) == 0 {
		t.Errorf("basic: %+v", basic)
	}
	if rep.OK || !strings.Contains(rep.Verdict, "attention") {
		t.Errorf("a rejected policy must show in the verdict: %q", rep.Verdict)
	}
	code, out, _ := cli(t, kubectlFake(t, envoyFixtures()), "gateway", "status", "--format", "pretty")
	for _, want := range []string{"Envoy Gateway policies", "infra/slow (BackendTrafficPolicy)", "Setura ignores: dns", "Accepted=False (Unsupported)"} {
		if !strings.Contains(out, want) {
			t.Errorf("pretty output lacks %q:\n%s", want, out)
		}
	}
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	_, js, _ := cli(t, kubectlFake(t, envoyFixtures()), "gateway", "status", "--format", "json")
	var back statusReport
	if err := json.Unmarshal([]byte(js), &back); err != nil || len(back.Policies) != 2 {
		t.Errorf("json: %v %s", err, js)
	}
	// Without Envoy Gateway CRDs the report has no policy section.
	plain, _ := clusterStatus(kubectlFake(t, statusFixtures()), "", false)
	if len(plain.Policies) != 0 {
		t.Errorf("unexpected policies %+v", plain.Policies)
	}
}

func TestDoctorGatewayKubeEnvoyPolicies(t *testing.T) {
	fx := envoyFixtures()
	delete(fx, "securitypolicies."+builtin.EnvoyGroup)
	env := dgEnv{cluster: kubectlFake(t, fx)}
	c := envoyPoliciesCheck(dgOptions{}, env)
	if c.State != "warn" || !strings.Contains(strings.Join(c.Details, "\n"), "Setura ignores dns") || c.Fix == "" {
		t.Errorf("%+v", c)
	}
	c = envoyPoliciesCheck(dgOptions{}, dgEnv{cluster: kubectlFake(t, envoyFixtures())})
	if c.State != "fail" || !strings.Contains(strings.Join(c.Details, "\n"), "not accepted (Unsupported)") {
		t.Errorf("%+v", c)
	}
	if c := envoyPoliciesCheck(dgOptions{}, dgEnv{cluster: kubectlFake(t, statusFixtures())}); c.State != "ok" || !strings.Contains(c.Message, "no Envoy Gateway") {
		t.Errorf("no CRDs: %+v", c)
	}
	answers := envoyFixtures()
	answers["customresourcedefinitions.apiextensions.k8s.io"] = obj{"items": crdSet("v1.7.0")}
	var out, errb bytes.Buffer
	code, err := runDoctorGatewayWith(kubectlFake(t, answers), []string{"--kube", "--admin", "127.0.0.1:1", "--format", "json", "--timeout", "1s"}, &out, &errb, plainUI, false)
	if err != nil || code != 1 {
		t.Fatalf("%d %v %s", code, err, errb.String())
	}
	var rep dgReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if ep := dgFind(&rep, "envoy-policies"); ep.State != "fail" || len(ep.Details) < 2 {
		t.Errorf("envoy-policies: %+v", ep)
	}
}

func TestGatewayInstallEnvoyCompatFlag(t *testing.T) {
	code, out, errs := cli(t, nil, "gateway", "install", "--envoy-compat", "--no-admin-secret")
	if code != 0 {
		t.Fatalf("exit %d %s", code, errs)
	}
	for _, want := range []string{"- --envoy-compat", `apiGroups: ["gateway.envoyproxy.io"]`, "backendtrafficpolicies/status"} {
		if !strings.Contains(out, want) {
			t.Errorf("install --envoy-compat lacks %q", want)
		}
	}
	// The permissions are for the optional CRDs only: reads and status, never create or delete.
	i := strings.Index(out, `apiGroups: ["gateway.envoyproxy.io"]`)
	if block := out[i : i+600]; strings.Contains(block, `"create"`) || strings.Contains(block, `"delete"`) {
		t.Errorf("too many verbs for the Envoy Gateway group:\n%s", block)
	}
	_, plain, _ := cli(t, nil, "gateway", "install", "--no-admin-secret")
	if strings.Contains(plain, "envoyproxy") {
		t.Error("RBAC for the Envoy Gateway CRDs printed without --envoy-compat")
	}
}
