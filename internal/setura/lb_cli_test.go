package setura

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func lbLint(t *testing.T, rules []any, ann obj, backends obj) map[string][]string {
	t.Helper()
	rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": rules}
	if ann != nil {
		rt[builtin.SeturaAnnotationsKey] = ann
	}
	snap := obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}}, route + "/r": rt}}
	if backends != nil {
		snap["backends"] = backends
	}
	rep, err := Lint(snap)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range asList(rep["findings"]) {
		m := asMap(f)
		out[asStr(m["id"])] = append(out[asStr(m["id"])], asStr(m["message"]))
	}
	return out
}

func TestLintLoadBalancerRules(t *testing.T) {
	a := []any{obj{"name": "a", "port": 80}}
	two := []any{obj{"name": "a", "port": 80, "weight": 1}, obj{"name": "b", "port": 80, "weight": 1}}
	hash := `{"algorithm":"consistentHash","consistentHash":{"on":"header","name":"X-User"}}`
	cases := []struct {
		name  string
		rules []any
		ann   obj
		be    obj
		id    string
		want  string
	}{
		{"clean field", []any{obj{"backendRefs": a, builtin.LoadBalancerKey: obj{"algorithm": "leastRequest"}}}, nil, nil, "", ""},
		{"clean annotation", []any{obj{"backendRefs": a}}, obj{builtin.LoadBalancerKey: `"random"`}, nil, "", ""},
		{"bad field", []any{obj{"backendRefs": a, builtin.LoadBalancerKey: obj{"algorithm": "fastest"}}}, nil, nil, "SET050", "want roundRobin"},
		{"bad annotation", []any{obj{"backendRefs": a}}, obj{builtin.LoadBalancerKey: `{"algorithm":"consistentHash"}`}, nil, "SET050", "needs a consistentHash block"},
		{"orphan rule number", []any{obj{"backendRefs": a}}, obj{builtin.LoadBalancerKey + ".rule-3": `"random"`}, nil, "SET050", "names no rule"},
		{"hash over two backends", []any{obj{"backendRefs": two}}, obj{builtin.LoadBalancerKey: hash}, nil, "SET051", "across 2 backendRefs"},
		{"hash with session", []any{obj{"backendRefs": a, "sessionPersistence": obj{"type": "Cookie"}}}, obj{builtin.LoadBalancerKey: hash}, nil, "SET051", "sessionPersistence"},
		{"hash on one backend is fine", []any{obj{"backendRefs": a}}, obj{builtin.LoadBalancerKey: hash}, nil, "", ""},
		{"bad backend endpoint", []any{obj{"backendRefs": a}}, nil, obj{"a": obj{"endpoints": []any{"unix:relative"}}}, "SET052", "absolute path"},
		{"bad backend lb", []any{obj{"backendRefs": a}}, nil, obj{"a": obj{"endpoints": []any{"a:80"}, "loadBalancer": obj{"algorithm": "x"}}}, "SET052", "loadBalancer"},
		{"bad backends annotation", []any{obj{"backendRefs": a}}, obj{builtin.BackendsKey: `{"x":{"endpoints":[]}}`}, nil, "SET052", "no endpoints"},
		{"undeclared backend", []any{obj{"backendRefs": []any{obj{"name": "ext", "group": builtin.BackendGroup, "kind": "Backend"}}}}, nil, nil, "SET053", "not declared"},
		{"declared in snapshot", []any{obj{"backendRefs": []any{obj{"name": "ext", "group": builtin.BackendGroup, "kind": "Backend"}}}}, nil, obj{"ext": obj{"endpoints": []any{"api.example.com:443"}}}, "", ""},
		{"declared by annotation", []any{obj{"backendRefs": []any{obj{"name": "ext", "group": builtin.BackendGroup, "kind": "Backend"}}}}, obj{builtin.BackendsKey: `{"ext":{"endpoints":["api.example.com:443"]}}`}, nil, "", ""},
	}
	for _, c := range cases {
		got := lbLint(t, c.rules, c.ann, c.be)
		for id := range got {
			if strings.HasPrefix(id, "SET05") && id != c.id {
				t.Errorf("%s: unexpected %s %v", c.name, id, got[id])
			}
		}
		if c.id == "" {
			continue
		}
		if len(got[c.id]) == 0 || !strings.Contains(strings.Join(got[c.id], "|"), c.want) {
			t.Errorf("%s: want %s containing %q, got %v", c.name, c.id, c.want, got)
		}
	}
	if ruleSeverity("SET050") != SeverityError || ruleSeverity("SET051") != SeverityWarning || ruleSeverity("SET052") != SeverityError || ruleSeverity("SET053") != SeverityError {
		t.Error("severities")
	}
	// A Setura Backend does not count as a foreign kind for SET014.
	mixed := []any{obj{"backendRefs": []any{obj{"name": "a", "port": 80}, obj{"name": "ext", "group": builtin.BackendGroup, "kind": "Backend"}}}}
	if got := lbLint(t, mixed, nil, obj{"ext": obj{"endpoints": []any{"x:1"}}}); len(got["SET014"]) != 0 {
		t.Errorf("SET014 on Service plus Backend: %v", got)
	}
}

func TestLoadBalancerFlagsHelpManCompletion(t *testing.T) {
	var b bytes.Buffer
	Man(&b)
	for _, w := range []string{"LOAD BALANCING AND EXTERNAL BACKENDS", "load\\-balancer", "leastRequest", "SET050", "dns\\-ttl\\-min"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("man page lacks %q", w)
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		b.Reset()
		Completion(sh, &b)
		for _, f := range []string{"load-balancer", "zone", "dns-ttl-min", "dns-ttl-max"} {
			if !strings.Contains(b.String(), f) {
				t.Errorf("%s completion lacks %s", sh, f)
			}
		}
	}
	var out, errb bytes.Buffer
	if code := runGateway([]string{"--help"}, &out, &errb); !strings.Contains(out.String()+errb.String(), "--load-balancer") {
		t.Errorf("help (code %d) lacks --load-balancer", code)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gw.json")
	os.WriteFile(cfg, []byte(`{"schema":"setura.route-specs/v1","resources":{}}`), 0o600)
	for _, bad := range [][]string{{"--load-balancer", "fastest"}, {"--load-balancer", `{"algorithm":"consistentHash"}`}, {"--dns-ttl-min", "1m", "--dns-ttl-max", "5s"}} {
		out.Reset()
		errb.Reset()
		if code := runGateway(append([]string{"run", "--config", cfg, "--admin", "off"}, bad...), &out, &errb); code != 2 {
			t.Errorf("%v: code %d, want 2 (%s)", bad, code, errb.String())
		}
	}
}

func TestWhyShowsLoadBalancing(t *testing.T) {
	cfg := `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
	 "gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"x","listeners":[{"name":"web","protocol":"HTTP","port":8080}]},
	 "httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["a.test"],"rules":[
	  {"setura.zyvor.dev/load-balancer":{"algorithm":"consistentHash","consistentHash":{"type":"maglev","on":"header","name":"X-User"}},
	   "backendRefs":[{"name":"v1","port":80}]}]}},
	 "backends":{"v1":{"endpoints":[{"address":"10.0.0.1:80","zone":"a","weight":2},{"address":"10.0.0.2:80","zone":"b"}]}}}`
	path := filepath.Join(t.TempDir(), "gw.json")
	os.WriteFile(path, []byte(cfg), 0o600)
	var out, errb bytes.Buffer
	if code := Main([]string{"why", "GET", "http://a.test:8080/", "--config", path, "--ascii", "-H", "X-User: alice"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	for _, want := range []string{"load balancing: consistentHash (Maglev on header x-user)", "(rule)", "Maglev hash of the header x-user selects http://10.0.0.", "weight 2", "zone a", "zone b"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q\n%s", want, out.String())
		}
	}
	out.Reset()
	Main([]string{"why", "GET", "http://a.test:8080/", "--config", path, "--ascii"}, &out, &errb)
	if !strings.Contains(out.String(), "not in the request") {
		t.Errorf("without the header:\n%s", out.String())
	}
}
