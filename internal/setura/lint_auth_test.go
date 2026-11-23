package setura

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func authFindings(t *testing.T, rule obj, spec obj) map[string][]string {
	t.Helper()
	rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}}
	for k, v := range spec {
		rt[k] = v
	}
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
		route + "/r":    rt}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range asList(rep["findings"]) {
		m := asMap(f)
		id := asStr(m["id"])
		if id == "SET016" || id == "SET017" || id == "SET018" {
			out[id] = append(out[id], asStr(m["message"]))
		}
	}
	return out
}

func authRule(policy obj) obj {
	return obj{builtin.AuthKey: policy, "backendRefs": []any{obj{"name": "a", "port": 80}}}
}

func TestLintAuthRules(t *testing.T) {
	jwks := `{"keys":[]}`
	_ = jwks
	// a sound policy is clean
	good := authRule(obj{"jwt": obj{"audience": []any{"api"}, "jwksUri": "https://idp.test/jwks"}, "apiKey": obj{"keys": []any{obj{"name": "a", "hash": "sha256$AAAA$" + strings.Repeat("0", 64)}}}})
	if got := authFindings(t, good, nil); len(got) != 0 {
		t.Fatalf("clean policy: %v", got)
	}
	// SET016
	got := authFindings(t, authRule(obj{"jwt": obj{"jwksUri": "https://idp.test/jwks"}}), nil)
	if len(got["SET016"]) != 1 || !strings.Contains(got["SET016"][0], "audience") {
		t.Errorf("no audience: %v", got)
	}
	got = authFindings(t, authRule(obj{"jwt": obj{"audience": []any{"api"}, "jwksUri": "http://idp.test/jwks"}}), nil)
	if len(got["SET016"]) != 1 || !strings.Contains(got["SET016"][0], "plain http") {
		t.Errorf("http jwks: %v", got)
	}
	// SET017
	got = authFindings(t, authRule(obj{"apiKey": obj{"keys": []any{obj{"name": "dev", "key": "plain"}}}, "basic": obj{"users": []any{obj{"name": "bob", "password": "pw"}}}}), nil)
	if len(got["SET017"]) != 2 {
		t.Errorf("clear text: %v", got)
	}
	for _, m := range got["SET017"] {
		if strings.Contains(m, "plain") && !strings.Contains(m, `"dev"`) || strings.Contains(m, "pw\"") {
			t.Errorf("message must name the entry, not repeat the secret: %s", m)
		}
	}
	// SET018
	got = authFindings(t, authRule(obj{"jwt": obj{"audience": []any{"api"}}}), nil)
	if len(got["SET018"]) != 1 {
		t.Errorf("invalid block: %v", got)
	}
	got = authFindings(t, authRule(obj{"bogus": 1}), nil)
	if len(got["SET018"]) != 1 || !strings.Contains(got["SET018"][0], "unknown field") {
		t.Errorf("unknown field: %v", got)
	}
	// annotations
	ann := func(kv ...string) obj {
		m := obj{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return obj{builtin.SeturaAnnotationsKey: m}
	}
	plain := obj{"backendRefs": []any{obj{"name": "a", "port": 80}}}
	got = authFindings(t, plain, ann(builtin.AuthKey, `{"apiKey":{"keys":[{"name":"x","key":"k"}]}}`, builtin.AuthKey+".rule-4", `{}`))
	if len(got["SET017"]) != 1 || len(got["SET018"]) != 1 || !strings.Contains(got["SET018"][0], "names no rule") {
		t.Errorf("annotations: %v", got)
	}
	got = authFindings(t, plain, ann(builtin.AuthKey, `{"jwt":`))
	if len(got["SET018"]) != 1 {
		t.Errorf("undecodable annotation: %v", got)
	}
}

func TestWhyShowsAuthDecision(t *testing.T) {
	cfg := `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
	  "gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":8080}]},
	  "httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["a.test"],"rules":[{
	    "setura.zyvor.dev/auth":{"apiKey":{"keys":[{"name":"ci","key":"s3cret"}]},"ipAllow":["10.0.0.0/8"]},
	    "backendRefs":[{"name":"v1","port":80}]}]}},
	  "backends":{"t/v1:80":"127.0.0.1:9"}}`
	path := filepath.Join(t.TempDir(), "gw.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := Main(args, &out, &errb)
		return code, out.String() + errb.String()
	}
	_, out := run("why", "GET", "http://a.test:8080/x", "--config", path, "--ascii", "--client-ip", "10.1.2.3", "-H", "X-API-Key: s3cret")
	for _, want := range []string{"auth: api key in X-API-Key", "would be admitted by apikey as ci", "X-Setura-Auth-Method"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cret") {
		t.Errorf("the credential is printed:\n%s", out)
	}
	_, out = run("why", "GET", "http://a.test:8080/x", "--config", path, "--ascii", "--client-ip", "10.1.2.3", "-H", "X-API-Key: wrong")
	if !strings.Contains(out, "refused with 401") || !strings.Contains(out, "WWW-Authenticate: ApiKey") {
		t.Errorf("bad key:\n%s", out)
	}
	_, out = run("why", "GET", "http://a.test:8080/x", "--config", path, "--ascii", "--client-ip", "192.0.2.1", "-H", "X-API-Key: s3cret")
	if !strings.Contains(out, "refused with 403") || !strings.Contains(out, "not on the allow list") {
		t.Errorf("address outside the list:\n%s", out)
	}
	_, out = run("why", "GET", "http://a.test:8080/x", "--config", path, "--ascii", "--format", "json", "-H", "X-API-Key: s3cret")
	if strings.Contains(out, "s3cret") || !strings.Contains(out, `"decision": "unknown"`) {
		t.Errorf("json without --client-ip:\n%s", out)
	}
}

func TestAuthRulesCoverGRPCRoute(t *testing.T) {
	specs := obj{grpcRoute + "/g": obj{
		"rules":                        []any{obj{"setura.zyvor.dev/auth": obj{"apiKey": obj{"keys": []any{obj{"name": "ci", "key": "clear"}}}}}},
		"setura.zyvor.dev/annotations": obj{"setura.zyvor.dev/auth.rule-3": `{"ipAllow":["10.0.0.0/8"]}`},
	}}
	got := authRules(specs, "demo")
	var ids []string
	for _, f := range got {
		ids = append(ids, f["id"].(string)+" "+f["resource"].(string))
	}
	want := []string{"SET017 GRPCRoute/demo/g", "SET018 GRPCRoute/demo/g"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("findings %v, want %v", ids, want)
	}
}

func TestLintSET031FaultWithoutTTL(t *testing.T) {
	find := func(rule obj, spec obj) []string {
		rt := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}}
		for k, v := range spec {
			rt[k] = v
		}
		rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
			gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
			route + "/r":    rt}})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range asList(rep["findings"]) {
			if m := asMap(f); asStr(m["id"]) == "SET031" {
				out = append(out, asStr(m["message"]))
			}
		}
		return out
	}
	be := []any{obj{"name": "a", "port": 80}}
	good := obj{builtin.FaultKey: obj{"percent": 5, "abort": obj{"status": 503}, "ttl": "10m"}, "backendRefs": be}
	if got := find(good, nil); len(got) != 0 {
		t.Errorf("valid fault flagged: %v", got)
	}
	bad := obj{builtin.FaultKey: obj{"percent": 5, "abort": obj{"status": 503}}, "backendRefs": be}
	if got := find(bad, nil); len(got) != 1 || !strings.Contains(got[0], "no ttl or expires") {
		t.Errorf("fault without ttl: %v", got)
	}
	ann := obj{builtin.SeturaAnnotationsKey: obj{builtin.FaultKey: `{"percent":5,"abort":{"status":503}}`, builtin.FaultKey + ".rule-4": `{}`}}
	got := find(obj{"backendRefs": be}, ann)
	if len(got) != 3 || !strings.Contains(strings.Join(got, "\n"), "names no rule") {
		t.Errorf("annotation without ttl, an empty fault and an orphan annotation: %v", got)
	}
}

func TestLintEdgeSecurityRules(t *testing.T) {
	filt := func(v string) []any {
		return []any{obj{"type": "RequestHeaderModifier", "requestHeaderModifier": obj{"set": []any{obj{"name": "X-U", "value": v}}}}}
	}
	oidc := func(extra obj) obj {
		o := obj{"issuer": "https://kc.example/realms/haven", "clientId": "app", "clientSecret": obj{"env": "S"}, "redirectUrl": "https://app.example/oauth2/callback",
			"cookieKeys": []any{obj{"env": "K"}}}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	cases := []struct {
		name string
		rule obj
		want []string
	}{
		{"clean oidc", obj{AuthKeyForTest: obj{"oidc": oidc(nil), "csrf": obj{}}}, nil},
		{"weak oidc", obj{AuthKeyForTest: obj{"oidc": oidc(obj{"issuer": "http://kc.example/realms/h", "clientSecret": nil, "cookie": obj{"secure": false, "sameSite": "None"}})}},
			[]string{"SET018"}}, // sameSite None with insecure cookie does not compile
		{"insecure cookie", obj{AuthKeyForTest: obj{"oidc": oidc(obj{"issuer": "http://kc.example/realms/h", "cookie": obj{"secure": false}})}}, []string{"SET060", "SET060", "SET062"}},
		{"public client", obj{AuthKeyForTest: obj{"oidc": oidc(obj{"clientSecret": nil}), "csrf": obj{}}}, []string{"SET060"}},
		{"loopback http issuer is fine", obj{AuthKeyForTest: obj{"oidc": oidc(obj{"issuer": "http://127.0.0.1:8080/realms/h"}), "csrf": obj{}}}, nil},
		{"authz no rules", obj{AuthKeyForTest: obj{"ipAllow": []any{"10.0.0.0/8"}, "authorization": obj{"rules": []any{}}}}, []string{"SET061"}},
		{"authz allow only under allow", obj{AuthKeyForTest: obj{"ipAllow": []any{"10.0.0.0/8"}, "authorization": obj{"defaultAction": "allow", "rules": []any{obj{"action": "allow"}}}}}, []string{"SET061"}},
		{"authz shadowed", obj{AuthKeyForTest: obj{"ipAllow": []any{"10.0.0.0/8"}, "authorization": obj{"rules": []any{obj{"name": "all", "action": "allow"}, obj{"action": "deny", "operations": []any{obj{"methods": []any{"DELETE"}}}}}}}}, []string{"SET061"}},
		{"claim var without policy", obj{"filters": filt("{claim:sub}")}, []string{"SET063"}},
		{"claim var with apikey only", obj{"filters": filt("x-{claim:sub}"), AuthKeyForTest: obj{"apiKey": obj{"keys": []any{obj{"name": "k", "key": "kk"}}}}}, []string{"SET063"}},
		{"claim var with jwt", obj{"filters": filt("{claim:sub}"), AuthKeyForTest: obj{"jwt": obj{"audience": []any{"a"}, "jwksUri": "https://i/jwks"}}}, nil},
		{"inject without auth", obj{AuthKeyForTest: obj{"inject": []any{obj{"header": "X-K", "secret": obj{"env": "T"}}}}}, []string{"SET065"}},
		{"inject behind ipAllow", obj{AuthKeyForTest: obj{"ipAllow": []any{"10.0.0.0/8"}, "inject": []any{obj{"header": "X-K", "secret": obj{"env": "T"}}}}}, nil},
		{"inline secret", obj{AuthKeyForTest: obj{"inject": []any{obj{"header": "X-K", "secret": obj{"value": "hunter2"}}}}}, []string{"SET018"}},
	}
	for _, c := range cases {
		rule := obj{"backendRefs": []any{obj{"name": "v1", "port": 80}}}
		for k, v := range c.rule {
			rule[k] = v
		}
		rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
			gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
			route + "/r":    obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}}}})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range asList(rep["findings"]) {
			if id := asStr(asMap(f)["id"]); strings.HasPrefix(id, "SET06") || id == "SET018" {
				got = append(got, id)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// invalid listener options
	for opt, want := range map[string]string{"TLS_RSA_WITH_RC4_128_SHA": "insecure", "NOPE": "unknown"} {
		rep, _ := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
			gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTPS", "port": 443,
				"tls": obj{"options": obj{"setura.zyvor.dev/tls-cipher-suites": opt, "setura.zyvor.dev/tls-session-resumption": "maybe"}}}}}}})
		n := 0
		for _, f := range asList(rep["findings"]) {
			if asStr(asMap(f)["id"]) == "SET064" {
				n++
				if msg := asStr(asMap(f)["message"]); !strings.Contains(msg, want) && !strings.Contains(msg, "on or off") {
					t.Errorf("message %q", msg)
				}
			}
		}
		if n != 2 {
			t.Errorf("%s: %d SET064 findings", opt, n)
		}
	}
}

const AuthKeyForTest = "setura.zyvor.dev/auth"
