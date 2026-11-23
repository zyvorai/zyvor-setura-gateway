package gateway

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// kitchenSinks holds, per kind, specs that between them use every field of
// the compatibility table. Each is translated; the notes must agree with the
// table, so the translator and the table cannot drift.
var kitchenSinks = map[string][]m{
	kBT: {
		{"retry": m{"numRetries": 3, "retryOn": m{"httpStatusCodes": l{502}, "triggers": l{"connect-failure", "reset"}},
			"perRetry": m{"timeout": "2s", "backOff": m{"baseInterval": "100ms", "maxInterval": "1s"}}},
			"timeout":        m{"http": m{"requestTimeout": "30s", "connectionIdleTimeout": "5m", "maxConnectionDuration": "1h"}, "tcp": m{"connectTimeout": "2s"}},
			"circuitBreaker": m{"maxConnections": 10, "maxPendingRequests": 5, "maxParallelRequests": 20, "maxParallelRetries": 3, "maxRequestsPerConnection": 2, "perEndpoint": m{"maxConnections": 1}},
			"loadBalancer":   m{"type": "LeastRequest"},
			"rateLimit":      m{"type": "Local", "local": m{"rules": l{m{"limit": m{"requests": 100, "unit": "Minute"}}}}},
			"faultInjection": m{"delay": m{"fixedDelay": "2s", "percentage": 10}, "abort": m{"httpStatus": 503, "percentage": 5, "grpcStatus": 14}},
			"mirrors":        l{m{"backendRef": m{"name": "shadow", "port": 80}, "percentage": 20}},
			"proxyProtocol":  m{"version": "V2"},
			"compression":    l{m{"type": "Gzip"}}, "tcpKeepalive": m{}, "connection": m{"bufferLimit": "1Mi"}, "dns": m{}, "http2": m{},
			"useClientProtocol": true, "telemetry": m{}, "httpUpgrade": l{}, "requestBuffer": m{}, "decompression": l{}, "responseOverride": l{}, "routingType": "Service"},
		{"rateLimit": m{"type": "Global", "global": m{}}},
		{"healthCheck": m{
			"active": m{"type": "HTTP", "interval": "5s", "timeout": "1s", "unhealthyThreshold": 3, "healthyThreshold": 2,
				"http": m{"path": "/ready", "method": "GET", "expectedStatuses": l{200}, "expectedResponse": m{}}},
			"passive": m{"consecutive5XxErrors": 4, "baseEjectionTime": "20s", "interval": "1s", "maxEjectionPercent": 50,
				"splitExternalLocalOriginErrors": true, "consecutiveLocalOriginFailures": 2, "consecutiveGatewayErrors": 2}}},
		{"healthCheck": m{"active": m{"type": "GRPC", "grpc": m{"service": "pkg.Svc"}}}},
		{"healthCheck": m{"active": m{"type": "TCP", "tcp": m{}}}},
	},
	kCT: {
		{"tls": m{"minVersion": "1.0", "maxVersion": "1.3", "ciphers": l{"x"}, "ecdhCurves": l{}, "signatureAlgorithms": l{}, "alpnProtocols": l{"h2"}, "session": m{},
			"clientValidation": m{"optional": true, "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}}},
			"enableProxyProtocol": true, "clientIPDetection": m{"xForwardedFor": m{"numTrustedHops": 1}},
			"path":         m{"escapedSlashesAction": "RejectRequest", "disableMergeSlashes": true},
			"timeout":      m{"http": m{"requestReceivedTimeout": "5s", "idleTimeout": "1m"}, "tcp": m{"idleTimeout": "1m"}},
			"connection":   m{"connectionLimit": m{}, "bufferLimit": "1Mi", "socketBufferLimit": "1Mi"},
			"tcpKeepalive": m{}, "headers": m{}, "http1": m{}, "http2": m{}, "http3": m{}, "healthCheck": m{}},
		{"tls": m{"minVersion": "1.2", "maxVersion": "1.0"}},
	},
	kSP: {
		{"cors": m{"allowOrigins": l{"*"}, "allowMethods": l{"GET"}, "allowHeaders": l{"X"}, "exposeHeaders": l{"Y"}, "allowCredentials": true, "maxAge": "1h"},
			"jwt": m{"optional": true, "providers": l{
				m{"name": "a", "issuer": "https://i", "audiences": l{"aud"}, "remoteJWKS": m{"uri": "https://i/jwks"}, "claimToHeaders": l{m{"header": "X-U", "claim": "sub"}},
					"forwardAccessToken": true, "extractFrom": m{}, "recomputeRoute": true},
				m{"name": "b", "issuer": "https://j", "localJWKS": m{"type": "Inline", "inline": `{"keys":[]}`}}}},
			"apiKeyAuth": m{"credentialRefs": l{m{"name": "keys"}}, "extractFrom": l{m{"headers": l{"X-Key"}}}, "sanitize": true, "forwardClientIDHeader": "X-Client"},
			"basicAuth":  m{"users": m{"name": "u"}},
			"oidc":       m{"provider": m{}},
			"extAuth": m{"http": m{"backendRefs": l{m{"name": "authz", "port": 9000}}, "path": "/v", "headersToBackend": l{"X"}},
				"headersToExtAuth": l{"Y"}, "bodyToExtAuth": m{}, "failOpen": true, "recomputeRoute": true},
			"authorization": m{"defaultAction": "Deny", "rules": l{m{"action": "Allow", "principal": m{"clientCIDRs": l{"10.0.0.0/8"}}}}}},
		{"jwt": m{"providers": l{m{"name": "c", "issuer": "https://k", "localJWKS": m{"type": "Inline", "inline": `{"keys":[]}`}}}}},
		{"extAuth": m{"grpc": m{"backendRefs": l{m{"name": "authz", "port": 9000}}}}},
		{"authorization": m{"rules": l{m{"action": "Deny", "principal": m{"jwt": m{}, "headers": l{}}, "operation": m{}}}}},
	},
}

func TestEnvoyCompatTableMatchesTranslator(t *testing.T) {
	for kind, specs := range kitchenSinks {
		notes := map[string][]FieldNote{}
		for _, spec := range specs {
			for _, n := range TranslateEnvoyPolicy(kind, spec, EnvoyOptions{}).Notes {
				notes[n.Field] = append(notes[n.Field], n)
			}
		}
		checkRows(t, kind, notes)
	}
	// HTTPRouteFilter and Backend have their own translators.
	notes := map[string][]FieldNote{}
	for _, spec := range []m{
		{"directResponse": m{"statusCode": 404, "contentType": "text/plain", "body": m{"type": "Inline", "inline": "gone"}}},
		{"directResponse": m{"body": m{"type": "ValueRef"}}},
		{"urlRewrite": m{"path": m{"replaceRegexMatch": m{"pattern": "a", "substitution": "b"}}, "hostname": m{"type": "Header"}}, "credentialInjection": m{}},
	} {
		for _, n := range TranslateHTTPRouteFilter(spec).Notes {
			notes[n.Field] = append(notes[n.Field], n)
		}
	}
	checkRows(t, kHRF, notes)
	notes = map[string][]FieldNote{}
	for _, spec := range []m{
		{"endpoints": l{m{"fqdn": m{"hostname": "a.example", "port": 80}}, m{"ip": m{"address": "10.0.0.1", "port": 80}}, m{"unix": m{"path": "/s"}}},
			"appProtocols": l{"gateway.envoyproxy.io/h2c"}, "type": "DynamicResolver", "tls": m{}, "fallback": true},
	} {
		for _, n := range TranslateEnvoyBackend(spec).Notes {
			notes[n.Field] = append(notes[n.Field], n)
		}
	}
	checkRows(t, kBK, notes)
}

func checkRows(t *testing.T, kind string, notes map[string][]FieldNote) {
	t.Helper()
	rows := map[string]CompatRow{}
	for _, r := range EnvoyCompatRows(kind) {
		rows[r.Field] = r
		ns := notes[r.Field]
		if len(ns) == 0 {
			t.Errorf("%s %s: no sample exercises this table row", kind, r.Field)
			continue
		}
		applied := false
		for _, n := range ns {
			if n.Applied() && r.Status == CompatUnsupported {
				t.Errorf("%s %s: the table says Unsupported but the translator applies it", kind, r.Field)
			}
			if n.Applied() && n.Status != r.Status && !(r.Status == CompatSupported && n.Status == CompatPartial) {
				t.Errorf("%s %s: note status %s, table status %s", kind, r.Field, n.Status, r.Status)
			}
			applied = applied || n.Applied()
		}
		if !applied && r.Status != CompatUnsupported {
			t.Errorf("%s %s: the table says %s but the translator never applies it", kind, r.Field, r.Status)
		}
	}
	for f := range notes {
		if _, ok := rows[f]; !ok {
			t.Errorf("%s: the translator reports %q, which the table does not list", kind, f)
		}
	}
}

func TestEnvoyTranslateValues(t *testing.T) {
	tr := TranslateEnvoyPolicy(kBT, kitchenSinks[kBT][0], EnvoyOptions{Name: "p", FaultTTL: "1h"})
	retry := tr.Rule["retry"].(map[string]any)
	if retry["attempts"] != 3 || retry["backoff"] != "100ms" || retry["perTryTimeout"] != "2s" {
		t.Errorf("retry %v", retry)
	}
	if tr.Rule["timeouts"].(map[string]any)["request"] != "30s" {
		t.Errorf("timeouts %v", tr.Rule["timeouts"])
	}
	if rl := tr.Rule["setura.zyvor.dev/rate-limit"].(map[string]any); rl["rate"] != "100/m" || rl["key"] != "route" {
		t.Errorf("rate limit %v", rl)
	}
	f := tr.Rule["setura.zyvor.dev/fault"].(map[string]any)
	if f["ttl"] != "1h" || f["latency"].(map[string]any)["delay"] != "2s" || f["abort"].(map[string]any)["status"] != 503 {
		t.Errorf("fault %v", f)
	}
	cb := tr.Backend["circuitBreaker"].(map[string]any)
	if cb["maxConnections"] != 10 || cb["maxPending"] != 5 || cb["maxRequests"] != 20 {
		t.Errorf("circuit breaker %v", cb)
	}
	if tr.Backend["proxyProtocol"] != "v2" || len(tr.Filters) != 1 || tr.Filters[0]["type"] != "RequestMirror" {
		t.Errorf("backend %v filters %v", tr.Backend, tr.Filters)
	}
	// A GRPCRoute takes none of the rule settings.
	g := TranslateEnvoyPolicy(kBT, m{"retry": m{"numRetries": 1}, "circuitBreaker": m{"maxConnections": 1}}, EnvoyOptions{TargetKind: "GRPCRoute"})
	if g.Rule != nil || g.Backend == nil {
		t.Errorf("GRPCRoute translation: rule %v backend %v", g.Rule, g.Backend)
	}
	// Security fields that cannot be translated fail closed.
	s := TranslateEnvoyPolicy(kSP, kitchenSinks[kSP][0], EnvoyOptions{})
	sort.Strings(s.FailClosed)
	if strings.Join(s.FailClosed, ",") != "basicAuth,oidc" {
		t.Errorf("fail closed: %v", s.FailClosed)
	}
	if s.Auth["jwt"].(map[string]any)["issuer"] != "https://i" || s.Auth["ipAllow"] == nil {
		t.Errorf("auth %v", s.Auth)
	}
	if got := TranslateEnvoyPolicy(kSP, kitchenSinks[kSP][3], EnvoyOptions{}).FailClosed; len(got) != 1 || got[0] != "authorization" {
		t.Errorf("authorization fail closed: %v", got)
	}
	ct := TranslateEnvoyPolicy(kCT, kitchenSinks[kCT][0], EnvoyOptions{})
	if ct.Listener["tlsMinVersion"] != "1.2" || ct.Listener["tlsMaxVersion"] != "1.3" || ct.Frontend["mode"] != "AllowInsecureFallback" {
		t.Errorf("client policy %v %v", ct.Listener, ct.Frontend)
	}
}

func TestEnvoyCompatDocInSync(t *testing.T) {
	want, err := os.ReadFile("../../docs/envoy-gateway-compat.md")
	if err != nil {
		t.Fatalf("docs/envoy-gateway-compat.md is missing: %v (run make compat)", err)
	}
	if EnvoyCompatMarkdown() != string(want) {
		t.Error("docs/envoy-gateway-compat.md is stale; run make compat")
	}
}

// ---- resolution ----

func envoyObj(kind, ns, name string, age int, spec m) *EnvoyObject {
	return &EnvoyObject{Kind: kind, NS: ns, Name: name, Generation: 1, Created: time.Unix(1700000000+int64(age), 0).UTC(), Annotations: map[string]string{}, Spec: spec}
}

func target(kind, name string, section ...string) m {
	t := m{"group": APIGroup, "kind": kind, "name": name}
	if len(section) > 0 {
		t["sectionName"] = section[0]
	}
	return t
}

func envoyCfg() *Config {
	return &Config{
		Gateways: []*Gateway{{NS: "infra", Name: "edge", Listeners: []Listener{{Name: "web", Port: 8080, Protocol: "HTTP"}, {Name: "tls", Port: 8443, Protocol: "HTTPS", TLS: &ListenerTLS{}}}}},
		Routes: []*Route{
			{NS: "infra", Name: "orders", Parents: []ParentRef{{Name: "edge"}}, Rules: []Rule{{Name: "read", BackendRefs: []BackendRef{{Name: "orders", Port: 80}}}, {Name: "admin"}}},
			{NS: "infra", Name: "billing", Parents: []ParentRef{{Name: "edge"}}, Rules: []Rule{{}}},
		},
		Backends: map[string]*BackendDef{"infra/orders:80": {Endpoints: []string{"127.0.0.1:1"}}},
	}
}

func outcome(res *EnvoyResult, key string) *EnvoyOutcome {
	for _, o := range res.Outcomes {
		if o.Object.Key() == key {
			return o
		}
	}
	return nil
}

func TestEnvoyPrecedenceAndMerge(t *testing.T) {
	cfg := envoyCfg()
	res := ApplyEnvoyCompat(cfg, EnvoyInput{Policies: []*EnvoyObject{
		// gateway wide: 10s timeout and 2 retries
		envoyObj(kBT, "infra", "gw", 0, m{"targetRefs": l{target("Gateway", "edge")}, "timeout": m{"http": m{"requestTimeout": "10s"}}, "retry": m{"numRetries": 2}}),
		// a younger policy on the same target loses
		envoyObj(kBT, "infra", "gw-late", 5, m{"targetRefs": l{target("Gateway", "edge")}, "timeout": m{"http": m{"requestTimeout": "99s"}}}),
		// orders replaces the gateway policy completely
		envoyObj(kBT, "infra", "orders", 1, m{"targetRefs": l{target("HTTPRoute", "orders")}, "timeout": m{"http": m{"requestTimeout": "3s"}}}),
		// billing merges over it
		envoyObj(kBT, "infra", "billing", 1, m{"targetRefs": l{target("HTTPRoute", "billing")}, "mergeType": "StrategicMerge", "timeout": m{"http": m{"requestTimeout": "7s"}}}),
		// the admin rule is the most specific
		envoyObj(kBT, "infra", "admin", 2, m{"targetRefs": l{target("HTTPRoute", "orders", "admin")}, "timeout": m{"http": m{"requestTimeout": "1s"}}}),
		envoyObj(kBT, "infra", "ghost", 2, m{"targetRefs": l{target("HTTPRoute", "nosuch")}, "retry": m{"numRetries": 9}}),
	}})
	rules := map[string]*Rule{"read": &cfg.Routes[0].Rules[0], "admin": &cfg.Routes[0].Rules[1], "billing": &cfg.Routes[1].Rules[0]}
	if g := rules["read"].Timeouts; g == nil || g.Request != "3s" || rules["read"].Retry != nil {
		t.Errorf("read: %+v retry %v (a route policy without mergeType replaces the gateway policy)", g, rules["read"].Retry)
	}
	if g := rules["admin"].Timeouts; g == nil || g.Request != "1s" {
		t.Errorf("admin: %+v", g)
	}
	b := rules["billing"]
	if b.Timeouts == nil || b.Timeouts.Request != "7s" || b.Retry == nil || *b.Retry.Attempts != 2 {
		t.Errorf("billing merged: %+v %+v", b.Timeouts, b.Retry)
	}
	if o := outcome(res, kBT+"/infra/gw-late"); len(o.Conflicts) != 1 || o.Conflicts[0] != kBT+"/infra/gw" || o.Wins != 0 {
		t.Errorf("gw-late: %+v", o)
	}
	if o := outcome(res, kBT+"/infra/gw"); len(o.OverriddenBy) == 0 {
		t.Errorf("gw overridden by: %v wins %d", o.OverriddenBy, o.Wins)
	}
	if o := outcome(res, kBT+"/infra/ghost"); len(o.Missing) != 1 || o.Missing[0] != "HTTPRoute nosuch" {
		t.Errorf("ghost: %+v", o)
	}
	if o := outcome(res, kBT+"/infra/billing"); len(o.Merged) != 1 {
		t.Errorf("billing merged: %v", o.Merged)
	}
	conds := outcome(res, kBT+"/infra/gw-late").Conditions(time.Now(), nil)
	if conds[0].Type != "Accepted" || conds[0].Status != "False" || conds[0].Reason != "Conflicted" || conds[1].Type != "Conflicted" {
		t.Errorf("conditions: %+v", conds)
	}
}

func TestEnvoySelectorsAndListenerLevel(t *testing.T) {
	cfg := envoyCfg()
	cfg.Routes[1].Labels = map[string]string{"team": "pay"}
	res := ApplyEnvoyCompat(cfg, EnvoyInput{Policies: []*EnvoyObject{
		envoyObj(kBT, "infra", "by-label", 0, m{"targetSelectors": l{m{"group": APIGroup, "kind": "HTTPRoute", "matchLabels": m{"team": "pay"}}}, "retry": m{"numRetries": 4}}),
		envoyObj(kCT, "infra", "tls", 0, m{"targetRefs": l{target("Gateway", "edge", "tls")}, "tls": m{"minVersion": "1.3"}}),
		envoyObj(kCT, "infra", "tls-gw", 0, m{"targetRefs": l{target("Gateway", "edge")}, "tls": m{"minVersion": "1.2"}}),
	}})
	if r := cfg.Routes[1].Rules[0].Retry; r == nil || *r.Attempts != 4 {
		t.Errorf("selector did not apply: %+v", r)
	}
	if cfg.Routes[0].Rules[0].Retry != nil {
		t.Error("selector applied to a route without the label")
	}
	if o := cfg.Gateways[0].Listeners[1].TLS.Options[TLSMinVersionOption]; o != "1.3" {
		t.Errorf("listener level policy: tls min %q", o)
	}
	if o := outcome(res, kCT+"/infra/tls-gw"); o.Wins != 1 || len(o.Ancestors) != 1 {
		t.Errorf("gateway level client policy: %+v", o)
	}
}

func TestEnvoyAuthFailsClosedAndKeepsNativeAuth(t *testing.T) {
	cfg := envoyCfg()
	native, _ := ParseAuthBlock([]byte(`{"ipAllow":["10.0.0.0/8"]}`))
	cfg.Routes[1].Rules[0].Auth = native
	res := ApplyEnvoyCompat(cfg, EnvoyInput{
		Policies: []*EnvoyObject{
			envoyObj(kSP, "infra", "basic", 0, m{"targetRefs": l{target("HTTPRoute", "orders", "read")}, "basicAuth": m{"users": m{"name": "u"}}}),
			envoyObj(kSP, "infra", "open", 0, m{"targetRefs": l{target("HTTPRoute", "orders", "admin")}, "basicAuth": m{"users": m{"name": "u"}}}),
			envoyObj(kSP, "infra", "keys", 0, m{"targetRefs": l{target("HTTPRoute", "billing")}, "apiKeyAuth": m{"credentialRefs": l{m{"name": "k"}}}}),
		},
		Secret: func(ns, name string) (map[string]string, bool) { return map[string]string{"alice": "s3cret"}, true },
	})
	if a := cfg.Routes[0].Rules[0].Auth; a == nil || len(a.IPDeny) != 2 {
		t.Errorf("an untranslatable basicAuth must deny: %+v", a)
	}
	if cfg.Routes[1].Rules[0].Auth != native {
		t.Error("a rule's own auth policy must win over the Envoy policy")
	}
	opened := envoyObj(kSP, "infra", "open2", 0, m{"targetRefs": l{target("HTTPRoute", "orders", "admin")}, "basicAuth": m{"users": m{"name": "u"}}})
	opened.Annotations[EnvoyFailOpenAnnotation] = "true"
	cfg2 := envoyCfg()
	ApplyEnvoyCompat(cfg2, EnvoyInput{Policies: []*EnvoyObject{opened}})
	if cfg2.Routes[0].Rules[1].Auth != nil {
		t.Error("the fail-open annotation must leave the rule unprotected")
	}
	o := outcome(res, kSP+"/infra/basic")
	c := o.Conditions(time.Now(), nil)
	if c[0].Status != "False" || c[0].Reason != "Unsupported" || !strings.Contains(c[0].Message, "basicAuth") {
		t.Errorf("conditions: %+v", c)
	}
	// API keys from a Secret become salted hashes, never clear text, and are stable across loads.
	cfgA, cfgB := envoyCfg(), envoyCfg()
	in := EnvoyInput{Policies: []*EnvoyObject{envoyObj(kSP, "infra", "keys", 0, m{"targetRefs": l{target("HTTPRoute", "billing")}, "apiKeyAuth": m{"credentialRefs": l{m{"name": "k"}}}})},
		Secret: func(ns, name string) (map[string]string, bool) { return map[string]string{"alice": "s3cret"}, true }}
	ApplyEnvoyCompat(cfgA, in)
	ApplyEnvoyCompat(cfgB, in)
	ka, kb := cfgA.Routes[1].Rules[0].Auth.APIKey, cfgB.Routes[1].Rules[0].Auth.APIKey
	if ka == nil || len(ka.Keys) != 1 || ka.Keys[0].Key != "" || !strings.HasPrefix(ka.Keys[0].Hash, "sha256$") || ka.Keys[0].Hash != kb.Keys[0].Hash {
		t.Errorf("api keys: %+v", ka)
	}
	// An unreadable Secret refuses traffic and says so.
	cfgC := envoyCfg()
	resC := ApplyEnvoyCompat(cfgC, EnvoyInput{Policies: in.Policies, Secret: func(string, string) (map[string]string, bool) { return nil, false }})
	if a := cfgC.Routes[1].Rules[0].Auth; a == nil || len(a.IPDeny) != 2 {
		t.Errorf("unreadable secret: %+v", a)
	}
	if got := outcome(resC, kSP+"/infra/keys").Invalid; len(got) != 1 {
		t.Errorf("invalid: %v", got)
	}
}

func TestEnvoyBackendAndDirectResponse(t *testing.T) {
	cfg := envoyCfg()
	cfg.Routes[1].Rules = []Rule{
		{BackendRefs: []BackendRef{{Group: EnvoyGroup, Kind: "Backend", Name: "ext", Port: 443}}},
		{Filters: []Filter{{Type: "ExtensionRef", ExtensionRef: &ObjRef{Group: EnvoyGroup, Kind: "HTTPRouteFilter", Name: "gone"}}}, BackendRefs: []BackendRef{{Name: "orders", Port: 80}}},
		{Filters: []Filter{{Type: "ExtensionRef", ExtensionRef: &ObjRef{Group: EnvoyGroup, Kind: "HTTPRouteFilter", Name: "regex"}}}},
	}
	ApplyEnvoyCompat(cfg, EnvoyInput{
		Backends: []*EnvoyObject{envoyObj(kBK, "infra", "ext", 0, m{"endpoints": l{m{"fqdn": m{"hostname": "api.example.test", "port": 443}}}, "appProtocols": l{"gateway.envoyproxy.io/h2c"}})},
		Filters: []*EnvoyObject{
			envoyObj(kHRF, "infra", "gone", 0, m{"directResponse": m{"statusCode": 410, "contentType": "text/plain", "body": m{"inline": "gone"}}}),
			envoyObj(kHRF, "infra", "regex", 0, m{"urlRewrite": m{"path": m{"replaceRegexMatch": m{"pattern": "^/a", "substitution": "/b"}}}}),
		},
	})
	rules := cfg.Routes[1].Rules
	ref := rules[0].BackendRefs[0]
	def := cfg.Backends[backendKey("infra", ref.Name, 443)]
	if ref.Kind != "" || def == nil || def.Endpoints[0] != "api.example.test:443" || def.Protocol != "h2c" {
		t.Errorf("backend: ref %+v def %+v", ref, def)
	}
	if d := rules[1].DirectResponse; d == nil || d.Status != 410 || d.Body != "gone" || len(rules[1].BackendRefs) != 0 || len(rules[1].Filters) != 0 {
		t.Errorf("direct response: %+v rule %+v", d, rules[1])
	}
	if len(rules[2].Filters) != 1 || rules[2].DirectResponse != nil {
		t.Errorf("a regex rewrite cannot be translated and must keep the ExtensionRef (so the route is refused): %+v", rules[2])
	}
}

func TestEnvoyMergeModes(t *testing.T) {
	base := m{"a": m{"x": 1, "y": 2}, "list": l{m{"name": "one", "v": 1}, m{"name": "two", "v": 2}}, "plain": l{1, 2}, "gone": 1}
	over := m{"a": m{"y": 3}, "list": l{m{"name": "two", "v": 9}, m{"name": "three", "v": 3}}, "plain": l{3}, "gone": nil, "mergeType": "x"}
	s := envoyMerge(base, over, "StrategicMerge")
	if s["a"].(map[string]any)["x"] != 1 || s["a"].(map[string]any)["y"] != 3 || len(s["list"].([]any)) != 3 || len(s["plain"].([]any)) != 1 || s["gone"] != nil {
		t.Errorf("strategic: %v", s)
	}
	if _, ok := s["mergeType"]; ok {
		t.Error("mergeType must not be merged")
	}
	j := envoyMerge(base, over, "JSONMerge")
	if len(j["list"].([]any)) != 2 {
		t.Errorf("json merge replaces lists: %v", j["list"])
	}
}
