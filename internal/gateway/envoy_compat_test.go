package gateway

import (
	"encoding/json"
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
			"rateLimit":      m{"type": "Local", "local": m{"rules": l{m{"limit": m{"requests": 100, "unit": "Minute"}}}}},
			"faultInjection": m{"delay": m{"fixedDelay": "2s", "percentage": 10}, "abort": m{"httpStatus": 503, "percentage": 5, "grpcStatus": 14}},
			"mirrors":        l{m{"backendRef": m{"name": "shadow", "port": 80}, "percentage": 20}},
			"proxyProtocol":  m{"version": "V2"},
			"compression":    l{m{"type": "Gzip"}, m{"type": "Brotli"}, m{"type": "Zstd"}}, "tcpKeepalive": m{}, "connection": m{"bufferLimit": "1Mi"}, "dns": m{}, "http2": m{},
			"useClientProtocol": true, "telemetry": m{}, "httpUpgrade": l{}, "requestBuffer": m{"limit": "1Mi"}, "decompression": l{}, "responseOverride": l{}, "routingType": "Service"},
		{"loadBalancer": m{"type": "LeastRequest", "slowStart": m{"window": "30s"}, "zoneAware": m{"preferLocal": m{"force": m{"minEndpointsInZoneThreshold": 1}}}, "endpointOverride": m{}}},
		{"loadBalancer": m{"type": "ConsistentHash", "consistentHash": m{"type": "Header", "header": m{"name": "x-user"}, "tableSize": 65537}}},
		{"rateLimit": m{"type": "Global", "global": m{"rules": l{m{"limit": m{"requests": 100, "unit": "Minute"}, "clientSelectors": l{m{"headers": l{m{"name": "x-user", "type": "Distinct"}}}}}}}}},
		{"healthCheck": m{
			"active": m{"type": "HTTP", "interval": "5s", "timeout": "1s", "unhealthyThreshold": 3, "healthyThreshold": 2,
				"http": m{"path": "/ready", "method": "GET", "expectedStatuses": l{200}, "expectedResponse": m{}}},
			"passive": m{"consecutive5XxErrors": 4, "baseEjectionTime": "20s", "interval": "1s", "maxEjectionPercent": 50,
				"splitExternalLocalOriginErrors": true, "consecutiveLocalOriginFailures": 2, "consecutiveGatewayErrors": 2}}},
		{"healthCheck": m{"active": m{"type": "GRPC", "grpc": m{"service": "pkg.Svc"}}}},
		{"healthCheck": m{"active": m{"type": "TCP", "tcp": m{}}}},
	},
	kCT: {
		{"tls": m{"minVersion": "1.0", "maxVersion": "1.3", "ciphers": l{"ECDHE-RSA-AES128-GCM-SHA256", "TLS_AES_128_GCM_SHA256", "bogus"}, "ecdhCurves": l{}, "signatureAlgorithms": l{}, "alpnProtocols": l{"h2"},
			"session":          m{"resumption": m{"stateless": m{}, "stateful": m{}}},
			"clientValidation": m{"optional": true, "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}, "subjectAltNames": l{"*.example.com", m{"type": "URI", "value": "spiffe://x/y"}}}},
			"enableProxyProtocol": true, "clientIPDetection": m{"xForwardedFor": m{"numTrustedHops": 1}},
			"path":         m{"escapedSlashesAction": "RejectRequest", "disableMergeSlashes": true},
			"timeout":      m{"http": m{"requestReceivedTimeout": "5s", "idleTimeout": "1m"}, "tcp": m{"idleTimeout": "1m"}},
			"connection":   m{"connectionLimit": m{"value": 100, "closeDelay": "1s"}, "bufferLimit": "1Mi", "socketBufferLimit": "1Mi"},
			"tcpKeepalive": m{}, "headers": m{"xForwardedClientCert": m{}}, "http1": m{}, "http2": m{}, "http3": m{}, "healthCheck": m{}},
		{"headers": m{"enableEnvoyHeaders": true}},
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
			"oidc": m{"provider": m{"issuer": "https://idp", "authorizationEndpoint": "https://idp/a", "tokenEndpoint": "https://idp/t", "endSessionEndpoint": "https://idp/e", "backendRefs": l{}},
				"clientID": "id", "clientSecret": m{"name": "oidc"}, "scopes": l{"email"}, "redirectURL": "https://app/oauth2/callback", "logoutPath": "/out", "forwardAccessToken": true,
				"cookieDomain": "app", "cookieConfig": m{"sameSite": "Strict"}, "cookieNames": m{}, "refreshToken": true, "disableTokenEncryption": true,
				"defaultTokenTTL": "1h", "defaultRefreshTokenTTL": "1h", "denyRedirect": m{}, "resources": l{"r"}},
			"extAuth": m{"http": m{"backendRefs": l{m{"name": "authz", "port": 9000}}, "path": "/v", "headersToBackend": l{"X"}},
				"headersToExtAuth": l{"Y"}, "bodyToExtAuth": m{}, "failOpen": true, "recomputeRoute": true},
			"authorization": m{"defaultAction": "Deny", "rules": l{m{"action": "Allow", "principal": m{"clientCIDRs": l{"10.0.0.0/8"}}}}}},
		{"jwt": m{"providers": l{m{"name": "c", "issuer": "https://k", "localJWKS": m{"type": "Inline", "inline": `{"keys":[]}`}}}}},
		{"extAuth": m{"grpc": m{"backendRefs": l{m{"name": "authz", "port": 9000}}}}},
		{"authorization": m{"rules": l{m{"action": "Deny", "principal": m{"jwt": m{}, "headers": l{}}, "operation": m{}}}}},
		{"authorization": m{"defaultAction": "Deny", "rules": l{m{"action": "Allow",
			"principal": m{"clientCIDRs": l{"10.0.0.0/8"}, "jwt": m{"claims": l{m{"name": "role", "valueType": "String", "values": l{"admin"}}}, "scopes": l{"read"}}, "headers": l{m{"name": "x-env", "values": l{"a", "b"}}}},
			"operation": m{"methods": l{"GET"}}}}}},
		{"oidc": m{"provider": m{"issuer": "https://idp"}, "clientIDRef": m{"name": "id"}}},
	},
}

// sinkOpts name a Redis server and an OIDC cookie key, so the fields that need them are translated.
var sinkOpts = EnvoyOptions{Namespace: "ns", Redis: "default", OIDCCookieKey: "env:SETURA_COOKIE_KEY"}

func TestEnvoyCompatTableMatchesTranslator(t *testing.T) {
	for kind, specs := range kitchenSinks {
		notes := map[string][]FieldNote{}
		for _, spec := range specs {
			for _, n := range TranslateEnvoyPolicy(kind, spec, sinkOpts).Notes {
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
		{"credentialInjection": m{"header": "Authorization", "overwrite": false, "credential": m{"valueRef": m{"name": "tok"}}}},
		{"urlRewrite": m{"path": m{"replaceRegexMatch": m{"pattern": "a", "substitution": "b"}}, "hostname": m{"type": "Header"}}, "credentialInjection": m{}},
	} {
		for _, n := range TranslateHTTPRouteFilter(spec, "ns").Notes {
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
	s := TranslateEnvoyPolicy(kSP, kitchenSinks[kSP][0], sinkOpts)
	sort.Strings(s.FailClosed)
	if strings.Join(s.FailClosed, ",") != "basicAuth" {
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

// ---- the edge and shaping features ----

func TestEnvoyLoadBalancerAndShapingFields(t *testing.T) {
	cfg := envoyCfg()
	res := ApplyEnvoyCompat(cfg, EnvoyInput{Policies: []*EnvoyObject{
		envoyObj(kBT, "infra", "shape", 0, m{"targetRefs": l{target("HTTPRoute", "orders")},
			"loadBalancer":  m{"type": "ConsistentHash", "consistentHash": m{"type": "Cookie", "cookie": m{"name": "sid", "ttl": "1h"}}},
			"compression":   l{m{"type": "Gzip"}, m{"type": "Brotli"}},
			"requestBuffer": m{"limit": "2Mi"}}),
	}})
	lb := cfg.Backends["infra/orders:80"].LoadBalancer
	if lb == nil || lb.Algorithm != AlgoConsistentHash || lb.ConsistentHash == nil || lb.ConsistentHash.On != "cookie" || lb.ConsistentHash.Name != "sid" || lb.ConsistentHash.TTL != "1h" {
		t.Errorf("load balancer: %+v", lb)
	}
	r := cfg.Routes[0].Rules[0]
	if r.Compress == nil || r.Compress.Enabled == nil || !*r.Compress.Enabled || len(r.Compress.Encodings) != 1 || r.Compress.Encodings[0] != "gzip" {
		t.Errorf("compress: %+v", r.Compress)
	}
	if r.Limits == nil || r.Limits.MaxRequestBody != "2097152" {
		t.Errorf("limits: %+v", r.Limits)
	}
	if ig := outcome(res, kBT+"/infra/shape").Ignored; len(ig) != 1 || ig[0] != "compression.brotli" {
		t.Errorf("ignored: %v", ig)
	}
	// zone aware and slow start on a least request balancer; a hash table size picks Maglev
	tr := TranslateEnvoyPolicy(kBT, m{"loadBalancer": m{"type": "LeastRequest", "slowStart": m{"window": "20s"}, "zoneAware": m{"preferLocal": m{}}}}, EnvoyOptions{})
	b, _ := json.Marshal(tr.Backend["loadBalancer"])
	if string(b) != `{"algorithm":"leastRequest","locality":{"preferLocalZone":true},"slowStart":{"window":"20s"}}` {
		t.Errorf("least request: %s", b)
	}
	tr = TranslateEnvoyPolicy(kBT, m{"loadBalancer": m{"type": "ConsistentHash", "consistentHash": m{"type": "SourceIP", "tableSize": 65537}}}, EnvoyOptions{})
	if h := tr.Backend["loadBalancer"].(map[string]any)["consistentHash"].(map[string]any); h["type"] != "maglev" || h["on"] != "sourceIP" {
		t.Errorf("maglev: %v", h)
	}
	// a GRPCRoute takes the backend setting but no rule field
	g := TranslateEnvoyPolicy(kBT, m{"loadBalancer": m{"type": "Random"}, "compression": l{m{"type": "Gzip"}}}, EnvoyOptions{TargetKind: "GRPCRoute"})
	if g.Backend["loadBalancer"] == nil || g.Rule != nil {
		t.Errorf("GRPCRoute: backend %v rule %v", g.Backend, g.Rule)
	}
}

func TestEnvoyGlobalRateLimitNeedsRedis(t *testing.T) {
	spec := m{"rateLimit": m{"type": "Global", "global": m{"rules": l{m{"limit": m{"requests": 10, "unit": "Second"}}}}}}
	none := TranslateEnvoyPolicy(kBT, spec, EnvoyOptions{})
	if none.Rule != nil || len(none.Ignored()) == 0 {
		t.Errorf("without a Redis name nothing is translated: %v %v", none.Rule, none.Ignored())
	}
	found := false
	for _, n := range none.Notes {
		found = found || (n.Field == "rateLimit.global" && strings.Contains(n.Reason, EnvoyRedisAnnotation))
	}
	if !found {
		t.Errorf("the note must name the annotation: %+v", none.Notes)
	}
	cfg := envoyCfg()
	obj := envoyObj(kBT, "infra", "global", 0, spec)
	obj.Spec["targetRefs"] = l{target("HTTPRoute", "orders")}
	obj.Annotations[EnvoyRedisAnnotation] = "limits"
	ApplyEnvoyCompat(cfg, EnvoyInput{Policies: []*EnvoyObject{obj}})
	rl := cfg.Routes[0].Rules[0].RateLimit
	if rl == nil || rl.Shared == nil || rl.Shared.Redis != "limits" || rl.Key != "route" || string(rl.Rate) != "10/s" {
		t.Errorf("rate limit: %+v", rl)
	}
}

func TestEnvoyOIDCAndAuthorization(t *testing.T) {
	cfg := envoyCfg()
	login := envoyObj(kSP, "infra", "login", 0, m{"targetRefs": l{target("HTTPRoute", "orders", "read")},
		"oidc": m{"provider": m{"issuer": "https://idp.test"}, "clientID": "web", "clientSecret": m{"name": "oidc"}, "redirectURL": "https://app.test/oauth2/callback"}})
	login.Annotations[EnvoyOIDCCookieKeyAnnotation] = "secret:keys#cookie"
	nokey := envoyObj(kSP, "infra", "nokey", 0, m{"targetRefs": l{target("HTTPRoute", "orders", "admin")},
		"oidc": m{"provider": m{"issuer": "https://idp.test"}, "clientID": "web", "redirectURL": "https://app.test/oauth2/callback"}})
	authz := envoyObj(kSP, "infra", "authz", 0, m{"targetRefs": l{target("HTTPRoute", "billing")},
		"authorization": m{"defaultAction": "Deny", "rules": l{m{"action": "Allow",
			"principal": m{"jwt": m{"claims": l{m{"name": "role", "values": l{"admin", "ops"}}}, "scopes": l{"orders.read"}}, "headers": l{m{"name": "x-env", "values": l{"a", "b"}}}},
			"operation": m{"methods": l{"GET"}}}}}})
	res := ApplyEnvoyCompat(cfg, EnvoyInput{Policies: []*EnvoyObject{login, nokey, authz}})
	o := cfg.Routes[0].Rules[0].Auth
	if o == nil || o.OIDC == nil || o.OIDC.Issuer != "https://idp.test" || o.OIDC.ClientSecret == nil || o.OIDC.ClientSecret.Secret.Key != "client-secret" || o.OIDC.ClientSecret.Secret.Namespace != "infra" ||
		len(o.OIDC.CookieKeys) != 1 || o.OIDC.CookieKeys[0].Secret.Name != "keys" || !o.OIDC.DisableRefresh {
		t.Errorf("oidc: %+v", o)
	}
	if got := outcome(res, kSP+"/infra/login"); len(got.FailClosed) != 0 || len(got.Invalid) != 0 {
		t.Errorf("a translated oidc policy must not fail closed: %+v", got)
	}
	// without the cookie key the policy cannot be enforced: refuse
	if a := cfg.Routes[0].Rules[1].Auth; a == nil || len(a.IPDeny) != 2 {
		t.Errorf("oidc without a cookie key must deny: %+v", a)
	}
	if got := outcome(res, kSP+"/infra/nokey").FailClosed; len(got) != 1 || got[0] != "oidc" {
		t.Errorf("fail closed: %v", got)
	}
	az := cfg.Routes[1].Rules[0].Auth
	if az == nil || az.Authorization == nil || az.Authorization.DefaultAction != "deny" || len(az.Authorization.Rules) != 2 {
		t.Fatalf("authorization: %+v", az)
	}
	r0 := az.Authorization.Rules[0]
	if r0.Action != "allow" || len(r0.Principals[0].Claims) != 1 || r0.Principals[0].Claims[0].In[1] != "ops" || r0.Principals[0].Scopes[0] != "orders.read" ||
		r0.Operations[0].Methods[0] != "GET" || r0.Operations[0].Headers[0].Name != "x-env" || r0.Operations[0].Headers[0].Exact != "a" || az.Authorization.Rules[1].Operations[0].Headers[0].Exact != "b" {
		t.Errorf("rule: %+v", r0)
	}
	if got := outcome(res, kSP+"/infra/authz").FailClosed; len(got) != 0 {
		t.Errorf("authorization is enforced now: %v", got)
	}
	// an operation member Setura cannot express still fails closed
	bad := TranslateEnvoyPolicy(kSP, m{"authorization": m{"rules": l{m{"action": "Allow", "principal": m{"clientCIDRs": l{"10.0.0.0/8"}}, "operation": m{"paths": l{"/x"}}}}}}, EnvoyOptions{})
	if len(bad.FailClosed) != 1 || bad.FailClosed[0] != "authorization" {
		t.Errorf("unsupported operation: %v", bad.FailClosed)
	}
}

func TestEnvoyCredentialInjectionAndListener(t *testing.T) {
	cfg := envoyCfg()
	cfg.Routes[0].Rules[0].Filters = []Filter{{Type: "ExtensionRef", ExtensionRef: &ObjRef{Group: EnvoyGroup, Kind: "HTTPRouteFilter", Name: "token"}}}
	ApplyEnvoyCompat(cfg, EnvoyInput{
		Filters: []*EnvoyObject{envoyObj(kHRF, "infra", "token", 0, m{"credentialInjection": m{"header": "X-Api-Token", "credential": m{"valueRef": m{"name": "up"}}}})},
		Policies: []*EnvoyObject{envoyObj(kCT, "infra", "client", 0, m{"targetRefs": l{target("Gateway", "edge", "tls")},
			"tls": m{"ciphers": l{"ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-CHACHA20-POLY1305"}, "session": m{"resumption": m{"stateless": m{}}},
				"clientValidation": m{"caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}, "subjectAltNames": l{"*.clients.test"}}},
			"connection": m{"connectionLimit": m{"value": 50}}})},
	})
	a := cfg.Routes[0].Rules[0].Auth
	if a == nil || len(a.Inject) != 1 || a.Inject[0].Header != "X-Api-Token" || a.Inject[0].Secret.Secret.Key != "credential" || a.Inject[0].Secret.Secret.Namespace != "infra" {
		t.Errorf("inject: %+v", a)
	}
	if len(cfg.Routes[0].Rules[0].Filters) != 0 {
		t.Errorf("the ExtensionRef must be consumed: %+v", cfg.Routes[0].Rules[0].Filters)
	}
	lis := cfg.Gateways[0].Listeners[1]
	if o := lis.TLS.Options[TLSCipherSuitesOption]; o != "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" {
		t.Errorf("ciphers %q", o)
	}
	if lis.TLS.Options[TLSSessionResumptionOption] != "on" || lis.Limits == nil || lis.Limits.MaxConnections != 50 {
		t.Errorf("listener: %+v %+v", lis.TLS.Options, lis.Limits)
	}
	pp := cfg.Gateways[0].TLS.Frontend.PerPort
	if len(pp) != 1 || pp[0].TLS.Validation.Allow == nil || pp[0].TLS.Validation.Allow.SAN[0] != "*.clients.test" {
		t.Errorf("frontend: %+v", pp)
	}
	// Go's insecure and TLS 1.3 suites are dropped with a note
	tr := TranslateEnvoyPolicy(kCT, m{"tls": m{"ciphers": l{"TLS_AES_128_GCM_SHA256", "ECDHE-RSA-DES-CBC3-SHA"}}}, EnvoyOptions{})
	if tr.Listener != nil || len(tr.Ignored()) != 1 {
		t.Errorf("no usable suite: %v %v", tr.Listener, tr.Ignored())
	}
}
