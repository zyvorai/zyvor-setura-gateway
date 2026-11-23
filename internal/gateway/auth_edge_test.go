package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// ---- authorization ----

func authzPolicy(k *jwtKey) m {
	hash, _ := HashAPIKey("deploy-key")
	return m{
		"jwt":    m{"issuer": "https://idp.test", "audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))},
		"apiKey": m{"header": "X-Api-Key", "keys": l{m{"name": "ci", "hash": hash}, m{"name": "other", "key": "other-key"}}},
		"authorization": m{"defaultAction": "deny", "rules": l{
			m{"name": "no-delete", "action": "deny", "operations": l{m{"methods": l{"DELETE"}}}},
			m{"name": "admin-area", "action": "allow", "principals": l{m{"claims": l{m{"name": "realm_access.roles", "exact": "admin"}}}},
				"operations": l{m{"paths": l{m{"prefix": "/admin"}}}}},
			m{"name": "ci-deploy", "action": "allow", "principals": l{m{"apiKeys": l{"ci"}}},
				"operations": l{m{"methods": l{"POST"}, "paths": l{m{"exact": "/deploy"}}}}},
			m{"name": "readers", "action": "allow",
				"principals": l{m{"scopes": l{"orders:read"}}, m{"claims": l{m{"name": "email", "prefix": "svc-"}}}},
				"operations": l{m{"methods": l{"GET", "HEAD"}, "paths": l{m{"regex": "/orders/[0-9]+"}}, "headers": l{m{"name": "X-Env", "exact": "prod"}}}}},
			m{"name": "tiers", "action": "allow", "principals": l{m{"claims": l{m{"name": "tier", "in": l{"gold", "silver"}}}}},
				"operations": l{m{"paths": l{m{"prefix": "/premium"}}}}},
			m{"name": "lan", "action": "allow", "principals": l{m{"cidrs": l{"127.0.0.0/8"}, "authenticated": true}},
				"operations": l{m{"paths": l{m{"prefix": "/internal"}}}}},
		}},
	}
}

func TestAuthorizationRules(t *testing.T) {
	k := newRSAKey(t, "k")
	s, up := authServer(t, authzPolicy(k), nil)
	tok := func(extra map[string]any) []string { return bearer(k.sign(t, nil, claims(extra))) }
	admin := map[string]any{"realm_access": m{"roles": l{"user", "admin"}}}
	cases := []struct {
		name   string
		method string
		path   string
		hdr    []string
		want   int
		rule   string
	}{
		{"admin on /admin", "GET", "/admin/users", tok(admin), 200, ""},
		{"admin may not DELETE (first match wins)", "DELETE", "/admin/users/1", tok(admin), 403, "no-delete"},
		{"plain user on /admin", "GET", "/admin/users", tok(map[string]any{"realm_access": m{"roles": l{"user"}}}), 403, "default"},
		{"api key by name", "POST", "/deploy", []string{"X-Api-Key", "deploy-key"}, 200, ""},
		{"api key wrong path", "GET", "/deploy", []string{"X-Api-Key", "deploy-key"}, 403, "default"},
		{"other key name", "POST", "/deploy", []string{"X-Api-Key", "other-key"}, 403, "default"},
		{"scope + regex + header", "GET", "/orders/42", append(tok(map[string]any{"scope": "openid orders:read"}), "X-Env", "prod"), 200, ""},
		{"scope but header differs", "GET", "/orders/42", append(tok(map[string]any{"scope": "orders:read"}), "X-Env", "dev"), 403, "default"},
		{"scope but path is not whole match", "GET", "/orders/42/items", append(tok(map[string]any{"scope": "orders:read"}), "X-Env", "prod"), 403, "default"},
		{"second principal (claim prefix)", "HEAD", "/orders/7", append(tok(map[string]any{"email": "svc-billing@x"}), "X-Env", "prod"), 200, ""},
		{"claim in list", "GET", "/premium/x", tok(map[string]any{"tier": "silver"}), 200, ""},
		{"claim not in list", "GET", "/premium/x", tok(map[string]any{"tier": "bronze"}), 403, "default"},
		{"cidr principal", "GET", "/internal/x", tok(nil), 200, ""},
		{"unauthenticated stays 401", "GET", "/admin/x", nil, 401, ""},
	}
	for _, c := range cases {
		before := len(up.seen())
		r := req(t, client(s.Addr(8080), nil), "http", c.method, "a.test", c.path, "", c.hdr...)
		if r.Status != c.want {
			t.Errorf("%s: %d, want %d (%s)", c.name, r.Status, c.want, r.Body)
			continue
		}
		if c.want == 403 {
			var j map[string]string
			if json.Unmarshal([]byte(r.Body), &j) != nil || j["error"] != "forbidden" || j["code"] != "authorization_denied" || j["rule"] != c.rule || j["message"] == "" {
				t.Errorf("%s: body %q", c.name, r.Body)
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || len(up.seen()) != before {
				t.Errorf("%s: content type %q, backend reached %v", c.name, r.Header.Get("Content-Type"), len(up.seen()) != before)
			}
		}
	}
	mt := metricsOf(s)
	for _, w := range []string{`action="allow",source="rule"}`, `action="deny",source="rule"}`, `action="deny",source="default"}`, `reason="authz"}`} {
		if !strings.Contains(mt, w) {
			t.Errorf("metrics lack %s", w)
		}
	}
	if strings.Contains(mt, "admin-area") {
		t.Error("rule names must not become metric labels")
	}
	// A default of allow lets unmatched requests through; a deny rule still wins.
	p := m{"apiKey": m{"keys": l{m{"name": "ci", "key": "k1"}}}, "authorization": m{"defaultAction": "allow",
		"rules": l{m{"name": "no-secret", "action": "deny", "operations": l{m{"paths": l{m{"prefix": "/secret"}}}}}}}}
	s2, _ := authServer(t, p, nil)
	if r := get(t, s2, "a.test", "/anything", "X-Api-Key", "k1"); r.Status != 200 {
		t.Errorf("default allow: %d", r.Status)
	}
	if r := get(t, s2, "a.test", "/secret/x", "X-Api-Key", "k1"); r.Status != 403 {
		t.Errorf("deny rule under default allow: %d", r.Status)
	}
}

func TestAuthorizationInWhy(t *testing.T) {
	k := newRSAKey(t, "k")
	s, _ := authServer(t, authzPolicy(k), nil)
	explain := func(method, path string, remote string, hdr ...string) *TraceAuth {
		er, err := ParseExplainRequest(method, "http://a.test:8080"+path, headerLines(hdr), "", "")
		if err != nil {
			t.Fatal(err)
		}
		er.Remote, er.Now = remote, t0
		return Explain(s.Table(), er).Winner.Auth
	}
	admin := bearer(k.sign(t, nil, claims(map[string]any{"realm_access": m{"roles": l{"admin"}}})))
	a := explain("GET", "/admin/x", "127.0.0.1", admin...)
	if a.Decision != "allow" || a.AuthzRule != "admin-area" || a.AuthzAction != "allow" {
		t.Errorf("allow: %+v", a)
	}
	a = explain("DELETE", "/admin/x", "127.0.0.1", admin...)
	if a.Decision != "deny" || a.Status != 403 || a.AuthzRule != "no-delete" || !strings.Contains(a.Reason, "no-delete") {
		t.Errorf("deny: %+v", a)
	}
	a = explain("GET", "/nothing", "127.0.0.1", admin...)
	if a.Decision != "deny" || a.AuthzRule != "default" || !strings.Contains(a.Reason, "default action is deny") {
		t.Errorf("default: %+v", a)
	}
	// A rule that needs the client address cannot be decided without one.
	a = explain("GET", "/internal/x", "", admin...)
	if a.Decision != "unknown" || !strings.Contains(a.Reason, "lan") {
		t.Errorf("no client address: %+v", a)
	}
}

func TestAuthzPrincipalsCertAndCIDR(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "billing-svc"}, DNSNames: []string{"billing.mesh.test"}}
	u, _ := url.Parse("spiffe://mesh/ns/prod/sa/billing")
	cert.URIs = []*url.URL{u}
	cc := &ClientCert{Verified: true, SAN: sanList(cert), leaf: cert}
	pol, err := compileAuthz(&AuthzPolicy{DefaultAction: "deny", Rules: []AuthzRule{
		{Name: "spiffe", Action: "allow", Principals: []AuthzPrincipal{{ClientCertSAN: []string{"spiffe://mesh/ns/prod/sa/billing"}}}},
		{Name: "dns", Action: "allow", Principals: []AuthzPrincipal{{ClientCertSAN: []string{"DNS:ledger.mesh.test"}}}},
		{Name: "cn", Action: "allow", Principals: []AuthzPrincipal{{ClientCertCN: []string{"reporting"}}}},
		{Name: "net", Action: "allow", Principals: []AuthzPrincipal{{CIDRs: []string{"10.1.0.0/16", "2001:db8::/32"}}}},
		{Name: "anon", Action: "deny", Principals: []AuthzPrincipal{{Authenticated: boolp(false)}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newReq("GET", "/")
	for _, c := range []struct {
		name   string
		caller authzCaller
		want   string
		unk    bool
	}{
		{"spiffe uri", authzCaller{cert: cc, certKnown: true, method: "none"}, "spiffe", false},
		{"dns san", authzCaller{cert: &ClientCert{Verified: true, leaf: &x509.Certificate{DNSNames: []string{"ledger.mesh.test"}}}, certKnown: true, method: "none"}, "dns", false},
		{"cn", authzCaller{cert: &ClientCert{Verified: true, leaf: &x509.Certificate{Subject: pkix.Name{CommonName: "reporting"}}}, certKnown: true, method: "none"}, "cn", false},
		{"unverified cert", authzCaller{cert: &ClientCert{Verified: false, leaf: cert}, certKnown: true, method: "jwt", ip: netip.MustParseAddr("10.1.2.3")}, "net", false},
		{"ipv6 cidr", authzCaller{certKnown: true, method: "jwt", ip: netip.MustParseAddr("2001:db8::7")}, "net", false},
		{"outside cidr", authzCaller{certKnown: true, method: "jwt", ip: netip.MustParseAddr("10.2.0.1")}, "default", false},
		{"anonymous", authzCaller{certKnown: true, method: "none", ip: netip.MustParseAddr("10.2.0.1")}, "anon", false},
		{"cert unknown offline", authzCaller{method: "jwt", ip: netip.MustParseAddr("10.2.0.1")}, "spiffe", true},
	} {
		m, unk := pol.decide(r, c.caller)
		if m.Rule != c.want || unk != c.unk {
			t.Errorf("%s: rule %q unknown %v, want %q %v", c.name, m.Rule, unk, c.want, c.unk)
		}
	}
	// Bad rules are refused.
	for name, p := range map[string]AuthzPolicy{
		"bad action":     {Rules: []AuthzRule{{Action: "maybe"}}},
		"bad default":    {DefaultAction: "log"},
		"bad regex":      {Rules: []AuthzRule{{Action: "allow", Operations: []AuthzOperation{{Paths: []AuthzString{{Regex: "("}}}}}}},
		"two forms":      {Rules: []AuthzRule{{Action: "allow", Operations: []AuthzOperation{{Paths: []AuthzString{{Exact: "/a", Prefix: "/"}}}}}}},
		"empty op":       {Rules: []AuthzRule{{Action: "allow", Operations: []AuthzOperation{{}}}}},
		"empty subject":  {Rules: []AuthzRule{{Action: "allow", Principals: []AuthzPrincipal{{}}}}},
		"bad cidr":       {Rules: []AuthzRule{{Action: "allow", Principals: []AuthzPrincipal{{CIDRs: []string{"10.0.0/8"}}}}}},
		"claim no test":  {Rules: []AuthzRule{{Action: "allow", Principals: []AuthzPrincipal{{Claims: []AuthzClaim{{Name: "x"}}}}}}},
		"header no test": {Rules: []AuthzRule{{Action: "allow", Operations: []AuthzOperation{{Headers: []AuthzHeader{{Name: "X"}}}}}}},
	} {
		if _, err := compileAuthz(&p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func newReq(method, target string) (*http.Request, error) {
	return http.NewRequest(method, "http://a.test"+target, nil)
}

// ---- CSRF ----

func TestCSRFOriginCheck(t *testing.T) {
	s, up := authServer(t, m{"csrf": m{"allowedOrigins": l{"https://app.zyvor.test"}}}, nil)
	post := func(hdr ...string) reply {
		return req(t, client(s.Addr(8080), nil), "http", "POST", "a.test", "/api", "x=1", hdr...)
	}
	for _, c := range []struct {
		name string
		hdr  []string
		want int
	}{
		{"no origin (not a browser)", nil, 200},
		{"same origin", []string{"Origin", "http://a.test"}, 200},
		{"default port spelled out", []string{"Origin", "http://a.test:80"}, 200},
		{"host case", []string{"Origin", "http://A.TEST"}, 200},
		{"scheme differs", []string{"Origin", "https://a.test"}, 403},
		{"other site", []string{"Origin", "http://evil.test"}, 403},
		{"null origin", []string{"Origin", "null"}, 403},
		{"allowed origin", []string{"Origin", "https://app.zyvor.test"}, 200},
		{"allowed origin other scheme", []string{"Origin", "http://app.zyvor.test"}, 403},
		{"referer same origin", []string{"Referer", "http://a.test/page?x=1"}, 200},
		{"referer other site", []string{"Referer", "http://evil.test/page"}, 403},
		{"origin wins over referer", []string{"Origin", "http://evil.test", "Referer", "http://a.test/"}, 403},
		{"bearer is exempt", []string{"Origin", "http://evil.test", "Authorization", "Bearer abc"}, 200},
	} {
		if r := post(c.hdr...); r.Status != c.want {
			t.Errorf("%s: %d, want %d", c.name, r.Status, c.want)
		} else if c.want == 403 {
			var j map[string]string
			if json.Unmarshal([]byte(r.Body), &j) != nil || j["code"] != "csrf_rejected" || !strings.Contains(j["message"], "csrf") {
				t.Errorf("%s: body %q", c.name, r.Body)
			}
		}
	}
	before := len(up.seen())
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if r := req(t, client(s.Addr(8080), nil), "http", m, "a.test", "/", "", "Origin", "http://evil.test"); r.Status != 200 {
			t.Errorf("%s with a foreign origin: %d", m, r.Status)
		}
	}
	if len(up.seen()) != before+3 {
		t.Error("safe methods must not be blocked")
	}
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		if r := req(t, client(s.Addr(8080), nil), "http", m, "a.test", "/", "", "Origin", "http://evil.test"); r.Status != 403 {
			t.Errorf("%s with a foreign origin: %d", m, r.Status)
		}
	}
	if !strings.Contains(metricsOf(s), `reason="csrf"}`) {
		t.Error("csrf denials are not counted")
	}
	// requireOrigin refuses a state changing request that says nothing about where it came from.
	s2, _ := authServer(t, m{"csrf": m{"requireOrigin": true, "safeMethods": l{"GET"}}}, nil)
	if r := req(t, client(s2.Addr(8080), nil), "http", "POST", "a.test", "/", ""); r.Status != 403 {
		t.Errorf("requireOrigin: %d", r.Status)
	}
	if r := req(t, client(s2.Addr(8080), nil), "http", "HEAD", "a.test", "/", ""); r.Status != 403 {
		t.Errorf("HEAD is not safe when safeMethods is GET: %d", r.Status)
	}
	// Behind TLS the origin is https.
	c, _ := compileCSRF(&CSRFPolicy{})
	r, _ := newReq("POST", "/")
	r.Host = "a.test"
	r.Header.Set("Origin", "https://a.test")
	if c.check(r, true) != "" || c.check(r, false) == "" {
		t.Error("https origin check")
	}
	if _, err := compileCSRF(&CSRFPolicy{AllowedOrigins: []string{"app.test"}}); err == nil {
		t.Error("an origin without a scheme is accepted")
	}
}

// ---- credential injection ----

func TestCredentialInjection(t *testing.T) {
	t.Setenv("TEST_UP_TOKEN", "tok-123")
	t.Setenv("TEST_UP_PASS", "p@ss:word")
	pol := m{"inject": l{
		m{"header": "X-Upstream-Key", "secret": m{"env": "TEST_UP_TOKEN"}},
		m{"header": "Authorization", "scheme": "Bearer", "secret": m{"env": "TEST_UP_TOKEN"}},
		m{"header": "X-Basic", "scheme": "Basic", "username": "svc", "secret": m{"env": "TEST_UP_PASS"}},
	}}
	s, up := authServer(t, pol, nil)
	r := get(t, s, "a.test", "/", "x-upstream-key", "client-value", "Authorization", "Bearer client-token", "X-Basic", "Basic Zm9vOmJhcg==")
	h := r.Echo.Headers
	if r.Status != 200 || h["x-upstream-key"] != "tok-123" || h["authorization"] != "Bearer tok-123" {
		t.Fatalf("injection: %d %v", r.Status, h)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:p@ss:word")); h["x-basic"] != want {
		t.Errorf("basic: %q", h["x-basic"])
	}
	if len(up.seen()) != 1 {
		t.Errorf("backend calls: %d", len(up.seen()))
	}
	// The explained request shows the header but never the value, and no secret is in the dump.
	tr := explainAuthFor(t, s, "127.0.0.1", "x-upstream-key", "client-value")
	tj, _ := json.Marshal(tr)
	cfg, _ := json.Marshal(s.Table().Cfg.Routes[0].Rules[0].Auth)
	if strings.Contains(string(tj), "tok-123") || strings.Contains(string(cfg), "tok-123") || strings.Contains(string(tj), "client-value") {
		t.Errorf("secret or client value in why/dump:\n%s\n%s", tj, cfg)
	}
	if got := tr.Winner.Backends[0].Request.Headers["X-Upstream-Key"]; got != redacted {
		t.Errorf("explained value %q", got)
	}
	// A secret that cannot be read makes the route invalid.
	t.Setenv("TEST_UP_TOKEN", "")
	s2, up2 := authServer(t, pol, nil)
	if r := get(t, s2, "a.test", "/"); r.Status == 200 || len(up2.seen()) != 0 {
		t.Errorf("missing secret: %d", r.Status)
	}
	for name, d := range map[string]m{"no secret": {"header": "X"}, "bad scheme": {"header": "X", "scheme": "Digest", "secret": m{"env": "A"}},
		"host": {"header": "Host", "secret": m{"env": "A"}}, "username w/o basic": {"header": "X", "username": "u", "secret": m{"env": "A"}}} {
		raw, _ := json.Marshal(m{"inject": l{d}})
		if _, err := ParseAuthBlock(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A secret read from a file follows the file when it changes.
func TestCredentialInjectionFileRotation(t *testing.T) {
	old := aiSecretRecheck
	aiSecretRecheck = 0
	t.Cleanup(func() { aiSecretRecheck = old })
	path := t.TempDir() + "/up.token"
	writeFile(t, path, []byte("first\n"))
	s, _ := authServer(t, m{"inject": l{m{"header": "X-Token", "secret": m{"file": path}}}}, nil)
	if r := get(t, s, "a.test", "/"); r.Echo.Headers["x-token"] != "first" {
		t.Fatalf("first: %v", r.Echo.Headers)
	}
	writeFile(t, path, []byte("second-longer\n"))
	if err := os.Chtimes(path, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := get(t, s, "a.test", "/"); r.Echo.Headers["x-token"] != "second-longer" {
		t.Errorf("after rotation: %v", r.Echo.Headers["x-token"])
	}
}

// ---- {claim:NAME} header variables ----

func TestClaimHeaderVariables(t *testing.T) {
	k := newRSAKey(t, "k")
	be, ups := upstreams(t, "a")
	filters := l{m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{
		"set": l{m{"name": "X-Who", "value": "{claim:sub}@{claim:tenant.name}"}, m{"name": "X-Roles", "value": "{claim:realm_access.roles}"},
			m{"name": "X-Missing", "value": "{claim:nope}"}},
		"add": l{m{"name": "X-Both", "value": "a-{claim:sub}"}}}}}
	r1 := rule("/", ref("a", 1))
	r1["filters"] = filters
	r1[authKeyT] = m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}}
	r2 := rule("/open", ref("a", 1))
	r2["filters"] = filters
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r2, r1)}, be), func(o *Options) { o.AuthClock = func() time.Time { return t0 } })
	_ = ups
	tok := bearer(k.sign(t, nil, claims(map[string]any{"tenant": m{"name": "acme"}, "realm_access": m{"roles": l{"a", "b"}}})))
	r := get(t, s, "a.test", "/x", append(tok, "X-Who", "forged", "X-Missing", "forged", "X-Roles", "forged", "X-Both", "pre")...)
	h := r.Echo.Headers
	if r.Status != 200 || h["x-who"] != "alice@acme" || h["x-roles"] != "a,b" || h["x-both"] != "pre,a-alice" {
		t.Fatalf("claim variables: %d %v", r.Status, h)
	}
	if _, ok := h["x-missing"]; ok {
		t.Errorf("a header with an unresolved claim is sent: %q", h["x-missing"])
	}
	// A route without a verified identity never carries a client's value for these headers.
	r = get(t, s, "a.test", "/open", "X-Who", "forged", "X-Roles", "admin")
	if r.Status != 200 || r.Echo.Headers["x-who"] != "" || r.Echo.Headers["x-roles"] != "" {
		t.Errorf("unauthenticated route: %v", r.Echo.Headers)
	}
	// "setura why" renders the same upstream request.
	er, _ := ParseExplainRequest("GET", "http://a.test:8080/x", headerLines(append(tok, "X-Who", "forged")), "", "")
	er.Remote, er.Now = "127.0.0.1", t0
	tr := Explain(s.Table(), er)
	got := tr.Winner.Backends[0].Request.Headers
	if got["X-Who"] != "alice@acme" || got["X-Roles"] != "a,b" || got["X-Both"] != "a-alice" {
		t.Errorf("why upstream headers: %v", got)
	}
	if _, ok := got["X-Missing"]; ok {
		t.Errorf("why shows a header the proxy does not send")
	}
	if v := ClaimVars("{claim:a}x{client_ip}{claim:b.c}{claim:"); len(v) != 2 || v[0] != "a" || v[1] != "b.c" {
		t.Errorf("ClaimVars: %v", v)
	}
}

// ---- TLS cipher suites and session resumption ----

func TestParseCipherSuites(t *testing.T) {
	ids, err := ParseCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	if err != nil || len(ids) != 2 || ids[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("%v %v", ids, err)
	}
	for in, want := range map[string]string{
		"TLS_RSA_WITH_RC4_128_SHA":     "insecure",
		"TLS_AES_128_GCM_SHA256":       "TLS 1.3",
		"TLS_CHACHA20_POLY1305_SHA256": "TLS 1.3",
		"NOT_A_SUITE":                  "unknown",
		" , ":                          "no cipher",
	} {
		if _, err := ParseCipherSuites(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if v, err := ParseResumption("OFF"); err != nil || v != "off" {
		t.Errorf("resumption: %q %v", v, err)
	}
	if _, err := ParseResumption("maybe"); err == nil {
		t.Error("resumption maybe accepted")
	}
}

func dialEdgeTLS(t *testing.T, s *Server, p *pki, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	cfg.RootCAs, cfg.ServerName = p.pool, "a.test"
	d := &tls.Dialer{Config: cfg}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", s.Addr(8443))
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func TestTLSCipherSuiteList(t *testing.T) {
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	for _, how := range []string{"flag", "listener"} {
		var s *Server
		var p *pki
		if how == "flag" {
			s, p = tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Ciphers: want} }, nil)
		} else {
			s, p = tlsVersionServer(t, nil, m{TLSCipherSuitesOption: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"})
		}
		c, err := dialEdgeTLS(t, s, p, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}})
		if err != nil {
			t.Fatalf("%s: %v", how, err)
		}
		if got := c.ConnectionState().CipherSuite; got != want[0] {
			t.Errorf("%s: negotiated %s", how, tls.CipherSuiteName(got))
		}
		c.Close()
		// A client that offers none of the listed suites is refused.
		if c, err := dialEdgeTLS(t, s, p, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}); err == nil {
			c.Close()
			t.Errorf("%s: a client without a listed suite was accepted", how)
		}
		// TLS 1.3 suites are not configurable and stay available.
		if c, err := dialEdgeTLS(t, s, p, &tls.Config{MinVersion: tls.VersionTLS13}); err != nil {
			t.Errorf("%s: TLS 1.3: %v", how, err)
		} else {
			c.Close()
		}
	}
	// An invalid list makes the listener invalid.
	for _, o := range []m{{TLSCipherSuitesOption: "TLS_RSA_WITH_RC4_128_SHA"}, {TLSSessionResumptionOption: "sometimes"}} {
		p := newPKI(t)
		be, _ := upstreams(t, "a")
		ln := tlsListener("a", "a.test", "a-cert")
		ln["tls"].(m)["options"] = o
		raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": httpsGateway(ln), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}}, "rules": l{rule("/", ref("a", 1))}}},
			"backends":  m{"t/a:80": be["a"]}, "secrets": m{"a-cert": p.files("a", "a.test")}})
		cfg, err := ParseConfig(raw, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if tb := BuildTable(cfg); tb.Listeners[0].Accepted.OK {
			t.Errorf("%v: listener must be invalid", o)
		}
	}
}

func TestTLSSessionResumption(t *testing.T) {
	resumes := func(s *Server, p *pki, version uint16) bool {
		cache := tls.NewLRUClientSessionCache(4)
		cfg := &tls.Config{MinVersion: version, MaxVersion: version, ClientSessionCache: cache}
		for i := 0; i < 2; i++ {
			c, err := dialEdgeTLS(t, s, p, cfg)
			if err != nil {
				t.Fatalf("dial %d with version %x: %v", i, version, err)
			}
			// the session ticket of TLS 1.3 arrives with the first read
			c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			c.Read(make([]byte, 1))
			again := c.ConnectionState().DidResume
			c.Close()
			if i == 1 {
				return again
			}
		}
		return false
	}
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		s, p := tlsVersionServer(t, nil, nil)
		if !resumes(s, p, v) {
			t.Errorf("%x: default should resume", v)
		}
		s, p = tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Resumption: "off"} }, nil)
		if resumes(s, p, v) {
			t.Errorf("%x: --tls-session-resumption off still resumes", v)
		}
		s, p = tlsVersionServer(t, func(o *Options) { o.TLS = TLSOptions{Resumption: "off"} }, m{TLSSessionResumptionOption: "on"})
		if !resumes(s, p, v) {
			t.Errorf("%x: the listener's 'on' should win over the flag", v)
		}
		s, p = tlsVersionServer(t, nil, m{TLSSessionResumptionOption: "off"})
		if resumes(s, p, v) {
			t.Errorf("%x: listener 'off' still resumes", v)
		}
	}
}

func TestTLSFlags(t *testing.T) {
	parse := func(args ...string) (Options, error) {
		var f limitFlags
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		addLimitFlags(fs, &f)
		if err := fs.Parse(args); err != nil {
			return Options{}, err
		}
		var o Options
		return o, f.apply(&o)
	}
	o, err := parse("--tls-cipher-suites", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "--tls-session-resumption", "off")
	if err != nil || len(o.TLS.Ciphers) != 1 || o.TLS.Resumption != "off" {
		t.Fatalf("%+v %v", o.TLS, err)
	}
	for _, a := range [][]string{{"--tls-cipher-suites", "TLS_RSA_WITH_RC4_128_SHA"}, {"--tls-session-resumption", "sometimes"}} {
		if _, err := parse(a...); err == nil {
			t.Errorf("%v accepted", a)
		}
	}
}

// Inject credentials and OIDC secrets can come from a Kubernetes Secret, with the
// same ReferenceGrant rule as TLS certificates and AI keys.
func TestAuthKubernetesSecrets(t *testing.T) {
	be, _ := upstreams(t, "a")
	mk := func(ns string) []byte {
		r := rule("/", ref("a", 1))
		r[authKeyT] = m{"inject": l{m{"header": "X-Svc", "secret": m{"secret": m{"name": "svc", "namespace": ns, "key": "token"}}}}}
		return snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be)
	}
	apply := func(raw []byte, keys map[string]string) *Server {
		cfg, err := ParseConfig(raw, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		cfg.AIKeys = keys
		s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off", Rand: seededRand(1)})
		t.Cleanup(s.Close)
		if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	cfg, _ := ParseConfig(mk("t"), t.TempDir())
	if refs := authSecretRefs(cfg.Routes[0].Rules[0].Auth); len(refs) != 1 || refs[0].Name != "svc" {
		t.Fatalf("the Kubernetes source would not read the Secret: %+v", refs)
	}
	s := apply(mk("t"), map[string]string{"t/svc#token": "from-k8s-secret"})
	if r := get(t, s, "a.test", "/"); r.Status != 200 || r.Echo.Headers["x-svc"] != "from-k8s-secret" {
		t.Errorf("secret value: %d %v", r.Status, r.Echo.Headers)
	}
	s = apply(mk("other"), map[string]string{"other/svc#token": "x"})
	if r := get(t, s, "a.test", "/"); r.Status == 200 {
		t.Error("a cross namespace Secret was used without a ReferenceGrant")
	}
	s = apply(mk("t"), nil)
	if r := get(t, s, "a.test", "/"); r.Status == 200 {
		t.Error("route served without its Secret")
	}
}
