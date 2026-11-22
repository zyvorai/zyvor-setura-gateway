package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const authKeyT = "setura.zyvor.dev/auth"

// authServer serves one route "a.test" whose rule carries policy.
func authServer(t *testing.T, policy m, mod func(*Options)) (*Server, *upstream) {
	t.Helper()
	be, ups := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	if policy != nil {
		r[authKeyT] = policy
	}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), func(o *Options) {
		o.AuthClock = func() time.Time { return t0 }
		if mod != nil {
			mod(o)
		}
	})
	return s, ups["a"]
}

func bearer(tok string) []string { return []string{"Authorization", "Bearer " + tok} }

func TestJWTRouteEndToEnd(t *testing.T) {
	k := newRSAKey(t, "k1")
	s, up := authServer(t, m{"jwt": m{"issuer": "https://idp.test", "audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k)),
		"requiredClaims": m{"scope": l{"read"}}, "claimHeaders": m{"X-User": "sub", "X-Scope": "scope"}}}, nil)
	ok := k.sign(t, nil, claims(map[string]any{"scope": "read write"}))

	// No token: 401 with a challenge and no backend call.
	r := get(t, s, "a.test", "/")
	if r.Status != 401 || !strings.HasPrefix(r.Header.Get("WWW-Authenticate"), `Bearer realm="setura"`) || len(up.seen()) != 0 {
		t.Fatalf("no token: %d %v", r.Status, r.Header)
	}
	// Bad token: 401 invalid_token. Expired token too.
	r = get(t, s, "a.test", "/", bearer(k.sign(t, nil, claims(map[string]any{"aud": "other"})))...)
	if r.Status != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("bad audience: %d %v", r.Status, r.Header)
	}
	r = get(t, s, "a.test", "/", bearer(k.sign(t, nil, claims(map[string]any{"exp": t0.Add(-time.Hour).Unix()})))...)
	if r.Status != 401 {
		t.Errorf("expired: %d", r.Status)
	}
	// Valid token without the scope: 403 insufficient_scope.
	r = get(t, s, "a.test", "/", bearer(k.sign(t, nil, claims(map[string]any{"scope": "write"})))...)
	if r.Status != 403 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("scope: %d %v", r.Status, r.Header)
	}
	// Valid: claims forwarded, spoofed identity headers dropped, token passed on.
	r = get(t, s, "a.test", "/", append(bearer(ok), "X-User", "root", "X-Setura-Auth-Subject", "root", "X-Setura-Client-Verified", "true", "x-setura-client-subject", "CN=root")...)
	if r.Status != 200 {
		t.Fatalf("valid token: %d %s", r.Status, r.Body)
	}
	h := r.Echo.Headers
	if h["x-user"] != "alice" || h["x-scope"] != "read write" || h["x-setura-auth-subject"] != "alice" || h["x-setura-auth-method"] != "jwt" {
		t.Errorf("identity headers: %v", h)
	}
	if _, bad := h["x-setura-client-verified"]; bad || h["x-setura-client-subject"] != "" {
		t.Errorf("client supplied identity reached the backend: %v", h)
	}
	if h["authorization"] == "" {
		t.Error("the token should be forwarded unless stripToken is set")
	}
	// A claim header the token does not provide is still removed from the client's request.
	r = get(t, s, "a.test", "/", append(bearer(k.sign(t, nil, claims(map[string]any{"scope": "read"}))), "X-User", "evil")...)
	if r.Status != 200 || r.Echo.Headers["x-user"] != "alice" {
		t.Errorf("x-user = %q", r.Echo.Headers["x-user"])
	}
}

func TestJWTFromJWKSURLWithRotation(t *testing.T) {
	k1, k2 := newECKey(t, "one"), newECKey(t, "two")
	var mu sync.Mutex
	doc, hits := jwksDoc(k1), 0
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		w.Write(doc)
	}))
	defer idp.Close()
	s, _ := authServer(t, m{"jwt": m{"audience": l{"api"}, "jwksUri": idp.URL + "/jwks", "jwksMinRefresh": "0s"}}, nil)
	if r := get(t, s, "a.test", "/", bearer(k1.sign(t, nil, claims(nil)))...); r.Status != 200 {
		t.Fatalf("first key: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/", bearer(k2.sign(t, nil, claims(nil)))...); r.Status != 401 {
		t.Fatalf("unknown key: %d", r.Status)
	}
	mu.Lock()
	doc = jwksDoc(k1, k2)
	mu.Unlock()
	if r := get(t, s, "a.test", "/", bearer(k2.sign(t, nil, claims(nil)))...); r.Status != 200 {
		t.Fatalf("rotated key should be picked up on an unknown kid: %d", r.Status)
	}
	// JWKS unreachable and nothing cached: 503, not an open door.
	dead, _ := authServer(t, m{"jwt": m{"audience": l{"api"}, "jwksUri": "http://127.0.0.1:1/jwks"}}, nil)
	if r := get(t, dead, "a.test", "/", bearer(k1.sign(t, nil, claims(nil)))...); r.Status != 503 {
		t.Errorf("unreachable JWKS: %d", r.Status)
	}
}

func TestAPIKeyHashedHeaderAndQuery(t *testing.T) {
	hash, err := HashAPIKey("s3cret-key-value")
	if err != nil {
		t.Fatal(err)
	}
	var log syncBuf
	s, up := authServer(t, m{"apiKey": m{"header": "X-Api-Key", "query": "api_key", "keys": l{m{"name": "ci", "hash": hash}}}}, func(o *Options) {
		o.AccessLog = &log
		o.Obs.LogQuery = true
	})
	if r := get(t, s, "a.test", "/"); r.Status != 401 || r.Header.Get("WWW-Authenticate") == "" {
		t.Errorf("no key: %d %v", r.Status, r.Header)
	}
	if r := get(t, s, "a.test", "/", "X-Api-Key", "wrong"); r.Status != 401 {
		t.Errorf("wrong key: %d", r.Status)
	}
	r := get(t, s, "a.test", "/x?a=1&api_key=s3cret-key-value", "X-Setura-Auth-Method", "spoof")
	if r.Status != 200 || r.Echo.Headers["x-setura-auth-subject"] != "ci" || r.Echo.Headers["x-setura-auth-method"] != "apikey" {
		t.Fatalf("query key: %d %v", r.Status, r.Echo.Headers)
	}
	if strings.Contains(r.Echo.Query, "s3cret") || r.Echo.Query != "a=1" {
		t.Errorf("the key reached the backend: %q", r.Echo.Query)
	}
	r = get(t, s, "a.test", "/", "X-Api-Key", "s3cret-key-value")
	if r.Status != 200 || r.Echo.Headers["x-api-key"] != "" {
		t.Errorf("header key: %d %v", r.Status, r.Echo.Headers)
	}
	_ = up
	if r := get(t, s, "a.test", "/y?b=2&api_key=BADKEY-123"); r.Status != 401 {
		t.Errorf("wrong query key: %d", r.Status)
	}
	s.FlushAccessLog()
	if strings.Contains(log.String(), "s3cret") || strings.Contains(log.String(), "BADKEY") {
		t.Errorf("access log leaks the key:\n%s", log.String())
	}
	if !strings.Contains(log.String(), `b=2\u0026api_key=\u003credacted\u003e`) {
		t.Errorf("access log should show the redacted parameter:\n%s", log.String())
	}
}

func TestAPIKeyClearTextAndWrongHashFormat(t *testing.T) {
	s, _ := authServer(t, m{"apiKey": m{"keys": l{m{"name": "dev", "key": "plain"}}}}, nil)
	if r := get(t, s, "a.test", "/", "X-API-Key", "plain"); r.Status != 200 {
		t.Errorf("clear text key: %d", r.Status)
	}
	for _, bad := range []m{{"name": "x", "hash": "md5$aa$bb"}, {"name": "x"}, {"name": "x", "hash": "sha256$AA$zz"}, {"name": "x", "key": "k", "hash": "sha256$AA$00"}} {
		if _, err := ParseAuthBlock(mustJSON(m{"apiKey": m{"keys": l{bad}}})); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	hash, err := HashPassword("correct horse", 1000)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := authServer(t, m{"basic": m{"realm": "files", "users": l{m{"name": "bob", "hash": hash}}}}, nil)
	r := get(t, s, "a.test", "/")
	if r.Status != 401 || r.Header.Get("WWW-Authenticate") != `Basic realm="files", charset="UTF-8"` {
		t.Errorf("challenge: %d %q", r.Status, r.Header.Get("WWW-Authenticate"))
	}
	basic := func(u, p string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p)) }
	for _, c := range []struct{ u, p string }{{"bob", "wrong"}, {"nobody", "correct horse"}, {"bob", ""}} {
		if r := get(t, s, "a.test", "/", "Authorization", basic(c.u, c.p)); r.Status != 401 {
			t.Errorf("%s/%s: %d", c.u, c.p, r.Status)
		}
	}
	for i := 0; i < 2; i++ { // the second one is served from the success cache
		r := get(t, s, "a.test", "/", "Authorization", basic("bob", "correct horse"))
		if r.Status != 200 || r.Echo.Headers["x-setura-auth-subject"] != "bob" {
			t.Errorf("valid: %d %v", r.Status, r.Echo.Headers)
		}
		if r.Echo.Headers["authorization"] != "" {
			t.Error("basic credentials must not be forwarded by default")
		}
	}
	if _, err := ParseAuthBlock(mustJSON(m{"basic": m{"users": l{m{"name": "a:b", "password": "x"}}}})); err == nil {
		t.Error("colon in user name accepted")
	}
	if _, err := ParseAuthBlock(mustJSON(m{"basic": m{"users": l{m{"name": "a", "hash": "pbkdf2-sha256$5$AA$AA"}}}})); err == nil {
		t.Error("tiny iteration count accepted")
	}
}

func TestAnyCredentialAdmits(t *testing.T) {
	k := newEdKey(t, "k")
	s, _ := authServer(t, m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}, "apiKey": m{"keys": l{m{"name": "svc", "key": "kk"}}}}, nil)
	if r := get(t, s, "a.test", "/", "X-API-Key", "kk"); r.Status != 200 {
		t.Errorf("api key: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/", bearer(k.sign(t, nil, claims(nil)))...); r.Status != 200 {
		t.Errorf("jwt: %d", r.Status)
	}
	r := get(t, s, "a.test", "/")
	if r.Status != 401 || len(r.Header.Values("WWW-Authenticate")) != 2 {
		t.Errorf("challenges: %d %v", r.Status, r.Header.Values("WWW-Authenticate"))
	}
}

func TestIPAccessLists(t *testing.T) {
	// The test client is 127.0.0.1.
	s, _ := authServer(t, m{"ipAllow": l{"10.0.0.0/8"}}, nil)
	if r := get(t, s, "a.test", "/"); r.Status != 403 {
		t.Errorf("not on the allow list: %d", r.Status)
	}
	s, _ = authServer(t, m{"ipAllow": l{"127.0.0.0/8"}, "ipDeny": l{"127.0.0.1"}}, nil)
	if r := get(t, s, "a.test", "/"); r.Status != 403 {
		t.Errorf("deny wins: %d", r.Status)
	}
	s, _ = authServer(t, m{"ipAllow": l{"127.0.0.0/8"}}, nil)
	if r := get(t, s, "a.test", "/"); r.Status != 200 {
		t.Errorf("allowed: %d", r.Status)
	}
	// X-Forwarded-For counts only from a trusted proxy.
	s, _ = authServer(t, m{"ipAllow": l{"203.0.113.0/24"}}, nil)
	if r := get(t, s, "a.test", "/", "X-Forwarded-For", "203.0.113.9"); r.Status != 403 {
		t.Errorf("untrusted XFF must be ignored: %d", r.Status)
	}
	prefixes, _ := ParseTrustedProxies("127.0.0.1")
	s, _ = authServer(t, m{"ipAllow": l{"203.0.113.0/24"}}, func(o *Options) { o.Obs.TrustedProxies = prefixes })
	if r := get(t, s, "a.test", "/", "X-Forwarded-For", "203.0.113.9"); r.Status != 200 {
		t.Errorf("trusted XFF: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/", "X-Forwarded-For", "198.51.100.1"); r.Status != 403 {
		t.Errorf("trusted XFF outside the list: %d", r.Status)
	}
}

func TestAuthDisabledAndInvalidPolicy(t *testing.T) {
	s, _ := authServer(t, m{"enabled": false, "apiKey": m{"keys": l{m{"name": "x", "key": "k"}}}}, nil)
	if r := get(t, s, "a.test", "/"); r.Status != 200 {
		t.Errorf("disabled policy: %d", r.Status)
	}
	// A broken policy must not turn into an unprotected route: the route is not served.
	s, up := authServer(t, m{"jwt": m{"audience": l{"api"}}}, nil)
	if r := get(t, s, "a.test", "/"); r.Status == 200 || len(up.seen()) != 0 {
		t.Errorf("invalid policy served the route: %d", r.Status)
	}
	acc := s.Status().Routes["t/r"].Parents[0].Conditions
	found := false
	for _, c := range acc {
		if c.Type == "Accepted" && c.Status == "False" && strings.Contains(c.Message, authKeyT) {
			found = true
		}
	}
	if !found {
		t.Errorf("route status should say the auth block is invalid: %+v", acc)
	}
}

func TestAuthAnnotations(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	policy := string(mustJSON(m{"apiKey": m{"keys": l{m{"name": "k", "key": "kk"}}}}))
	r1 := route("a.test", rule("/", ref("a", 1)), rule("/open", ref("b", 1)))
	r1["setura.zyvor.dev/annotations"] = m{authKeyT: policy, authKeyT + ".rule-2": `{"enabled": false}`}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": r1}, be), nil)
	if r := get(t, s, "a.test", "/"); r.Status != 401 {
		t.Errorf("route wide annotation: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/", "X-API-Key", "kk"); r.Status != 200 {
		t.Errorf("annotated policy with key: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/open"); r.Status != 200 {
		t.Errorf("rule-specific annotation switches it off: %d", r.Status)
	}
	bad := route("a.test", rule("/", ref("a", 1)))
	bad["setura.zyvor.dev/annotations"] = m{authKeyT: `{"jwt": `}
	s = startServer(t, snap(httpGateway(""), map[string]m{"r": bad}, be), nil)
	if r := get(t, s, "a.test", "/"); r.Status == 200 {
		t.Error("an undecodable annotation must not leave the route open")
	}
}

func TestConfigDumpAndErrorsNeverLeakSecrets(t *testing.T) {
	hash, _ := HashAPIKey("topsecret")
	pwHash, _ := HashPassword("pw-topsecret", 1000)
	s, _ := authServer(t, m{
		"jwt":    m{"audience": l{"api"}, "jwksUri": "https://user:hunter2@idp.test/jwks?token=QUERYSECRET"},
		"apiKey": m{"keys": l{m{"name": "a", "hash": hash}, m{"name": "b", "key": "clear-topsecret"}}},
		"basic":  m{"users": l{m{"name": "u", "hash": pwHash}, m{"name": "v", "password": "clear-pw"}}},
	}, nil)
	dump, _ := json.Marshal(s.Table().Cfg.Dump())
	for _, secret := range []string{"hunter2", "QUERYSECRET", "topsecret", "clear-pw", hash, pwHash, "pbkdf2-sha256$", "sha256$"} {
		if strings.Contains(string(dump), secret) {
			t.Errorf("/config leaks %q", secret)
		}
	}
	if !strings.Contains(string(dump), `"name":"a"`) || !strings.Contains(string(dump), `u003credacted`) {
		t.Errorf("the dump should still show names and redaction markers: %s", dump)
	}
	// compile errors mention the URL without its credentials
	_, err := ParseAuthBlock(mustJSON(m{"jwt": m{"jwksUri": "ftp://u:hunter2@idp.test/x?token=QUERYSECRET"}}))
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "QUERYSECRET") {
		t.Errorf("error: %v", err)
	}
}

func TestRedactHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"https://u:p@h.test/a/b?token=1#x": "https://<redacted>@h.test/a/b?<redacted>",
		"https://h.test/jwks":              "https://h.test/jwks",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := redactQuery("a=1&access_token=zz&b=2&mine=x", "mine"); got != "a=1&access_token=<redacted>&b=2&mine=<redacted>" {
		t.Errorf("redactQuery = %q", got)
	}
}
