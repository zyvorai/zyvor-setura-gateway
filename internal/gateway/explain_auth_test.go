package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func explainAuthFor(t *testing.T, s *Server, remote string, hdr ...string) *Trace {
	t.Helper()
	er, err := ParseExplainRequest("GET", "http://a.test:8080/p?x=1", headerLines(hdr), "", "")
	if err != nil {
		t.Fatal(err)
	}
	er.Remote, er.Now = remote, t0
	return Explain(s.Table(), er)
}

// The explainer must show the decision and the upstream request the data path
// produces for the same credentials: same evaluate, same identity headers.
func TestWhyAuthMatchesDataPath(t *testing.T) {
	k := newRSAKey(t, "k")
	hash, _ := HashAPIKey("key-123")
	policy := m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k)), "claimHeaders": m{"X-User": "sub"}},
		"apiKey": m{"query": "api_key", "keys": l{m{"name": "ci", "hash": hash}}}}
	s, up := authServer(t, policy, nil)
	good := k.sign(t, nil, claims(nil))
	cases := []struct {
		name string
		hdr  []string
		q    string
		code int
		dec  string
	}{
		{"jwt", append(bearer(good), "X-User", "spoof", "X-Setura-Client-Subject", "x"), "", 200, "allow"},
		{"api key", nil, "&api_key=key-123", 200, "allow"},
		{"nothing", nil, "", 401, "deny"},
		{"bad key", nil, "&api_key=nope", 401, "deny"},
	}
	for _, c := range cases {
		before := len(up.seen())
		live := req(t, client(s.Addr(8080), nil), "http", "GET", "a.test:8080", "/p?x=1"+c.q, "", c.hdr...)
		if live.Status != c.code {
			t.Fatalf("%s: live status %d, want %d", c.name, live.Status, c.code)
		}
		er, err := ParseExplainRequest("GET", "http://a.test:8080/p?x=1"+c.q, headerLines(c.hdr), "", "")
		if err != nil {
			t.Fatal(err)
		}
		er.Remote, er.Now = "127.0.0.1", t0
		tr := Explain(s.Table(), er)
		a := tr.Winner.Auth
		if a == nil || !a.Applies || a.Decision != c.dec || (c.dec == "deny" && a.Status != c.code) {
			t.Fatalf("%s: explain auth = %+v", c.name, a)
		}
		if c.dec != "allow" {
			if len(up.seen()) != before {
				t.Errorf("%s: backend reached", c.name)
			}
			continue
		}
		seen := up.seen()[before]
		got := tr.Winner.Backends[0].Request
		u, _ := url.Parse(got.URL)
		if u.RawQuery != seen.Query {
			t.Errorf("%s: query explain %q proxy %q", c.name, u.RawQuery, seen.Query)
		}
		for k, v := range got.Headers {
			lk := strings.ToLower(k)
			if sv, ok := seen.Headers[lk]; !ok && v != redacted {
				t.Errorf("%s: explain shows %s, proxy did not send it", c.name, k)
			} else if ok && v != redacted && sv != v && lk != "traceparent" && lk != "x-request-id" {
				t.Errorf("%s: %s explain %q proxy %q", c.name, k, v, sv)
			}
		}
		for k := range seen.Headers {
			if strings.HasPrefix(k, "x-setura-auth-") || k == "x-user" {
				if _, ok := got.Headers[http.CanonicalHeaderKey(k)]; !ok {
					t.Errorf("%s: proxy sent %s, explain does not show it", c.name, k)
				}
			}
		}
		if _, bad := got.Headers["X-Setura-Client-Subject"]; bad {
			t.Errorf("%s: explain kept a client supplied identity header", c.name)
		}
	}
}

func TestWhyHidesCredentials(t *testing.T) {
	k := newRSAKey(t, "k")
	s, _ := authServer(t, m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}, "apiKey": m{"header": "X-Custom-Key", "query": "ak", "keys": l{m{"name": "a", "key": "kk"}}}}, nil)
	tok := k.sign(t, nil, claims(nil))
	basic := base64.StdEncoding.EncodeToString([]byte("u:pw-SECRET"))
	tr := explainAuthFor(t, s, "127.0.0.1", "Authorization", "Bearer "+tok, "X-Custom-Key", "kk-SECRET", "Cookie", "sid=SESSION-SECRET", "Proxy-Authorization", "Basic "+basic)
	tr.Request.RawQuery = "" // the helper's query is a fixed x=1
	raw, _ := json.Marshal(tr)
	for _, secret := range []string{tok, strings.Split(tok, ".")[1], "kk-SECRET", "SESSION-SECRET", basic} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("trace contains a credential: %s", secret)
		}
	}
	tr = explainAuthFor(t, s, "127.0.0.1")
	er, _ := ParseExplainRequest("GET", "http://a.test:8080/?ak=QUERY-SECRET&z=1", nil, "", "")
	er.Remote, er.Now = "127.0.0.1", t0
	tr = Explain(s.Table(), er)
	raw, _ = json.Marshal(tr)
	if bytes.Contains(raw, []byte("QUERY-SECRET")) || !bytes.Contains(raw, []byte("z=1")) {
		t.Errorf("query credential in trace: %s", raw)
	}
}

func TestWhyAuthUnknownWhenItCannotBeSimulated(t *testing.T) {
	// A JWKS fetched from a URL cannot be consulted offline, an address list needs
	// --client-ip, a client certificate needs a handshake.
	s, _ := authServer(t, m{"jwt": m{"audience": l{"api"}, "jwksUri": "http://127.0.0.1:1/jwks"}}, nil)
	tr := explainAuthFor(t, s, "127.0.0.1", bearer(newRSAKey(t, "k").sign(t, nil, claims(nil)))...)
	if a := tr.Winner.Auth; a.Decision != "unknown" || !strings.Contains(a.Reason, "JWKS") {
		t.Errorf("jwks url offline: %+v", a)
	}
	s, _ = authServer(t, m{"ipAllow": l{"10.0.0.0/8"}, "requireClientCert": true}, nil)
	if a := explainAuthFor(t, s, "").Winner.Auth; a.Decision != "unknown" || !strings.Contains(a.Reason, "client address") || !strings.Contains(a.Reason, "client certificate") {
		t.Errorf("acl+cert: %+v", a)
	}
	if a := explainAuthFor(t, s, "192.0.2.1").Winner.Auth; a.Decision != "deny" || a.Status != 403 {
		t.Errorf("address outside the allow list: %+v", a)
	}
	s, _ = authServer(t, nil, nil)
	if a := explainAuthFor(t, s, "").Winner.Auth; a == nil || a.Applies || a.Decision != "allow" {
		t.Errorf("no policy: %+v", a)
	}
}

func TestHashCommand(t *testing.T) {
	for _, kind := range []string{"apikey", "password"} {
		var out, errb bytes.Buffer
		args := []string{"--kind", kind}
		if kind == "password" {
			args = append(args, "--iterations", "1000")
		}
		if code := hashCmd(args, strings.NewReader("some secret\n"), &out, &errb); code != 0 {
			t.Fatalf("%s: %d %s", kind, code, errb.String())
		}
		h := strings.TrimSpace(out.String())
		block := m{"apiKey": m{"keys": l{m{"name": "n", "hash": h}}}}
		if kind == "password" {
			block = m{"basic": m{"users": l{m{"name": "n", "hash": h}}}}
		}
		p, err := ParseAuthBlock(mustJSON(block))
		if err != nil {
			t.Fatalf("%s: the printed hash is not accepted: %v", kind, err)
		}
		if kind == "apikey" {
			if _, ok := p.c.apikey.check("some secret"); !ok {
				t.Error("hash does not verify its key")
			}
			if _, ok := p.c.apikey.check("other"); ok {
				t.Error("hash verifies another key")
			}
		} else if !p.c.basic.check("n", "some secret", time.Now()) || p.c.basic.check("n", "other", time.Now()) {
			t.Error("password hash verification")
		}
		if strings.Contains(out.String(), "some secret") {
			t.Error("the secret was echoed")
		}
	}
	var out, errb bytes.Buffer
	if hashCmd([]string{"--kind", "apikey"}, strings.NewReader(""), &out, &errb) == 0 || hashCmd([]string{"--kind", "x"}, strings.NewReader("a\n"), &out, &errb) == 0 {
		t.Error("bad input accepted")
	}
}
