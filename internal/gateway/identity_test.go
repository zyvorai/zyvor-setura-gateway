package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- client certificate allow-list ----

func leafWith(cn string, dns []string, uris []string, emails []string) *x509.Certificate {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, DNSNames: dns, EmailAddresses: emails}
	for _, u := range uris {
		pu, _ := url.Parse(u)
		c.URIs = append(c.URIs, pu)
	}
	return c
}

func TestClientAllowMatching(t *testing.T) {
	cases := []struct {
		name string
		a    ClientAllow
		cert *x509.Certificate
		want bool
	}{
		{"exact dns", ClientAllow{SAN: []string{"svc.corp.test"}}, leafWith("x", []string{"SVC.corp.test"}, nil, nil), true},
		{"other dns", ClientAllow{SAN: []string{"svc.corp.test"}}, leafWith("x", []string{"evil.corp.test"}, nil, nil), false},
		{"wildcard", ClientAllow{SAN: []string{"*.corp.test"}}, leafWith("x", []string{"a.b.corp.test"}, nil, nil), true},
		{"wildcard needs a prefix", ClientAllow{SAN: []string{"*.corp.test"}}, leafWith("x", []string{"corp.test"}, nil, nil), false},
		{"wildcard no partial label", ClientAllow{SAN: []string{"*.corp.test"}}, leafWith("x", []string{"evilcorp.test"}, nil, nil), false},
		{"uri", ClientAllow{SAN: []string{"spiffe://td/ns/a/sa/b"}}, leafWith("x", nil, []string{"spiffe://td/ns/a/sa/b"}, nil), true},
		{"uri typed, dns cert", ClientAllow{SAN: []string{"uri:svc.corp.test"}}, leafWith("x", []string{"svc.corp.test"}, nil, nil), false},
		{"dns typed", ClientAllow{SAN: []string{"dns:svc.corp.test"}}, leafWith("x", []string{"svc.corp.test"}, nil, nil), true},
		{"email wildcard is a suffix of the address", ClientAllow{SAN: []string{"email:*.corp.test"}}, leafWith("x", nil, nil, []string{"a@mail.corp.test"}), true},
		{"email exact", ClientAllow{SAN: []string{"email:a@corp.test"}}, leafWith("x", nil, nil, []string{"A@corp.test"}), true},
		{"email wildcard needs the dot", ClientAllow{SAN: []string{"email:*.corp.test"}}, leafWith("x", nil, nil, []string{"a@corp.test"}), false},
		{"cn exact", ClientAllow{CN: []string{"alice"}}, leafWith("alice", nil, nil, nil), true},
		{"cn mismatch", ClientAllow{CN: []string{"alice"}}, leafWith("bob", []string{"alice"}, nil, nil), false},
		{"cn wildcard", ClientAllow{CN: []string{"*.corp.test"}}, leafWith("a.corp.test", nil, nil, nil), true},
		{"san or cn", ClientAllow{SAN: []string{"nope.test"}, CN: []string{"alice"}}, leafWith("alice", nil, nil, nil), true},
		{"empty allows all", ClientAllow{}, leafWith("x", nil, nil, nil), true},
	}
	for _, c := range cases {
		ca, err := c.a.compile()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := ca.allows(c.cert); got != c.want {
			t.Errorf("%s: allows = %v, want %v", c.name, got, c.want)
		}
	}
	for _, bad := range []string{`{"san":["a.*.test"]}`, `{"san":["*"]}`, `{"cn":["*."]}`, `{"san":[""]}`, `{"sans":["x"]}`, `{"san":["a"]} x`} {
		if _, err := ParseClientAllow([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// issueURI makes a server certificate with a URI SAN, for the XFCC By field.
func (p *pki) serverWithURI(name, host, uri string) m {
	p.n++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.n), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(p.dir, name+".crt"), filepath.Join(p.dir, name+".key")
	os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return m{"certFile": cf, "keyFile": kf}
}

// allowServer is mtlsServer with a Gateway hook, options and a server certificate of the caller's choosing.
func allowServer(t *testing.T, srvSecret m, clientCA *pki, mode string, policy m, gwMod func(gw m), mod func(*Options)) *Server {
	t.Helper()
	be, _ := upstreams(t, "a")
	gw := httpsGateway(tlsListener("web", "", "srv-cert"))
	val := m{"caCertificateRefs": l{m{"kind": "ConfigMap", "name": "clients-ca"}}}
	if mode != "" {
		val["mode"] = mode
	}
	gw["tls"] = m{"frontend": m{"default": m{"validation": val}}}
	if gwMod != nil {
		gwMod(gw)
	}
	r := rule("/", ref("a", 1))
	if policy != nil {
		r[authKeyT] = policy
	}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "r": route("a.test", r)},
		"backends":  m{"t/a:80": be["a"]},
		"secrets":   m{"srv-cert": srvSecret, "clients-ca": m{"cert": clientCA.caPEM()}}})
	return startServer(t, raw, mod)
}

func allowAnnotation(v string) func(gw m) {
	return func(gw m) { gw["setura.zyvor.dev/annotations"] = m{ClientAllowKey: v} }
}

func rejectedTotal(s *Server) (n int64) {
	for _, v := range s.ext.certRejectSnapshot() {
		n += v
	}
	return n
}

func TestClientAllowListHandshake(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	var diag syncBuf
	s := allowServer(t, srv.files("srv", "a.test"), ca, "", nil, allowAnnotation(`{"san":["*.corp.test","spiffe://td/ok"],"cn":["batch-runner"]}`),
		func(o *Options) { o.Diag = &diag })
	for name, c := range map[string]tls.Certificate{
		"wildcard dns": ca.clientCert("anything", "alice.corp.test", ""),
		"uri":          ca.clientCert("anything", "", "spiffe://td/ok"),
		"cn":           ca.clientCert("batch-runner", "", ""),
	} {
		if r := req(t, mtlsClient(s, srv, c), "https", "GET", "a.test", "/", ""); r.Status != 200 {
			t.Errorf("%s: %d", name, r.Status)
		}
	}
	if n := rejectedTotal(s); n != 0 {
		t.Fatalf("accepted certificates were counted as rejected: %d", n)
	}
	for name, c := range map[string]tls.Certificate{
		"other dns":  ca.clientCert("alice", "alice.other.test", ""),
		"other uri":  ca.clientCert("alice", "", "spiffe://td/evil"),
		"no names":   ca.clientCert("alice", "", ""),
		"cn but san": ca.clientCert("batch-runner2", "", ""),
	} {
		if resp, err := mtlsClient(s, srv, c).Get("https://a.test/"); err == nil {
			resp.Body.Close()
			t.Errorf("%s: handshake succeeded", name)
		}
	}
	if n := rejectedTotal(s); n != 4 {
		t.Errorf("rejections counted: %d, want 4", n)
	}
	if !strings.Contains(diag.String(), "not on the allow-list") {
		t.Errorf("rejection not logged: %q", diag.String())
	}
	var mb strings.Builder
	s.writeExtMetrics(&mb)
	if !strings.Contains(mb.String(), `setura_gateway_client_cert_rejected_total{listener="`) {
		t.Errorf("metric missing:\n%s", mb.String())
	}
}

func TestClientAllowFlagDefaultAndOverride(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	def, err := ParseClientAllowFlags([]string{"a.corp.test, b.corp.test"}, nil)
	if err != nil || def == nil || len(def.SAN) != 2 {
		t.Fatalf("flags: %v %v", def, err)
	}
	// No Gateway annotation: the flag default applies.
	s := allowServer(t, srv.files("srv", "a.test"), ca, "", nil, nil, func(o *Options) { o.ClientAllow = def })
	if r := req(t, mtlsClient(s, srv, ca.clientCert("x", "b.corp.test", "")), "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Errorf("flag allowed: %d", r.Status)
	}
	if resp, err := mtlsClient(s, srv, ca.clientCert("x", "c.corp.test", "")).Get("https://a.test/"); err == nil {
		resp.Body.Close()
		t.Error("flag default did not refuse c.corp.test")
	}
	// The Gateway annotation replaces the default.
	s = allowServer(t, srv.files("srv2", "a.test"), ca, "", nil, allowAnnotation(`{"san":["c.corp.test"]}`), func(o *Options) { o.ClientAllow = def })
	if r := req(t, mtlsClient(s, srv, ca.clientCert("x", "c.corp.test", "")), "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Errorf("annotation allowed: %d", r.Status)
	}
	if resp, err := mtlsClient(s, srv, ca.clientCert("x", "b.corp.test", "")).Get("https://a.test/"); err == nil {
		resp.Body.Close()
		t.Error("annotation should replace the flag default")
	}
	// The snapshot field on the validation block works too.
	s = allowServer(t, srv.files("srv3", "a.test"), ca, "", nil, func(gw m) {
		v := gw["tls"].(m)["frontend"].(m)["default"].(m)["validation"].(m)
		v[ClientAllowKey] = m{"cn": l{"only-me"}}
	}, nil)
	if r := req(t, mtlsClient(s, srv, ca.clientCert("only-me", "", "")), "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Errorf("snapshot field allowed: %d", r.Status)
	}
	if resp, err := mtlsClient(s, srv, ca.clientCert("someone", "", "")).Get("https://a.test/"); err == nil {
		resp.Body.Close()
		t.Error("snapshot field did not refuse")
	}
}

func TestClientAllowBadAnnotationFailsClosed(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	s := allowServer(t, srv.files("srv", "a.test"), ca, "", nil, allowAnnotation(`{"san":["a.*.test"]}`), nil)
	if s.Addr(8443) != "" {
		t.Error("listener with an invalid allow-list is serving")
	}
}

func TestClientAllowInsecureFallbackRefusedCert(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	s := allowServer(t, srv.files("srv", "a.test"), ca, ModeAllowInsecureFallback, m{"requireClientCert": true},
		allowAnnotation(`{"san":["ok.corp.test"]}`), nil)
	// Trusted CA but not on the list: served by the listener, refused by the route, forwarded as unverified.
	if r := req(t, mtlsClient(s, srv, ca.clientCert("x", "bad.corp.test", "")), "https", "GET", "a.test", "/", ""); r.Status != 403 {
		t.Errorf("refused certificate: %d", r.Status)
	}
	if n := rejectedTotal(s); n != 1 {
		t.Errorf("counted %d", n)
	}
	if r := req(t, mtlsClient(s, srv, ca.clientCert("x", "ok.corp.test", "")), "https", "GET", "a.test", "/", ""); r.Status != 200 || r.Echo.Headers["x-setura-client-verified"] != "true" {
		t.Errorf("allowed certificate: %d %v", r.Status, r.Echo.Headers)
	}
}

// ---- X-Forwarded-Client-Cert ----

func TestXFCC(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	secret := srv.serverWithURI("srvuri", "a.test", "spiffe://gw/edge")
	spoof := []string{"X-Forwarded-Client-Cert", "Hash=deadbeef;Subject=\"CN=root\""}
	cert := ca.clientCert("alice", "alice.corp.test", "spiffe://corp/alice")
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])

	s := allowServer(t, secret, ca, "", nil, nil, func(o *Options) { o.ClientCertXFCC = true })
	r := req(t, mtlsClient(s, srv, cert), "https", "GET", "a.test", "/", "", spoof...)
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	h := r.Echo.Headers
	want := `By=spiffe://gw/edge;Hash=` + h["x-setura-client-fingerprint"] + `;Subject="` + leaf.Subject.String() + `";URI=spiffe://corp/alice;DNS=alice.corp.test`
	if h["x-forwarded-client-cert"] != want {
		t.Errorf("XFCC = %q\nwant   %q", h["x-forwarded-client-cert"], want)
	}
	if len(h["x-setura-client-fingerprint"]) != 64 || h["x-setura-client-verified"] != "true" {
		t.Errorf("X-Setura-Client-* must stay alongside: %v", h)
	}

	// Off by default: the client's own value is dropped and none is written.
	s = allowServer(t, secret, ca, "", nil, nil, nil)
	r = req(t, mtlsClient(s, srv, cert), "https", "GET", "a.test", "/", "", spoof...)
	if v, ok := r.Echo.Headers["x-forwarded-client-cert"]; ok {
		t.Errorf("XFCC forwarded while disabled: %q", v)
	}

	// Enabled but the client sent no certificate (fallback): the spoofed value is stripped, nothing replaces it.
	s = allowServer(t, secret, ca, ModeAllowInsecureFallback, nil, nil, func(o *Options) { o.ClientCertXFCC = true })
	r = req(t, mtlsClient(s, srv), "https", "GET", "a.test", "/", "", spoof...)
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	if v, ok := r.Echo.Headers["x-forwarded-client-cert"]; ok {
		t.Errorf("spoofed XFCC reached the backend: %q", v)
	}
	// An untrusted certificate carries no XFCC either.
	rogue := newPKI(t)
	r = req(t, mtlsClient(s, srv, rogue.clientCert("m", "m.test", "")), "https", "GET", "a.test", "/", "", spoof...)
	if v, ok := r.Echo.Headers["x-forwarded-client-cert"]; ok || r.Echo.Headers["x-setura-client-verified"] != "false" {
		t.Errorf("untrusted certificate: XFCC %q, %v", v, r.Echo.Headers)
	}
}

// ---- header value variables ----

func varsServer(t *testing.T, mod func(*Options)) (*Server, *upstream) {
	be, ups := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	r["filters"] = l{m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{
		"set": l{m{"name": "X-Real-Client-IP", "value": "{client_ip}"}, m{"name": "X-Rid", "value": "{request_id}"},
			m{"name": "X-Where", "value": "{scheme}://{host}|{listener}"}, m{"name": "X-Literal", "value": "{unknown}"}},
		"add": l{m{"name": "X-Seen", "value": "ip={client_ip}"}},
	}}}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), mod)
	return s, ups["a"]
}

func TestHeaderVariables(t *testing.T) {
	s, _ := varsServer(t, nil)
	r := get(t, s, "a.test:8080", "/", "X-Real-Client-IP", "6.6.6.6", "X-Forwarded-For", "7.7.7.7", "X-Request-Id", "req-42", "X-Where", "client", "X-Seen", "client")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	h := r.Echo.Headers
	if h["x-real-client-ip"] != "127.0.0.1" {
		t.Errorf("client-supplied X-Real-Client-IP not overwritten by the peer: %q", h["x-real-client-ip"])
	}
	if h["x-rid"] != "req-42" || r.Header.Get("X-Request-Id") != "req-42" {
		t.Errorf("request_id %q, response %q", h["x-rid"], r.Header.Get("X-Request-Id"))
	}
	if !strings.HasPrefix(h["x-where"], "http://a.test:8080|") || !strings.Contains(h["x-where"], "web") {
		t.Errorf("scheme/host/listener: %q", h["x-where"])
	}
	if h["x-literal"] != "{unknown}" {
		t.Errorf("unknown variable should stay literal: %q", h["x-literal"])
	}
	if h["x-seen"] != "client,ip=127.0.0.1" {
		t.Errorf("add: %q", h["x-seen"])
	}
	// Generated id: the header carries the same value the response does.
	r = get(t, s, "a.test", "/")
	if id := r.Header.Get("X-Request-Id"); id == "" || r.Echo.Headers["x-rid"] != id {
		t.Errorf("generated request id %q vs backend %q", id, r.Echo.Headers["x-rid"])
	}
}

// TestHeaderVariablesExplainEquivalence checks that why/explain renders the
// same expansion the proxy performs.
func TestHeaderVariablesExplainEquivalence(t *testing.T) {
	s, ups := varsServer(t, nil)
	hdrs := []string{"X-Real-Client-IP", "6.6.6.6", "X-Request-Id", "req-42"}
	live := get(t, s, "a.test:8080", "/p", hdrs...)
	if live.Status != 200 {
		t.Fatalf("status %d", live.Status)
	}
	seen := ups.seen()[0]
	er, err := ParseExplainRequest("GET", "http://a.test:8080/p", headerLines(hdrs), "", "")
	if err != nil {
		t.Fatal(err)
	}
	er.Remote = "127.0.0.1"
	tr := Explain(s.Table(), er)
	if tr.Winner == nil || len(tr.Winner.Backends) == 0 || tr.Winner.Backends[0].Request == nil {
		t.Fatalf("no upstream request\n%s", dumpTrace(tr))
	}
	up := tr.Winner.Backends[0].Request.Headers
	for _, k := range []string{"X-Real-Client-Ip", "X-Rid", "X-Where", "X-Literal", "X-Seen"} {
		if up[k] != seen.Headers[strings.ToLower(k)] {
			t.Errorf("%s: explain %q, proxy %q", k, up[k], seen.Headers[strings.ToLower(k)])
		}
	}
}

func TestHeaderVariablesGRPC(t *testing.T) {
	be, bs := grpcBackends(t, "g")
	rl := grule(nil, gref("g", 1))
	rl["filters"] = l{m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{"set": l{m{"name": "X-Added", "value": "{client_ip}/{request_id}"}}}}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(rl), be, nil), nil)
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"x"}, "X-Request-Id", "rid-7", "X-Added", "client")
	if r.Status != "0" {
		t.Fatalf("status %q", r.Status)
	}
	if got := bs["g"].seen[0].Custom; got != "127.0.0.1/rid-7" {
		t.Errorf("X-Added = %q", got)
	}
	if r.Header.Get("X-Request-Id") != "rid-7" {
		t.Errorf("response request id %q", r.Header.Get("X-Request-Id"))
	}
}

// ---- access log filtering ----

func identLogLines(t *testing.T, b *syncBuf) []logLine {
	t.Helper()
	var out []logLine
	for _, ln := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if ln == "" {
			continue
		}
		var l logLine
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("bad line %q: %v", ln, err)
		}
		out = append(out, l)
	}
	return out
}

func logServer(t *testing.T, mod func(*Options)) (*Server, *syncBuf) {
	be, _ := upstreams(t, "a")
	var buf syncBuf
	routes := map[string]m{"r": route("a.test", rule("/", ref("a", 1))), "bad": route("bad.test", rule("/", ref("missing", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) {
		o.AccessLog = &buf
		mod(o)
	})
	return s, &buf
}

func TestAccessLogExclude(t *testing.T) {
	s, buf := logServer(t, func(o *Options) { o.Obs.AccessLogExclude = []string{"/edge-health", "/healthz*"} })
	for _, p := range []string{"/edge-health", "/healthz", "/healthz/ready?x=1", "/edge-health2", "/api", "/edge-health"} {
		get(t, s, "a.test", p)
	}
	s.FlushAccessLog()
	var paths []string
	for _, l := range identLogLines(t, buf) {
		paths = append(paths, l.Path)
	}
	if got := strings.Join(paths, " "); got != "/edge-health2 /api" {
		t.Errorf("logged paths: %q", got)
	}
	if n := s.stats.Snapshot()["requests"]; n != int64(6) {
		t.Errorf("excluded requests must still count in metrics: %v", n)
	}
	var mb strings.Builder
	s.writeExtMetrics(&mb)
	if !strings.Contains(mb.String(), `setura_gateway_accesslog_skipped_total{reason="excluded"} 4`) {
		t.Errorf("skipped metric:\n%s", mb.String())
	}
	if err := ValidateLogExclude([]string{"health"}); err == nil {
		t.Error("pattern without a leading slash accepted")
	}
}

func TestAccessLogSample(t *testing.T) {
	s, buf := logServer(t, func(o *Options) { o.Obs.AccessLogSample = 1000 })
	get(t, s, "a.test", "/one")
	get(t, s, "a.test", "/two")
	get(t, s, "a.test", "/three")
	if r := get(t, s, "bad.test", "/e1"); r.Status != 500 {
		t.Fatalf("status %d", r.Status)
	}
	get(t, s, "bad.test", "/e2")
	s.FlushAccessLog()
	var paths []string
	for _, l := range identLogLines(t, buf) {
		paths = append(paths, l.Path)
	}
	if got := strings.Join(paths, " "); got != "/one /e1 /e2" {
		t.Errorf("logged paths: %q (the first request and every 5xx)", got)
	}
	if n := s.stats.Snapshot()["requests"]; n != int64(5) {
		t.Errorf("sampled-out requests must still count in metrics: %v", n)
	}
	// 1 in 3 over a plain run.
	s, buf = logServer(t, func(o *Options) { o.Obs.AccessLogSample = 3 })
	for i := 0; i < 7; i++ {
		get(t, s, "a.test", "/p")
	}
	s.FlushAccessLog()
	if n := len(identLogLines(t, buf)); n != 3 {
		t.Errorf("sample 3 of 7: %d lines, want 3", n)
	}
}

// ---- GRPCRoute policy ----

func grpcPolicyServer(t *testing.T, policy m, annotations m, mod func(*Options)) (*Server, *grpcBackend) {
	be, bs := grpcBackends(t, "g")
	rl := grule(nil, gref("g", 1))
	if policy != nil {
		rl[authKeyT] = policy
	}
	rt := grpcRoute("", rl)
	if annotations != nil {
		rt["setura.zyvor.dev/annotations"] = annotations
	}
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": rt}, be, nil), func(o *Options) {
		o.AuthClock = func() time.Time { return t0 }
		if mod != nil {
			mod(o)
		}
	})
	return s, bs["g"]
}

func TestGRPCRouteAPIKeyStatusMapping(t *testing.T) {
	s, be := grpcPolicyServer(t, m{"apiKey": m{"header": "x-api-key", "keys": l{m{"name": "ci", "key": "secret"}}}}, nil, nil)
	c := h2cClient(s.Addr(8080))
	call := func(hdr ...string) grpcReply {
		return grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"hi"}, hdr...)
	}
	for name, r := range map[string]grpcReply{"no key": call(), "wrong key": call("X-Api-Key", "nope")} {
		if r.HTTP != 200 || r.Status != "16" || len(r.Msgs) != 0 {
			t.Errorf("%s: http %d grpc-status %q msgs %v, want 200 / 16 (UNAUTHENTICATED)", name, r.HTTP, r.Status, r.Msgs)
		}
	}
	if n := len(be.paths()); n != 0 {
		t.Fatalf("a rejected call reached the backend (%d)", n)
	}
	r := call("X-Api-Key", "secret", "X-Setura-Auth-Subject", "spoof")
	if r.Status != "0" || len(r.Msgs) != 1 {
		t.Fatalf("valid key: %+v", r)
	}
	auth, _, _, _ := s.ext.snapshot()
	if auth[[3]string{"GRPCRoute/t/g", "denied", "unauthenticated"}] != 2 || auth[[3]string{"GRPCRoute/t/g", "allowed", ""}] != 1 {
		t.Errorf("auth counters: %v", auth)
	}
}

func TestGRPCRouteIPDenyAndAnnotation(t *testing.T) {
	// ipDeny through the annotation form, whole route.
	s, be := grpcPolicyServer(t, nil, m{AuthKey: `{"ipDeny":["127.0.0.0/8"]}`}, nil)
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"hi"})
	if r.HTTP != 200 || r.Status != "7" {
		t.Errorf("denied address: http %d grpc-status %q, want 200 / 7 (PERMISSION_DENIED)", r.HTTP, r.Status)
	}
	if len(be.paths()) != 0 {
		t.Error("denied call reached the backend")
	}
	// ipAllow that includes the client passes.
	s, _ = grpcPolicyServer(t, nil, m{AuthRuleAnnotation(1): `{"ipAllow":["127.0.0.1"]}`}, nil)
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"hi"}); r.Status != "0" {
		t.Errorf("allowed address: %q", r.Status)
	}
	// A broken annotation must not serve unprotected.
	s, _ = grpcPolicyServer(t, nil, m{AuthKey: `{"ipAllow":["not-an-ip"]}`}, nil)
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"hi"}); r.Status == "0" {
		t.Error("route with an invalid auth annotation served")
	}
}

func TestGRPCRouteJWT(t *testing.T) {
	k := newRSAKey(t, "k1")
	s, _ := grpcPolicyServer(t, m{"jwt": m{"issuer": "https://idp.test", "audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}}, nil, nil)
	c := h2cClient(s.Addr(8080))
	call := func(hdr ...string) grpcReply {
		return grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"hi"}, hdr...)
	}
	if r := call(); r.Status != "16" {
		t.Errorf("no token: %q", r.Status)
	}
	if r := call(bearer(k.sign(t, nil, claims(map[string]any{"aud": "other"})))...); r.Status != "16" {
		t.Errorf("wrong audience: %q", r.Status)
	}
	if r := call(bearer(k.sign(t, nil, claims(nil)))...); r.Status != "0" {
		t.Errorf("valid token: %q", r.Status)
	}
}

func TestGRPCRouteRateLimit(t *testing.T) {
	var log syncBuf
	s, be := grpcPolicyServer(t, nil, nil, func(o *Options) {
		o.AccessLog = &log
		o.Obs.RateLimit = RateLimitConfig{Rate: 1, Per: time.Hour, Burst: 1, Key: "route"}
	})
	c := h2cClient(s.Addr(8080))
	if r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"a"}); r.Status != "0" {
		t.Fatalf("first call: %q", r.Status)
	}
	r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"b"})
	if r.HTTP != 200 || r.Status != "8" || len(r.Msgs) != 0 {
		t.Errorf("second call: http %d grpc-status %q, want 200 / 8 (RESOURCE_EXHAUSTED)", r.HTTP, r.Status)
	}
	if r.Header.Get("Grpc-Retry-Pushback-Ms") == "" {
		t.Error("no grpc-retry-pushback-ms")
	}
	if len(be.paths()) != 1 {
		t.Errorf("backend saw %d calls", len(be.paths()))
	}
	s.FlushAccessLog()
	lines := identLogLines(t, &log)
	last := lines[len(lines)-1]
	if !last.RateLimited || last.Status != 429 || last.GRPCStatus == nil || *last.GRPCStatus != 8 {
		t.Errorf("log line: %+v", last)
	}
}
