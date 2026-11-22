package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// clientCert issues a client certificate from the PKI.
func (p *pki) clientCert(cn string, dns string, uri string) tls.Certificate {
	p.n++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.n + 4096), Subject: pkix.Name{CommonName: cn, Organization: []string{"Acme"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if dns != "" {
		tmpl.DNSNames = []string{dns}
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (p *pki) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw}))
}

// mtlsServer serves a.test over HTTPS with frontend validation in the given mode.
func mtlsServer(t *testing.T, srvPKI, clientCA *pki, mode string, policy m) *Server {
	t.Helper()
	be, _ := upstreams(t, "a")
	gw := httpsGateway(tlsListener("web", "", "srv-cert"))
	val := m{"caCertificateRefs": l{m{"kind": "ConfigMap", "name": "clients-ca"}}}
	if mode != "" {
		val["mode"] = mode
	}
	gw["tls"] = m{"frontend": m{"default": m{"validation": val}}}
	r := rule("/", ref("a", 1))
	if policy != nil {
		r[authKeyT] = policy
	}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "r": route("a.test", r)},
		"backends":  m{"t/a:80": be["a"]},
		"secrets":   m{"srv-cert": srvPKI.files("srv", "a.test"), "clients-ca": m{"cert": clientCA.caPEM()}}})
	return startServer(t, raw, nil)
}

func mtlsClient(s *Server, srv *pki, certs ...tls.Certificate) *http.Client {
	c := tlsClient(s.Addr(8443), srv, "a.test")
	c.Transport.(*http.Transport).TLSClientConfig.Certificates = certs
	return c
}

func TestClientCertAllowValidOnly(t *testing.T) {
	srv, ca, rogue := newPKI(t), newPKI(t), newPKI(t)
	s := mtlsServer(t, srv, ca, "", nil)
	// No certificate, or one from another CA: the handshake fails.
	for name, certs := range map[string][]tls.Certificate{"none": nil, "untrusted": {rogue.clientCert("mallory", "", "")}} {
		if resp, err := mtlsClient(s, srv, certs...).Get("https://a.test/"); err == nil {
			resp.Body.Close()
			t.Errorf("%s: handshake succeeded", name)
		}
	}
	c := ca.clientCert("alice", "alice.corp.test", "spiffe://corp/alice")
	r := req(t, mtlsClient(s, srv, c), "https", "GET", "a.test", "/", "",
		"X-Setura-Client-Subject", "CN=root", "X-Setura-Client-Verified", "false", "x-setura-client-san", "DNS:evil")
	if r.Status != 200 {
		t.Fatalf("valid certificate: %d %s", r.Status, r.Body)
	}
	h := r.Echo.Headers
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if h["x-setura-client-verified"] != "true" || !strings.Contains(h["x-setura-client-subject"], "CN=alice") ||
		h["x-setura-client-san"] != "DNS:alice.corp.test,URI:spiffe://corp/alice" ||
		h["x-setura-client-serial"] != leaf.SerialNumber.Text(16) || len(h["x-setura-client-fingerprint"]) != 64 {
		t.Errorf("client certificate headers: %v", h)
	}
}

func TestClientCertInsecureFallback(t *testing.T) {
	srv, ca, rogue := newPKI(t), newPKI(t), newPKI(t)
	s := mtlsServer(t, srv, ca, ModeAllowInsecureFallback, nil)
	spoof := []string{"X-Setura-Client-Verified", "true", "X-Setura-Client-Subject", "CN=root"}
	// No certificate: served, and the spoofed identity is gone.
	r := req(t, mtlsClient(s, srv), "https", "GET", "a.test", "/", "", spoof...)
	if r.Status != 200 || r.Echo.Headers["x-setura-client-verified"] != "" || r.Echo.Headers["x-setura-client-subject"] != "" {
		t.Errorf("no certificate: %d %v", r.Status, r.Echo.Headers)
	}
	// A certificate that does not chain to the CA: served, marked unverified, fields not forwarded.
	r = req(t, mtlsClient(s, srv, rogue.clientCert("mallory", "m.test", "")), "https", "GET", "a.test", "/", "", spoof...)
	if r.Status != 200 || r.Echo.Headers["x-setura-client-verified"] != "false" || r.Echo.Headers["x-setura-client-subject"] != "" || r.Echo.Headers["x-setura-client-san"] != "" {
		t.Errorf("untrusted certificate: %d %v", r.Status, r.Echo.Headers)
	}
	r = req(t, mtlsClient(s, srv, ca.clientCert("alice", "", "")), "https", "GET", "a.test", "/", "")
	if r.Status != 200 || r.Echo.Headers["x-setura-client-verified"] != "true" {
		t.Errorf("valid certificate: %d %v", r.Status, r.Echo.Headers)
	}
}

func TestRouteRequiresVerifiedClientCert(t *testing.T) {
	srv, ca, rogue := newPKI(t), newPKI(t), newPKI(t)
	s := mtlsServer(t, srv, ca, ModeAllowInsecureFallback, m{"requireClientCert": true})
	if r := req(t, mtlsClient(s, srv), "https", "GET", "a.test", "/", ""); r.Status != 403 {
		t.Errorf("no certificate: %d", r.Status)
	}
	if r := req(t, mtlsClient(s, srv, rogue.clientCert("m", "", "")), "https", "GET", "a.test", "/", ""); r.Status != 403 {
		t.Errorf("untrusted certificate: %d", r.Status)
	}
	if r := req(t, mtlsClient(s, srv, ca.clientCert("alice", "", "")), "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Errorf("valid certificate: %d", r.Status)
	}
}

func TestBadClientCARefDoesNotServe(t *testing.T) {
	srv, ca := newPKI(t), newPKI(t)
	be, _ := upstreams(t, "a")
	for name, cref := range map[string]m{"missing": {"kind": "ConfigMap", "name": "nope"}, "wrong kind": {"kind": "Service", "name": "clients-ca"}} {
		gw := httpsGateway(tlsListener("web", "", "srv-cert"))
		gw["tls"] = m{"frontend": m{"default": m{"validation": m{"caCertificateRefs": l{cref}}}}}
		raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": gw, rtKeyT + "r": route("a.test", rule("/", ref("a", 1)))},
			"backends":  m{"t/a:80": be["a"]},
			"secrets":   m{"srv-cert": srv.files("srv", "a.test"), "clients-ca": m{"cert": ca.caPEM()}}})
		s := startServer(t, raw, nil)
		if s.Addr(8443) != "" {
			t.Errorf("%s: the listener must not serve without its validation", name)
		}
		var msg string
		for _, ls := range s.Status().Gateways["t/gw"].Listeners {
			for _, c := range ls.Conditions {
				if c.Type == "ResolvedRefs" && c.Status == "False" {
					msg = c.Reason
				}
			}
		}
		if msg != "InvalidCACertificateRef" {
			t.Errorf("%s: ResolvedRefs reason %q", name, msg)
		}
	}
}

func TestIdentityHeadersStrippedOnPlainHTTP(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), nil)
	r := get(t, s, "a.test", "/", "X-Setura-Client-Subject", "CN=root", "X-Setura-Auth-Subject", "root", "X-Setura-Client-Verified", "true", "X-Other", "ok")
	for _, k := range []string{"x-setura-client-subject", "x-setura-auth-subject", "x-setura-client-verified"} {
		if _, bad := r.Echo.Headers[k]; bad {
			t.Errorf("%s reached the backend", k)
		}
	}
	if r.Echo.Headers["x-other"] != "ok" {
		t.Error("unrelated headers must pass")
	}
}
