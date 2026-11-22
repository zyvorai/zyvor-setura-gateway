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
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const btlsKey = "backendtlspolicies.gateway.networking.k8s.io/"

func policy(target string, v m) m {
	return m{"targetRefs": l{m{"group": "", "kind": "Service", "name": target}}, "validation": v}
}

// tlsBackend is an HTTPS server whose certificate (issued by p) names dnsNames
// and spiffe URIs; with clientCA set it demands a client certificate.
func httpsBackend(t *testing.T, p *pki, clientCA *x509.CertPool, dnsNames []string, uris ...string) (addr string, certs func() []string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.n++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.n), Subject: pkix.Name{CommonName: dnsNames[0]}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, u := range uris {
		pu, _ := url.Parse(u)
		tmpl.URIs = append(tmpl.URIs, pu)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	var seenSubjects []string
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			mu.Lock()
			seenSubjects = append(seenSubjects, r.TLS.PeerCertificates[0].Subject.CommonName)
			mu.Unlock()
		}
		w.Header().Set("X-Sni", r.TLS.ServerName)
		w.Write([]byte("secure"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	if clientCA != nil {
		srv.TLS.ClientAuth, srv.TLS.ClientCAs = tls.RequireAndVerifyClientCert, clientCA
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seenSubjects...) }
}

func pkiCAPEM(p *pki) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw}))
}

func btlsSnapshot(t *testing.T, backend string, policies map[string]m, caCerts m, gw m) []byte {
	res := m{gwKeyT + "gw": gw, rtKeyT + "r": route("", rule("/", ref("secure", 1)))}
	for k, v := range policies {
		res[btlsKey+k] = v
	}
	top := m{"caCertificates": caCerts}
	return snapRes(res, map[string]any{"secure": backend}, top)
}

func policyConds(s *Server, key string) map[string]Condition {
	out := map[string]Condition{}
	if ps := s.Status().Policies[key]; ps != nil && len(ps.Ancestors) > 0 {
		for _, c := range ps.Ancestors[0].Conditions {
			out[c.Type] = c
		}
	}
	return out
}

func TestBackendTLSPolicyVerifiesBackend(t *testing.T) {
	p := newPKI(t)
	addr, _ := httpsBackend(t, p, nil, []string{"secure.internal"}, "spiffe://mesh/ns/a/sa/secure")
	cas := m{"ca-bundle": m{"pem": pkiCAPEM(p)}, "junk": m{"pem": "not a certificate"}}
	good := policy("secure", m{"hostname": "secure.internal", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca-bundle"}}})
	// Plain host:port endpoints are upgraded to https by the policy.
	s := startServer(t, btlsSnapshot(t, addr, map[string]m{"p": good}, cas, httpGateway("")), nil)
	r := get(t, s, "x.test", "/")
	if r.Status != 200 || r.Body != "secure" || r.Header.Get("X-Sni") != "secure.internal" {
		t.Fatalf("good policy: %d %q sni=%q", r.Status, r.Body, r.Header.Get("X-Sni"))
	}
	if c := policyConds(s, "t/p"); c["Accepted"].Status != "True" || c["ResolvedRefs"].Status != "True" {
		t.Errorf("policy conditions: %+v", c)
	}
	if ps := s.Status().Policies["t/p"]; len(ps.Ancestors) != 1 || ps.Ancestors[0].AncestorRef.Name != "gw" || ps.Ancestors[0].ControllerName != ControllerName {
		t.Errorf("ancestors: %+v", ps)
	}
	if c := cond(s.Status().Routes["t/r"].Parents[0].Conditions, "ResolvedRefs"); c.Status != "True" {
		t.Errorf("a satisfied policy leaves the route resolved: %+v", c)
	}

	// Wrong hostname: the certificate does not match, the request fails with a 5xx.
	bad := policy("secure", m{"hostname": "other.internal", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca-bundle"}}})
	s = startServer(t, btlsSnapshot(t, addr, map[string]m{"p": bad}, cas, httpGateway("")), nil)
	if r = get(t, s, "x.test", "/"); r.Status < 500 {
		t.Errorf("a hostname mismatch must fail, got %d", r.Status)
	}
	// A different CA: verification fails.
	other := newPKI(t)
	s = startServer(t, btlsSnapshot(t, addr, map[string]m{"p": good}, m{"ca-bundle": m{"pem": pkiCAPEM(other)}}, httpGateway("")), nil)
	if r = get(t, s, "x.test", "/"); r.Status < 500 {
		t.Errorf("an untrusted certificate must fail, got %d", r.Status)
	}
}

func TestBackendTLSPolicySubjectAltNames(t *testing.T) {
	p := newPKI(t)
	addr, _ := httpsBackend(t, p, nil, []string{"secure.internal"}, "spiffe://mesh/ns/a/sa/secure")
	cas := m{"ca": m{"pem": pkiCAPEM(p)}}
	with := func(sans l) []byte {
		return btlsSnapshot(t, addr, map[string]m{"p": policy("secure", m{"hostname": "sni-only.test", "subjectAltNames": sans,
			"caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}})}, cas, httpGateway(""))
	}
	// SNI is the policy hostname, authentication is by SAN only.
	if r := get(t, startServer(t, with(l{m{"type": "URI", "uri": "spiffe://mesh/ns/a/sa/secure"}}), nil), "x.test", "/"); r.Status != 200 || r.Header.Get("X-Sni") != "sni-only.test" {
		t.Errorf("URI SAN: %d sni=%q", r.Status, r.Header.Get("X-Sni"))
	}
	if r := get(t, startServer(t, with(l{m{"type": "Hostname", "hostname": "secure.internal"}}), nil), "x.test", "/"); r.Status != 200 {
		t.Errorf("hostname SAN: %d", r.Status)
	}
	if r := get(t, startServer(t, with(l{m{"type": "Hostname", "hostname": "nope.internal"}, m{"type": "URI", "uri": "spiffe://mesh/other"}}), nil), "x.test", "/"); r.Status < 500 {
		t.Errorf("no matching SAN must fail, got %d", r.Status)
	}
}

func TestBackendTLSPolicyInvalid(t *testing.T) {
	p := newPKI(t)
	addr, _ := httpsBackend(t, p, nil, []string{"secure.internal"})
	cas := m{"ca": m{"pem": pkiCAPEM(p)}, "junk": m{"pem": "garbage"}}
	cases := []struct {
		name     string
		v        m
		accepted string
		aReason  string
		rReason  string
	}{
		{"missing", m{"hostname": "h", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "gone"}}}, "False", "NoValidCACertificate", "InvalidCACertificateRef"},
		{"malformed", m{"hostname": "h", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "junk"}}}, "False", "NoValidCACertificate", "InvalidCACertificateRef"},
		{"kind", m{"hostname": "h", "caCertificateRefs": l{m{"group": "invalid.io", "kind": "InvalidKind", "name": "x"}}}, "False", "NoValidCACertificate", "InvalidKind"},
		{"one bad one good", m{"hostname": "secure.internal", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}, m{"kind": "ConfigMap", "name": "gone"}}}, "True", "Accepted", "InvalidCACertificateRef"},
		{"both sources", m{"hostname": "h", "wellKnownCACertificates": "System", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}}, "False", "Invalid", "ResolvedRefs"},
		{"unknown well known", m{"hostname": "h", "wellKnownCACertificates": "acme.io/ca"}, "False", "Invalid", "ResolvedRefs"},
	}
	for _, c := range cases {
		s := startServer(t, btlsSnapshot(t, addr, map[string]m{"p": policy("secure", c.v)}, cas, httpGateway("")), nil)
		conds := policyConds(s, "t/p")
		if conds["Accepted"].Status != c.accepted || conds["Accepted"].Reason != c.aReason || conds["ResolvedRefs"].Reason != c.rReason {
			t.Errorf("%s: %+v", c.name, conds)
		}
		if r := get(t, s, "x.test", "/"); r.Status < 500 {
			t.Errorf("%s: traffic to a backend with an unusable policy must fail (5xx), got %d: it must never fall back to plaintext", c.name, r.Status)
		}
		if rc := cond(s.Status().Routes["t/r"].Parents[0].Conditions, "ResolvedRefs"); rc.Status != "True" {
			t.Errorf("%s: the route stays resolved (the spec puts the reasons on the policy): %+v", c.name, rc)
		}
	}
}

func TestBackendTLSPolicyConflictAndGeneration(t *testing.T) {
	p := newPKI(t)
	addr, _ := httpsBackend(t, p, nil, []string{"secure.internal"})
	cas := m{"ca": m{"pem": pkiCAPEM(p)}}
	mk := func(name, created string) m {
		pol := policy("secure", m{"hostname": "secure.internal", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}})
		pol["metadata"] = m{"creationTimestamp": created}
		return pol
	}
	s := startServer(t, btlsSnapshot(t, addr, map[string]m{"old": mk("old", "2026-01-01T00:00:00Z"), "new": mk("new", "2026-02-01T00:00:00Z")}, cas, httpGateway("")), nil)
	if c := policyConds(s, "t/old"); c["Accepted"].Status != "True" {
		t.Errorf("older policy wins: %+v", c)
	}
	if c := policyConds(s, "t/new"); c["Accepted"].Status != "False" || c["Accepted"].Reason != "Conflicted" {
		t.Errorf("newer policy conflicts: %+v", c)
	}
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Errorf("the winning policy serves traffic: %d", r.Status)
	}
	if ps := s.Status().Policies["t/old"]; ps.ObservedGeneration == 0 {
		t.Errorf("observedGeneration must be set: %+v", ps)
	}
}

func TestBackendTLSMutual(t *testing.T) {
	p := newPKI(t)
	clientPKI := newPKI(t)
	addr, subjects := httpsBackend(t, p, clientPKI.pool, []string{"secure.internal"})
	// The client certificate is the Gateway's spec.tls.backend.clientCertificateRef.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientPKI.n++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(clientPKI.n), Subject: pkix.Name{CommonName: "gateway-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, clientPKI.ca, &key.PublicKey, clientPKI.key)
	kb, _ := x509.MarshalECPrivateKey(key)
	secret := m{"cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "key": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))}

	good := policy("secure", m{"hostname": "secure.internal", "caCertificateRefs": l{m{"kind": "ConfigMap", "name": "ca"}}})
	gw := httpGateway("")
	gw["tls"] = m{"backend": m{"clientCertificateRef": m{"name": "client-cert"}}}
	raw := btlsSnapshot(t, addr, map[string]m{"p": good}, m{"ca": m{"pem": pkiCAPEM(p)}}, gw)
	var doc m
	if err := jsonUnmarshalT(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["secrets"] = m{"client-cert": secret}
	s := startServer(t, mustJSON(doc), nil)
	if r := get(t, s, "x.test", "/"); r.Status != 200 || len(subjects()) != 1 || subjects()[0] != "gateway-client" {
		t.Fatalf("mTLS: %d, backend saw client certs %v", r.Status, subjects())
	}
	if c := cond(s.Status().Gateways["t/gw"].Conditions, "ResolvedRefs"); c.Status != "True" {
		t.Errorf("gateway ResolvedRefs: %+v", c)
	}
	// Without the Gateway's client certificate the backend refuses the handshake.
	s = startServer(t, btlsSnapshot(t, addr, map[string]m{"p": good}, m{"ca": m{"pem": pkiCAPEM(p)}}, httpGateway("")), nil)
	if r := get(t, s, "x.test", "/"); r.Status < 500 {
		t.Errorf("a backend that requires mTLS must refuse a client without a certificate, got %d", r.Status)
	}
	// A clientCertificateRef that does not resolve is reported on the Gateway.
	doc["secrets"] = m{}
	s = startServer(t, mustJSON(doc), nil)
	if c := cond(s.Status().Gateways["t/gw"].Conditions, "ResolvedRefs"); c.Status != "False" || c.Reason != "InvalidClientCertificateRef" {
		t.Errorf("unresolved client certificate: %+v", c)
	}
}

func TestBackendTLSGRPCAndSystemPool(t *testing.T) {
	// wellKnownCACertificates: System is accepted (the pool may be empty on a bare machine).
	p := newPKI(t)
	addr, _ := httpsBackend(t, p, nil, []string{"secure.internal"})
	s := startServer(t, btlsSnapshot(t, addr, map[string]m{"p": policy("secure", m{"hostname": "secure.internal", "wellKnownCACertificates": "System"})}, m{}, httpGateway("")), nil)
	if c := policyConds(s, "t/p"); c["Accepted"].Status != "True" {
		t.Errorf("System pool: %+v", c)
	}
	// The test CA is not in the system pool, so the handshake must fail.
	if r := get(t, s, "x.test", "/"); r.Status < 500 {
		t.Errorf("System roots must not trust the test CA: %d", r.Status)
	}
	_ = net.IPv4zero
}

func jsonUnmarshalT(raw []byte, v any) error { return json.Unmarshal(raw, v) }
