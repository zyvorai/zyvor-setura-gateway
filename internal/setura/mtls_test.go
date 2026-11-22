package setura

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testPKI struct {
	caPEM, clientCert, clientKey string
	server                       *tls.Config
	serverCert                   tls.Certificate
	ca                           *x509.Certificate
	caKey                        *ecdsa.PrivateKey
}

var serial int64 = 100

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	parent, pk := tmpl, key
	if ca != nil {
		parent, pk = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

// newPKI builds a CA, a server cert (valid serverDays) and a client cert, and a
// server config that requires and verifies client certificates.
func newPKI(t *testing.T, serverDays int, auth tls.ClientAuthType) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := &testPKI{ca: ca, caKey: caKey}
	p.caPEM = write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	srv, _, _ := issue(t, ca, caKey, &x509.Certificate{Subject: pkix.Name{CommonName: "orders.mactra.test"}, DNSNames: []string{"orders.mactra.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotAfter: time.Now().Add(time.Duration(serverDays)*24*time.Hour + time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	p.serverCert = srv
	_, cc, ck := issue(t, ca, caKey, &x509.Certificate{Subject: pkix.Name{CommonName: "client-1"}, NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	p.clientCert, p.clientKey = write("client.pem", cc), write("client.key", ck)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	p.server = &tls.Config{Certificates: []tls.Certificate{srv}, ClientAuth: auth, ClientCAs: pool}
	return p
}

func probeMTLS(t *testing.T, pki *testPKI, mut func(*ProbeOptions)) *Report {
	t.Helper()
	o := NewProbe(fixture(t, pki.server))
	o.Address, o.CA, o.Backend = "127.0.0.1", pki.caPEM, "orders-v1"
	if mut != nil {
		mut(&o)
	}
	r, err := Probe(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMTLSClientCertPresented(t *testing.T) {
	pki := newPKI(t, 90, tls.RequireAndVerifyClientCert)
	for _, minTLS := range []string{"", "1.2", "1.3"} {
		r := probeMTLS(t, pki, func(o *ProbeOptions) {
			o.Cert, o.Key, o.MinTLS = pki.clientCert, pki.clientKey, minTLS
			o.WarnExpiryDays = 30
		})
		if !r.OK {
			t.Fatalf("min %q: %+v", minTLS, r.Steps["tls"])
		}
		s := r.Step("tls")
		is(t, s.Get("client_cert"), "presented")
		if s.Get("cipher_suite") == "" || s.Get("server_subject") == nil || s.Get("server_issuer") == nil || s.Get("not_after") == nil {
			t.Fatalf("missing details: %+v", s)
		}
		if d := s.Get("days_to_expiry").(int); d < 89 || d > 90 {
			t.Fatalf("days %d", d)
		}
		if s.Get("expiry_warning") != nil {
			t.Fatal("unexpected warning")
		}
	}
}

func TestMTLSMissingCertFailsClearly(t *testing.T) {
	pki := newPKI(t, 90, tls.RequireAndVerifyClientCert)
	for _, minTLS := range []string{"1.2", "1.3"} {
		r := probeMTLS(t, pki, func(o *ProbeOptions) { o.MinTLS = minTLS })
		if r.OK {
			t.Fatal("expected failure")
		}
		s := r.Step("tls")
		is(t, s.State(), "failed")
		contains(t, asStr(s.Get("reason")), "requires a client certificate")
		is(t, s.Get("client_cert"), "rejected")
	}
}

func TestMTLSRejectedCert(t *testing.T) {
	pki := newPKI(t, 90, tls.RequireAndVerifyClientCert)
	other := newPKI(t, 90, tls.NoClientCert) // client cert from a different CA
	r := probeMTLS(t, pki, func(o *ProbeOptions) { o.Cert, o.Key = other.clientCert, other.clientKey })
	is(t, r.Step("tls").State(), "failed")
	contains(t, asStr(r.Step("tls").Get("reason")), "rejected the presented client certificate")
}

func TestMTLSNotRequestedAndExpiry(t *testing.T) {
	pki := newPKI(t, 3, tls.NoClientCert)
	r := probeMTLS(t, pki, func(o *ProbeOptions) { o.WarnExpiryDays = 10 })
	if !r.OK {
		t.Fatal(r.Step("tls"))
	}
	is(t, r.Step("tls").Get("client_cert"), "not_requested")
	is(t, r.Step("tls").State(), "ok")
	contains(t, asStr(r.Step("tls").Get("expiry_warning")), "expires in")
	r = probeMTLS(t, pki, func(o *ProbeOptions) { o.MinCertDays = 10 })
	is(t, r.Step("tls").State(), "failed")
	contains(t, asStr(r.Step("tls").Get("reason")), "minimum is 10")
	if r.OK {
		t.Fatal("min cert days should fail the probe")
	}
}

func TestMTLSServerNameAndOptionValidation(t *testing.T) {
	pki := newPKI(t, 90, tls.NoClientCert)
	r := probeMTLS(t, pki, func(o *ProbeOptions) { o.ServerName = "wrong.example.test" })
	is(t, r.Step("tls").State(), "failed")
	for _, o := range []ProbeOptions{{Cert: "a"}, {MinTLS: "1.1"}, {WarnExpiryDays: -1}} {
		o.URL, o.Status, o.Timeout = "https://x.test", 200, 1
		if _, err := Probe(o); err == nil {
			t.Fatalf("%+v should be invalid", o)
		}
	}
}

func TestMTLSCheckFileAndCLI(t *testing.T) {
	pki := newPKI(t, 90, tls.RequireAndVerifyClientCert)
	url := fixture(t, pki.server)
	file := filepath.Join(t.TempDir(), "c.json")
	body := `[{"url":"` + url + `","address":"127.0.0.1","ca":"` + pki.caPEM + `","cert":"` + pki.clientCert + `","key":"` + pki.clientKey +
		`","server_name":"orders.mactra.test","min_tls":"1.3","min_cert_days":30,"warn_expiry_days":10}]`
	os.WriteFile(file, []byte(body), 0o600)
	code, out, errs := cli(t, nil, "check", file)
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	contains(t, out, `"client_cert": "presented"`)
	code, out, _ = cli(t, nil, "explain", url, "--address", "127.0.0.1", "--ca", pki.caPEM, "--json")
	is(t, code, 1)
	contains(t, out, "requires a client certificate")
	code, out, _ = cli(t, nil, "explain", url, "--address", "127.0.0.1", "--ca", pki.caPEM, "--cert", pki.clientCert, "--key", pki.clientKey,
		"--tls-server-name", "orders.mactra.test", "--min-tls", "1.2")
	is(t, code, 0)
	contains(t, out, "client_cert=presented")
	body = strings.Replace(body, `"min_cert_days":30`, `"min_cert_days":400`, 1)
	os.WriteFile(file, []byte(body), 0o600)
	if code, _, _ := cli(t, nil, "check", file); code != 1 {
		t.Fatalf("min_cert_days 400 should fail, got %d", code)
	}
}

func TestEvidenceTLSFields(t *testing.T) {
	pki := newPKI(t, 3, tls.NoClientCert)
	r := probeMTLS(t, pki, func(o *ProbeOptions) { o.WarnExpiryDays = 10 })
	var rep any = decode(t, r)
	facts, err := Evidence(rep)
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, f := range facts {
		all += f.Observation + "\n"
	}
	contains(t, all, "expiry warning")
	contains(t, all, "client_cert=not_requested")
}

func TestCertsCommand(t *testing.T) {
	pki := newPKI(t, 3, tls.RequireAndVerifyClientCert)
	srvURL := fixture(t, pki.server)
	addr := strings.TrimSuffix(strings.TrimPrefix(srvURL, "https://orders.mactra.test"), "/checkout?q=1")
	addr = "127.0.0.1" + addr
	code, m := cliJSON(t, "certs", addr, "--ca", pki.caPEM, "--sni", "orders.mactra.test", "--cert", pki.clientCert, "--key", pki.clientKey, "--json")
	is(t, code, 0)
	is(t, m["verified"], true)
	chain := m["chain"].([]any)
	c0 := chain[0].(map[string]any)
	for _, k := range []string{"subject", "issuer", "sans", "not_before", "not_after", "key_type", "signature_algorithm"} {
		if c0[k] == nil {
			t.Fatalf("missing %s: %v", k, c0)
		}
	}
	// expiring within threshold
	code, m = cliJSON(t, "certs", addr, "--ca", pki.caPEM, "--sni", "orders.mactra.test", "--cert", pki.clientCert, "--key", pki.clientKey, "--json", "--warn-expiry-days", "30")
	is(t, code, 1)
	is(t, m["expiring"], true)
	// untrusted (system roots)
	code, m = cliJSON(t, "certs", addr, "--sni", "orders.mactra.test", "--cert", pki.clientCert, "--key", pki.clientKey, "--json")
	is(t, code, 1)
	is(t, m["verified"], false)
	// text mode, and missing client cert gives an error exit
	code, out, _ := cli(t, nil, "certs", addr, "--ca", pki.caPEM, "--sni", "orders.mactra.test", "--cert", pki.clientCert, "--key", pki.clientKey)
	is(t, code, 0)
	contains(t, out, "verified: yes")
	if code, _, errs := cli(t, nil, "certs", addr, "--ca", pki.caPEM, "--sni", "orders.mactra.test"); code == 0 {
		t.Fatal("expected failure without client cert")
	} else {
		contains(t, errs, "client certificate")
	}
}
