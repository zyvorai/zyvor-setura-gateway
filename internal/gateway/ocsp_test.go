package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ocspLeaf issues a server certificate that names an OCSP responder, as a chain
// of leaf and CA ready for a listener.
func (p *pki) ocspLeaf(name, responder string) (tls.Certificate, *x509.Certificate) {
	p.n++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.n + 9000), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), OCSPServer: []string{responder},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, p.ca.Raw}, PrivateKey: key, Leaf: leaf}, leaf
}

// ocspAnswer builds a signed OCSP response for leaf, signed by the CA.
func (p *pki) ocspAnswer(leaf *x509.Certificate, good bool, this, next time.Time) []byte {
	id, err := ocspCertIDFor(leaf, p.ca)
	if err != nil {
		p.t.Fatal(err)
	}
	single := ocspSingle{CertID: id, ThisUpdate: this, NextUpdate: next}
	if good {
		single.Good = true
	} else {
		single.Revoked = ocspRevoked{Time: this}
	}
	rd := ocspResponseData{ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: p.ca.RawSubject},
		ProducedAt: this, Responses: []ocspSingle{single}}
	tbs, err := asn1.Marshal(rd)
	if err != nil {
		p.t.Fatal(err)
	}
	d := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, d[:])
	if err != nil {
		p.t.Fatal(err)
	}
	rd.Raw = tbs
	basic, err := asn1.Marshal(ocspBasic{TBS: rd, SigAlg: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Sig: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		p.t.Fatal(err)
	}
	out, err := asn1.Marshal(ocspResponse{Status: 0, Bytes: ocspResponseBytes{Type: oidBasicOCSP, Response: basic}})
	if err != nil {
		p.t.Fatal(err)
	}
	return out
}

func TestOCSPResponseChecks(t *testing.T) {
	p, other := newPKI(t), newPKI(t)
	_, leaf := p.ocspLeaf("a.test", "http://responder.invalid")
	now := time.Now()
	good := p.ocspAnswer(leaf, true, now.Add(-time.Minute), now.Add(time.Hour))
	if this, next, err := checkOCSPResponse(good, leaf, p.ca, now); err != nil || next.Sub(this) != time.Hour+time.Minute {
		t.Fatalf("good response: %v", err)
	}
	for name, c := range map[string]struct {
		raw  []byte
		want string
	}{
		"revoked":      {p.ocspAnswer(leaf, false, now.Add(-time.Minute), now.Add(time.Hour)), "revoked"},
		"expired":      {p.ocspAnswer(leaf, true, now.Add(-2*time.Hour), now.Add(-time.Hour)), "expired"},
		"not yet":      {p.ocspAnswer(leaf, true, now.Add(time.Hour), now.Add(2*time.Hour)), "not valid yet"},
		"wrong signer": {other.ocspAnswer(leaf, true, now.Add(-time.Minute), now.Add(time.Hour)), "signature"},
		"garbage":      {[]byte("nope"), "DER"},
	} {
		if _, _, err := checkOCSPResponse(c.raw, leaf, p.ca, now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// the request is a well-formed OCSPRequest for this certificate
	req, err := buildOCSPRequest(leaf, p.ca)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ocspRequest
	if rest, err := asn1.Unmarshal(req, &parsed); err != nil || len(rest) != 0 || parsed.TBS.Requests[0].CertID.Serial.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("request does not round trip: %v", err)
	}
}

func TestOCSPManagerRefreshAndToleratesFailure(t *testing.T) {
	p := newPKI(t)
	cert, leaf := p.ocspLeaf("a.test", "http://responder.invalid/ocsp")
	clock := time.Now()
	var mu sync.Mutex
	down, calls := false, 0
	m := newOCSPManager(nil)
	m.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	m.fetch = func(ctx context.Context, url string, req []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if down {
			return nil, errors.New("responder unreachable")
		}
		return p.ocspAnswer(leaf, true, clock.Add(-time.Minute), clock.Add(4*time.Hour)), nil
	}
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	m.sync([]tls.Certificate{cert})
	if got := m.staple(&cert); len(got.OCSPStaple) != 0 {
		t.Fatal("stapled before any fetch")
	}
	m.refresh(context.Background())
	first := m.staple(&cert).OCSPStaple
	if len(first) == 0 || calls != 1 {
		t.Fatalf("no staple after refresh (calls %d)", calls)
	}
	// Not due yet: no second fetch.
	advance(time.Hour)
	m.refresh(context.Background())
	if calls != 1 {
		t.Errorf("refetched before half the validity: %d calls", calls)
	}
	// Due, but the responder is down: the old staple keeps being served, retries back off.
	advance(2 * time.Hour)
	mu.Lock()
	down = true
	mu.Unlock()
	m.refresh(context.Background())
	if calls != 2 || len(m.staple(&cert).OCSPStaple) == 0 {
		t.Fatalf("a failed refresh must keep the staple (calls %d)", calls)
	}
	m.refresh(context.Background())
	if calls != 2 {
		t.Errorf("retried immediately after a failure: %d calls", calls)
	}
	// Recovery after the backoff.
	advance(2 * time.Minute)
	mu.Lock()
	down = false
	mu.Unlock()
	m.refresh(context.Background())
	if calls != 3 {
		t.Errorf("no retry after the backoff: %d calls", calls)
	}
	// The staple is dropped once it expires and nothing replaced it.
	mu.Lock()
	down = true
	mu.Unlock()
	advance(10 * time.Hour)
	if len(m.staple(&cert).OCSPStaple) != 0 {
		t.Error("an expired staple is still served")
	}
	// A certificate that leaves the table stops being tracked.
	m.sync(nil)
	if len(m.ents) != 0 {
		t.Error("entry kept after the certificate went away")
	}
}

func TestOCSPStapledOnListener(t *testing.T) {
	p := newPKI(t)
	var hits atomic.Int32
	var leaf *x509.Certificate
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		now := time.Now()
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(p.ocspAnswer(leaf, true, now.Add(-time.Minute), now.Add(time.Hour)))
	}))
	defer responder.Close()
	var cert tls.Certificate
	cert, leaf = p.ocspLeaf("a.test", responder.URL)
	certFile, keyFile := writePair(t, p, cert)
	be, _ := upstreams(t, "a")
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpsGateway(tlsListener("web", "", "srv-cert")), rtKeyT + "r": route("a.test", rule("/", ref("a", 1)))},
		"backends":  m{"t/a:80": be["a"]},
		"secrets":   m{"srv-cert": m{"certFile": certFile, "keyFile": keyFile}}})
	s := startServer(t, raw, func(o *Options) { o.OCSPStaple = true })
	addr := s.Addr(8443)
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool, ServerName: "a.test"})
		if err != nil {
			t.Fatal(err)
		}
		staple := conn.ConnectionState().OCSPResponse
		conn.Close()
		if len(staple) > 0 {
			if _, _, err := checkOCSPResponse(staple, leaf, p.ca, time.Now()); err != nil {
				t.Fatalf("stapled response is not valid: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no OCSP staple after 5s (%d responder hits)", hits.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writePair writes a tls.Certificate chain and key as PEM files for a secrets entry.
func writePair(t *testing.T, p *pki, c tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	return writeChain(t, p.dir, "ocsp", c)
}

func writeChain(t *testing.T, dir, name string, c tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kb, err := x509.MarshalECPrivateKey(c.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(certFile, chain, 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}
