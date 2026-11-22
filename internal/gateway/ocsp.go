package gateway

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // OCSP CertID is defined over SHA-1 (RFC 6960)
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// OCSP stapling for listener certificates (--ocsp-staple). There is no OCSP
// package in the standard library, so this file builds the request and parses
// the response with encoding/asn1: only what stapling needs (one CertID, good
// or revoked, validity window, signature check), nothing else.
//
// A response is stapled only when its signature verifies against the issuer
// (or a delegated responder the issuer signed), it answers for this
// certificate, says "good" and is inside its validity window. A responder that
// is down or answers badly changes nothing: the previous staple stays until
// it expires, then the certificate is served without one.

var (
	oidSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidBasicOCSP  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPSigner = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

type ocspCertID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	Serial        *big.Int
}

type ocspRequest struct {
	TBS struct {
		Requests []struct{ CertID ocspCertID }
	}
}

type ocspResponseBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

type ocspResponse struct {
	Status asn1.Enumerated
	Bytes  ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

type ocspRevoked struct {
	Time   time.Time       `asn1:"generalized"`
	Reason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type ocspSingle struct {
	CertID     ocspCertID
	Good       asn1.Flag        `asn1:"tag:0,optional"`
	Revoked    ocspRevoked      `asn1:"tag:1,optional"`
	Unknown    asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type ocspResponseData struct {
	Raw         asn1.RawContent
	Version     int `asn1:"optional,default:0,explicit,tag:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingle
}

type ocspBasic struct {
	TBS    ocspResponseData
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
	Certs  []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

var ocspSigAlgs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

func ocspCertIDFor(leaf, issuer *x509.Certificate) (ocspCertID, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return ocspCertID{}, err
	}
	nh := sha1.Sum(issuer.RawSubject)
	kh := sha1.Sum(spki.Key.RightAlign())
	return ocspCertID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
		NameHash: nh[:], KeyHash: kh[:], Serial: leaf.SerialNumber}, nil
}

// buildOCSPRequest is the DER of an OCSPRequest for leaf.
func buildOCSPRequest(leaf, issuer *x509.Certificate) ([]byte, error) {
	id, err := ocspCertIDFor(leaf, issuer)
	if err != nil {
		return nil, err
	}
	var req ocspRequest
	req.TBS.Requests = []struct{ CertID ocspCertID }{{id}}
	return asn1.Marshal(req)
}

// checkOCSPResponse validates raw as an answer for leaf and returns its
// validity window. Any failure means the response must not be stapled.
func checkOCSPResponse(raw []byte, leaf, issuer *x509.Certificate, now time.Time) (this, next time.Time, err error) {
	var resp ocspResponse
	if rest, e := asn1.Unmarshal(raw, &resp); e != nil || len(rest) > 0 {
		return this, next, errors.New("response is not a DER OCSPResponse")
	}
	if resp.Status != 0 {
		return this, next, fmt.Errorf("responder status %d", int(resp.Status))
	}
	if !resp.Bytes.Type.Equal(oidBasicOCSP) {
		return this, next, errors.New("not a basic OCSP response")
	}
	var b ocspBasic
	if rest, e := asn1.Unmarshal(resp.Bytes.Response, &b); e != nil || len(rest) > 0 {
		return this, next, errors.New("malformed basic response")
	}
	algo, ok := ocspSigAlgs[b.SigAlg.Algorithm.String()]
	if !ok {
		return this, next, errors.New("unsupported signature algorithm")
	}
	signer := issuer
	for _, rv := range b.Certs { // a delegated responder, signed by the issuer
		c, e := x509.ParseCertificate(rv.FullBytes)
		if e != nil || c.CheckSignatureFrom(issuer) != nil {
			continue
		}
		for _, eku := range c.UnknownExtKeyUsage {
			if eku.Equal(oidOCSPSigner) {
				signer = c
			}
		}
	}
	if err := signer.CheckSignature(algo, b.TBS.Raw, b.Sig.RightAlign()); err != nil {
		return this, next, errors.New("signature does not verify")
	}
	want, err := ocspCertIDFor(leaf, issuer)
	if err != nil {
		return this, next, err
	}
	for _, s := range b.TBS.Responses {
		if !bytes.Equal(s.CertID.NameHash, want.NameHash) || !bytes.Equal(s.CertID.KeyHash, want.KeyHash) || s.CertID.Serial.Cmp(want.Serial) != 0 {
			continue
		}
		switch {
		case !bool(s.Good):
			if bool(s.Unknown) {
				return this, next, errors.New("responder does not know the certificate")
			}
			return this, next, errors.New("the certificate is reported revoked")
		case s.NextUpdate.IsZero():
			return this, next, errors.New("response has no nextUpdate")
		case now.Before(s.ThisUpdate.Add(-5 * time.Minute)):
			return this, next, errors.New("response is not valid yet")
		case !now.Before(s.NextUpdate):
			return this, next, errors.New("response has expired")
		}
		return s.ThisUpdate, s.NextUpdate, nil
	}
	return this, next, errors.New("response does not answer for this certificate")
}

// ---- manager ----

type ocspEntry struct {
	leaf, issuer *x509.Certificate
	server       string
	staple       []byte
	next         time.Time // staple expiry
	refreshAt    time.Time
	retryAt      time.Time
	failures     int
	lastErr      string
}

type ocspManager struct {
	mu    sync.Mutex
	ents  map[string]*ocspEntry
	now   func() time.Time
	fetch func(ctx context.Context, url string, req []byte) ([]byte, error)
	diag  func(format string, a ...any)

	stop chan struct{}
	wg   sync.WaitGroup
}

func newOCSPManager(diag func(string, ...any)) *ocspManager {
	m := &ocspManager{ents: map[string]*ocspEntry{}, now: time.Now, diag: diag, stop: make(chan struct{})}
	cl := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	m.fetch = func(ctx context.Context, url string, body []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/ocsp-request")
		resp, err := cl.Do(req)
		if err != nil {
			return nil, errors.New("responder unreachable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("responder answered %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
		if err != nil || len(b) > 1<<20 {
			return nil, errors.New("unreadable or oversized response")
		}
		return b, nil
	}
	return m
}

func (m *ocspManager) say(format string, a ...any) {
	if m.diag != nil {
		m.diag(format, a...)
	}
}

func certKey(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// sync makes the manager track exactly these certificates. A certificate
// needs an issuer in its chain and an OCSP responder URL to be tracked.
func (m *ocspManager) sync(certs []tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, c := range certs {
		if len(c.Certificate) < 2 {
			continue
		}
		leaf, err1 := x509.ParseCertificate(c.Certificate[0])
		issuer, err2 := x509.ParseCertificate(c.Certificate[1])
		if err1 != nil || err2 != nil || len(leaf.OCSPServer) == 0 {
			continue
		}
		k := certKey(leaf)
		keep[k] = true
		if m.ents[k] == nil {
			m.ents[k] = &ocspEntry{leaf: leaf, issuer: issuer, server: leaf.OCSPServer[0]}
		}
	}
	for k := range m.ents {
		if !keep[k] {
			delete(m.ents, k)
		}
	}
}

// refresh fetches a response for every tracked certificate that is due. A
// failure schedules a retry with backoff and leaves any current staple alone.
func (m *ocspManager) refresh(ctx context.Context) {
	m.mu.Lock()
	var due []*ocspEntry
	now := m.now()
	for _, e := range m.ents {
		if (len(e.staple) == 0 || !now.Before(e.refreshAt)) && !now.Before(e.retryAt) {
			due = append(due, e)
		}
	}
	m.mu.Unlock()
	for _, e := range due {
		m.refreshOne(ctx, e)
	}
}

func (m *ocspManager) refreshOne(ctx context.Context, e *ocspEntry) {
	fail := func(err error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		e.failures++
		backoff := time.Minute << min(e.failures-1, 6)
		if backoff > time.Hour {
			backoff = time.Hour
		}
		e.retryAt = m.now().Add(backoff)
		e.lastErr = err.Error()
		m.say("ocsp: %s: %v (retrying in %s)", e.leaf.Subject.CommonName, err, backoff)
	}
	req, err := buildOCSPRequest(e.leaf, e.issuer)
	if err != nil {
		fail(err)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := m.fetch(rctx, e.server, req)
	if err != nil {
		fail(err)
		return
	}
	this, next, err := checkOCSPResponse(raw, e.leaf, e.issuer, m.now())
	if err != nil {
		fail(err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e.staple, e.next, e.failures, e.lastErr, e.retryAt = raw, next, 0, "", time.Time{}
	e.refreshAt = this.Add(next.Sub(this) / 2)
	m.say("ocsp: stapled %s until %s", e.leaf.Subject.CommonName, next.UTC().Format(time.RFC3339))
}

// staple returns c with its current OCSP response attached, or c itself.
func (m *ocspManager) staple(c *tls.Certificate) *tls.Certificate {
	if m == nil || c == nil || len(c.Certificate) == 0 {
		return c
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return c
		}
	}
	m.mu.Lock()
	e := m.ents[certKey(leaf)]
	var staple []byte
	if e != nil && len(e.staple) > 0 && m.now().Before(e.next) {
		staple = e.staple
	}
	m.mu.Unlock()
	if staple == nil {
		return c
	}
	cp := *c
	cp.OCSPStaple = staple
	return &cp
}

// run refreshes in the background until stop is closed.
func (m *ocspManager) run() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		tk := time.NewTicker(time.Minute)
		defer tk.Stop()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { <-m.stop; cancel() }()
		for {
			m.refresh(ctx)
			select {
			case <-m.stop:
				return
			case <-tk.C:
			}
		}
	}()
}

func (m *ocspManager) close() {
	if m == nil {
		return
	}
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

// ocspSync tracks the certificates of a freshly applied table and starts an
// immediate refresh, without delaying the apply.
func (s *Server) ocspSync(t *Table) {
	if !s.opts.OCSPStaple {
		return
	}
	var certs []tls.Certificate
	for _, l := range t.Listeners {
		if l.Serving {
			certs = append(certs, l.Certs...)
		}
	}
	m := s.ocsp.Load()
	if m == nil {
		m = newOCSPManager(s.diag)
		m.sync(certs)
		m.run()
		s.ocsp.Store(m)
		return
	}
	m.sync(certs)
	go m.refresh(context.Background())
}

// stapled is certFor's last step.
func (s *Server) stapled(c *tls.Certificate) *tls.Certificate {
	return s.ocsp.Load().staple(c)
}
