package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A hand-written in-process ACME server (RFC 8555) for the client tests. It
// verifies every JWS signature, enforces single-use nonces, drives orders
// through pending, processing and valid, and issues certificates from its own
// CA. It never leaves the process: nothing here touches a network beyond
// httptest's loopback listener.

type acmeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newACMEClock() *acmeClock {
	return &acmeClock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
}
func (c *acmeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *acmeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeProblem struct {
	Status     int
	Type       string
	Detail     string
	RetryAfter string
}

type fOrder struct {
	id          string
	idents      []string
	authz       []string
	status      string
	csrNames    []string
	certificate string
}

type fAuthz struct {
	id         string
	domain     string // identifier value, wildcard prefix removed
	wildcard   bool
	status     string
	token      string
	chosen     string // challenge type the client answered
	validation string // failure detail when invalid
}

type fakeACME struct {
	t     *testing.T
	srv   *httptest.Server
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
	clock *acmeClock

	mu         sync.Mutex
	nonces     map[string]bool
	used       map[string]bool
	nonceReuse int
	nextID     int
	accounts   map[string]*ecdsa.PublicKey // kid URL -> key
	orders     map[string]*fOrder
	authzs     map[string]*fAuthz
	counts     map[string]int
	csrKeyMap  map[string]*ecdsa.PublicKey
	chains     map[string][]byte
	issued     []string // serial numbers handed out, in order
	serial     int64

	badNonces      int                      // answer the next N signed POSTs with badNonce
	failOrder      func(n int) *fakeProblem // consulted at every newOrder (n counts from 1)
	forgetAccounts bool                     // answer the next signed POST with accountDoesNotExist
	lifetime       time.Duration            // certificate lifetime (default 90 days)
	validate       func(typ, domain, token, keyAuth string) error
	offer          []string // challenge types offered (default http-01, tls-alpn-01, dns-01)
}

func newFakeACME(t *testing.T, clock *acmeClock) *fakeACME {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake acme ca"},
		NotBefore: clock.Now().Add(-24 * time.Hour), NotAfter: clock.Now().Add(20 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	f := &fakeACME{t: t, ca: ca, caKey: key, pool: pool, clock: clock, nonces: map[string]bool{}, used: map[string]bool{},
		csrKeyMap: map[string]*ecdsa.PublicKey{}, chains: map[string][]byte{}, accounts: map[string]*ecdsa.PublicKey{}, orders: map[string]*fOrder{}, authzs: map[string]*fAuthz{}, counts: map[string]int{},
		lifetime: 90 * 24 * time.Hour, serial: 100, offer: []string{"http-01", "tls-alpn-01", "dns-01"}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACME) dirURL() string { return f.srv.URL + "/dir" }

func (f *fakeACME) count(k string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[k]
}

func (f *fakeACME) freshNonce() string {
	f.nextID++
	n := fmt.Sprintf("nonce-%d", f.nextID)
	f.nonces[n] = true
	return n
}

func (f *fakeACME) writeJSON(w http.ResponseWriter, status int, v any, hdr ...string) {
	w.Header().Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		w.Header().Set(hdr[i], hdr[i+1])
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeACME) problem(w http.ResponseWriter, p *fakeProblem) {
	if p.RetryAfter != "" {
		w.Header().Set("Retry-After", p.RetryAfter)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.NewEncoder(w).Encode(map[string]any{"type": p.Type, "detail": p.Detail, "status": p.Status})
}

func b64d(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

func thumbOf(k *ecdsa.PublicKey) string {
	x, y := k.X.Bytes(), k.Y.Bytes()
	x = append(make([]byte, 32-len(x)), x...)
	y = append(make([]byte, 32-len(y)), y...)
	s := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(x), b64(y))
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

// verify checks the JWS of a POST and returns the payload, the account key and its kid.
func (f *fakeACME) verify(r *http.Request) (payload []byte, key *ecdsa.PublicKey, kid string, prob *fakeProblem) {
	bad := func(typ, detail string) *fakeProblem {
		return &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:" + typ, Detail: detail}
	}
	body, _ := io.ReadAll(r.Body)
	if ct := r.Header.Get("Content-Type"); ct != "application/jose+json" {
		return nil, nil, "", bad("malformed", "content type "+ct)
	}
	var env struct{ Protected, Payload, Signature string }
	if json.Unmarshal(body, &env) != nil {
		return nil, nil, "", bad("malformed", "not a JWS")
	}
	var prot struct {
		Alg   string          `json:"alg"`
		Nonce string          `json:"nonce"`
		URL   string          `json:"url"`
		Kid   string          `json:"kid"`
		JWK   json.RawMessage `json:"jwk"`
	}
	if json.Unmarshal(b64d(env.Protected), &prot) != nil || prot.Alg != "ES256" {
		return nil, nil, "", bad("malformed", "bad protected header")
	}
	if prot.URL != f.srv.URL+r.URL.Path {
		return nil, nil, "", bad("unauthorized", "url "+prot.URL+" does not match the request")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.badNonces > 0 {
		f.badNonces--
		return nil, nil, "", &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:badNonce", Detail: "injected"}
	}
	if !f.nonces[prot.Nonce] {
		if f.used[prot.Nonce] {
			f.nonceReuse++
		}
		return nil, nil, "", &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:badNonce", Detail: "unknown or used nonce"}
	}
	delete(f.nonces, prot.Nonce)
	f.used[prot.Nonce] = true
	switch {
	case len(prot.JWK) > 0 && prot.Kid != "":
		return nil, nil, "", bad("malformed", "both jwk and kid")
	case len(prot.JWK) > 0:
		var j struct{ Crv, Kty, X, Y string }
		if json.Unmarshal(prot.JWK, &j) != nil || j.Crv != "P-256" || j.Kty != "EC" {
			return nil, nil, "", bad("badPublicKey", "unsupported jwk")
		}
		key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(b64d(j.X)), Y: new(big.Int).SetBytes(b64d(j.Y))}
	case prot.Kid != "":
		if f.forgetAccounts {
			f.forgetAccounts = false
			delete(f.accounts, prot.Kid)
		}
		if key = f.accounts[prot.Kid]; key == nil {
			return nil, nil, "", &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:accountDoesNotExist", Detail: "no such account"}
		}
		kid = prot.Kid
	default:
		return nil, nil, "", bad("malformed", "no jwk or kid")
	}
	sig := b64d(env.Signature)
	h := sha256.Sum256([]byte(env.Protected + "." + env.Payload))
	if len(sig) != 64 || !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, "", bad("malformed", "bad signature")
	}
	return b64d(env.Payload), key, kid, nil
}

func (f *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	f.mu.Lock()
	f.counts[r.Method+" "+firstSeg(path)]++
	f.mu.Unlock()
	switch {
	case path == "/dir" && r.Method == http.MethodGet:
		f.writeJSON(w, 200, map[string]string{"newNonce": f.srv.URL + "/nonce", "newAccount": f.srv.URL + "/acct", "newOrder": f.srv.URL + "/order"})
		return
	case path == "/nonce":
		f.mu.Lock()
		n := f.freshNonce()
		f.mu.Unlock()
		w.Header().Set("Replay-Nonce", n)
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post only", 405)
		return
	}
	payload, key, kid, prob := f.verify(r)
	f.mu.Lock()
	w.Header().Set("Replay-Nonce", f.freshNonce())
	f.mu.Unlock()
	if prob != nil {
		f.problem(w, prob)
		return
	}
	switch seg := firstSeg(path); seg {
	case "acct":
		f.handleAccount(w, payload, key)
	case "order":
		if path == "/order" {
			f.handleNewOrder(w, payload, kid)
		} else {
			f.handleOrderPoll(w, path)
		}
	case "authz":
		f.handleAuthz(w, path)
	case "chall":
		f.handleChallenge(w, path, payload)
	case "finalize":
		f.handleFinalize(w, path, payload)
	case "cert":
		f.handleCert(w, path)
	default:
		f.problem(w, &fakeProblem{Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "no such resource " + path})
	}
}

func firstSeg(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return p
}

func lastSeg(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

func (f *fakeACME) handleAccount(w http.ResponseWriter, payload []byte, key *ecdsa.PublicKey) {
	var pl struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
	}
	json.Unmarshal(payload, &pl)
	if !pl.TermsOfServiceAgreed {
		f.problem(w, &fakeProblem{Status: 403, Type: "urn:ietf:params:acme:error:userActionRequired", Detail: "agree to the terms"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for kid, k := range f.accounts {
		if k.X.Cmp(key.X) == 0 && k.Y.Cmp(key.Y) == 0 {
			f.writeJSON(w, 200, map[string]string{"status": "valid"}, "Location", kid, "Replay-Nonce", f.freshNonce())
			return
		}
	}
	kid := fmt.Sprintf("%s/acct/%d", f.srv.URL, len(f.accounts)+1+f.counts["accounts-made"])
	f.counts["accounts-made"]++
	f.accounts[kid] = key
	f.writeJSON(w, 201, map[string]any{"status": "valid", "contact": pl.Contact}, "Location", kid)
}

func (f *fakeACME) handleNewOrder(w http.ResponseWriter, payload []byte, kid string) {
	if kid == "" {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "newOrder needs a kid"})
		return
	}
	f.mu.Lock()
	n := f.counts["orders-made"] + 1
	hook := f.failOrder
	f.mu.Unlock()
	if hook != nil {
		if p := hook(n); p != nil {
			f.mu.Lock()
			f.counts["orders-made"]++
			f.mu.Unlock()
			f.problem(w, p)
			return
		}
	}
	var pl struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
	}
	if json.Unmarshal(payload, &pl) != nil || len(pl.Identifiers) == 0 {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "no identifiers"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts["orders-made"]++
	o := &fOrder{id: strconv.Itoa(f.counts["orders-made"]), status: "pending"}
	for _, id := range pl.Identifiers {
		if id.Type != "dns" {
			f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:unsupportedIdentifier", Detail: id.Type})
			return
		}
		f.nextID++
		az := &fAuthz{id: strconv.Itoa(f.nextID), domain: strings.TrimPrefix(id.Value, "*."), wildcard: strings.HasPrefix(id.Value, "*."), status: "pending", token: fmt.Sprintf("tok%d-%s", f.nextID, strings.Repeat("x", 12))}
		f.authzs[az.id] = az
		o.authz = append(o.authz, az.id)
		o.idents = append(o.idents, id.Value)
	}
	f.orders[o.id] = o
	f.writeJSON(w, 201, f.orderJSON(o), "Location", f.srv.URL+"/order/"+o.id)
}

func (f *fakeACME) orderJSON(o *fOrder) map[string]any {
	var ids []map[string]string
	for _, i := range o.idents {
		ids = append(ids, map[string]string{"type": "dns", "value": i})
	}
	var az []string
	for _, a := range o.authz {
		az = append(az, f.srv.URL+"/authz/"+a)
	}
	out := map[string]any{"status": o.status, "identifiers": ids, "authorizations": az, "finalize": f.srv.URL + "/finalize/" + o.id}
	if o.certificate != "" {
		out["certificate"] = f.srv.URL + "/cert/" + o.certificate
	}
	return out
}

func (f *fakeACME) handleOrderPoll(w http.ResponseWriter, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[lastSeg(path)]
	if o == nil {
		f.problem(w, &fakeProblem{Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "no such order"})
		return
	}
	if o.status == "processing" { // one round of "processing" so the client must poll
		f.issue(o)
	}
	f.writeJSON(w, 200, f.orderJSON(o))
}

func (f *fakeACME) authzJSON(a *fAuthz) map[string]any {
	var chs []map[string]any
	for _, typ := range f.offer {
		ch := map[string]any{"type": typ, "url": f.srv.URL + "/chall/" + a.id + "-" + typ, "token": a.token, "status": "pending"}
		if a.chosen == typ && a.status == "invalid" {
			ch["status"] = "invalid"
			ch["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": a.validation, "status": 403}
		}
		chs = append(chs, ch)
	}
	return map[string]any{"status": a.status, "identifier": map[string]string{"type": "dns", "value": a.domain}, "wildcard": a.wildcard, "challenges": chs}
}

func (f *fakeACME) handleAuthz(w http.ResponseWriter, path string) {
	f.mu.Lock()
	a := f.authzs[lastSeg(path)]
	if a == nil {
		f.mu.Unlock()
		f.problem(w, &fakeProblem{Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "no such authz"})
		return
	}
	if a.status == "processing" {
		typ, domain, token := a.chosen, a.domain, a.token
		val := f.validate
		kid := f.accountThumbFor(a)
		f.mu.Unlock()
		var err error
		if val == nil {
			err = fmt.Errorf("no validator")
		} else {
			err = val(typ, domain, token, token+"."+kid)
		}
		f.mu.Lock()
		if err != nil {
			a.status, a.validation = "invalid", err.Error()
		} else {
			a.status = "valid"
		}
	}
	j := f.authzJSON(a)
	f.mu.Unlock()
	f.writeJSON(w, 200, j)
}

// accountThumbFor returns the thumbprint of the (only) account in play. The
// fake supports one account at a time, which is all the client tests need.
func (f *fakeACME) accountThumbFor(*fAuthz) string {
	for _, k := range f.accounts {
		return thumbOf(k)
	}
	return ""
}

func (f *fakeACME) handleChallenge(w http.ResponseWriter, path string, payload []byte) {
	if strings.TrimSpace(string(payload)) != "{}" {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "challenge payload must be {}"})
		return
	}
	id := lastSeg(path)
	i := strings.IndexByte(id, '-')
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.authzs[id[:i]]
	if a == nil || a.status != "pending" {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "authorization is not pending"})
		return
	}
	a.status, a.chosen = "processing", id[i+1:]
	f.writeJSON(w, 200, map[string]any{"type": a.chosen, "url": f.srv.URL + path, "token": a.token, "status": "processing"})
}

func (f *fakeACME) handleFinalize(w http.ResponseWriter, path string, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[lastSeg(path)]
	if o == nil {
		f.problem(w, &fakeProblem{Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "no such order"})
		return
	}
	for _, id := range o.authz {
		if f.authzs[id].status != "valid" {
			f.problem(w, &fakeProblem{Status: 403, Type: "urn:ietf:params:acme:error:orderNotReady", Detail: "authorization " + id + " is " + f.authzs[id].status})
			return
		}
	}
	var pl struct{ CSR string }
	json.Unmarshal(payload, &pl)
	csr, err := x509.ParseCertificateRequest(b64d(pl.CSR))
	if err != nil || csr.CheckSignature() != nil {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:badCSR", Detail: "unusable CSR"})
		return
	}
	if strings.Join(csr.DNSNames, ",") != strings.Join(o.idents, ",") {
		f.problem(w, &fakeProblem{Status: 400, Type: "urn:ietf:params:acme:error:badCSR", Detail: "CSR names " + strings.Join(csr.DNSNames, ",") + " differ from the order"})
		return
	}
	o.csrNames = csr.DNSNames
	f.csrKeyMap[o.id] = csr.PublicKey.(*ecdsa.PublicKey)
	o.status = "processing"
	f.writeJSON(w, 200, f.orderJSON(o))
}

// issue signs the certificate for a processing order (callers hold f.mu).
func (f *fakeACME) issue(o *fOrder) {
	f.serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(f.serial), Subject: pkix.Name{CommonName: o.csrNames[0]}, DNSNames: o.csrNames,
		NotBefore: f.clock.Now(), NotAfter: f.clock.Now().Add(f.lifetime), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, f.csrKeyMap[o.id], f.caKey)
	if err != nil {
		f.t.Errorf("fake acme: %v", err)
		return
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})...)
	f.chains[o.id] = chain
	o.certificate = o.id
	o.status = "valid"
	f.issued = append(f.issued, strconv.FormatInt(f.serial, 10))
}

func (f *fakeACME) handleCert(w http.ResponseWriter, path string) {
	f.mu.Lock()
	chain := f.chains[lastSeg(path)]
	f.mu.Unlock()
	if chain == nil {
		f.problem(w, &fakeProblem{Status: 404, Type: "urn:ietf:params:acme:error:malformed", Detail: "no such certificate"})
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(chain)
}

func (f *fakeACME) issuedSerials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.issued...)
}

// noSleep is the Sleep of tests: polling never waits, it only honours cancellation.
func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func noJitter(time.Duration) time.Duration { return 0 }
