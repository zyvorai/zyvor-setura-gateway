package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ACME (RFC 8555) client for HTTPS listeners, standard library only.
//
// A listener that has a hostname but no certificateRefs gets its certificate
// from here. The manager owns an account key, orders one certificate per
// hostname, proves control with HTTP-01 (served by the gateway on its plain
// HTTP listeners), TLS-ALPN-01 (served on its HTTPS listeners) or, for
// wildcards, a DNS-01 hook, stores the result in a directory and swaps it into
// the live listeners. Existing connections are never touched: a handshake simply
// starts seeing the new certificate.

const (
	// ACMEStagingURL is the default directory: staging issues untrusted
	// certificates, so a misconfiguration cannot burn production rate limits.
	ACMEStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// ACMEProductionURL is used only with --acme-production.
	ACMEProductionURL = "https://acme-v02.api.letsencrypt.org/directory"

	acmeChallengePrefix = "/.well-known/acme-challenge/"
	acmeALPN            = "acme-tls/1"
)

// ACMEOptions configures the ACME manager.
type ACMEOptions struct {
	Dir          string // account and certificate storage (0700 directories, 0600 files)
	DirectoryURL string // overrides the staging/production choice
	Production   bool   // use the Let's Encrypt production directory
	Email        string // optional account contact
	DNSHook      string // command run as "CMD present|cleanup DOMAIN VALUE" for DNS-01 (wildcards)
	Challenge    string // "", "http-01" or "tls-alpn-01" (preferred non-DNS challenge)

	// Test seams.
	HTTPClient *http.Client
	Now        func() time.Time
	Sleep      func(ctx context.Context, d time.Duration) error
	Jitter     func(max time.Duration) time.Duration
	PollEvery  time.Duration // between authorization/order polls (default 2s)
	Diag       func(format string, a ...any)
}

func (o *ACMEOptions) directory() string {
	switch {
	case o.DirectoryURL != "":
		return o.DirectoryURL
	case o.Production:
		return ACMEProductionURL
	}
	return ACMEStagingURL
}

// acmeError is an RFC 7807 problem document from the CA.
type acmeError struct {
	Status     int
	Type       string
	Detail     string
	RetryAfter time.Duration
}

func (e *acmeError) Error() string {
	t := strings.TrimPrefix(e.Type, "urn:ietf:params:acme:error:")
	if t == "" {
		t = "error"
	}
	return fmt.Sprintf("acme %s (HTTP %d): %s", t, e.Status, e.Detail)
}

func (e *acmeError) is(kind string) bool { return e.Type == "urn:ietf:params:acme:error:"+kind }
func (e *acmeError) rateLimited() bool {
	return e.is("rateLimited") || e.Status == http.StatusTooManyRequests
}

type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

type acmeDir struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type acmeIdent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeOrder struct {
	Status         string       `json:"status"`
	Identifiers    []acmeIdent  `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *acmeProblem `json:"error"`
}

type acmeChallenge struct {
	Type   string       `json:"type"`
	URL    string       `json:"url"`
	Token  string       `json:"token"`
	Status string       `json:"status"`
	Error  *acmeProblem `json:"error"`
}

type acmeAuthz struct {
	Status     string          `json:"status"`
	Identifier acmeIdent       `json:"identifier"`
	Wildcard   bool            `json:"wildcard"`
	Challenges []acmeChallenge `json:"challenges"`
}

// ACMEInfo is the per-domain state shown on the admin /acme endpoint.
type ACMEInfo struct {
	Domain    string `json:"domain"`
	Issued    bool   `json:"issued"`
	NotAfter  string `json:"notAfter,omitempty"`
	RenewAt   string `json:"renewAt,omitempty"`
	LastError string `json:"lastError,omitempty"`
	NextTry   string `json:"nextTry,omitempty"`
	Failures  int    `json:"failures,omitempty"`
}

type acmeDomain struct {
	renewAt  time.Time
	nextTry  time.Time
	fails    int
	lastErr  string
	notAfter time.Time
}

type acmeManager struct {
	o      ACMEOptions
	hc     *http.Client
	key    *ecdsa.PrivateKey
	jwkStr string // canonical JWK, for the thumbprint
	thumb  string

	workMu sync.Mutex // serialises tick and obtain
	mu     sync.Mutex
	dir    *acmeDir
	kid    string
	nonces []string

	certs  atomic.Pointer[map[string]*tls.Certificate] // domain -> certificate
	alpn   sync.Map                                    // domain -> *tls.Certificate (TLS-ALPN-01)
	tokens sync.Map                                    // token -> key authorization (HTTP-01)

	dmu     sync.Mutex
	domains map[string]*acmeDomain
	kick    chan struct{}
	stop    chan struct{}
	started bool
	wg      sync.WaitGroup

	noHTTP    atomic.Bool // the gateway serves no plain HTTP listener, so HTTP-01 cannot work
	onInstall func()      // called after a certificate was swapped in
}

func newACMEManager(o ACMEOptions) (*acmeManager, error) {
	if o.Dir == "" {
		return nil, errors.New("acme: no storage directory (--acme-dir)")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Diag == nil {
		o.Diag = func(string, ...any) {}
	}
	if o.PollEvery <= 0 {
		o.PollEvery = 2 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtxErr
	}
	if o.Jitter == nil {
		o.Jitter = func(max time.Duration) time.Duration {
			if max <= 0 {
				return 0
			}
			return time.Duration(mrand.Int63n(int64(max)))
		}
	}
	switch o.Challenge {
	case "", "http-01", "tls-alpn-01":
	default:
		return nil, fmt.Errorf("acme: --acme-challenge %q: want http-01 or tls-alpn-01", o.Challenge)
	}
	u, err := url.Parse(o.directory())
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("acme: bad directory URL %q", o.directory())
	}
	if u.Scheme != "https" {
		h := u.Hostname()
		if ip := net.ParseIP(h); u.Scheme != "http" || (h != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("acme: directory %q must be https (plain http only on loopback)", o.directory())
		}
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	for _, d := range []string{o.Dir, filepath.Join(o.Dir, "certs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("acme: %w", err)
		}
	}
	os.Chmod(o.Dir, 0o700)
	m := &acmeManager{o: o, hc: o.HTTPClient, domains: map[string]*acmeDomain{}, kick: make(chan struct{}, 1), stop: make(chan struct{})}
	if err := m.loadAccountKey(); err != nil {
		return nil, err
	}
	empty := map[string]*tls.Certificate{}
	m.certs.Store(&empty)
	return m, nil
}

func sleepCtxErr(ctx context.Context, d time.Duration) error {
	if !sleepCtx(ctx, d) {
		return ctx.Err()
	}
	return nil
}

func (m *acmeManager) now() time.Time { return m.o.Now() }

// ---- storage ----

func writeSecretFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *acmeManager) loadAccountKey() error {
	p := filepath.Join(m.o.Dir, "account.key")
	if b, err := os.ReadFile(p); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return fmt.Errorf("acme: %s is not PEM", p)
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return fmt.Errorf("acme: %s: %w", p, err)
		}
		m.setKey(k)
		return nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := writeSecretFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	m.setKey(k)
	return nil
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func (m *acmeManager) setKey(k *ecdsa.PrivateKey) {
	m.key = k
	// Canonical (RFC 7638) member order: crv, kty, x, y.
	m.jwkStr = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(pad32(k.X)), b64(pad32(k.Y)))
	sum := sha256.Sum256([]byte(m.jwkStr))
	m.thumb = b64(sum[:])
}

func (m *acmeManager) kidPath() string {
	sum := sha256.Sum256([]byte(m.o.directory()))
	return filepath.Join(m.o.Dir, fmt.Sprintf("account-%x.json", sum[:4]))
}

func domainDir(root, domain string) string {
	safe := strings.NewReplacer("*", "_wildcard_", "/", "_", "\\", "_", ":", "_").Replace(domain)
	return filepath.Join(root, "certs", safe)
}

func (m *acmeManager) persistCert(domain string, chain, keyPEM []byte) error {
	d := domainDir(m.o.Dir, domain)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if err := writeSecretFile(filepath.Join(d, "key.pem"), keyPEM); err != nil {
		return err
	}
	return writeSecretFile(filepath.Join(d, "fullchain.pem"), chain)
}

func (m *acmeManager) loadCert(domain string) (*tls.Certificate, error) {
	d := domainDir(m.o.Dir, domain)
	chain, err := os.ReadFile(filepath.Join(d, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(d, "key.pem"))
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return nil, err
	}
	if !certNamesDomain(c.Leaf, domain) {
		return nil, fmt.Errorf("stored certificate does not name %s", domain)
	}
	return &c, nil
}

func certNamesDomain(leaf *x509.Certificate, domain string) bool {
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(n, domain) {
			return true
		}
	}
	return false
}

// ---- domains, certificates, scheduling ----

// renewTime is when to renew: two thirds into the lifetime, minus jitter of up
// to one twenty-fourth of the lifetime so a fleet does not renew in lockstep.
func (m *acmeManager) renewTime(leaf *x509.Certificate) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(life * 2 / 3).Add(-m.o.Jitter(life / 24))
}

// ValidACMEDomain explains why a name cannot be ordered, or "".
func (m *acmeManager) domainProblem(domain string) string {
	if strings.HasPrefix(domain, "*.") && m.o.DNSHook == "" {
		return "wildcard hostname " + domain + " needs the DNS-01 challenge: set --acme-dns-hook CMD, or use a Secret"
	}
	if domain == "" || strings.Contains(domain, "*") && !strings.HasPrefix(domain, "*.") {
		return "unusable hostname " + strconv.Quote(domain)
	}
	if ip := net.ParseIP(domain); ip != nil {
		return "ACME cannot issue for the IP address " + domain
	}
	return ""
}

// setDomains replaces the set of names to keep certificates for.
func (m *acmeManager) setDomains(names []string) {
	m.dmu.Lock()
	next := map[string]*acmeDomain{}
	for _, n := range names {
		n = strings.ToLower(n)
		if m.domainProblem(n) != "" {
			continue
		}
		if d := m.domains[n]; d != nil {
			next[n] = d
			continue
		}
		d := &acmeDomain{}
		if c, err := m.loadCert(n); err == nil && m.now().Before(c.Leaf.NotAfter) {
			m.install(n, c)
			d.renewAt, d.notAfter = m.renewTime(c.Leaf), c.Leaf.NotAfter
		}
		next[n] = d
	}
	m.domains = next
	m.dmu.Unlock()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *acmeManager) install(domain string, c *tls.Certificate) {
	for {
		old := m.certs.Load()
		cp := make(map[string]*tls.Certificate, len(*old)+1)
		for k, v := range *old {
			cp[k] = v
		}
		cp[domain] = c
		if m.certs.CompareAndSwap(old, &cp) {
			return
		}
	}
}

// cert returns the certificate for an SNI name: exact, then the wildcard.
func (m *acmeManager) cert(sni string) *tls.Certificate {
	if m == nil {
		return nil
	}
	sni = strings.ToLower(sni)
	cs := *m.certs.Load()
	if c := cs[sni]; c != nil {
		return c
	}
	if i := strings.IndexByte(sni, '.'); i > 0 {
		return cs["*"+sni[i:]]
	}
	return nil
}

// allCerts lists the installed certificates (for OCSP stapling).
func (m *acmeManager) allCerts() []tls.Certificate {
	if m == nil {
		return nil
	}
	var out []tls.Certificate
	for _, c := range *m.certs.Load() {
		out = append(out, *c)
	}
	return out
}

// challengeCert is the TLS-ALPN-01 certificate being validated for sni.
func (m *acmeManager) challengeCert(sni string) *tls.Certificate {
	if m == nil {
		return nil
	}
	if v, ok := m.alpn.Load(strings.ToLower(sni)); ok {
		return v.(*tls.Certificate)
	}
	return nil
}

var acmeTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)

// serveHTTP01 answers /.well-known/acme-challenge/TOKEN.
func (m *acmeManager) serveHTTP01(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.URL.Path, acmeChallengePrefix)
	if r.Method != http.MethodGet && r.Method != http.MethodHead || !acmeTokenRE.MatchString(tok) {
		http.NotFound(w, r)
		return
	}
	v, ok := m.tokens.Load(tok)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	io.WriteString(w, v.(string))
}

// Info reports the state of every managed domain.
func (m *acmeManager) Info() []ACMEInfo {
	if m == nil {
		return nil
	}
	m.dmu.Lock()
	defer m.dmu.Unlock()
	var out []ACMEInfo
	for n, d := range m.domains {
		i := ACMEInfo{Domain: n, LastError: d.lastErr, Failures: d.fails}
		if !d.notAfter.IsZero() {
			i.Issued, i.NotAfter, i.RenewAt = true, d.notAfter.UTC().Format(time.RFC3339), d.renewAt.UTC().Format(time.RFC3339)
		}
		if d.fails > 0 {
			i.NextTry = d.nextTry.UTC().Format(time.RFC3339)
		}
		out = append(out, i)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// tick orders or renews every domain that is due and returns how long until
// the next one is. It is the whole scheduler; run only adds a timer.
func (m *acmeManager) tick(ctx context.Context) time.Duration {
	m.workMu.Lock()
	defer m.workMu.Unlock()
	m.dmu.Lock()
	names := make([]string, 0, len(m.domains))
	for n := range m.domains {
		names = append(names, n)
	}
	m.dmu.Unlock()
	sort.Strings(names)
	var next time.Duration = 12 * time.Hour
	for _, n := range names {
		if ctx.Err() != nil {
			return next
		}
		m.dmu.Lock()
		d := m.domains[n]
		if d == nil {
			m.dmu.Unlock()
			continue
		}
		now := m.now()
		due := d.renewAt.IsZero() || !now.Before(d.renewAt)
		wait := time.Duration(0)
		switch {
		case !due:
			wait = d.renewAt.Sub(now)
		case now.Before(d.nextTry):
			wait = d.nextTry.Sub(now)
			due = false
		}
		m.dmu.Unlock()
		if !due {
			next = min(next, wait)
			continue
		}
		err := m.obtain(ctx, n)
		m.dmu.Lock()
		if err != nil {
			d.fails++
			d.lastErr = err.Error()
			back := m.backoff(d.fails, err)
			d.nextTry = m.now().Add(back)
			next = min(next, back)
			m.o.Diag("acme: %s: %v (retrying in %s)", n, err, back.Round(time.Second))
		} else {
			d.fails, d.lastErr = 0, ""
			next = min(next, max(d.renewAt.Sub(m.now()), time.Second))
		}
		m.dmu.Unlock()
	}
	return max(next, time.Second)
}

// backoff is exponential (1m doubling to 6h) with jitter, and at least as long
// as a rate-limit answer's Retry-After (an hour when it gave none).
func (m *acmeManager) backoff(fails int, err error) time.Duration {
	d := time.Minute << min(fails-1, 10)
	d = min(d, 6*time.Hour)
	d += m.o.Jitter(d / 4)
	var ae *acmeError
	if errors.As(err, &ae) && ae.rateLimited() {
		ra := ae.RetryAfter
		if ra <= 0 {
			ra = time.Hour
		}
		d = max(d, ra)
	}
	return d
}

func (m *acmeManager) start() {
	m.dmu.Lock()
	if m.started {
		m.dmu.Unlock()
		return
	}
	m.started = true
	m.dmu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-m.stop; cancel() }()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			d := m.tick(ctx)
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-m.kick:
				t.Stop()
			case <-t.C:
			}
		}
	}()
}

func (m *acmeManager) close() {
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

// ---- protocol ----

func (m *acmeManager) directory(ctx context.Context) (*acmeDir, error) {
	m.mu.Lock()
	d := m.dir
	m.mu.Unlock()
	if d != nil {
		return d, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.o.directory(), nil)
	resp, err := m.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, m.problem(resp, body)
	}
	d = &acmeDir{}
	if err := json.Unmarshal(body, d); err != nil || d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return nil, errors.New("acme: directory is missing newNonce, newAccount or newOrder")
	}
	m.mu.Lock()
	m.dir = d
	m.mu.Unlock()
	return d, nil
}

func (m *acmeManager) retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(m.now()), 0)
	}
	return 0
}

func (m *acmeManager) problem(resp *http.Response, body []byte) *acmeError {
	e := &acmeError{Status: resp.StatusCode, RetryAfter: m.retryAfter(resp)}
	var p acmeProblem
	if json.Unmarshal(body, &p) == nil && p.Type != "" {
		e.Type, e.Detail = p.Type, p.Detail
	} else {
		e.Detail = strings.TrimSpace(string(body))
		if len(e.Detail) > 200 {
			e.Detail = e.Detail[:200]
		}
	}
	return e
}

func (m *acmeManager) takeNonce(ctx context.Context, d *acmeDir) (string, error) {
	m.mu.Lock()
	if n := len(m.nonces); n > 0 {
		v := m.nonces[n-1]
		m.nonces = m.nonces[:n-1]
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.NewNonce, nil)
	resp, err := m.hc.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		return n, nil
	}
	return "", errors.New("acme: newNonce returned no Replay-Nonce")
}

func (m *acmeManager) saveNonce(resp *http.Response) {
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		m.mu.Lock()
		if len(m.nonces) < 16 {
			m.nonces = append(m.nonces, n)
		}
		m.mu.Unlock()
	}
}

func (m *acmeManager) sign(protected map[string]any, payload []byte) ([]byte, error) {
	pb, _ := json.Marshal(protected)
	signing := b64(pb) + "." + b64(payload)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, m.key, h[:])
	if err != nil {
		return nil, err
	}
	sig := append(pad32(r), pad32(s)...)
	return json.Marshal(map[string]string{"protected": b64(pb), "payload": b64(payload), "signature": b64(sig)})
}

// post sends a signed request. payload nil means POST-as-GET (empty payload).
// A badNonce answer is retried with the fresh nonce it carries.
func (m *acmeManager) post(ctx context.Context, u string, payload any, newAccount bool) (*http.Response, []byte, error) {
	d, err := m.directory(ctx)
	if err != nil {
		return nil, nil, err
	}
	var pl []byte
	if payload != nil {
		if pl, err = json.Marshal(payload); err != nil {
			return nil, nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		nonce, err := m.takeNonce(ctx, d)
		if err != nil {
			return nil, nil, err
		}
		prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": u}
		if newAccount {
			prot["jwk"] = json.RawMessage(m.jwkStr)
		} else {
			m.mu.Lock()
			kid := m.kid
			m.mu.Unlock()
			if kid == "" {
				return nil, nil, errors.New("acme: no account")
			}
			prot["kid"] = kid
		}
		body, err := m.sign(prot, pl)
		if err != nil {
			return nil, nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := m.hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		m.saveNonce(resp)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, rb, nil
		}
		pe := m.problem(resp, rb)
		if pe.is("badNonce") && attempt < 3 {
			continue
		}
		return resp, rb, pe
	}
}

func (m *acmeManager) ensureAccount(ctx context.Context) error {
	m.mu.Lock()
	kid := m.kid
	m.mu.Unlock()
	if kid != "" {
		return nil
	}
	if b, err := os.ReadFile(m.kidPath()); err == nil {
		var v struct {
			KID string `json:"kid"`
		}
		if json.Unmarshal(b, &v) == nil && v.KID != "" {
			m.mu.Lock()
			m.kid = v.KID
			m.mu.Unlock()
			return nil
		}
	}
	d, err := m.directory(ctx)
	if err != nil {
		return err
	}
	pl := map[string]any{"termsOfServiceAgreed": true}
	if m.o.Email != "" {
		pl["contact"] = []string{"mailto:" + m.o.Email}
	}
	resp, _, err := m.post(ctx, d.NewAccount, pl, true)
	if err != nil {
		return fmt.Errorf("new account: %w", err)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return errors.New("acme: new account returned no Location")
	}
	m.mu.Lock()
	m.kid = loc
	m.mu.Unlock()
	b, _ := json.Marshal(map[string]string{"kid": loc, "directory": m.o.directory()})
	return writeSecretFile(m.kidPath(), b)
}

func (m *acmeManager) forgetAccount() {
	m.mu.Lock()
	m.kid = ""
	m.mu.Unlock()
	os.Remove(m.kidPath())
}

func (m *acmeManager) keyAuth(token string) string { return token + "." + m.thumb }

// obtain runs one full order for domain and installs the result.
func (m *acmeManager) obtain(ctx context.Context, domain string) error {
	err := m.obtainOnce(ctx, domain)
	var ae *acmeError
	if errors.As(err, &ae) && ae.is("accountDoesNotExist") {
		m.forgetAccount()
		err = m.obtainOnce(ctx, domain)
	}
	return err
}

func (m *acmeManager) obtainOnce(ctx context.Context, domain string) error {
	if p := m.domainProblem(domain); p != "" {
		return errors.New(p)
	}
	if err := m.ensureAccount(ctx); err != nil {
		return err
	}
	d, err := m.directory(ctx)
	if err != nil {
		return err
	}
	resp, body, err := m.post(ctx, d.NewOrder, map[string]any{"identifiers": []acmeIdent{{Type: "dns", Value: domain}}}, false)
	if err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	orderURL := resp.Header.Get("Location")
	var ord acmeOrder
	if err := json.Unmarshal(body, &ord); err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	if ord.Status == "invalid" {
		return fmt.Errorf("order invalid: %s", problemText(ord.Error))
	}
	for _, az := range ord.Authorizations {
		if err := m.authorize(ctx, az, domain); err != nil {
			return err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}, key)
	if err != nil {
		return err
	}
	_, body, err = m.post(ctx, ord.Finalize, map[string]string{"csr": b64(csr)}, false)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	if err := json.Unmarshal(body, &ord); err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	for tries := 0; ord.Status != "valid"; tries++ {
		if ord.Status == "invalid" {
			return fmt.Errorf("order invalid: %s", problemText(ord.Error))
		}
		if tries > 60 {
			return errors.New("order did not become valid in time")
		}
		if orderURL == "" {
			return errors.New("order has no URL to poll")
		}
		if err := m.o.Sleep(ctx, m.pollDelay(resp)); err != nil {
			return err
		}
		if resp, body, err = m.post(ctx, orderURL, nil, false); err != nil {
			return fmt.Errorf("poll order: %w", err)
		}
		if err := json.Unmarshal(body, &ord); err != nil {
			return err
		}
	}
	if ord.Certificate == "" {
		return errors.New("valid order has no certificate URL")
	}
	_, chain, err := m.post(ctx, ord.Certificate, nil, false)
	if err != nil {
		return fmt.Errorf("download certificate: %w", err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	c, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("issued certificate does not match our key: %w", err)
	}
	if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
		return err
	}
	if !certNamesDomain(c.Leaf, domain) {
		return fmt.Errorf("issued certificate does not name %s", domain)
	}
	if err := m.persistCert(domain, chain, keyPEM); err != nil {
		return fmt.Errorf("storing certificate: %w", err)
	}
	m.install(domain, &c)
	m.dmu.Lock()
	if dd := m.domains[domain]; dd != nil {
		dd.renewAt, dd.notAfter = m.renewTime(c.Leaf), c.Leaf.NotAfter
	}
	m.dmu.Unlock()
	m.o.Diag("acme: certificate for %s installed (expires %s)", domain, c.Leaf.NotAfter.UTC().Format(time.RFC3339))
	if m.onInstall != nil {
		m.onInstall()
	}
	return nil
}

func problemText(p *acmeProblem) string {
	if p == nil {
		return "no detail"
	}
	return strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:") + ": " + p.Detail
}

func (m *acmeManager) pollDelay(resp *http.Response) time.Duration {
	if resp != nil {
		if ra := m.retryAfter(resp); ra > 0 {
			return min(ra, time.Minute)
		}
	}
	return m.o.PollEvery
}

// challengeOrder lists the challenge types to try, best first.
func (m *acmeManager) challengeOrder(wildcard bool) []string {
	if wildcard {
		return []string{"dns-01"}
	}
	var out []string
	pref := m.o.Challenge
	if pref == "" {
		pref = "tls-alpn-01"
		if !m.noHTTP.Load() {
			pref = "http-01"
		}
	}
	out = append(out, pref)
	for _, t := range []string{"http-01", "tls-alpn-01"} {
		if t != pref && m.o.Challenge == "" {
			out = append(out, t)
		}
	}
	if m.o.DNSHook != "" {
		out = append(out, "dns-01")
	}
	return out
}

func (m *acmeManager) authorize(ctx context.Context, azURL, domain string) error {
	resp, body, err := m.post(ctx, azURL, nil, false)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	var az acmeAuthz
	if err := json.Unmarshal(body, &az); err != nil {
		return err
	}
	if az.Status == "valid" {
		return nil
	}
	if az.Status != "pending" {
		return fmt.Errorf("authorization for %s is %s", domain, az.Status)
	}
	wildcard := az.Wildcard || strings.HasPrefix(domain, "*.")
	var ch *acmeChallenge
	for _, typ := range m.challengeOrder(wildcard) {
		for i := range az.Challenges {
			if az.Challenges[i].Type == typ {
				ch = &az.Challenges[i]
				break
			}
		}
		if ch != nil {
			break
		}
	}
	if ch == nil {
		return fmt.Errorf("none of the challenges offered for %s can be answered (wanted %s)", domain, strings.Join(m.challengeOrder(wildcard), ", "))
	}
	host := strings.TrimPrefix(domain, "*.")
	ka := m.keyAuth(ch.Token)
	cleanup, err := m.provision(ctx, ch.Type, host, ch.Token, ka)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, _, err := m.post(ctx, ch.URL, map[string]string{}, false); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	for tries := 0; ; tries++ {
		if err := m.o.Sleep(ctx, m.pollDelay(resp)); err != nil {
			return err
		}
		if resp, body, err = m.post(ctx, azURL, nil, false); err != nil {
			return fmt.Errorf("poll authorization: %w", err)
		}
		az = acmeAuthz{}
		if err := json.Unmarshal(body, &az); err != nil {
			return err
		}
		switch az.Status {
		case "valid":
			return nil
		case "invalid":
			for _, c := range az.Challenges {
				if c.Error != nil {
					return fmt.Errorf("%s validation failed for %s: %s", c.Type, domain, problemText(c.Error))
				}
			}
			return fmt.Errorf("authorization for %s is invalid", domain)
		}
		if tries > 60 {
			return fmt.Errorf("authorization for %s stayed %s", domain, az.Status)
		}
	}
}

// provision makes the challenge answerable and returns the cleanup.
func (m *acmeManager) provision(ctx context.Context, typ, host, token, ka string) (func(), error) {
	switch typ {
	case "http-01":
		m.tokens.Store(token, ka)
		return func() { m.tokens.Delete(token) }, nil
	case "tls-alpn-01":
		c, err := alpnChallengeCert(host, ka)
		if err != nil {
			return nil, err
		}
		m.alpn.Store(strings.ToLower(host), c)
		return func() { m.alpn.Delete(strings.ToLower(host)) }, nil
	case "dns-01":
		sum := sha256.Sum256([]byte(ka))
		val := b64(sum[:])
		run := func(verb string) error {
			cmd := exec.CommandContext(ctx, m.o.DNSHook, verb, host, val)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("dns hook %s: %v: %s", verb, err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		if err := run("present"); err != nil {
			return nil, err
		}
		return func() {
			if err := run("cleanup"); err != nil {
				m.o.Diag("acme: %v", err)
			}
		}, nil
	}
	return nil, fmt.Errorf("unsupported challenge %s", typ)
}

var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// alpnChallengeCert builds the TLS-ALPN-01 validation certificate (RFC 8737).
func alpnChallengeCert(host, keyAuth string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	val, err := asn1.Marshal(sum[:])
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidACMEIdentifier, Critical: true, Value: val}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ---- server wiring ----

// acmeHello is the GetCertificate of every HTTPS listener: ALPN validation
// handshakes get the challenge certificate, everything else the normal choice.
func (s *Server) acmeHello(spec int, h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.acme != nil {
		for _, p := range h.SupportedProtos {
			if p == acmeALPN {
				if c := s.acme.challengeCert(h.ServerName); c != nil {
					return c, nil
				}
				return nil, errors.New("no pending ACME challenge for " + h.ServerName)
			}
		}
	}
	return s.certFor(spec, h.ServerName)
}

// httpProtos are the ALPN protocols of HTTPS listeners.
func (s *Server) httpProtos() []string {
	if s.acme != nil {
		return []string{"h2", "http/1.1", acmeALPN}
	}
	return []string{"h2", "http/1.1"}
}

// acmeSync tells the manager which hostnames the applied table needs.
func (s *Server) acmeSync(t *Table) {
	if s.acme == nil {
		return
	}
	var names []string
	plain := false
	for _, l := range t.Listeners {
		if !l.Serving {
			continue
		}
		if l.L.Protocol == "HTTP" {
			plain = true
		}
		if l.ACME {
			names = append(names, l.Host)
		}
	}
	s.acme.noHTTP.Store(!plain)
	s.acme.setDomains(names)
	if len(names) > 0 {
		s.acme.start()
	}
}

// ACMEInfo lists the ACME managed domains (nil without ACME).
func (s *Server) ACMEInfo() []ACMEInfo { return s.acme.Info() }
