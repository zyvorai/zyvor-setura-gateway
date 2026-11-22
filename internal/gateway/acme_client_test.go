package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers ----

func newTestMgr(t *testing.T, f *fakeACME, clk *acmeClock, dir string, mod func(*ACMEOptions)) *acmeManager {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	o := ACMEOptions{Dir: dir, DirectoryURL: f.dirURL(), HTTPClient: f.srv.Client(), Now: clk.Now, Sleep: noSleep, Jitter: noJitter}
	if mod != nil {
		mod(&o)
	}
	m, err := newACMEManager(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.close)
	return m
}

// validateHTTP01 answers the CA's HTTP-01 fetch against base (a URL serving serveHTTP01 or a gateway).
func validateHTTP01(base string) func(typ, domain, token, ka string) error {
	return func(typ, domain, token, ka string) error {
		if typ != "http-01" {
			return fmt.Errorf("unexpected challenge type %s", typ)
		}
		req, _ := http.NewRequest("GET", base+acmeChallengePrefix+token, nil)
		req.Host = domain
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(b) != ka {
			return fmt.Errorf("http-01: got %d %q, want the key authorization", resp.StatusCode, b)
		}
		return nil
	}
}

// validateALPN performs a TLS-ALPN-01 validation handshake against addr.
func validateALPN(addr string) func(typ, domain, token, ka string) error {
	return func(typ, domain, token, ka string) error {
		if typ != "tls-alpn-01" {
			return fmt.Errorf("unexpected challenge type %s", typ)
		}
		c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: domain, NextProtos: []string{acmeALPN}, InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		defer c.Close()
		st := c.ConnectionState()
		if st.NegotiatedProtocol != acmeALPN {
			return fmt.Errorf("negotiated %q, want %s", st.NegotiatedProtocol, acmeALPN)
		}
		leaf := st.PeerCertificates[0]
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
			return fmt.Errorf("challenge certificate names %v", leaf.DNSNames)
		}
		for _, e := range leaf.Extensions {
			if e.Id.Equal(oidACMEIdentifier) {
				var got []byte
				if _, err := asn1.Unmarshal(e.Value, &got); err != nil {
					return err
				}
				want := sha256.Sum256([]byte(ka))
				if !e.Critical || string(got) != string(want[:]) {
					return errors.New("acmeIdentifier extension is wrong")
				}
				return nil
			}
		}
		return errors.New("no acmeIdentifier extension")
	}
}

func certSerial(c *tls.Certificate) string { return c.Leaf.SerialNumber.String() }

// ---- protocol tests (no gateway) ----

func TestACMEIssueHTTP01AndStorage(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	dir := t.TempDir()
	m := newTestMgr(t, f, clk, dir, func(o *ACMEOptions) { o.Email = "ops@example.test" })
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)

	m.setDomains([]string{"app.example.test"})
	m.tick(context.Background())
	c := m.cert("app.example.test")
	if c == nil {
		t.Fatalf("no certificate installed: %+v", m.Info())
	}
	if !certNamesDomain(c.Leaf, "app.example.test") {
		t.Fatalf("certificate names %v", c.Leaf.DNSNames)
	}
	if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: f.pool, DNSName: "app.example.test", CurrentTime: clk.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("issued chain does not verify: %v", err)
	}
	for _, k := range []string{"POST acct", "POST order", "POST authz", "POST chall", "POST finalize", "POST cert"} {
		if f.count(k) == 0 {
			t.Errorf("the client never made a %q request", k)
		}
	}
	if n := f.count("POST acct"); n != 1 {
		t.Errorf("new-account requests = %d", n)
	}
	if f.nonceReuse != 0 {
		t.Errorf("client reused a nonce %d times", f.nonceReuse)
	}
	if _, ok := m.tokens.Load("anything"); ok {
		t.Error("challenge tokens must be cleaned up")
	}

	// Everything on disk is private: 0600 files in 0700 directories.
	var files []string
	filepath.Walk(dir, func(p string, st os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		perm := st.Mode().Perm()
		if st.IsDir() && perm != 0o700 {
			t.Errorf("%s mode %o, want 0700", p, perm)
		}
		if !st.IsDir() {
			files = append(files, filepath.Base(p))
			if perm != 0o600 {
				t.Errorf("%s mode %o, want 0600", p, perm)
			}
		}
		return nil
	})
	joined := strings.Join(files, " ")
	for _, want := range []string{"account.key", "key.pem", "fullchain.pem"} {
		if !strings.Contains(joined, want) {
			t.Errorf("stored files %q lack %s", joined, want)
		}
	}

	// A restart reuses the account and the stored certificate: no new order.
	m2 := newTestMgr(t, f, clk, dir, nil)
	m2.setDomains([]string{"app.example.test"})
	if c2 := m2.cert("app.example.test"); c2 == nil || certSerial(c2) != certSerial(c) {
		t.Fatal("the stored certificate was not loaded at start")
	}
	m2.tick(context.Background())
	if f.count("orders-made") != 1 || f.count("POST acct") != 1 {
		t.Errorf("restart ordered again: orders %d, accounts %d", f.count("orders-made"), f.count("POST acct"))
	}
}

func TestACMETLSALPN01(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", func(o *ACMEOptions) { o.Challenge = "tls-alpn-01" })
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{NextProtos: []string{acmeALPN}, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c := m.challengeCert(h.ServerName); c != nil {
			return c, nil
		}
		return nil, errors.New("no challenge")
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.validate = validateALPN(srv.Listener.Addr().String())
	m.setDomains([]string{"alpn.example.test"})
	m.tick(context.Background())
	if m.cert("alpn.example.test") == nil {
		t.Fatalf("no certificate: %+v", m.Info())
	}
	if m.challengeCert("alpn.example.test") != nil {
		t.Error("the challenge certificate must be removed after validation")
	}
}

func TestACMEWildcardNeedsDNSHook(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	if p := m.domainProblem("*.wild.example.test"); !strings.Contains(p, "--acme-dns-hook") || !strings.Contains(p, "DNS-01") {
		t.Errorf("wildcard without a hook says %q", p)
	}
	m.setDomains([]string{"*.wild.example.test"})
	m.tick(context.Background())
	if f.count("orders-made") != 0 || len(m.Info()) != 0 {
		t.Error("a wildcard without a DNS hook must not be ordered")
	}
	if p := m.domainProblem("1.2.3.4"); !strings.Contains(p, "IP") {
		t.Errorf("IP address says %q", p)
	}
}

func TestACMEWildcardDNS01Hook(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	hookDir := t.TempDir()
	hook := filepath.Join(hookDir, "hook.sh")
	script := "#!/bin/sh\ncd \"$(dirname \"$0\")\"\necho \"$1 $2\" >> calls\ncase \"$1\" in present) printf %s \"$3\" > txt ;; cleanup) rm -f txt ;; esac\n"
	if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := newTestMgr(t, f, clk, "", func(o *ACMEOptions) { o.DNSHook = hook })
	f.validate = func(typ, domain, token, ka string) error {
		if typ != "dns-01" {
			return fmt.Errorf("challenge %s, want dns-01 for a wildcard", typ)
		}
		got, err := os.ReadFile(filepath.Join(hookDir, "txt"))
		if err != nil {
			return fmt.Errorf("TXT record not published: %v", err)
		}
		sum := sha256.Sum256([]byte(ka))
		if string(got) != b64(sum[:]) {
			return fmt.Errorf("TXT %q is wrong", got)
		}
		return nil
	}
	m.setDomains([]string{"*.wild.example.test"})
	m.tick(context.Background())
	c := m.cert("anything.wild.example.test")
	if c == nil {
		t.Fatalf("wildcard certificate not issued: %+v", m.Info())
	}
	if c.Leaf.DNSNames[0] != "*.wild.example.test" {
		t.Errorf("names %v", c.Leaf.DNSNames)
	}
	if m.cert("wild.example.test") != nil {
		t.Error("the wildcard must not cover the apex")
	}
	calls, _ := os.ReadFile(filepath.Join(hookDir, "calls"))
	if string(calls) != "present wild.example.test\ncleanup wild.example.test\n" {
		t.Errorf("hook calls = %q", calls)
	}
	if _, err := os.Stat(filepath.Join(hookDir, "txt")); err == nil {
		t.Error("the TXT record was not cleaned up")
	}
}

func TestACMERenewalAtTwoThirdsWithJitter(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)
	m.setDomains([]string{"r.example.test"})

	wait := m.tick(context.Background())
	first := m.cert("r.example.test")
	if first == nil {
		t.Fatalf("not issued: %+v", m.Info())
	}
	if want := 12 * time.Hour; wait != want {
		t.Errorf("next wake in %v, want the 12h safety cap", wait)
	}
	if got, want := m.Info()[0].RenewAt, clk.Now().Add(60*24*time.Hour).UTC().Format(time.RFC3339); got != want {
		t.Errorf("renewAt = %s, want %s (two thirds of 90 days)", got, want)
	}
	clk.Advance(59 * 24 * time.Hour)
	m.tick(context.Background())
	if f.count("orders-made") != 1 {
		t.Fatal("renewed before two thirds of the lifetime")
	}
	clk.Advance(24*time.Hour + time.Second)
	m.tick(context.Background())
	second := m.cert("r.example.test")
	if f.count("orders-made") != 2 || second == nil || certSerial(second) == certSerial(first) {
		t.Fatalf("not renewed at two thirds: orders %d", f.count("orders-made"))
	}
	if got := f.issuedSerials(); len(got) != 2 {
		t.Errorf("issued %v", got)
	}

	// The jitter moves the renewal earlier, by at most a 24th of the lifetime.
	life := first.Leaf.NotAfter.Sub(first.Leaf.NotBefore)
	m.o.Jitter = func(max time.Duration) time.Duration {
		if max != life/24 {
			t.Errorf("jitter ceiling %v, want %v", max, life/24)
		}
		return max
	}
	if got, want := m.renewTime(first.Leaf), first.Leaf.NotBefore.Add(life*2/3-life/24); !got.Equal(want) {
		t.Errorf("renewTime = %v, want %v", got, want)
	}
}

func TestACMEErrorsBackOffAndRecover(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)
	f.failOrder = func(n int) *fakeProblem {
		if n == 1 {
			return &fakeProblem{Status: 500, Type: "urn:ietf:params:acme:error:serverInternal", Detail: "database is on fire"}
		}
		return nil
	}
	m.setDomains([]string{"e.example.test"})
	wait := m.tick(context.Background())
	info := m.Info()[0]
	if info.Issued || info.Failures != 1 || !strings.Contains(info.LastError, "database is on fire") || !strings.Contains(info.LastError, "serverInternal") {
		t.Fatalf("error not recorded: %+v", info)
	}
	if wait != time.Minute {
		t.Errorf("first retry in %v, want 1m", wait)
	}
	m.tick(context.Background())
	if f.count("orders-made") != 1 {
		t.Fatal("retried before the backoff elapsed")
	}
	clk.Advance(time.Minute + time.Second)
	m.tick(context.Background())
	if m.cert("e.example.test") == nil {
		t.Fatalf("did not recover: %+v", m.Info())
	}
	if i := m.Info()[0]; i.Failures != 0 || i.LastError != "" {
		t.Errorf("failure state not cleared: %+v", i)
	}
}

func TestACMERateLimitHonoursRetryAfter(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)
	f.failOrder = func(n int) *fakeProblem {
		if n == 1 {
			return &fakeProblem{Status: 429, Type: "urn:ietf:params:acme:error:rateLimited", Detail: "too many certificates already issued", RetryAfter: "7200"}
		}
		return nil
	}
	m.setDomains([]string{"limited.example.test"})
	if wait := m.tick(context.Background()); wait < 2*time.Hour {
		t.Fatalf("retry scheduled in %v, want at least the 2h Retry-After", wait)
	}
	clk.Advance(119 * time.Minute)
	m.tick(context.Background())
	if f.count("orders-made") != 1 {
		t.Fatal("retried inside the Retry-After window")
	}
	clk.Advance(2 * time.Minute)
	m.tick(context.Background())
	if m.cert("limited.example.test") == nil {
		t.Fatalf("not issued after the window: %+v", m.Info())
	}

	// With no Retry-After a rate limit still waits an hour.
	if d := m.backoff(1, &acmeError{Status: 429, Type: "urn:ietf:params:acme:error:rateLimited"}); d != time.Hour {
		t.Errorf("rate limit without Retry-After backs off %v, want 1h", d)
	}
	if d := m.backoff(20, errors.New("x")); d != 6*time.Hour {
		t.Errorf("backoff cap = %v, want 6h", d)
	}
}

func TestACMEFailedChallengeReportsCAReason(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	f.validate = func(string, string, string, string) error { return errors.New("connection refused from the validator") }
	m.setDomains([]string{"bad.example.test"})
	m.tick(context.Background())
	i := m.Info()[0]
	if i.Issued || !strings.Contains(i.LastError, "http-01 validation failed") || !strings.Contains(i.LastError, "connection refused from the validator") {
		t.Fatalf("CA reason not surfaced: %+v", i)
	}
	if f.count("POST finalize") != 0 {
		t.Error("finalized an order whose authorization failed")
	}
	if _, ok := m.tokens.Load("x"); ok {
		t.Error("token leaked")
	}
}

func TestACMEReplayNonceHandling(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)
	f.badNonces = 3 // three signed requests are answered badNonce; the client must retry with the fresh nonce
	m.setDomains([]string{"n.example.test"})
	m.tick(context.Background())
	if m.cert("n.example.test") == nil {
		t.Fatalf("badNonce was not retried: %+v", m.Info())
	}
	if f.nonceReuse != 0 {
		t.Errorf("nonce reused %d times", f.nonceReuse)
	}
	// Nonces come from the Replay-Nonce of previous answers: one HEAD to
	// newNonce is enough for the whole order, not one per request.
	if heads := f.count("HEAD nonce"); heads > 2 {
		t.Errorf("%d newNonce requests, want the pool to be reused", heads)
	}
}

func TestACMEAccountDoesNotExistReregisters(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	m := newTestMgr(t, f, clk, "", nil)
	gw := httptest.NewServer(http.HandlerFunc(m.serveHTTP01))
	t.Cleanup(gw.Close)
	f.validate = validateHTTP01(gw.URL)
	m.setDomains([]string{"acct.example.test"})
	m.tick(context.Background())
	f.mu.Lock()
	f.forgetAccounts = true
	f.mu.Unlock()
	clk.Advance(61 * 24 * time.Hour)
	m.tick(context.Background())
	if f.count("accounts-made") != 2 {
		t.Fatalf("accounts made = %d, want the client to register again", f.count("accounts-made"))
	}
	if len(f.issuedSerials()) != 2 || m.Info()[0].LastError != "" {
		t.Errorf("renewal after re-registration failed: %+v", m.Info())
	}
}

func TestACMEDirectorySelectionAndSafety(t *testing.T) {
	if got := (&ACMEOptions{}).directory(); got != ACMEStagingURL || !strings.Contains(got, "staging") {
		t.Errorf("default directory %q must be staging", got)
	}
	if got := (&ACMEOptions{Production: true}).directory(); got != ACMEProductionURL || strings.Contains(got, "staging") {
		t.Errorf("--acme-production directory %q", got)
	}
	if got := (&ACMEOptions{Production: true, DirectoryURL: "https://x.test/d"}).directory(); got != "https://x.test/d" {
		t.Errorf("explicit directory must win, got %q", got)
	}
	dir := t.TempDir()
	if _, err := newACMEManager(ACMEOptions{Dir: dir, DirectoryURL: "http://acme.example.com/dir"}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain http to a remote CA must be refused, got %v", err)
	}
	if _, err := newACMEManager(ACMEOptions{Dir: dir, DirectoryURL: "http://127.0.0.1:1/dir"}); err != nil {
		t.Errorf("loopback http is allowed for tests: %v", err)
	}
	if _, err := newACMEManager(ACMEOptions{DirectoryURL: "https://x.test/d"}); err == nil {
		t.Error("a missing storage directory must be refused")
	}
	if _, err := newACMEManager(ACMEOptions{Dir: dir, Challenge: "dns-99"}); err == nil {
		t.Error("an unknown challenge must be refused")
	}
	m := newTestMgr(t, newFakeACME(t, newACMEClock()), newACMEClock(), "", nil)
	if got := m.challengeOrder(true); len(got) != 1 || got[0] != "dns-01" {
		t.Errorf("wildcard challenges %v", got)
	}
	if got := m.challengeOrder(false); got[0] != "http-01" {
		t.Errorf("auto challenge order %v", got)
	}
	m.noHTTP.Store(true)
	if got := m.challengeOrder(false); got[0] != "tls-alpn-01" {
		t.Errorf("without an HTTP listener the first choice is %v", got)
	}
}

// ---- gateway integration ----

type acmeGW struct {
	s    *Server
	f    *fakeACME
	clk  *acmeClock
	addr atomic.Pointer[Server]
}

// startACMEGateway serves an HTTP listener (8080) and an HTTPS listener (8443)
// whose hostname has no certificateRefs, with ACME against the fake CA.
func startACMEGateway(t *testing.T, challenge, dir string) *acmeGW {
	t.Helper()
	g := &acmeGW{clk: newACMEClock()}
	g.f = newFakeACME(t, g.clk)
	wait := func() *Server {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if s := g.addr.Load(); s != nil {
				return s
			}
		}
		return nil
	}
	g.f.validate = func(typ, domain, token, ka string) error {
		s := wait()
		if s == nil {
			return errors.New("gateway not up")
		}
		switch typ {
		case "http-01":
			return validateHTTP01("http://"+s.Addr(8080))("http-01", domain, token, ka)
		case "tls-alpn-01":
			return validateALPN(s.Addr(8443))(typ, domain, token, ka)
		}
		return errors.New("unexpected " + typ)
	}
	be, _ := upstreams(t, "a")
	gwSpec := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080},
		m{"name": "secure", "protocol": "HTTPS", "port": 8443, "hostname": "app.acme.test", "tls": m{"mode": "Terminate"}},
	}}
	raw := snap(gwSpec, map[string]m{"r": route("", rule("/", ref("a", 1)))}, be)
	if dir == "" {
		dir = t.TempDir()
	}
	g.s = startServer(t, raw, func(o *Options) {
		o.Cert.ACME = &ACMEOptions{Dir: dir, DirectoryURL: g.f.dirURL(), HTTPClient: g.f.srv.Client(), Now: g.clk.Now, Sleep: noSleep, Jitter: noJitter, Challenge: challenge}
	})
	g.addr.Store(g.s)
	return g
}

func (g *acmeGW) waitCert(t *testing.T, domain string) *tls.Certificate {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if c := g.s.acme.cert(domain); c != nil {
			return c
		}
	}
	t.Fatalf("no certificate for %s: %+v", domain, g.s.ACMEInfo())
	return nil
}

func (g *acmeGW) client(host string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: g.f.pool, ServerName: host, Time: g.clk.Now},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, g.s.Addr(8443))
		}}}
}

// fetch GETs https://host/ and reports the serving certificate and whether the connection was reused.
func fetch(t *testing.T, c *http.Client, host string) (serial string, reused bool, body string) {
	t.Helper()
	var info httptrace.GotConnInfo
	req, _ := http.NewRequest("GET", "https://"+host+"/", nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { info = i }}))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET https://%s/: %v", host, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.String(), info.Reused, string(b)
}

func TestACMEGatewayHTTP01EndToEndAndHotSwap(t *testing.T) {
	g := startACMEGateway(t, "", "")
	g.waitCert(t, "app.acme.test")

	c1 := g.client("app.acme.test")
	serial1, _, body := fetch(t, c1, "app.acme.test")
	if !strings.Contains(body, `"name":"a"`) {
		t.Fatalf("not routed to the backend: %s", body)
	}
	if _, reused, _ := fetch(t, c1, "app.acme.test"); !reused {
		t.Fatal("test setup: the keep-alive connection was not reused")
	}
	if g.f.count("orders-made") != 1 {
		t.Fatalf("orders = %d", g.f.count("orders-made"))
	}

	// HTTP-01 is answered by the plain listener only for tokens it holds, and the
	// rest of that listener still routes normally.
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + g.s.Addr(8080) + acmeChallengePrefix + "unknowntoken123")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown challenge token answered %d", resp.StatusCode)
	}
	if r := get(t, g.s, "any.test", "/"); r.Status != 200 {
		t.Errorf("normal routing on the HTTP listener broke: %d", r.Status)
	}

	// Renewal swaps the certificate into the live listener: new handshakes see it,
	// the connection that was already open keeps working untouched.
	g.clk.Advance(61 * 24 * time.Hour)
	g.s.acme.tick(context.Background())
	if len(g.f.issuedSerials()) != 2 {
		t.Fatalf("not renewed: %v / %+v", g.f.issuedSerials(), g.s.ACMEInfo())
	}
	serial2, _, _ := fetch(t, g.client("app.acme.test"), "app.acme.test")
	if serial2 == serial1 {
		t.Fatal("a new connection still got the old certificate")
	}
	serialOld, reused, _ := fetch(t, c1, "app.acme.test")
	if !reused || serialOld != serial1 {
		t.Fatalf("the open connection was disturbed: reused=%v serial=%s want %s", reused, serialOld, serial1)
	}
	if info := g.s.ACMEInfo(); len(info) != 1 || !info[0].Issued || info[0].LastError != "" {
		t.Errorf("ACMEInfo = %+v", info)
	}
}

func TestACMEGatewayTLSALPN01(t *testing.T) {
	g := startACMEGateway(t, "tls-alpn-01", "")
	g.waitCert(t, "app.acme.test")
	if g.f.count("orders-made") != 1 {
		t.Fatalf("orders = %d", g.f.count("orders-made"))
	}
	if _, _, body := fetch(t, g.client("app.acme.test"), "app.acme.test"); !strings.Contains(body, `"name":"a"`) {
		t.Fatalf("not routed: %s", body)
	}
	// Outside a validation an acme-tls/1 handshake gets nothing.
	_, err := tls.Dial("tcp", g.s.Addr(8443), &tls.Config{ServerName: "app.acme.test", NextProtos: []string{acmeALPN}, InsecureSkipVerify: true})
	if err == nil {
		t.Error("an ALPN validation handshake without a pending challenge must fail")
	}
}

func TestACMEGatewayReusesStoredCertificateAfterRestart(t *testing.T) {
	dir := t.TempDir()
	g := startACMEGateway(t, "", dir)
	c := g.waitCert(t, "app.acme.test")
	// Same directory, same CA: the second gateway serves the stored certificate at once.
	be, _ := upstreams(t, "a")
	gwSpec := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080},
		m{"name": "secure", "protocol": "HTTPS", "port": 8443, "hostname": "app.acme.test", "tls": m{"mode": "Terminate"}}}}
	raw := snap(gwSpec, map[string]m{"r": route("", rule("/", ref("a", 1)))}, be)
	s2 := startServer(t, raw, func(o *Options) {
		o.Cert.ACME = &ACMEOptions{Dir: dir, DirectoryURL: g.f.dirURL(), HTTPClient: g.f.srv.Client(), Now: g.clk.Now, Sleep: noSleep, Jitter: noJitter}
	})
	if c2 := s2.acme.cert("app.acme.test"); c2 == nil || certSerial(c2) != certSerial(c) {
		t.Fatal("stored certificate not loaded")
	}
	g.s = s2
	if _, _, body := fetch(t, g.client("app.acme.test"), "app.acme.test"); !strings.Contains(body, `"name":"a"`) {
		t.Fatalf("not routed: %s", body)
	}
	if g.f.count("orders-made") != 1 {
		t.Errorf("restart placed another order (%d)", g.f.count("orders-made"))
	}
}

func TestACMEGatewayWildcardListenerExplainsWhyNotServing(t *testing.T) {
	clk := newACMEClock()
	f := newFakeACME(t, clk)
	be, _ := upstreams(t, "a")
	gwSpec := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "wild", "protocol": "HTTPS", "port": 8443, "hostname": "*.acme.test", "tls": m{"mode": "Terminate"}}}}
	s := startServer(t, snap(gwSpec, map[string]m{"r": route("", rule("/", ref("a", 1)))}, be), func(o *Options) {
		o.Cert.ACME = &ACMEOptions{Dir: t.TempDir(), DirectoryURL: f.dirURL(), HTTPClient: f.srv.Client(), Now: clk.Now, Sleep: noSleep, Jitter: noJitter}
	})
	var msg string
	for _, ls := range s.Status().Gateways["t/gw"].Listeners {
		for _, c := range ls.Conditions {
			if c.Type == "ResolvedRefs" {
				msg = c.Message
				if c.Status != "False" {
					t.Errorf("ResolvedRefs = %s", c.Status)
				}
			}
		}
	}
	if !strings.Contains(msg, "--acme-dns-hook") || !strings.Contains(msg, "*.acme.test") {
		t.Errorf("message %q must explain the wildcard needs DNS-01", msg)
	}
	if f.count("orders-made") != 0 {
		t.Error("ordered a wildcard without a DNS hook")
	}
}

func newTestFlagSet(t *testing.T, c *certFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addCertFlags(fs, c)
	return fs
}

func TestACMENeverTouchesTheNetworkByDefault(t *testing.T) {
	// A server built with ACME options but a loopback fake never dials anything
	// else; and the production URL needs the explicit flag.
	var c certFlags
	var o Options
	fs := newTestFlagSet(t, &c)
	if err := fs.Parse([]string{"--acme-dir", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := c.apply(&o); err != nil {
		t.Fatal(err)
	}
	if o.Cert.ACME == nil || o.Cert.ACME.directory() != ACMEStagingURL {
		t.Fatalf("--acme-dir alone must use staging, got %+v", o.Cert.ACME)
	}
	var c2 certFlags
	fs2 := newTestFlagSet(t, &c2)
	if err := fs2.Parse([]string{"--acme-production"}); err != nil {
		t.Fatal(err)
	}
	if err := c2.apply(&Options{}); err == nil {
		t.Error("--acme-production without --acme-dir must be refused")
	}
}
