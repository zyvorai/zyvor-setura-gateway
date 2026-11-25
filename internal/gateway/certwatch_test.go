package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- file mode: polling by mtime ----

func writeAged(t *testing.T, path string, b []byte, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

// certConfig writes a config with one HTTPS listener whose certificate comes
// from files, plus a CA bundle file in caCertificates.
func certConfig(t *testing.T, p *pki, age time.Duration) (cfgPath, certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()
	c, k := p.issue("a.test")
	certFile, keyFile, caFile = filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key"), filepath.Join(dir, "ca.crt")
	writeAged(t, certFile, c, age)
	writeAged(t, keyFile, k, age)
	writeAged(t, caFile, c, age)
	be, _ := upstreams(t, "a")
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources":      m{gwKeyT + "gw": httpsGateway(tlsListener("web", "", "srv-cert")), rtKeyT + "r": route("a.test", rule("/", ref("a", 1)))},
		"backends":       m{"t/a:80": be["a"]},
		"secrets":        m{"srv-cert": m{"certFile": certFile, "keyFile": keyFile}},
		"caCertificates": m{"bundle": m{"file": caFile}}})
	cfgPath = filepath.Join(dir, "gw.json")
	writeAged(t, cfgPath, raw, age)
	return
}

func TestFileSourceAnswersFromMtimeUntilSomethingChanges(t *testing.T) {
	p := newPKI(t)
	cfg, certFile, _, caFile := certConfig(t, p, time.Hour)
	src := FileSource{cfg}
	ld1, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ld2, _ := src.Load(context.Background())
	if ld1 != ld2 {
		t.Fatal("a quiet poll must be answered from the remembered load, without reading or parsing anything")
	}

	// A rotated certificate file is noticed by its mtime.
	c2, _ := p.issue("a.test")
	writeAged(t, certFile, c2, time.Hour-time.Minute)
	ld3, _ := src.Load(context.Background())
	if ld3 == ld1 || ld3.Hash == ld1.Hash {
		t.Fatal("a changed certificate file was not noticed")
	}
	ld4, _ := src.Load(context.Background())
	if ld4 != ld3 {
		t.Fatal("not memoized again after the change")
	}

	// So is a rotated client or backend CA bundle, which used to be invisible to reloads.
	c3, _ := p.issue("ca.test")
	writeAged(t, caFile, c3, time.Hour-2*time.Minute)
	ld5, _ := src.Load(context.Background())
	if ld5.Hash == ld3.Hash {
		t.Fatal("a changed CA bundle file did not change the configuration hash")
	}

	// A file that vanishes and returns is a change both times.
	os.Remove(caFile)
	if ld6, _ := src.Load(context.Background()); ld6 == ld5 {
		t.Error("a deleted CA file was not noticed")
	}
}

func TestFileSourceDoesNotTrustFreshTimestamps(t *testing.T) {
	// A file written within the timestamp granularity of its own read may be
	// rewritten with the same size and the same mtime; such loads are not
	// remembered (git's racy-timestamp rule), so the rewrite is still seen.
	p := newPKI(t)
	cfg, certFile, _, _ := certConfig(t, p, 0)
	src := FileSource{cfg}
	ld1, _ := src.Load(context.Background())
	if ld2, _ := src.Load(context.Background()); ld2 == ld1 {
		t.Fatal("a load of just-written files must not be memoized")
	}
	st, _ := os.Stat(certFile)
	old, _ := os.ReadFile(certFile)
	repl := make([]byte, len(old))
	copy(repl, old)
	repl[len(repl)/2] ^= 0x01 // same size, different content
	os.WriteFile(certFile, repl, 0o600)
	os.Chtimes(certFile, st.ModTime(), st.ModTime()) // and the same mtime
	ld3, _ := src.Load(context.Background())
	if ld3.Hash == ld1.Hash {
		t.Fatal("a same-size same-mtime rewrite of a fresh file was missed")
	}
}

func TestFileModeRotatesListenerCertificateWithoutDroppingConnections(t *testing.T) {
	p := newPKI(t)
	cfg, certFile, keyFile, _ := certConfig(t, p, time.Hour)
	s, _, _ := startFile(t, cfg, func(o *Options) { o.PortMap = map[int]int{8443: 0} })
	serialOf := func() string {
		c, err := tls.Dial("tcp", s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "a.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serialOf()
	keep := tlsClient(s.Addr(8443), p, "a.test")
	if r := req(t, keep, "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	c, k := p.issue("a.test")
	writeFile(t, certFile, c)
	writeFile(t, keyFile, k)
	waitFor(t, "the rotated certificate to be served", func() bool { return serialOf() != before })
	if r := req(t, keep, "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Fatalf("the established client broke across the rotation: %d", r.Status)
	}
}

func TestHalfWrittenCertificateRotationKeepsTheListener(t *testing.T) {
	defer func(d time.Duration) { certSettle = d }(certSettle)
	certSettle = time.Hour // set before the server starts, restored after it stops
	p := newPKI(t)
	cfg, certFile, keyFile, _ := certConfig(t, p, 2*time.Hour)
	s := New(Options{PortMap: map[int]int{8443: 0}, Admin: "off", Rand: seededRand(1)})
	defer s.Close()
	src := FileSource{cfg}
	reload := func() (bool, error) { return s.Reload(context.Background(), src) }
	if _, err := reload(); err != nil {
		t.Fatal(err)
	}
	addr := s.Addr(8443)
	serial := func() string {
		c, err := tls.Dial("tcp", s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "a.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serial()
	c, k := p.issue("a.test")
	writeFile(t, certFile, c) // the key still belongs to the old certificate
	for i := 0; i < 2; i++ {
		if changed, err := reload(); changed || err == nil || !strings.Contains(err.Error(), "waiting for the certificate and key") {
			t.Fatalf("half-written rotation: changed %v err %v", changed, err)
		}
	}
	if s.Addr(8443) != addr || serial() != before || s.Status().LastReload.OK {
		t.Fatal("the previous certificate must keep serving and the reload must be reported")
	}
	writeFile(t, keyFile, k)
	if changed, err := reload(); !changed || err != nil {
		t.Fatalf("completed rotation: %v %v", changed, err)
	}
	if s.Addr(8443) != addr || serial() == before {
		t.Fatal("the new certificate is not served on the same socket")
	}
	// A pair that stays broken is applied once the files have settled, as before.
	c2, _ := p.issue("a.test")
	writeAged(t, certFile, c2, 3*time.Hour)
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(keyFile, old, old); err != nil {
		t.Fatal(err)
	}
	if changed, err := reload(); !changed || err != nil {
		t.Fatalf("settled broken pair: %v %v", changed, err)
	}
	if s.Addr(8443) != "" {
		t.Fatal("a listener without a usable certificate must not serve")
	}
}

// ---- OCSP stapling across reloads ----

func TestOCSPStapleSurvivesReloadsAndFollowsRenewal(t *testing.T) {
	p := newPKI(t)
	var leaf atomic.Pointer[tlsLeaf]
	var hits atomic.Int32
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		now := time.Now()
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(p.ocspAnswer(leaf.Load().leaf, true, now.Add(-time.Minute), now.Add(time.Hour)))
	}))
	defer responder.Close()
	cert1, leaf1 := p.ocspLeaf("a.test", responder.URL)
	leaf.Store(&tlsLeaf{leaf1})
	cf, kf := writeChain(t, p.dir, "one", cert1)
	be, _ := upstreams(t, "a")
	mk := func(cf, kf string, extra string) []byte {
		return mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": httpsGateway(tlsListener("web", "", "srv-cert")), rtKeyT + "r": route("a.test", rule("/"+extra, ref("a", 1)))},
			"backends":  m{"t/a:80": be["a"]}, "secrets": m{"srv-cert": m{"certFile": cf, "keyFile": kf}}})
	}
	s := startServer(t, mk(cf, kf, ""), func(o *Options) { o.OCSPStaple = true })
	handshake := func() (staple []byte, serial string) {
		c, err := tls.Dial("tcp", s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "a.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		st := c.ConnectionState()
		return st.OCSPResponse, st.PeerCertificates[0].SerialNumber.String()
	}
	waitFor(t, "the first staple", func() bool { st, _ := handshake(); return len(st) > 0 })

	// A reload that keeps the certificate keeps its staple: the very next handshake has it.
	for i, extra := range []string{"x", "y"} {
		cfg, _ := ParseConfig(mk(cf, kf, extra), t.TempDir())
		if err := s.Apply(&Loaded{Config: cfg, Hash: fmt.Sprint("reload", i)}); err != nil {
			t.Fatal(err)
		}
		if st, _ := handshake(); len(st) == 0 {
			t.Fatalf("reload %d dropped the OCSP staple", i)
		}
	}

	// A renewed certificate is stapled too, once the manager has fetched its response.
	cert2, leaf2 := p.ocspLeaf("a.test", responder.URL)
	leaf.Store(&tlsLeaf{leaf2})
	cf2, kf2 := writeChain(t, p.dir, "two", cert2)
	cfg, _ := ParseConfig(mk(cf2, kf2, ""), t.TempDir())
	if err := s.Apply(&Loaded{Config: cfg, Hash: "renewed"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the renewed certificate's staple", func() bool {
		st, serial := handshake()
		if serial != leaf2.SerialNumber.String() {
			t.Fatalf("serving serial %s, want the renewed %s", serial, leaf2.SerialNumber)
		}
		if len(st) == 0 {
			return false
		}
		_, _, err := checkOCSPResponse(st, leaf2, p.ca, time.Now())
		return err == nil
	})
}

type tlsLeaf struct{ leaf *x509.Certificate }

// ---- Kubernetes mode: Secret watches ----

var secretsCollRE = regexp.MustCompile(`^/api/v1/namespaces/([^/]+)/secrets$`)

// secretWatchAPI sits in front of the fake API and serves watches of single
// Secrets selected by metadata.name, which the fake API itself does not.
type secretWatchAPI struct {
	*httptest.Server
	mu    sync.Mutex
	subs  map[string][]chan []byte
	paths []string
	rv    int
}

func newSecretWatchAPI(t *testing.T, api *fakeAPI) *secretWatchAPI {
	w := &secretWatchAPI{subs: map[string][]chan []byte{}, rv: 1000}
	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mt := secretsCollRE.FindStringSubmatch(r.URL.Path)
		if mt == nil {
			api.Config.Handler.ServeHTTP(rw, r)
			return
		}
		sel, _ := url.ParseQuery(r.URL.Query().Get("fieldSelector"))
		key := mt[1] + "/" + sel.Get("metadata.name")
		if r.URL.Query().Get("watch") != "1" {
			json.NewEncoder(rw).Encode(m{"items": l{}, "metadata": m{"resourceVersion": "1000"}})
			return
		}
		ch := make(chan []byte, 16)
		w.mu.Lock()
		w.subs[key] = append(w.subs[key], ch)
		w.paths = append(w.paths, r.URL.RequestURI())
		w.mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(200)
		fl := rw.(http.Flusher)
		fl.Flush()
		for {
			select {
			case line := <-ch:
				rw.Write(line)
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(w.Close)
	return w
}

func (w *secretWatchAPI) watchers(key string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.subs[key])
}

func (w *secretWatchAPI) notify(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rv++
	line := fmt.Sprintf(`{"type":"MODIFIED","object":{"metadata":{"resourceVersion":"%d"}}}`+"\n", w.rv)
	for _, ch := range w.subs[key] {
		ch <- []byte(line)
	}
}

func TestKubeSecretWatchPicksUpCertManagerRenewalInSeconds(t *testing.T) {
	p := newPKI(t)
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	c1, k1 := p.issue("secure.test")
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "tls", "protocol": "HTTPS", "port": 8443, "hostname": "secure.test", "allowedRoutes": m{"namespaces": m{"from": "All"}},
			"tls": m{"certificateRefs": l{m{"name": "edge-cert", "namespace": "certs"}}}}}}})
	put := func(c, k []byte) {
		api.put("secrets", "certs", "edge-cert", m{"type": "kubernetes.io/tls", "data": m{
			"tls.crt": base64.StdEncoding.EncodeToString(c), "tls.key": base64.StdEncoding.EncodeToString(k)}})
	}
	put(c1, k1)
	api.put("referencegrants", "certs", "g", m{"spec": m{"from": l{m{"group": APIGroup, "kind": "Gateway", "namespace": "infra"}}, "to": l{m{"group": "", "kind": "Secret"}}}})
	sw := newSecretWatchAPI(t, api)

	ks := NewKubeSource(sw.URL, sw.Client(), func() string { return "test-token" }, nil)
	ks.Resync = time.Hour // only watch events can drive a reload in this test
	ks.watchBackoff = 10 * time.Millisecond
	s := New(Options{PortMap: map[int]int{8443: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, time.Hour) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "ready", s.Ready)
	waitFor(t, "the Secret watch to open", func() bool { return sw.watchers("certs/edge-cert") >= 1 })

	sw.mu.Lock()
	path := sw.paths[0]
	sw.mu.Unlock()
	if want := "fieldSelector=metadata.name%3Dedge-cert"; !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(path) {
		t.Errorf("watch request %q does not select the one Secret by name (%s)", path, want)
	}
	serialOf := func() string {
		c, err := tls.Dial("tcp", s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "secure.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serialOf()

	// cert-manager renews: the Secret changes, the API emits an event, the gateway reloads at once.
	start := time.Now()
	c2, k2 := p.issue("secure.test")
	put(c2, k2)
	sw.notify("certs/edge-cert")
	waitFor(t, "the renewed Secret to be served", func() bool { return serialOf() != before })
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("renewal took %v to reach the listener", d)
	}
}

func TestRefWatchPathsAreRecordedPerLoad(t *testing.T) {
	var r refWatches
	r.begin()
	r.note("/api/v1/namespaces/certs/secrets/edge-cert")
	r.note("/api/v1/namespaces/infra/configmaps/ca")
	r.note("/api/v1/namespaces/infra/services/x") // not a watched kind
	r.note("/api/v1/namespaces/certs/secrets?limit=1")
	if len(r.seen) != 2 || !r.seen["certs/secrets/edge-cert"] || !r.seen["infra/configmaps/ca"] {
		t.Fatalf("seen %v", r.seen)
	}
	if got := withQuery("/a?x=1", "y=2"); got != "/a?x=1&y=2" {
		t.Errorf("withQuery %q", got)
	}
	if got := withQuery("/a", "y=2"); got != "/a?y=2" {
		t.Errorf("withQuery %q", got)
	}
}

// ---- Alt-Svc ----

func TestAltSvcOnHTTPSResponsesOnly(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	gw := httpsGateway(tlsListener("web", "a.test", "a-cert"), m{"name": "plain", "protocol": "HTTP", "port": 8080})
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "r": route("", rule("/", ref("a", 1)))},
		"backends":  m{"t/a:80": be["a"]}, "secrets": m{"a-cert": p.files("a", "a.test")}})
	const v = `h3=":443"; ma=86400`
	s := startServer(t, raw, func(o *Options) { o.Cert.AltSvc = v })
	if r := req(t, tlsClient(s.Addr(8443), p, "a.test"), "https", "GET", "a.test", "/", ""); r.Header.Get("Alt-Svc") != v {
		t.Errorf("HTTPS response Alt-Svc = %q, want %q", r.Header.Get("Alt-Svc"), v)
	}
	if r := get(t, s, "a.test", "/"); r.Header.Get("Alt-Svc") != "" {
		t.Errorf("plain HTTP response must not advertise an alternative service, got %q", r.Header.Get("Alt-Svc"))
	}
	if err := validAltSvc("h3=\":443\"\r\nX: y"); err == nil {
		t.Error("header injection through --alt-svc must be refused")
	}
	s2 := New(Options{Cert: CertOptions{AltSvc: "bad\nvalue"}})
	defer s2.Close()
	if s2.acmeErr == nil {
		t.Error("a bad Alt-Svc value must fail at startup")
	}
}
