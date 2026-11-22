package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// echo is what every test upstream returns.
type echo struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []echo
}

func (u *upstream) seen() []echo {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]echo(nil), u.reqs...)
}

func newUpstream(t *testing.T, name string) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e := echo{Name: name, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Host: r.Host, Headers: map[string]string{}, Body: string(b)}
		for k := range r.Header {
			e.Headers[strings.ToLower(k)] = r.Header.Get(k)
		}
		u.mu.Lock()
		u.reqs = append(u.reqs, e)
		u.mu.Unlock()
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("X-Upstream", name)
		w.Header().Set("X-Resp-Set", "from-upstream")
		w.Header().Set(BackendHeader, "spoofed")
		if r.URL.Path == "/slow" {
			time.Sleep(300 * time.Millisecond)
		}
		json.NewEncoder(w).Encode(e)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) addr() string { return strings.TrimPrefix(u.URL, "http://") }

type m = map[string]any
type l = []any

const gwKeyT = "gateways.gateway.networking.k8s.io/"
const rtKeyT = "httproutes.gateway.networking.k8s.io/"

func httpGateway(host string) m {
	l := m{"name": "web", "protocol": "HTTP", "port": 8080}
	if host != "" {
		l["hostname"] = host
	}
	return m{"gatewayClassName": "setura", "listeners": []any{l}}
}

func route(host string, rules ...m) m {
	r := m{"parentRefs": []any{m{"name": "gw"}}, "rules": rules}
	if host != "" {
		r["hostnames"] = []any{host}
	}
	return r
}

func ref(name string, weight int) m {
	b := m{"name": name, "port": 80}
	if weight >= 0 {
		b["weight"] = weight
	}
	return b
}

func rule(path string, backends ...m) m {
	r := m{"backendRefs": toList(backends)}
	if path != "" {
		r["matches"] = []any{m{"path": m{"type": "PathPrefix", "value": path}}}
	}
	return r
}

func toList(in []m) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// snap builds a snapshot with the given gateway spec, routes and backends.
func snap(gw m, routes map[string]m, backends map[string]any) []byte {
	res := m{gwKeyT + "gw": gw}
	for k, v := range routes {
		res[rtKeyT+k] = v
	}
	b := m{}
	for k, v := range backends {
		b["t/"+k+":80"] = v
	}
	raw, _ := json.Marshal(m{"schema": SnapshotSchema, "namespace": "t", "resources": res, "backends": b})
	return raw
}

func upstreams(t *testing.T, names ...string) (map[string]any, map[string]*upstream) {
	be, ups := map[string]any{}, map[string]*upstream{}
	for _, n := range names {
		u := newUpstream(t, n)
		ups[n] = u
		be[n] = u.addr()
	}
	return be, ups
}

// startServer applies raw and returns a running server (no admin unless set).
func startServer(t *testing.T, raw []byte, mod func(*Options)) *Server {
	t.Helper()
	opts := Options{PortMap: map[int]int{8080: 0, 8443: 0}, Admin: "off", Rand: seededRand(1)}
	if mod != nil {
		mod(&opts)
	}
	s := New(opts)
	t.Cleanup(s.Close)
	cfg, err := ParseConfig(raw, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func startFile(t *testing.T, path string, mod func(*Options)) (*Server, context.CancelFunc, chan error) {
	t.Helper()
	opts := Options{PortMap: map[int]int{8080: 0}, Admin: "127.0.0.1:0", Rand: seededRand(1), Lint: nil}
	if mod != nil {
		mod(&opts)
	}
	s := New(opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, FileSource{path}, 20*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for !s.Ready() {
		select {
		case err := <-done:
			t.Fatalf("server exited: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return s, cancel, done
}

func seededRand(seed uint64) func(int) int {
	var mu sync.Mutex
	state := seed*6364136223846793005 + 1442695040888963407
	return func(n int) int {
		mu.Lock()
		defer mu.Unlock()
		state = state*6364136223846793005 + 1442695040888963407
		return int((state >> 33) % uint64(n))
	}
}

type reply struct {
	Status int
	Header http.Header
	Body   string
	Echo   echo
}

// client dials addr whatever the URL host says, never follows redirects.
func client(addr string, tlsCfg *tls.Config) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, addr)
			}}}
}

func get(t *testing.T, s *Server, host, target string, hdr ...string) reply {
	t.Helper()
	return req(t, client(s.Addr(8080), nil), "http", "GET", host, target, "", hdr...)
}

func req(t *testing.T, c *http.Client, scheme, method, host, target, body string, hdr ...string) reply {
	t.Helper()
	rq, err := http.NewRequest(method, scheme+"://"+host+target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		rq.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := reply{Status: resp.StatusCode, Header: resp.Header, Body: string(b)}
	json.Unmarshal(b, &r.Echo)
	return r
}

// pki makes a CA and issues leaf certificates, written under dir.
type pki struct {
	t    *testing.T
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	dir  string
	n    int64
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{t: t, ca: ca, key: key, pool: pool, dir: t.TempDir(), n: 1}
}

// issue returns PEM cert and key for the DNS names.
func (p *pki) issue(names ...string) (certPEM, keyPEM []byte) {
	p.n++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.n), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

// files writes an issued pair and returns a secrets entry.
func (p *pki) files(name string, names ...string) m {
	c, k := p.issue(names...)
	cf, kf := filepath.Join(p.dir, name+".crt"), filepath.Join(p.dir, name+".key")
	os.WriteFile(cf, c, 0o600)
	os.WriteFile(kf, k, 0o600)
	return m{"certFile": cf, "keyFile": kf}
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

var _ = bytes.NewReader
