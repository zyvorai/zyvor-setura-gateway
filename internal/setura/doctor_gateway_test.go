package setura

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func dgCert(t *testing.T, host string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type dgCfg struct {
	ports    [][2]any // port, protocol
	hostname string
	secrets  map[string]string // name -> cert PEM
	backends map[string][]string
}

func writeDGConfig(t *testing.T, c dgCfg) string {
	t.Helper()
	var listeners []any
	for i, p := range c.ports {
		l := map[string]any{"name": fmt.Sprintf("l%d", i), "port": p[0], "protocol": p[1]}
		if p[1] == "HTTPS" {
			var refs []any
			for n := range c.secrets {
				refs = append(refs, map[string]any{"name": n})
			}
			l["tls"] = map[string]any{"certificateRefs": refs}
			if c.hostname != "" {
				l["hostname"] = c.hostname
			}
		}
		listeners = append(listeners, l)
	}
	backends := map[string]any{}
	var refs []any
	for k, eps := range c.backends {
		backends[k] = map[string]any{"endpoints": eps}
		name, _, _ := strings.Cut(k, ":")
		refs = append(refs, map[string]any{"name": name, "port": 80})
	}
	secrets := map[string]any{}
	for n, pem := range c.secrets {
		secrets[n] = map[string]any{"cert": pem}
	}
	doc := map[string]any{"schema": "setura.route-specs/v1", "namespace": "default", "backends": backends, "secrets": secrets,
		"resources": map[string]any{
			"gateways.gateway.networking.k8s.io/gw": map[string]any{"gatewayClassName": "setura", "listeners": listeners},
			"httproutes.gateway.networking.k8s.io/r": map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}},
				"rules": []any{map[string]any{"backendRefs": refs}}},
		}}
	b, _ := json.Marshal(doc)
	p := filepath.Join(t.TempDir(), "setura.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dgBackend(t *testing.T, date func() string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if date != nil {
			w.Header().Set("Date", date())
		}
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func dgTestEnv() dgEnv {
	env := defaultDGEnv(2 * time.Second)
	env.listen = func(string, string) (net.Listener, error) {
		return nil, &net.OpError{Op: "listen", Err: syscall.EADDRINUSE}
	}
	env.token = func() string { return "" }
	return env
}

func dgFreeListen(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

func dgFind(r *dgReport, id string) dgCheck {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return dgCheck{}
}

func dgOpts(cfg, admin string, explicit bool) dgOptions {
	return dgOptions{Config: cfg, Admin: admin, AdminExplicit: explicit, WarnCertDays: 14, Timeout: 2 * time.Second}
}

func TestDoctorGatewayConfig(t *testing.T) {
	env := dgTestEnv()
	env.listen = dgFreeListen
	r := doctorGateway(dgOpts(filepath.Join(t.TempDir(), "nope.json"), "127.0.0.1:1", false), env)
	if c := dgFind(r, "config"); c.State != "fail" || !strings.Contains(c.Message, "cannot read") {
		t.Fatalf("config = %+v", c)
	}
	if r.OK || !strings.Contains(r.Verdict, "1 problem needs fixing") {
		t.Fatalf("verdict %q ok=%v", r.Verdict, r.OK)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"schema":"nope"}`), 0o600)
	r = doctorGateway(dgOpts(bad, "127.0.0.1:1", false), env)
	if c := dgFind(r, "config"); c.State != "fail" || !strings.Contains(c.Message, "cannot parse") {
		t.Fatalf("config = %+v", c)
	}
	if c := dgFind(r, "lint"); c.State != "skip" {
		t.Fatalf("lint = %+v", c)
	}
	r = doctorGateway(dgOpts("", "127.0.0.1:1", false), env)
	if c := dgFind(r, "config"); c.State != "skip" || !r.OK {
		t.Fatalf("no config: %+v ok=%v", c, r.OK)
	}
}

func TestDoctorGatewayPortsAndBackends(t *testing.T) {
	be := dgBackend(t, nil)
	cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8080, "HTTP"}, {8080, "TCP"}}, backends: map[string][]string{"api:80": {be}}})
	env := dgTestEnv()
	r := doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env)
	if c := dgFind(r, "ports"); c.State != "fail" || !strings.Contains(strings.Join(c.Details, " "), "both HTTP and TCP") {
		t.Fatalf("ports = %+v", c)
	}

	// a port held by another process
	cfg = writeDGConfig(t, dgCfg{ports: [][2]any{{8081, "HTTP"}}, backends: map[string][]string{"api:80": {be}}})
	r = doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env)
	if c := dgFind(r, "ports"); c.State != "fail" || !strings.Contains(c.Message, "port clash") {
		t.Fatalf("busy = %+v", c)
	}
	if c := dgFind(r, "backends"); c.State != "ok" {
		t.Fatalf("backends = %+v", c)
	}
	// free ports
	env.listen = dgFreeListen
	r = doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env)
	if c := dgFind(r, "ports"); c.State != "ok" {
		t.Fatalf("free = %+v", c)
	}
	// a real held port is detected through the default listen
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg = writeDGConfig(t, dgCfg{ports: [][2]any{{port, "HTTP"}}, backends: map[string][]string{"api:80": {be}}})
	env.listen = net.Listen
	if c := dgFind(doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env), "ports"); c.State != "fail" {
		t.Fatalf("real busy = %+v", c)
	}
}

func TestDoctorGatewayBackendsDown(t *testing.T) {
	up := dgBackend(t, nil)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	env := dgTestEnv()
	env.listen = dgFreeListen

	cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8082, "HTTP"}}, backends: map[string][]string{"api:80": {up, deadAddr}}})
	c := dgFind(doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env), "backends")
	if c.State != "warn" || !strings.Contains(strings.Join(c.Details, " "), deadAddr) {
		t.Fatalf("partial = %+v", c)
	}
	cfg = writeDGConfig(t, dgCfg{ports: [][2]any{{8082, "HTTP"}}, backends: map[string][]string{"api:80": {deadAddr}}})
	r := doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env)
	c = dgFind(r, "backends")
	if c.State != "fail" || r.OK || !strings.Contains(r.Next, "nc -vz") {
		t.Fatalf("all down = %+v next=%q", c, r.Next)
	}
	if !strings.Contains(strings.Join(c.Details, " "), "refused") {
		t.Fatalf("details = %v", c.Details)
	}
}

func TestDoctorGatewayCerts(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	env := dgTestEnv()
	env.listen = dgFreeListen
	env.now = func() time.Time { return now }
	cases := []struct {
		name  string
		cert  string
		host  string
		state string
		text  string
	}{
		{"valid", dgCert(t, "a.test", now.Add(-time.Hour), now.Add(90*24*time.Hour)), "a.test", "ok", "valid for 90"},
		{"expiring", dgCert(t, "a.test", now.Add(-time.Hour), now.Add(3*24*time.Hour+time.Hour)), "a.test", "warn", "expires in 3 days"},
		{"expired", dgCert(t, "a.test", now.Add(-48*time.Hour), now.Add(-time.Hour)), "a.test", "fail", "expired on"},
		{"wrong name", dgCert(t, "other.test", now.Add(-time.Hour), now.Add(90*24*time.Hour)), "a.test", "warn", "does not cover"},
		{"garbage", "not a pem", "a.test", "fail", "no certificate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8443, "HTTPS"}}, hostname: c.host, secrets: map[string]string{"tls": c.cert}})
			ck := dgFind(doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env), "certs")
			if ck.State != c.state || !strings.Contains(strings.Join(ck.Details, " "), c.text) {
				t.Fatalf("certs = %+v", ck)
			}
		})
	}
	r := doctorGateway(dgOpts(writeDGConfig(t, dgCfg{ports: [][2]any{{8080, "HTTP"}}}), "127.0.0.1:1", false), env)
	if c := dgFind(r, "certs"); c.State != "skip" {
		t.Fatalf("no certs = %+v", c)
	}
}

func TestDoctorGatewayClockSkew(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		skew  time.Duration
		state string
	}{{0, "ok"}, {-30 * time.Second, "warn"}, {-5 * time.Minute, "fail"}} {
		be := dgBackend(t, func() string { return now.Add(c.skew).UTC().Format(http.TimeFormat) })
		env := dgTestEnv()
		env.listen = dgFreeListen
		env.now = func() time.Time { return now }
		cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8083, "HTTP"}}, backends: map[string][]string{"api:80": {be}}})
		ck := dgFind(doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env), "clock")
		if ck.State != c.state {
			t.Errorf("skew %v: %+v", c.skew, ck)
		}
	}
}

// fakeAdmin enforces a token when want is set and serves /metrics.
func dgFakeAdmin(t *testing.T, want, metrics string) string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if want != "" && r.Header.Get("Authorization") != "Bearer "+want {
			http.Error(w, "token required", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/metrics" {
			io.WriteString(w, metrics)
			return
		}
		io.WriteString(w, "{}")
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func TestDoctorGatewayAdminAuth(t *testing.T) {
	cases := []struct {
		name, serverToken, envToken, state, text string
		explicit                                 bool
		down                                     bool
	}{
		{"open", "", "", "ok", "no token required", true, false},
		{"protected ok", "s3", "s3", "ok", "is accepted", true, false},
		{"protected no token", "s3", "", "warn", "SETURA_ADMIN_TOKEN is not set", true, false},
		{"wrong token", "s3", "nope", "fail", "rejected", true, false},
		{"unreachable explicit", "", "", "fail", "cannot reach", true, true},
		{"unreachable default", "", "", "skip", "no gateway answered", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := "127.0.0.1:1"
			if !c.down {
				addr = dgFakeAdmin(t, c.serverToken, "")
			}
			env := dgTestEnv()
			env.listen = dgFreeListen
			env.token = func() string { return c.envToken }
			t.Setenv("SETURA_ADMIN_TOKEN", c.envToken)
			r := doctorGateway(dgOpts("", addr, c.explicit), env)
			ck := dgFind(r, "admin")
			if ck.State != c.state || !strings.Contains(ck.Message, c.text) {
				t.Fatalf("admin = %+v", ck)
			}
		})
	}
}

func TestDoctorGatewayEjected(t *testing.T) {
	metrics := `setura_gateway_endpoint_healthy{backend="api:80",endpoint="10.0.0.1:80"} 1
setura_gateway_endpoint_healthy{backend="api:80",endpoint="10.0.0.2:80"} 0
setura_gateway_endpoint_ejected{backend="api:80",endpoint="10.0.0.1:80"} 1
setura_gateway_endpoint_ejected{backend="api:80",endpoint="10.0.0.2:80"} 0
`
	addr := dgFakeAdmin(t, "", metrics)
	env := dgTestEnv()
	r := doctorGateway(dgOpts("", addr, true), env)
	ck := dgFind(r, "endpoints")
	if ck.State != "warn" || len(ck.Details) != 2 || !strings.Contains(ck.Message, "1 ejected, 1 failing") {
		t.Fatalf("endpoints = %+v", ck)
	}
	if !r.OK || !strings.Contains(r.Verdict, "1 warning, nothing blocking") {
		t.Fatalf("verdict %q", r.Verdict)
	}
	healthy := dgFakeAdmin(t, "", "setura_gateway_endpoint_healthy{backend=\"api:80\",endpoint=\"10.0.0.1:80\"} 1\nsetura_gateway_endpoint_ejected{backend=\"api:80\",endpoint=\"10.0.0.1:80\"} 0\n")
	if ck := dgFind(doctorGateway(dgOpts("", healthy, true), env), "endpoints"); ck.State != "ok" {
		t.Fatalf("healthy = %+v", ck)
	}
	// the gateway holds its own port: not a clash
	be := dgBackend(t, nil)
	cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8084, "HTTP"}}, backends: map[string][]string{"api:80": {be}}})
	if ck := dgFind(doctorGateway(dgOpts(cfg, addr, true), env), "ports"); ck.State != "ok" || !strings.Contains(strings.Join(ck.Details, " "), "running gateway") {
		t.Fatalf("own port = %+v", ck)
	}
}

func TestDoctorGatewayPrettyAndCLI(t *testing.T) {
	be := dgBackend(t, nil)
	cfg := writeDGConfig(t, dgCfg{ports: [][2]any{{8085, "HTTP"}}, backends: map[string][]string{"api:80": {be}}})
	env := dgTestEnv()
	env.listen = dgFreeListen
	r := doctorGateway(dgOpts(cfg, "127.0.0.1:1", false), env)
	out := plainUI.DoctorGatewayPretty(r)
	for _, w := range []string{"✓ Config", "Gateway looks healthy", "Next: setura connections --admin 127.0.0.1:1", "– Admin API"} {
		if !strings.Contains(out, w) {
			t.Errorf("pretty lacks %q:\n%s", w, out)
		}
	}
	bad := doctorGateway(dgOpts(filepath.Join(t.TempDir(), "x.json"), "127.0.0.1:1", false), env)
	out = plainUI.DoctorGatewayPretty(bad)
	if !strings.Contains(out, "✗ Config") || !strings.Contains(out, "1 problem needs fixing") || !strings.Contains(out, "Next: Check the path") {
		t.Errorf("failure output:\n%s", out)
	}

	var so, se bytes.Buffer
	code, err := runDoctorGateway([]string{"--config", filepath.Join(t.TempDir(), "x.json"), "--admin", "127.0.0.1:1", "--format", "json", "--timeout", "1s"}, &so, &se, plainUI, false)
	if err != nil || code != 1 {
		t.Fatalf("code %d err %v", code, err)
	}
	var doc dgReport
	if json.Unmarshal(so.Bytes(), &doc) != nil || doc.Schema != "setura.doctor.gateway/v1" || doc.OK || len(doc.Checks) != 8 {
		t.Fatalf("json: %s", so.String())
	}
	code, _ = runDoctorGateway([]string{"--format", "yaml"}, &so, &se, plainUI, false)
	if code != 2 {
		t.Fatalf("bad format code %d", code)
	}
	code, _ = runDoctorGateway([]string{"extra"}, &so, &se, plainUI, false)
	if code != 2 {
		t.Fatalf("extra arg code %d", code)
	}
}

func TestDoctorDispatchesToGateway(t *testing.T) {
	var so, se bytes.Buffer
	code := runWith(nil, []string{"doctor", "gateway", "--admin", "127.0.0.1:1", "--format", "json"}, &so, &se)
	if code != 1 || !strings.Contains(so.String(), "setura.doctor.gateway/v1") {
		t.Fatalf("code %d out %s err %s", code, so.String(), se.String())
	}
}
