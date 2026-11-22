package setura

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture serves /checkout?q=1 for Host orders.mactra.test:PORT and sets the
// X-Setura-Backend identity header.
func fixture(t *testing.T, cfg *tls.Config) (url string) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		good := r.Host == "orders.mactra.test:"+port && r.URL.RequestURI() == "/checkout?q=1"
		w.Header().Set("X-Setura-Backend", "orders-v1")
		w.Header().Set("X-Env", "staging")
		if good {
			w.WriteHeader(200)
			w.Write([]byte("orders service ready"))
		} else {
			w.WriteHeader(404)
		}
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected bad-certificate handshakes are noisy
	scheme := "http"
	if cfg != nil {
		srv.TLS = cfg
		srv.StartTLS()
		scheme = "https"
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return scheme + "://orders.mactra.test:" + port + "/checkout?q=1"
}

// selfSigned returns a TLS server config and the PEM file path of its CA cert.
func selfSigned(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "orders.mactra.test"},
		DNSNames: []string{"orders.mactra.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, path
}

// fakeCluster answers kubectl calls with queued stdout bodies.
type call struct {
	stdout, stderr string
	code           int
}

func fakeCluster(calls ...call) (*Cluster, *[][]string) {
	var seen [][]string
	i := 0
	return &Cluster{Context: "", Exec: func(args []string) (string, string, int, error) {
		seen = append(seen, args)
		if i >= len(calls) {
			i = len(calls) - 1
		}
		c := calls[i]
		i++
		return c.stdout, c.stderr, c.code, nil
	}}, &seen
}

func js(v any) call { b, _ := json.Marshal(v); return call{stdout: string(b)} }

func cli(t *testing.T, c *Cluster, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runWith(c, args, &out, &errb)
	return code, out.String(), errb.String()
}

func cliJSON(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	code, out, errs := cli(t, nil, args...)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("exit %d stderr %q stdout %q: %v", code, errs, out, err)
	}
	return code, m
}

func contains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

func is(t *testing.T, got, want any) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// decode round-trips a value through JSON into generic data.
func decode(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
