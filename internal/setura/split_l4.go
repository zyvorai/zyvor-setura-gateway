package setura

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Samplers for "setura split" beyond plain HTTP: gRPC calls (GRPCRoute weights)
// and bare TLS handshakes (TLSRoute passthrough weights). A gateway applies
// GRPCRoute weights per call and TLSRoute weights per connection, so every
// sample uses a new connection.

// splitCertIdentities are the --identity values of a tls:// split.
var splitCertIdentities = map[string]bool{"cert-cn": true, "cert-san": true, "cert-sha256": true}

const (
	grpcHealthMethod = "grpc.health.v1.Health/Check"
	// splitFingerprintLen is how many hex digits of the leaf certificate's
	// SHA-256 fingerprint identify a backend with --identity cert-sha256.
	splitFingerprintLen = 16
)

// splitSample is the outcome of one attempt: an identity, or why it failed.
type splitSample struct {
	ident  string
	failed string
}

// splitSampler makes one attempt. An error means the options are invalid and
// the whole run must stop; network and protocol failures go in the sample.
type splitSampler func() (splitSample, error)

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, userErrorf("no certificates found in %s", path)
	}
	return pool, nil
}

func splitTimeout(p ProbeOptions) (time.Duration, error) {
	if !(p.Timeout > 0 && p.Timeout <= 60) {
		return 0, userError("timeout must be positive and at most 60 seconds")
	}
	if p.Address != "" && net.ParseIP(p.Address) == nil {
		return 0, userErrorf("%s does not appear to be an IPv4 or IPv6 address", pyRepr(p.Address))
	}
	return time.Duration(p.Timeout * float64(time.Second)), nil
}

// tlsSampler handshakes with tls://HOST:PORT, verifying the certificate for the
// SNI name, and identifies the backend by the leaf certificate it presented.
func tlsSampler(o SplitOptions) (splitSampler, error) {
	u, err := url.Parse(o.Probe.URL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.Port() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, userError("expected tls://HOST:PORT")
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
		return nil, userError("invalid port")
	}
	if !splitCertIdentities[o.CertIdentity] {
		return nil, userError("--identity must be cert-cn, cert-san or cert-sha256")
	}
	name := o.SNI
	if name == "" {
		name = u.Hostname()
	}
	if net.ParseIP(name) != nil {
		return nil, userError("a TLSRoute is chosen by SNI: use a hostname in the URL or give --sni NAME")
	}
	timeout, err := splitTimeout(o.Probe)
	if err != nil {
		return nil, err
	}
	roots, err := loadRoots(o.Probe.CA)
	if err != nil {
		return nil, err
	}
	dial := u.Hostname()
	if o.Probe.Address != "" {
		dial = o.Probe.Address
	}
	target := net.JoinHostPort(dial, u.Port())
	return func() (splitSample, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		d := tls.Dialer{Config: &tls.Config{ServerName: name, RootCAs: roots}}
		conn, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return splitSample{failed: "tls: " + err.Error()}, nil
		}
		defer conn.Close()
		peers := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if len(peers) == 0 {
			return splitSample{failed: "tls: the server presented no certificate"}, nil
		}
		return splitSample{ident: certIdentity(peers[0], o.CertIdentity)}, nil
	}, nil
}

func certIdentity(c *x509.Certificate, kind string) string {
	v := ""
	switch kind {
	case "cert-cn":
		v = c.Subject.CommonName
	case "cert-san":
		if len(c.DNSNames) > 0 {
			v = c.DNSNames[0]
		}
	case "cert-sha256":
		sum := sha256.Sum256(c.Raw)
		v = hex.EncodeToString(sum[:])[:splitFingerprintLen]
	}
	if v == "" {
		return splitNone
	}
	return clipStr(v, maxSplitNameLen)
}

// grpcPath validates SERVICE/METHOD and returns the request path.
func grpcPath(m string) (string, error) {
	svc, meth, ok := strings.Cut(strings.TrimPrefix(m, "/"), "/")
	valid := func(s string, dots bool) bool {
		if s == "" || len(s) > 512 {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || dots && c == '.') {
				return false
			}
		}
		return true
	}
	if !ok || !valid(svc, true) || !valid(meth, false) {
		return "", userError("--grpc-method expects package.Service/Method")
	}
	return "/" + svc + "/" + meth, nil
}

// grpcSampler sends one unary call with an empty request message over h2c
// (http://) or TLS (https://) and reads the identity from response metadata.
func grpcSampler(o SplitOptions) (splitSampler, error) {
	u, err := url.Parse(o.Probe.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, userError("a gRPC split expects http://HOST:PORT (h2c) or https://HOST:PORT without a path; choose the call with --grpc-method")
	}
	port := u.Port()
	if port == "" {
		if port = "80"; u.Scheme == "https" {
			port = "443"
		}
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, userError("invalid port")
	}
	method := o.GRPCMethod
	if method == "" {
		method = grpcHealthMethod
	}
	path, err := grpcPath(method)
	if err != nil {
		return nil, err
	}
	// Any other method may change server state; an empty message is still a call.
	if path != "/"+grpcHealthMethod && !o.Probe.AllowUnsafeMethod {
		return nil, userErrorf("calling %s may change server state: add --allow-unsafe-method to send it (with an empty message)", strings.TrimPrefix(path, "/"))
	}
	if err := o.Probe.validateRequest(); err != nil {
		return nil, err
	}
	for name := range o.Probe.RequestHeaders {
		if l := strings.ToLower(name); l == "content-type" || strings.HasPrefix(l, "grpc-") {
			return nil, userErrorf("request header %q is set by the gRPC call and cannot be overridden", name)
		}
	}
	timeout, err := splitTimeout(o.Probe)
	if err != nil {
		return nil, err
	}
	roots, err := loadRoots(o.Probe.CA)
	if err != nil {
		return nil, err
	}
	dial := u.Hostname()
	if o.Probe.Address != "" {
		dial = o.Probe.Address
	}
	target := net.JoinHostPort(dial, port)
	secure := u.Scheme == "https"
	return func() (splitSample, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		protos := new(http.Protocols)
		tr := &http.Transport{Protocols: protos, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		}}
		if secure {
			protos.SetHTTP2(true)
			tr.TLSClientConfig = &tls.Config{ServerName: u.Hostname(), RootCAs: roots}
		} else {
			protos.SetUnencryptedHTTP2(true)
		}
		defer tr.CloseIdleConnections()
		fail := func(f string, a ...any) (splitSample, error) {
			return splitSample{failed: "grpc: " + fmt.Sprintf(f, a...)}, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.Scheme+"://"+u.Host+path, bytes.NewReader(make([]byte, 5)))
		if err != nil {
			return splitSample{}, userErrorf("invalid target: %v", err)
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Header.Set("User-Agent", "zyvor-setura")
		for k, v := range o.Probe.RequestHeaders {
			req.Header.Set(k, v)
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return fail("%v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fail("HTTP status %d", resp.StatusCode)
		}
		// Trailers arrive only after the body has been read to its end.
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody+1))
		if err != nil {
			return fail("%v", err)
		}
		if n > maxBody {
			return fail("response is larger than %d bytes", maxBody)
		}
		code, msg := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
		if code == "" { // trailers-only response
			code, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
		}
		switch code {
		case "0":
		case "":
			return fail("response has no grpc-status")
		default:
			return fail("grpc-status %s %s", clipStr(code, 8), clipStr(msg, 200))
		}
		vals := resp.Header.Values(o.Identity)
		if len(vals) == 0 {
			vals = resp.Trailer.Values(o.Identity)
		}
		if len(vals) == 0 {
			return splitSample{ident: splitNone}, nil
		}
		return splitSample{ident: clipStr(strings.Join(vals, ", "), maxSplitNameLen)}, nil
	}, nil
}
