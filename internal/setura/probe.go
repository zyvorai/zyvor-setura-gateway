package setura

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxBody bounds how much of a response body an assertion will read.
const maxBody = 1 << 20

// Probe stage names, in the order they are attempted and reported.
var stages = []string{"dns", "tcp", "tls", "http", "backend", "assert"}

type kv struct {
	K string
	V any
}

// Step is an ordered set of fields describing one probe stage.
type Step []kv

func (s Step) Get(k string) any {
	for _, p := range s {
		if p.K == k {
			return p.V
		}
	}
	return nil
}

func (s *Step) Set(k string, v any) {
	for i := range *s {
		if (*s)[i].K == k {
			(*s)[i].V = v
			return
		}
	}
	*s = append(*s, kv{k, v})
}

func (s Step) State() string { return asStr(s.Get("state")) }

func (s Step) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, p := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(p.K)
		v, err := marshalNoEscape(p.V)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Report is the result of one probe.
type Report struct {
	URL       string
	OK        bool
	Steps     map[string]*Step
	ElapsedMS float64
}

func (r *Report) Step(name string) Step { return *r.Steps[name] }

func (r *Report) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	url, _ := marshalNoEscape(r.URL)
	fmt.Fprintf(&b, `{"url":%s,"ok":%t,"steps":{`, url, r.OK)
	for i, name := range stages {
		if i > 0 {
			b.WriteByte(',')
		}
		step, err := r.Steps[name].MarshalJSON()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, `"%s":%s`, name, step)
	}
	ms, _ := json.Marshal(r.ElapsedMS)
	fmt.Fprintf(&b, `},"elapsed_ms":%s}`, ms)
	return b.Bytes(), nil
}

// ProbeOptions describes one request. Use NewProbe for defaults.
type ProbeOptions struct {
	URL     string
	Address string
	CA      string
	Backend string // empty means no identity assertion
	Status  int
	Timeout float64

	// Optional response assertions. Header values are compared exactly; the
	// value "*" only requires the header to be present.
	Headers      map[string]string
	BodyContains string
	MaxMS        float64 // total latency budget in milliseconds; 0 disables

	// Optional TLS client authentication and policy (see mtls.go).
	Cert, Key      string
	ServerName     string
	MinTLS         string
	WarnExpiryDays int
	MinCertDays    int
}

// NewProbe returns options with the default expected status (200) and timeout (4s).
func NewProbe(url string) ProbeOptions { return ProbeOptions{URL: url, Status: 200, Timeout: 4} }

// lookupIP is replaced in tests to inject DNS failures.
var lookupIP = func(host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out, nil
}

var tlsNames = map[uint16]string{
	tls.VersionTLS10: "TLSv1", tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2", tls.VersionTLS13: "TLSv1.3",
}

// Probe observes one direct HTTP/1.1 request from the current host.
// Input validation failures return an error; network failures are recorded in
// the returned report.
func Probe(o ProbeOptions) (*Report, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return nil, userError("expected an absolute HTTP(S) URL without credentials")
	}
	if u.Fragment != "" || strings.ContainsAny(o.URL, "#") && u.Fragment != "" {
		return nil, userError("encode spaces and omit fragments and control characters")
	}
	for _, c := range o.URL {
		if c < 33 || c == 127 {
			return nil, userError("encode spaces and omit fragments and control characters")
		}
	}
	host := strings.ToLower(u.Hostname())
	secure := u.Scheme == "https"
	port := 80
	if secure {
		port = 443
	}
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return nil, userError("invalid port or expected HTTP status")
		}
	}
	if port < 1 || port > 65535 || o.Status < 100 || o.Status > 599 {
		return nil, userError("invalid port or expected HTTP status")
	}
	if !(o.Timeout > 0 && o.Timeout <= 60) || math.IsNaN(o.Timeout) {
		return nil, userError("timeout must be positive and at most 60 seconds")
	}
	if o.MaxMS < 0 || math.IsNaN(o.MaxMS) {
		return nil, userError("max latency must not be negative")
	}
	if o.Address != "" && net.ParseIP(o.Address) == nil {
		return nil, userErrorf("%s does not appear to be an IPv4 or IPv6 address", pyRepr(o.Address))
	}
	if err := o.tlsOpts().validate(); err != nil {
		return nil, err
	}
	timeout := time.Duration(o.Timeout * float64(time.Second))

	r := &Report{URL: o.URL, Steps: map[string]*Step{}}
	for _, name := range stages {
		r.Steps[name] = &Step{{"state", "untested"}}
	}
	if !secure {
		r.Steps["tls"] = &Step{{"state", "unused"}}
	}
	if o.Backend == "" {
		r.Steps["backend"] = &Step{{"state", "unused"}}
	}
	asserting := len(o.Headers) > 0 || o.BodyContains != "" || o.MaxMS > 0
	if !asserting {
		r.Steps["assert"] = &Step{{"state", "unused"}}
	}

	stage := "dns"
	start := time.Now()
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	var mst *mtlsState
	fail := func(err error) {
		if reason, ok := clientCertFailure(err, mst); ok {
			r.Steps["tls"].Set("state", "failed")
			r.Steps["tls"].Set("reason", reason)
			r.Steps["tls"].Set("client_cert", "rejected")
			return
		}
		step := r.Steps[stage]
		step.Set("state", "failed")
		step.Set("reason", err.Error())
	}
	run := func() error {
		var addrs []string
		if o.Address != "" {
			addrs = []string{o.Address}
			r.Steps[stage] = &Step{{"state", "overridden"}, {"addresses", addrs}}
		} else {
			found, err := lookupIP(host)
			if err != nil {
				return err
			}
			seen := map[string]bool{}
			for _, a := range found {
				if !seen[a] {
					seen[a] = true
					addrs = append(addrs, a)
				}
			}
			r.Steps[stage] = &Step{{"state", "ok"}, {"addresses", addrs}}
		}

		stage = "tcp"
		lastErr := fmt.Errorf("no addresses returned")
		for _, a := range addrs {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(a, strconv.Itoa(port)), timeout)
			if err != nil {
				lastErr = err
				continue
			}
			conn = c
			break
		}
		if conn == nil {
			return lastErr
		}
		peer := conn.RemoteAddr().String()
		if h, _, err := net.SplitHostPort(peer); err == nil {
			peer = h
		}
		r.Steps[stage] = &Step{{"state", "ok"}, {"peer", peer}}

		if secure {
			stage = "tls"
			cfg := &tls.Config{ServerName: host}
			if o.CA != "" {
				pem, err := os.ReadFile(o.CA)
				if err != nil {
					return err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return fmt.Errorf("no certificates found in %s", o.CA)
				}
				cfg.RootCAs = pool
			}
			var err error
			if mst, err = o.tlsOpts().configure(cfg); err != nil {
				return err
			}
			tc := tls.Client(conn, cfg)
			conn = tc
			_ = tc.SetDeadline(time.Now().Add(timeout))
			if err := tc.Handshake(); err != nil {
				return err
			}
			step, reason := o.tlsOpts().tlsStep(tc.ConnectionState(), mst)
			r.Steps[stage] = step
			if reason != "" {
				return fmt.Errorf("%s", reason)
			}
		}

		stage = "http"
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: zyvor-setura\r\n\r\n", path, u.Host); err != nil {
			return err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		r.Steps[stage] = &Step{{"state", "ok"}, {"status", resp.StatusCode}, {"expected", o.Status}}
		if resp.StatusCode != o.Status {
			return fmt.Errorf("expected HTTP %d, received %d", o.Status, resp.StatusCode)
		}
		if o.Backend != "" {
			stage = "backend"
			actual := "None"
			if vals := resp.Header.Values("X-Setura-Backend"); len(vals) > 0 {
				actual = pyRepr(strings.Join(vals, ", "))
			}
			if actual != pyRepr(o.Backend) {
				return fmt.Errorf("expected %s, received %s", pyRepr(o.Backend), actual)
			}
			r.Steps[stage] = &Step{{"state", "ok"}, {"identity", o.Backend}}
		}
		if asserting {
			stage = "assert"
			checked := 0
			for _, name := range sortedKeys(o.Headers) {
				want := o.Headers[name]
				vals := resp.Header.Values(name)
				if len(vals) == 0 {
					return fmt.Errorf("header %s is missing", name)
				}
				if got := strings.Join(vals, ", "); want != "*" && got != want {
					return fmt.Errorf("header %s: expected %s, received %s", name, pyRepr(want), pyRepr(got))
				}
				checked++
			}
			if o.BodyContains != "" {
				body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
				if err != nil {
					return err
				}
				if !bytes.Contains(body, []byte(o.BodyContains)) {
					return fmt.Errorf("response body does not contain %s", pyRepr(o.BodyContains))
				}
				checked++
			}
			elapsed := float64(time.Since(start).Microseconds()) / 1000
			if o.MaxMS > 0 {
				if elapsed > o.MaxMS {
					return fmt.Errorf("responded in %.1f ms, budget is %.1f ms", elapsed, o.MaxMS)
				}
				checked++
			}
			r.Steps[stage] = &Step{{"state", "ok"}, {"checks", checked}}
		}
		return nil
	}
	if err := run(); err != nil {
		fail(err)
	} else {
		r.OK = true
	}
	r.ElapsedMS = math.Round(float64(time.Since(start).Microseconds())/100) / 10
	return r, nil
}
