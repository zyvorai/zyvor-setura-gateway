package setura

import (
	"bytes"
	"fmt"
	"strings"
)

// Request shaping for probes. A GET with only a Host header cannot verify a
// route that matches on method or request header, a CORS preflight, or a
// header-based canary. These limits keep a check file or flag from turning
// the verifier into a request smuggler or a bulk sender.
const (
	maxRequestHeaders     = 32
	maxRequestHeaderName  = 128
	maxRequestHeaderValue = 4096
	maxRequestHeaderBytes = 16 << 10
)

// safeMethods never change server state by convention. Other methods need the
// caller to say so (allow_unsafe_method / --allow-unsafe-method) and are sent
// without a body.
var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}
var unsafeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// connectionHeaders belong to the transport and framing; a probe that set them
// could desynchronise itself from the gateway or fake another Host.
var connectionHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true, "keep-alive": true, "expect": true,
	"proxy-connection": true, "http2-settings": true,
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// requestMethod returns the validated upper-case method for o.
func (o ProbeOptions) requestMethod() (string, error) {
	m := strings.ToUpper(strings.TrimSpace(o.Method))
	if m == "" {
		return "GET", nil
	}
	switch {
	case safeMethods[m]:
		return m, nil
	case unsafeMethods[m]:
		if !o.AllowUnsafeMethod {
			return "", userErrorf("method %s can change server state: add --allow-unsafe-method (allow_unsafe_method) to send it; the probe never sends a body", m)
		}
		return m, nil
	}
	return "", userErrorf("unsupported method %q: use GET, HEAD, OPTIONS, or POST, PUT, PATCH, DELETE with --allow-unsafe-method", o.Method)
}

// validateRequest checks the method and request headers. It never echoes a
// header value, which may be a credential.
func (o ProbeOptions) validateRequest() error {
	if _, err := o.requestMethod(); err != nil {
		return err
	}
	if len(o.RequestHeaders) > maxRequestHeaders {
		return userErrorf("at most %d request headers are allowed", maxRequestHeaders)
	}
	seen := map[string]bool{}
	total := 0
	for name, v := range o.RequestHeaders {
		if name == "" || len(name) > maxRequestHeaderName {
			return userErrorf("request header names must be 1 to %d characters", maxRequestHeaderName)
		}
		for i := 0; i < len(name); i++ {
			if !isTokenChar(name[i]) {
				return userErrorf("request header name %q has an invalid character", name)
			}
		}
		l := strings.ToLower(name)
		if connectionHeaders[l] {
			return userErrorf("request header %s is set by the probe and cannot be overridden (the URL host is the Host header; use --address to pick the server)", name)
		}
		if seen[l] {
			return userErrorf("request header %s is given twice", name)
		}
		seen[l] = true
		if len(v) > maxRequestHeaderValue {
			return userErrorf("request header %s is longer than %d bytes", name, maxRequestHeaderValue)
		}
		for i := 0; i < len(v); i++ {
			if c := v[i]; (c < 0x20 && c != '\t') || c == 0x7f {
				return userErrorf("request header %s contains a control character", name)
			}
		}
		total += len(name) + len(v) + 4
	}
	if total > maxRequestHeaderBytes {
		return userErrorf("request headers total more than %d bytes", maxRequestHeaderBytes)
	}
	return nil
}

// writeRequestHead renders an HTTP/1.1 request head. Headers are sorted so the
// bytes are deterministic.
func (o ProbeOptions) writeRequestHead(method, path, host string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, path, host)
	ua := true
	for _, n := range sortedKeys(o.RequestHeaders) {
		if strings.EqualFold(n, "user-agent") {
			ua = false
		}
		fmt.Fprintf(&b, "%s: %s\r\n", n, o.RequestHeaders[n])
	}
	if ua {
		b.WriteString("User-Agent: zyvor-setura\r\n")
	}
	if unsafeMethods[method] {
		b.WriteString("Content-Length: 0\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// parseRequestHeaderFlags turns repeated "Name: value" flags into a map.
func parseRequestHeaderFlags(flags []string) (map[string]string, error) {
	if len(flags) == 0 {
		return nil, nil
	}
	m := map[string]string{}
	for _, h := range flags {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, userError("--request-header expects \"Name: value\"")
		}
		if _, dup := m[name]; dup {
			return nil, userErrorf("request header %s is given twice", name)
		}
		m[name] = strings.TrimSpace(value)
	}
	return m, nil
}

// applyCheckRequest reads the request-shaping keys of one check case into o.
func applyCheckRequest(m obj, o *ProbeOptions) error {
	if v, ok := m["method"]; ok {
		s, isStr := v.(string)
		if !isStr {
			return userError("method must be a string")
		}
		o.Method = s
	}
	if v, ok := m["allow_unsafe_method"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return userError("allow_unsafe_method must be true or false")
		}
		o.AllowUnsafeMethod = b
	}
	if h, ok := m["request_headers"]; ok {
		hm := asMap(h)
		if hm == nil {
			return userError("request_headers must be an object of header names to values")
		}
		o.RequestHeaders = map[string]string{}
		for k, v := range hm {
			sv, isStr := v.(string)
			if !isStr {
				return userErrorf("request header %s must be a string", k)
			}
			o.RequestHeaders[k] = sv
		}
	}
	return nil
}

var requestCheckKeys = []string{"method", "allow_unsafe_method", "request_headers"}
