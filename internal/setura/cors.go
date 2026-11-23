package setura

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// CORS preflight verification. "setura cors" sends the OPTIONS request a
// browser would send and judges the answer against the rules of the Fetch
// standard's CORS-preflight fetch. It is a client-side check of one response,
// not a browser: it cannot see what a browser cache, an extension or a
// private-network policy would do.

const (
	maxCORSHeaders = 32
	maxCORSValue   = 2048
)

// CORSRequest is what a browser would ask in a preflight.
type CORSRequest struct {
	Origin      string
	Method      string
	Headers     []string // names the real request will send
	Credentials bool     // the real request will carry credentials
}

// CORSFinding is one verdict about a preflight response.
type CORSFinding struct {
	Level   string // "fail" or "warn"
	Message string
}

// ValidateCORSRequest checks the inputs of a preflight.
func ValidateCORSRequest(r CORSRequest) error {
	u, err := url.Parse(r.Origin)
	if r.Origin != "null" && (err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil || strings.ContainsAny(r.Origin, "\r\n \t")) {
		return userError("--origin must look like https://app.example (scheme, host and optional port only)")
	}
	if strings.HasSuffix(r.Origin, "/") {
		return userError("--origin must not end with a slash: browsers send the bare origin")
	}
	m := strings.TrimSpace(r.Method)
	if m == "" || len(m) > 32 {
		return userError("--request-method is required")
	}
	for i := 0; i < len(m); i++ {
		if !isTokenChar(m[i]) {
			return userError("--request-method has an invalid character")
		}
	}
	if len(r.Headers) > maxCORSHeaders {
		return userErrorf("at most %d --request-headers names are allowed", maxCORSHeaders)
	}
	for _, h := range r.Headers {
		if h == "" || len(h) > maxRequestHeaderName {
			return userError("header names in --request-headers must be 1 to 128 characters")
		}
		for i := 0; i < len(h); i++ {
			if !isTokenChar(h[i]) {
				return userErrorf("header name %q has an invalid character", h)
			}
		}
	}
	return nil
}

func corsList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// EvaluatePreflight judges a preflight response (status and headers) for r.
// It returns findings; a response passes when none has level "fail".
func EvaluatePreflight(r CORSRequest, status int, h http.Header) []CORSFinding {
	var f []CORSFinding
	fail := func(format string, a ...any) { f = append(f, CORSFinding{"fail", fmt.Sprintf(format, a...)}) }
	warn := func(format string, a ...any) { f = append(f, CORSFinding{"warn", fmt.Sprintf(format, a...)}) }

	if status < 200 || status > 299 {
		fail("preflight answered HTTP %d: browsers require a 2xx (200 or 204) answer to OPTIONS", status)
	}
	acao := h.Values("Access-Control-Allow-Origin")
	wildcardOK := !r.Credentials
	switch {
	case len(acao) == 0:
		fail("no Access-Control-Allow-Origin: the origin %s is not allowed", r.Origin)
	case len(acao) > 1 || strings.Contains(acao[0], ","):
		fail("Access-Control-Allow-Origin has several values; browsers accept exactly one")
	case acao[0] == "*":
		if r.Credentials {
			fail("Access-Control-Allow-Origin is * but the request carries credentials: browsers refuse a wildcard then")
		}
	case acao[0] != r.Origin:
		fail("Access-Control-Allow-Origin is %q, not the requesting origin %q", clipStr(acao[0], 80), r.Origin)
	default:
		if !varyHas(h, "Origin") {
			warn("Access-Control-Allow-Origin names a single origin but Vary does not include Origin: a shared cache can serve this answer to another origin")
		}
	}

	if r.Credentials {
		if v := h.Values("Access-Control-Allow-Credentials"); len(v) != 1 || v[0] != "true" {
			fail("credentials are requested but Access-Control-Allow-Credentials is not exactly \"true\"")
		}
	}

	methods := corsList(h.Values("Access-Control-Allow-Methods"))
	if !corsSafelistedMethod(r.Method) {
		switch {
		case hasToken(methods, "*") && wildcardOK:
		case hasToken(methods, "*"):
			fail("Access-Control-Allow-Methods is * but the request carries credentials: browsers do not honour the wildcard then, list %s explicitly", r.Method)
		case !hasExact(methods, r.Method):
			fail("Access-Control-Allow-Methods does not list %s", r.Method)
		}
	}

	allowed := corsList(h.Values("Access-Control-Allow-Headers"))
	star := hasToken(allowed, "*") && wildcardOK
	for _, name := range r.Headers {
		switch {
		case strings.EqualFold(name, "authorization"):
			// The wildcard never covers Authorization.
			if !hasFold(allowed, name) {
				fail("Access-Control-Allow-Headers does not list Authorization (a wildcard does not cover it)")
			}
		case corsSafelistedHeader(name):
		case star || hasFold(allowed, name):
		case hasToken(allowed, "*"):
			fail("Access-Control-Allow-Headers is * but the request carries credentials: list %s explicitly", name)
		default:
			fail("Access-Control-Allow-Headers does not list %s", name)
		}
	}

	if v := h.Values("Access-Control-Max-Age"); len(v) > 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(v[0])); err != nil || n < 0 || len(v) > 1 {
			fail("Access-Control-Max-Age %q is not a single non-negative integer", clipStr(strings.Join(v, ", "), 40))
		} else if n == 0 {
			warn("Access-Control-Max-Age is 0: browsers will send a preflight before every request")
		}
	}
	return f
}

func varyHas(h http.Header, name string) bool {
	for _, v := range corsList(h.Values("Vary")) {
		if v == "*" || strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

func hasToken(list []string, t string) bool {
	for _, v := range list {
		if v == t {
			return true
		}
	}
	return false
}

// hasExact compares methods case-sensitively, as the Fetch standard does for
// methods that are not normalised (DELETE, PUT and OPTIONS are upper-cased by
// a browser, so an upper-case entry is what has to be listed).
func hasExact(list []string, m string) bool { return hasToken(list, m) }

func hasFold(list []string, name string) bool {
	for _, v := range list {
		if strings.EqualFold(v, name) {
			return true
		}
	}
	return false
}

func corsSafelistedMethod(m string) bool { return m == "GET" || m == "HEAD" || m == "POST" }

// corsSafelistedHeader lists request headers a browser sends without
// preflight permission (Content-Type only for its three simple values, which
// this check cannot know, so Content-Type is treated as needing a listing).
func corsSafelistedHeader(n string) bool {
	switch strings.ToLower(n) {
	case "accept", "accept-language", "content-language":
		return true
	}
	return false
}

func runCORS(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	address := fs.String("address", "", "connect to this numeric IP, preserving Host and TLS identity")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	timeout := fs.Float64("timeout", 4, "timeout in seconds")
	origin := fs.String("origin", "", "the requesting origin, for example https://app.example (required)")
	method := fs.String("request-method", "GET", "the method the real request will use")
	headers := fs.String("request-headers", "", "comma-separated header names the real request will send")
	creds := fs.Bool("credentials", false, "the real request carries credentials (cookies or Authorization)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura cors: expected URL")
		return 2, usageError{"URL"}
	}
	req := CORSRequest{Origin: *origin, Method: strings.ToUpper(strings.TrimSpace(*method)), Headers: corsList([]string{*headers}), Credentials: *creds}
	if err := ValidateCORSRequest(req); err != nil {
		return 0, err
	}
	reqHdr := map[string]string{"Origin": req.Origin, "Access-Control-Request-Method": req.Method}
	if len(req.Headers) > 0 {
		reqHdr["Access-Control-Request-Headers"] = strings.ToLower(strings.Join(req.Headers, ","))
	}
	p := NewProbe(pos[0])
	p.Address, p.CA, p.Timeout = *address, *ca, *timeout
	p.Method, p.RequestHeaders = "OPTIONS", reqHdr
	var status int
	var hdr http.Header
	p.capture = func(r *http.Response) { status, hdr = r.StatusCode, r.Header.Clone() }
	rep, err := Probe(p)
	if err != nil {
		return 0, err
	}
	if hdr == nil {
		if *asJSON {
			return 1, writeJSON(stdout, obj{"ok": false, "error": failureReason(rep), "findings": []any{}})
		}
		fmt.Fprintf(stdout, "no preflight answer: %s\n", failureReason(rep))
		return 1, nil
	}
	findings := EvaluatePreflight(req, status, hdr)
	ok := true
	list := []any{}
	for _, f := range findings {
		if f.Level == "fail" {
			ok = false
		}
		list = append(list, obj{"level": f.Level, "message": f.Message})
	}
	if *asJSON {
		return boolExit(!ok), writeJSON(stdout, obj{"ok": ok, "status": status, "origin": req.Origin, "method": req.Method,
			"request_headers": nonNilStrings(req.Headers), "credentials": req.Credentials, "findings": list})
	}
	fmt.Fprintf(stdout, "OPTIONS %s -> HTTP %d  (origin %s, method %s)\n", pos[0], status, req.Origin, req.Method)
	for _, f := range findings {
		fmt.Fprintf(stdout, "%-4s %s\n", strings.ToUpper(f.Level), f.Message)
	}
	if ok {
		fmt.Fprintln(stdout, "PASS preflight would be accepted by a browser that follows the Fetch standard")
	}
	return boolExit(!ok), nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
