package gateway

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// CSRFPolicy protects the unsafe methods of a route against cross-site
// requests: the Origin header (or, without one, the Referer) of a POST, PUT,
// PATCH or DELETE must be the origin the request is addressed to, or one of
// AllowedOrigins. A request that carries a bearer token in Authorization is
// exempt: a browser does not attach that on its own, so it cannot be forged
// by another site.
type CSRFPolicy struct {
	// AllowedOrigins are extra accepted origins (scheme://host[:port]).
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
	// SafeMethods are never checked (default GET, HEAD, OPTIONS, TRACE).
	SafeMethods []string `json:"safeMethods,omitempty"`
	// RequireOrigin refuses an unsafe request that has neither Origin nor
	// Referer (default: such a request is a non-browser client and passes).
	RequireOrigin bool `json:"requireOrigin,omitempty"`
}

type compiledCSRF struct {
	allowed map[string]bool
	safe    map[string]bool
	require bool
}

func compileCSRF(p *CSRFPolicy) (*compiledCSRF, error) {
	c := &compiledCSRF{allowed: map[string]bool{}, safe: map[string]bool{}, require: p.RequireOrigin}
	for _, o := range p.AllowedOrigins {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return nil, fmt.Errorf("csrf.allowedOrigins %q: want scheme://host[:port]", o)
		}
		c.allowed[originOf(u.Scheme, u.Host)] = true
	}
	ms := p.SafeMethods
	if len(ms) == 0 {
		ms = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	}
	for _, m := range ms {
		c.safe[strings.ToUpper(m)] = true
	}
	return c, nil
}

// originOf renders scheme://host with the default port removed and the host lower-cased.
func originOf(scheme, host string) string {
	scheme, host = strings.ToLower(scheme), strings.ToLower(host)
	def := ":80"
	if scheme == "https" {
		def = ":443"
	}
	host = strings.TrimSuffix(host, def)
	return scheme + "://" + host
}

// check returns "" when the request passes, else the reason. https says
// whether the request arrived over TLS.
func (c *compiledCSRF) check(r *http.Request, https bool) string {
	if c == nil || c.safe[strings.ToUpper(r.Method)] {
		return ""
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return ""
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	self := originOf(scheme, r.Host)
	ok := func(o string) bool { return o == self || c.allowed[o] }
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return "csrf: the Origin header is not an origin (" + clip(cleanHeaderValue(o), 40) + ")"
		}
		if !ok(originOf(u.Scheme, u.Host)) {
			return "csrf: cross-origin " + r.Method + " from " + clip(originOf(u.Scheme, u.Host), 80)
		}
		return ""
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" {
			return "csrf: the Referer header is not a URL"
		}
		if !ok(originOf(u.Scheme, u.Host)) {
			return "csrf: cross-origin " + r.Method + " referred from " + clip(originOf(u.Scheme, u.Host), 80)
		}
		return ""
	}
	if c.require {
		return "csrf: " + r.Method + " without an Origin or Referer header"
	}
	return ""
}

// InjectDef puts a secret into a header of the request sent upstream, after
// removing whatever the client sent under that name. Scheme "" sends the
// secret as is, "Bearer" sends "Bearer SECRET", "Basic" sends the base64 of
// "USERNAME:SECRET" (without a username the secret is taken to be
// "user:password" already).
type InjectDef struct {
	Header   string       `json:"header"`
	Secret   *AISecretRef `json:"secret"`
	Scheme   string       `json:"scheme,omitempty"`
	Username string       `json:"username,omitempty"`
}

type cInject struct {
	d   InjectDef
	sec *aiSecret // nil until the secrets are resolved (offline views)
}

func (d InjectDef) validate(i int) error {
	w := fmt.Sprintf("inject[%d]", i)
	if d.Header == "" || strings.ContainsAny(d.Header, " :\r\n") || strings.EqualFold(d.Header, "host") {
		return fmt.Errorf("%s.header: bad header name %q", w, d.Header)
	}
	switch d.Scheme {
	case "", "Bearer", "Basic":
	default:
		return fmt.Errorf("%s.scheme %q: want Bearer or Basic (or leave it out)", w, d.Scheme)
	}
	if d.Username != "" && d.Scheme != "Basic" {
		return fmt.Errorf("%s.username only applies to scheme Basic", w)
	}
	return validateSecretRef(w+".secret", d.Secret, true)
}

// validateSecretRef checks that exactly one source is named. A secret value
// written into a route would be visible to everyone who can read it, so there
// is no inline value.
func validateSecretRef(where string, r *AISecretRef, required bool) error {
	if r == nil {
		if required {
			return fmt.Errorf("%s: required; name exactly one of env, file or secret (a secret written into the route would be visible to everyone who can read it)", where)
		}
		return nil
	}
	n := 0
	if r.Env != "" {
		n++
	}
	if r.File != "" {
		n++
	}
	if r.Secret != nil {
		n++
		if r.Secret.Name == "" || r.Secret.Key == "" {
			return fmt.Errorf("%s: secret needs name and key", where)
		}
	}
	if n != 1 {
		return fmt.Errorf("%s: needs exactly one of env, file or secret", where)
	}
	return nil
}

// value is the header value for the current secret.
func (c *cInject) value(sec *aiSecret) string {
	if sec == nil {
		return redacted
	}
	s := sec.get()
	switch c.d.Scheme {
	case "Bearer":
		return "Bearer " + s
	case "Basic":
		if c.d.Username != "" {
			s = c.d.Username + ":" + s
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	}
	return s
}
