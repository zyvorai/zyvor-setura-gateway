package gateway

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// CORS is the HTTPRoute CORS filter (Gateway API 1.5, standard channel).
type CORS struct {
	AllowOrigins     []string `json:"allowOrigins,omitempty"`
	AllowCredentials *bool    `json:"allowCredentials,omitempty"`
	AllowMethods     []string `json:"allowMethods,omitempty"`
	AllowHeaders     []string `json:"allowHeaders,omitempty"`
	ExposeHeaders    []string `json:"exposeHeaders,omitempty"`
	MaxAge           int      `json:"maxAge,omitempty"`
}

// defaultCORSMaxAge is the spec default for maxAge, in seconds.
const defaultCORSMaxAge = 5

func (c *CORS) credentials() bool { return c.AllowCredentials != nil && *c.AllowCredentials }

// validate rejects a filter that cannot do what it says.
func (c *CORS) validate() error {
	if c.MaxAge < 0 {
		return fmt.Errorf("cors.maxAge must not be negative")
	}
	for _, o := range c.AllowOrigins {
		if o == "*" {
			continue
		}
		u, err := url.Parse(o)
		if strings.Contains(o, "*") {
			u, err = url.Parse(strings.Replace(o, "*", "w", 1))
			if strings.Count(o, "*") != 1 || !(strings.Contains(o, "://*.") || strings.HasSuffix(o, "://*")) {
				return fmt.Errorf("cors.allowOrigins %q: a wildcard must lead the host (scheme://*.example.com or scheme://*)", o)
			}
		}
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
			return fmt.Errorf("cors.allowOrigins %q must be * or scheme://host[:port]", o)
		}
	}
	return nil
}

// originMatches reports whether origin satisfies one allowOrigins entry.
func originMatches(pattern, origin string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, origin)
	}
	ps, ph, _ := strings.Cut(pattern, "://")
	os, oh, ok := strings.Cut(origin, "://")
	if !ok || !strings.EqualFold(ps, os) {
		return false
	}
	if ph == "*" {
		return true // any host of that scheme
	}
	suffix := strings.TrimPrefix(ph, "*") // ".example.com[:port]"
	oh = strings.ToLower(oh)
	suffix = strings.ToLower(suffix)
	return len(oh) > len(suffix) && strings.HasSuffix(oh, suffix) && !strings.HasPrefix(oh, ".")
}

// allowOrigin returns the Access-Control-Allow-Origin value for an Origin and
// whether the response varies by origin (it echoes it).
func (c *CORS) allowOrigin(origin string) (value string, ok, echo bool) {
	if origin == "" {
		return "", false, false
	}
	wildcard := false
	for _, p := range c.AllowOrigins {
		if p == "*" {
			wildcard = true
		} else if originMatches(p, origin) {
			return origin, true, true
		}
	}
	if wildcard {
		if c.credentials() {
			return origin, true, true // "*" is not valid with credentials; echo
		}
		return "*", true, false
	}
	return "", false, false
}

func joinList(v []string) string { return strings.Join(v, ", ") }

func hasStar(v []string) bool {
	for _, s := range v {
		if s == "*" {
			return true
		}
	}
	return false
}

// isPreflight reports whether r is a CORS preflight request.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != ""
}

// preflightHeaders builds the headers the gateway answers a preflight with.
// A disallowed origin gets none (the browser then blocks the request).
func (c *CORS) preflightHeaders(in *http.Request) http.Header {
	h := http.Header{}
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	origin, ok, _ := c.allowOrigin(in.Header.Get("Origin"))
	if !ok {
		return h
	}
	h.Set("Access-Control-Allow-Origin", origin)
	if c.credentials() {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	switch {
	case hasStar(c.AllowMethods) && c.credentials():
		h.Set("Access-Control-Allow-Methods", in.Header.Get("Access-Control-Request-Method"))
	case hasStar(c.AllowMethods):
		h.Set("Access-Control-Allow-Methods", "*")
	case len(c.AllowMethods) > 0:
		h.Set("Access-Control-Allow-Methods", joinList(c.AllowMethods))
	}
	switch {
	case hasStar(c.AllowHeaders) && c.credentials():
		if rh := in.Header.Get("Access-Control-Request-Headers"); rh != "" {
			h.Set("Access-Control-Allow-Headers", rh)
		}
	case hasStar(c.AllowHeaders):
		h.Set("Access-Control-Allow-Headers", "*")
	case len(c.AllowHeaders) > 0:
		h.Set("Access-Control-Allow-Headers", joinList(c.AllowHeaders))
	}
	age := c.MaxAge
	if age == 0 {
		age = defaultCORSMaxAge
	}
	h.Set("Access-Control-Max-Age", strconv.Itoa(age))
	return h
}

// applyResponse adds the CORS headers of an actual (non-preflight) response.
func (c *CORS) applyResponse(h http.Header, in *http.Request) {
	origin, ok, echo := c.allowOrigin(in.Header.Get("Origin"))
	if echo || (!ok && !hasStar(c.AllowOrigins)) {
		h.Add("Vary", "Origin")
	}
	if !ok {
		return
	}
	h.Set("Access-Control-Allow-Origin", origin)
	if c.credentials() {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if len(c.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", joinList(c.ExposeHeaders))
	}
}

// corsOf returns the CORS filter among fs (the first one wins).
func corsOf(fs []Filter) *CORS {
	for _, f := range fs {
		if f.Type == "CORS" && f.CORS != nil {
			return f.CORS
		}
	}
	return nil
}

// preflightTarget finds the CORS policy that answers a preflight for r on
// listener l. A preflight is routed as the request it announces
// (Access-Control-Request-Method), so a rule matching only GET still answers
// the OPTIONS that precedes a GET. It returns nil when r is not a preflight or
// the winning rule has no CORS filter.
func (l *RTListener) preflightTarget(r *http.Request, host string) (*Entry, *CORS) {
	if !isPreflight(r) {
		return nil, nil
	}
	rr := r.Clone(r.Context())
	rr.Method = strings.ToUpper(r.Header.Get("Access-Control-Request-Method"))
	e := l.selectEntry(rr, host)
	if e == nil {
		return nil, nil
	}
	fs := append([]Filter(nil), e.Rule.Rule.Filters...)
	if len(e.Rule.Refs) == 1 { // a single backendRef's filters are unambiguous
		fs = append(fs, e.Rule.Refs[0].Filters...)
	}
	if c := corsOf(fs); c != nil {
		return e, c
	}
	return nil, nil
}

func describeCORS(c *CORS) string {
	parts := []string{"origins " + joinList(c.AllowOrigins)}
	if c.credentials() {
		parts = append(parts, "credentials")
	}
	if len(c.AllowMethods) > 0 {
		parts = append(parts, "methods "+joinList(c.AllowMethods))
	}
	if len(c.AllowHeaders) > 0 {
		parts = append(parts, "headers "+joinList(c.AllowHeaders))
	}
	if len(c.ExposeHeaders) > 0 {
		parts = append(parts, "exposes "+joinList(c.ExposeHeaders))
	}
	return "CORS: " + strings.Join(parts, "; ") + "; preflights are answered by the gateway"
}
