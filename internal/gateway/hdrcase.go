package gateway

import "net/http"

// Go canonicalises header names (Www-Authenticate, X-Ratelimit-Limit). HTTP
// header names are case-insensitive and HTTP/2 lowercases them, but the
// documented spellings of these two families are what people grep for and some
// HTTP/1 clients and tests compare, so on HTTP/1 the gateway sends them as
// documented by storing the key as written (net/http writes map keys as-is).

const (
	hdrWWWAuthenticate = "WWW-Authenticate"
	hdrRLLimit         = "X-RateLimit-Limit"
	hdrRLRemaining     = "X-RateLimit-Remaining"
	hdrRLReset         = "X-RateLimit-Reset"
)

// setExact sets a header keeping the spelling of name.
func setExact(h http.Header, name, value string) {
	h[name] = []string{value}
}

// addExact appends a value keeping the spelling of name.
func addExact(h http.Header, name, value string) {
	h[name] = append(h[name], value)
}
