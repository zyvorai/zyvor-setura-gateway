//go:build !go1.24

package gateway

import "net/http"

// Before Go 1.24 the standard library cannot serve or dial cleartext HTTP/2,
// so gRPC works on TLS listeners and https:// backends only.
func enableH2C(*http.Server, bool) {}

func newH2CTransport() *http.Transport { return nil }
