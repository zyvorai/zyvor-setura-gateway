package gateway

import (
	"net"
	"net/http"
	"time"
)

// enableH2C lets a plain-TCP server speak HTTP/2 with prior knowledge (h2c)
// next to HTTP/1.1. TLS ports negotiate h2 through ALPN already.
func enableH2C(srv *http.Server, tlsPort bool) {
	if tlsPort {
		return
	}
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Protocols = &p
}

// newH2CTransport dials http:// gRPC backends with HTTP/2 prior knowledge.
func newH2CTransport() *http.Transport {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Transport{Protocols: &p,
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:    256,
		IdleConnTimeout: 90 * time.Second}
}
