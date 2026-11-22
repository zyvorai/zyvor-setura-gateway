package setura

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// alpnProtos returns the ALPN list a probe offers. HTTP/2 probes offer only
// h2 so a server that cannot speak it is reported at the tls stage.
func alpnProtos(o ProbeOptions) []string {
	if o.HTTP2 {
		return []string{"h2", "http/1.1"}
	}
	return nil
}

// h2Transport returns an http.Transport that uses conn, an already
// established and verified TLS connection that negotiated h2, exactly once.
// Because the connection is dialed by the probe pipeline, --address pinning,
// the Host header and TLS identity checks are untouched.
func h2Transport(conn net.Conn, timeout time.Duration) *http.Transport {
	used := false
	return &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("connection already consumed")
			}
			used = true
			return conn, nil
		},
		ResponseHeaderTimeout: timeout,
	}
}

// h2Get issues GET path over conn using HTTP/2.
func h2Get(conn net.Conn, u *url.URL, path string, timeout time.Duration) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+u.Host+path, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Host = u.Host
	req.Header.Set("User-Agent", "zyvor-setura")
	resp, err := h2Transport(conn, timeout).RoundTrip(req)
	if err != nil {
		cancel()
		return nil, err
	}
	// The probe closes the body; release the context with it.
	resp.Body = &cancelBody{resp.Body, cancel}
	return resp, nil
}

type cancelBody struct {
	rc interface {
		Read([]byte) (int, error)
		Close() error
	}
	cancel context.CancelFunc
}

func (c *cancelBody) Read(p []byte) (int, error) { return c.rc.Read(p) }
func (c *cancelBody) Close() error               { c.cancel(); return c.rc.Close() }
