package gateway

import (
	"crypto/tls"
	"net"
	"time"
)

// replayConn serves bytes that were already read from the socket (the
// ClientHello) before reading on.
type replayConn struct {
	net.Conn
	pre []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// terminateTLS finishes the TLS handshake on a connection whose ClientHello
// was already read (raw), using the certificate selection of the HTTPS
// listeners. The ALPN protocols offered to the client are those named by the
// listener's TLSRoute rules, so a client that offers only others is refused
// by the handshake. It returns the decrypted connection and the negotiated
// protocol.
func (s *Server) terminateTLS(c net.Conn, raw []byte, port int, l *RTListener) (*tls.Conn, string, error) {
	var protos []string
	seen := map[string]bool{}
	for _, e := range l.TLSEntries {
		for _, p := range e.ALPN {
			if !seen[p] {
				seen[p] = true
				protos = append(protos, p)
			}
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: protos,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return s.certFor(port, h.ServerName) }}
	tc := tls.Server(&replayConn{Conn: c, pre: raw}, cfg)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, "", err
	}
	c.SetDeadline(time.Time{})
	return tc, tc.ConnectionState().NegotiatedProtocol, nil
}
