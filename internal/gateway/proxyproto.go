package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol (HAProxy spec, versions 1 and 2), inbound and outbound.
//
// Inbound: a listener named by --proxy-protocol only believes a header from the
// configured source networks. A trusted peer must send one (a connection
// without it is closed); any other peer is served as a plain connection, so a
// stranger cannot forge a client address. The address in the header becomes the
// connection's RemoteAddr, which is what --trusted-proxies, rate limits, the
// access log and the connections history all read.
//
// Outbound: a backend with proxyProtocol: v1|v2 gets a header first on every
// connection, carrying the client address.

const (
	ppV2Sig      = "\r\n\r\n\x00\r\nQUIT\n"
	ppV1Max      = 107
	ppReadWindow = 5 * time.Second
)

// proxyAddrs is what a PROXY header says about the connection.
type proxyAddrs struct {
	src, dst net.Addr // nil for LOCAL and UNKNOWN: keep the transport addresses
}

func readProxyHeader(br *bufio.Reader) (proxyAddrs, error) {
	sig, err := br.Peek(5)
	if err != nil {
		return proxyAddrs{}, fmt.Errorf("proxy protocol: %w", err)
	}
	if string(sig) == "PROXY" {
		return readProxyV1(br)
	}
	if b, err := br.Peek(len(ppV2Sig)); err == nil && string(b) == ppV2Sig {
		return readProxyV2(br)
	}
	return proxyAddrs{}, errors.New("proxy protocol: no PROXY header")
}

func readProxyV1(br *bufio.Reader) (proxyAddrs, error) {
	var line []byte
	for len(line) < ppV1Max {
		b, err := br.ReadByte()
		if err != nil {
			return proxyAddrs{}, fmt.Errorf("proxy protocol v1: %w", err)
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return proxyAddrs{}, errors.New("proxy protocol v1: header not terminated by CRLF within 107 bytes")
	}
	f := strings.Fields(string(line[:len(line)-2]))
	if len(f) < 2 || f[0] != "PROXY" {
		return proxyAddrs{}, errors.New("proxy protocol v1: malformed header")
	}
	switch f[1] {
	case "UNKNOWN":
		return proxyAddrs{}, nil
	case "TCP4", "TCP6":
	default:
		return proxyAddrs{}, fmt.Errorf("proxy protocol v1: unsupported protocol %q", f[1])
	}
	if len(f) != 6 {
		return proxyAddrs{}, errors.New("proxy protocol v1: want PROXY TCPx SRC DST SPORT DPORT")
	}
	src, err1 := netip.ParseAddr(f[2])
	dst, err2 := netip.ParseAddr(f[3])
	sp, err3 := strconv.ParseUint(f[4], 10, 16)
	dp, err4 := strconv.ParseUint(f[5], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || src.Is4() != (f[1] == "TCP4") || dst.Is4() != (f[1] == "TCP4") {
		return proxyAddrs{}, errors.New("proxy protocol v1: bad address or port")
	}
	return proxyAddrs{src: net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, uint16(sp))), dst: net.TCPAddrFromAddrPort(netip.AddrPortFrom(dst, uint16(dp)))}, nil
}

func readProxyV2(br *bufio.Reader) (proxyAddrs, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return proxyAddrs{}, fmt.Errorf("proxy protocol v2: %w", err)
	}
	if hdr[12]>>4 != 2 {
		return proxyAddrs{}, errors.New("proxy protocol v2: bad version")
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		return proxyAddrs{}, fmt.Errorf("proxy protocol v2: %w", err)
	}
	switch hdr[12] & 0x0f {
	case 0: // LOCAL: health check from the proxy itself
		return proxyAddrs{}, nil
	case 1:
	default:
		return proxyAddrs{}, errors.New("proxy protocol v2: unknown command")
	}
	var out proxyAddrs
	switch hdr[13] >> 4 {
	case 1: // AF_INET
		if n < 12 {
			return proxyAddrs{}, errors.New("proxy protocol v2: short IPv4 block")
		}
		s, _ := netip.AddrFromSlice(body[0:4])
		d, _ := netip.AddrFromSlice(body[4:8])
		out = proxyAddrs{src: tcpAddr(s, binary.BigEndian.Uint16(body[8:10])), dst: tcpAddr(d, binary.BigEndian.Uint16(body[10:12]))}
	case 2: // AF_INET6
		if n < 36 {
			return proxyAddrs{}, errors.New("proxy protocol v2: short IPv6 block")
		}
		s, _ := netip.AddrFromSlice(body[0:16])
		d, _ := netip.AddrFromSlice(body[16:32])
		out = proxyAddrs{src: tcpAddr(s, binary.BigEndian.Uint16(body[32:34])), dst: tcpAddr(d, binary.BigEndian.Uint16(body[34:36]))}
	default: // AF_UNSPEC and AF_UNIX: keep the transport addresses
	}
	return out, nil
}

func tcpAddr(a netip.Addr, port uint16) net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(a.Unmap(), port))
}

// ppListener wraps a listener so that connections from trusted sources get
// their PROXY header read lazily, on first use of the connection.
type ppListener struct {
	net.Listener
	trusted trustedNets
}

func (l *ppListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || !l.trusted.contains(a.AddrPort().Addr()) {
		return c, nil
	}
	return &ppConn{Conn: c, br: bufio.NewReaderSize(c, 512)}, nil
}

// wrapProxyProtocol applies --proxy-protocol to a freshly bound TCP listener.
func (s *Server) wrapProxyProtocol(spec int, ln net.Listener) net.Listener {
	if nets := s.opts.Cert.ProxyProtocol[spec]; len(nets) > 0 {
		return &ppListener{Listener: ln, trusted: trustedNets(nets)}
	}
	return ln
}

// ppConn parses the header on first Read, RemoteAddr or LocalAddr. net/http and
// the raw proxies ask for the remote address on the connection's own goroutine,
// so the wait never blocks Accept.
type ppConn struct {
	net.Conn
	br       *bufio.Reader
	once     sync.Once
	err      error
	src, dst net.Addr
}

func (c *ppConn) init() {
	c.once.Do(func() {
		c.Conn.SetReadDeadline(time.Now().Add(ppReadWindow))
		h, err := readProxyHeader(c.br)
		c.Conn.SetReadDeadline(time.Time{})
		if err != nil {
			c.err = err
			c.Conn.Close()
			return
		}
		c.src, c.dst = h.src, h.dst
	})
}

func (c *ppConn) Read(p []byte) (int, error) {
	if c.init(); c.err != nil {
		return 0, c.err
	}
	return c.br.Read(p)
}

func (c *ppConn) RemoteAddr() net.Addr {
	if c.init(); c.src != nil {
		return c.src
	}
	return c.Conn.RemoteAddr()
}

func (c *ppConn) LocalAddr() net.Addr {
	if c.init(); c.dst != nil {
		return c.dst
	}
	return c.Conn.LocalAddr()
}

func (c *ppConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// ---- outbound ----

// ValidProxyVersion checks a backend's proxyProtocol value.
func validProxyVersion(v string) error {
	switch v {
	case "", "v1", "v2":
		return nil
	}
	return fmt.Errorf("proxyProtocol %q: want v1 or v2", v)
}

// encodeProxyHeader builds a header for a client connection src -> dst. Without
// a usable pair (health checks, mirrors) it builds the LOCAL/UNKNOWN form that
// tells the backend there is no client behind the connection.
func encodeProxyHeader(version string, src, dst net.Addr) []byte {
	sa, _ := src.(*net.TCPAddr)
	da, _ := dst.(*net.TCPAddr)
	ok := sa != nil && da != nil
	var sip, dip netip.Addr
	if ok {
		sip, dip = sa.AddrPort().Addr().Unmap(), da.AddrPort().Addr().Unmap()
		ok = sip.IsValid() && dip.IsValid() && sip.Is4() == dip.Is4()
	}
	if version == "v1" {
		if !ok {
			return []byte("PROXY UNKNOWN\r\n")
		}
		fam := "TCP6"
		if sip.Is4() {
			fam = "TCP4"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, sip, dip, sa.Port, da.Port))
	}
	b := []byte(ppV2Sig)
	if !ok {
		return append(b, 0x20, 0x00, 0, 0) // LOCAL, AF_UNSPEC
	}
	var blk []byte
	fam := byte(0x11)
	if sip.Is4() {
		s4, d4 := sip.As4(), dip.As4()
		blk = append(append(s4[:], d4[:]...), 0, 0, 0, 0)
	} else {
		fam = 0x21
		s6, d6 := sip.As16(), dip.As16()
		blk = append(append(s6[:], d6[:]...), 0, 0, 0, 0)
	}
	binary.BigEndian.PutUint16(blk[len(blk)-4:], uint16(sa.Port))
	binary.BigEndian.PutUint16(blk[len(blk)-2:], uint16(da.Port))
	b = append(b, 0x21, fam, byte(len(blk)>>8), byte(len(blk)))
	return append(b, blk...)
}

type proxyCtxKey struct{}

// proxyClient is what the dialer puts into a header: the client and the
// gateway address it connected to.
type proxyClient struct{ src, dst net.Addr }

// withProxyClient records the inbound connection of r on its context, for the
// dialers of backends that want a PROXY header.
func withProxyClient(ctx context.Context, src, dst net.Addr) context.Context {
	return context.WithValue(ctx, proxyCtxKey{}, proxyClient{src, dst})
}

// proxyDialer dials a backend and writes the PROXY header before anything else.
// It is used by transports that disable keep-alives, so a connection never
// carries more than one client's requests.
func proxyDialer(version string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		pc, _ := ctx.Value(proxyCtxKey{}).(proxyClient)
		if _, err := c.Write(encodeProxyHeader(version, pc.src, pc.dst)); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
}

// writeProxyTo sends the header on a raw upstream connection of a TLS
// passthrough or TCP route when the backend asks for it.
func writeProxyTo(up net.Conn, b *Backend, client net.Conn) error {
	if b == nil || b.ProxyProto == "" {
		return nil
	}
	_, err := up.Write(encodeProxyHeader(b.ProxyProto, client.RemoteAddr(), client.LocalAddr()))
	return err
}
