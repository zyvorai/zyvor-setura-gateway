package gateway

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func jsonUnmarshal(s string, v any) error   { return json.Unmarshal([]byte(s), v) }
func dialRaw(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
func bufioReader(c net.Conn) *bufio.Reader  { return bufio.NewReader(c) }

// httpTestUpgrade is a backend that switches protocols and echoes lines.
func httpTestUpgrade(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		rw.WriteString(line)
		rw.Flush()
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func tlsDial(addr string, p *pki, sni string) (*tls.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool, ServerName: sni})
}
