package gateway

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawHead sends a minimal HTTP/1.1 request and returns the response head as sent.
func rawHead(t *testing.T, addr, host string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	var head strings.Builder
	br := bufio.NewReader(c)
	for {
		ln, err := br.ReadString('\n')
		head.WriteString(ln)
		if err != nil || ln == "\r\n" {
			return head.String()
		}
	}
}

func TestChallengeHeaderKeepsDocumentedSpelling(t *testing.T) {
	s, _ := authServer(t, m{"apiKey": m{"keys": l{m{"name": "dev", "key": "plain"}}}}, nil)
	head := rawHead(t, s.Addr(8080), "a.test")
	if !strings.Contains(head, "\r\nWWW-Authenticate: ") || strings.Contains(head, "Www-Authenticate") {
		t.Fatalf("the challenge must be sent as WWW-Authenticate:\n%s", head)
	}
}

func TestRateLimitHeadersKeepDocumentedSpelling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setRateLimitHeaders(w.Header(), sharedDecision{headers: true, limit: 5, remaining: 2, reset: 1500 * time.Millisecond})
	}))
	defer srv.Close()
	head := rawHead(t, strings.TrimPrefix(srv.URL, "http://"), "x")
	for _, want := range []string{"\r\nX-RateLimit-Limit: 5", "\r\nX-RateLimit-Remaining: 2", "\r\nX-RateLimit-Reset: 2"} {
		if !strings.Contains(head, want) {
			t.Errorf("missing %q in:\n%s", want, head)
		}
	}
}

func TestSharedFallbackBurstIsNotOne(t *testing.T) {
	l := newLimiter(RateLimitConfig{Rate: 30, Per: time.Minute, Shared: &SharedLimit{}}, nil)
	if l.burst != 30 {
		t.Fatalf("fallback burst for 30/m = %v, want 30", l.burst)
	}
	l = newLimiter(RateLimitConfig{Rate: 10000, Per: time.Hour, Shared: &SharedLimit{}}, nil)
	if l.burst != sharedFallbackBurstCap {
		t.Fatalf("fallback burst is capped: %v", l.burst)
	}
	l = newLimiter(RateLimitConfig{Rate: 30, Per: time.Minute, Shared: &SharedLimit{FallbackReplicas: 3}}, nil)
	if l.burst != 10 {
		t.Fatalf("replica share of the burst: %v", l.burst)
	}
	// a plain (non shared) N/m limit keeps its documented default burst of 1
	if l = newLimiter(RateLimitConfig{Rate: 30, Per: time.Minute}, nil); l.burst != 1 {
		t.Fatalf("plain limiter burst changed: %v", l.burst)
	}
}

func TestFmtTokenRateIsReadable(t *testing.T) {
	for in, want := range map[float64]string{5: "5 tokens/s", 100.0 / 60: "1.67 tokens/s", 1.0 / 30: "2 tokens/min", 10.0 / 3600: "10 tokens/h"} {
		if got := fmtTokenRate(in); got != want {
			t.Errorf("fmtTokenRate(%v) = %q, want %q", in, got, want)
		}
	}
}
