package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An upstream that echoes X-Request-Id (Netra does) must not make the response
// carry the header twice: the id pre-set on the writer and the upstream's copy
// used to be added side by side.
func TestRequestIDNotDuplicatedWhenUpstreamEchoesIt(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)
	addr := strings.TrimPrefix(up.URL, "http://")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/ok", ref("a", 1)))}, map[string]any{"a": addr}), nil)

	r := get(t, s, "x.test", "/ok")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	ids := r.Header.Values("X-Request-Id")
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("X-Request-Id values = %q, want exactly one", ids)
	}

	// A client-supplied id is kept, still once.
	r = get(t, s, "x.test", "/ok", "X-Request-Id", "abc-123")
	if ids := r.Header.Values("X-Request-Id"); len(ids) != 1 || ids[0] != "abc-123" {
		t.Fatalf("with client id: X-Request-Id values = %q", ids)
	}
}
