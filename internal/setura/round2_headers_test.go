package setura

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderExpectations(t *testing.T) {
	h := http.Header{}
	h.Add("Cache-Control", "public, max-age=300")
	h.Add("X-Env", "staging")
	ok := map[string]string{"X-Env": "staging", "Cache-Control": "~max-age=\\d+", "X-Env2": "!", "x-env": "*"}
	for n, w := range ok {
		if err := checkHeader(h, n, w); err != nil {
			t.Errorf("%s %s: %v", n, w, err)
		}
	}
	bad := map[string]string{"X-Env": "!", "Cache-Control": "~no-store", "X-Missing": "*", "X-Missing2": "~x", "X-Env2": "x"}
	for n, w := range bad {
		if err := checkHeader(h, n, w); err == nil {
			t.Errorf("%s %s should fail", n, w)
		}
	}
}

func TestExplainHeaderOperators(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
	}))
	t.Cleanup(srv.Close)
	if code, _ := cliJSON(t, "explain", srv.URL, "--json", "--header", "Cache-Control: ~^max-age=\\d+$", "--header", "Set-Cookie: !"); code != 0 {
		t.Errorf("operators should pass: %d", code)
	}
	if code, _ := cliJSON(t, "explain", srv.URL, "--json", "--header", "Cache-Control: !"); code != 1 {
		t.Errorf("absent check should fail: %d", code)
	}
	if code, _, _ := cli(t, nil, "explain", srv.URL, "--header", "X: ~("); code != 2 {
		t.Errorf("bad regex: %d", code)
	}
}
