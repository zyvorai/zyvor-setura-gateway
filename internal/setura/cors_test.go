package setura

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func failsOf(f []CORSFinding) (fails, warns []string) {
	for _, x := range f {
		if x.Level == "fail" {
			fails = append(fails, x.Message)
		} else {
			warns = append(warns, x.Message)
		}
	}
	return
}

func TestEvaluatePreflight(t *testing.T) {
	const origin = "https://app.example"
	good := hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "GET, PUT, DELETE",
		"Access-Control-Allow-Headers", "Content-Type, X-Token", "Vary", "Origin", "Access-Control-Max-Age", "600")
	cases := map[string]struct {
		req    CORSRequest
		status int
		h      http.Header
		fail   string // substring expected in a failure; "" means no failure
		warn   string
	}{
		"clean":           {CORSRequest{origin, "PUT", []string{"content-type", "X-Token"}, false}, 204, good, "", ""},
		"status 403":      {CORSRequest{origin, "PUT", nil, false}, 403, good, "HTTP 403", ""},
		"status 301":      {CORSRequest{origin, "PUT", nil, false}, 301, good, "HTTP 301", ""},
		"no ACAO":         {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Methods", "PUT"), "no Access-Control-Allow-Origin", ""},
		"wrong origin":    {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", "https://other.example", "Access-Control-Allow-Methods", "PUT"), "not the requesting origin", ""},
		"origin case":     {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", "https://APP.example", "Access-Control-Allow-Methods", "PUT"), "not the requesting origin", ""},
		"null origin":     {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", "null", "Access-Control-Allow-Methods", "PUT"), "not the requesting origin", ""},
		"two ACAO":        {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Origin", "*", "Access-Control-Allow-Methods", "PUT"), "several values", ""},
		"comma ACAO":      {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin+", https://b.example", "Access-Control-Allow-Methods", "PUT"), "several values", ""},
		"star ok":         {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", "*", "Access-Control-Allow-Methods", "*"), "", ""},
		"star with creds": {CORSRequest{origin, "PUT", nil, true}, 204, hdr("Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true", "Access-Control-Allow-Methods", "PUT"), "wildcard", ""},
		"creds missing":   {CORSRequest{origin, "PUT", nil, true}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Vary", "Origin"), "Allow-Credentials", ""},
		"creds TRUE":      {CORSRequest{origin, "PUT", nil, true}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Credentials", "TRUE", "Access-Control-Allow-Methods", "PUT", "Vary", "Origin"), "Allow-Credentials", ""},
		"creds ok":        {CORSRequest{origin, "PUT", nil, true}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Credentials", "true", "Access-Control-Allow-Methods", "PUT", "Vary", "Origin"), "", ""},
		"method missing":  {CORSRequest{origin, "PATCH", nil, false}, 204, good, "does not list PATCH", ""},
		"method case":     {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "put", "Vary", "Origin"), "does not list PUT", ""},
		"safelisted GET":  {CORSRequest{origin, "GET", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Vary", "Origin"), "", ""},
		"star methods w/ creds": {CORSRequest{origin, "PUT", nil, true}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Credentials", "true",
			"Access-Control-Allow-Methods", "*", "Vary", "Origin"), "Allow-Methods is *", ""},
		"header missing":      {CORSRequest{origin, "PUT", []string{"X-Other"}, false}, 204, good, "does not list X-Other", ""},
		"header case folded":  {CORSRequest{origin, "PUT", []string{"x-token"}, false}, 204, good, "", ""},
		"star headers":        {CORSRequest{origin, "PUT", []string{"X-Other"}, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Access-Control-Allow-Headers", "*", "Vary", "Origin"), "", ""},
		"star headers + auth": {CORSRequest{origin, "PUT", []string{"Authorization"}, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Access-Control-Allow-Headers", "*", "Vary", "Origin"), "Authorization", ""},
		"star headers creds":  {CORSRequest{origin, "PUT", []string{"X-Other"}, true}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Credentials", "true", "Access-Control-Allow-Methods", "PUT", "Access-Control-Allow-Headers", "*", "Vary", "Origin"), "Allow-Headers is *", ""},
		"safelisted header":   {CORSRequest{origin, "PUT", []string{"Accept"}, false}, 204, good, "", ""},
		"no vary":             {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT"), "", "Vary"},
		"max-age junk":        {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Vary", "Origin", "Access-Control-Max-Age", "soon"), "Max-Age", ""},
		"max-age negative":    {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Vary", "Origin", "Access-Control-Max-Age", "-5"), "Max-Age", ""},
		"max-age zero":        {CORSRequest{origin, "PUT", nil, false}, 204, hdr("Access-Control-Allow-Origin", origin, "Access-Control-Allow-Methods", "PUT", "Vary", "Origin", "Access-Control-Max-Age", "0"), "", "Max-Age is 0"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fails, warns := failsOf(EvaluatePreflight(c.req, c.status, c.h))
			if c.fail == "" && len(fails) != 0 {
				t.Fatalf("unexpected failures: %v", fails)
			}
			if c.fail != "" && !strings.Contains(strings.Join(fails, "|"), c.fail) {
				t.Fatalf("want failure containing %q, got %v", c.fail, fails)
			}
			if c.warn != "" && !strings.Contains(strings.Join(warns, "|"), c.warn) {
				t.Fatalf("want warning containing %q, got %v", c.warn, warns)
			}
			if c.warn == "" && len(warns) != 0 && c.fail == "" {
				t.Fatalf("unexpected warnings: %v", warns)
			}
		})
	}
}

func TestValidateCORSRequestHostile(t *testing.T) {
	long := strings.Repeat("h", 129)
	many := make([]string, maxCORSHeaders+1)
	for i := range many {
		many[i] = "x-h"
	}
	cases := map[string]CORSRequest{
		"no origin":      {"", "GET", nil, false},
		"path origin":    {"https://a.example/x", "GET", nil, false},
		"query origin":   {"https://a.example?x=1", "GET", nil, false},
		"trailing slash": {"https://a.example/", "GET", nil, false},
		"ftp":            {"ftp://a.example", "GET", nil, false},
		"userinfo":       {"https://u:p@a.example", "GET", nil, false},
		"crlf origin":    {"https://a.example\r\nX: 1", "GET", nil, false},
		"space origin":   {"https://a .example", "GET", nil, false},
		"empty method":   {"https://a.example", "", nil, false},
		"bad method":     {"https://a.example", "G ET", nil, false},
		"long header":    {"https://a.example", "GET", []string{long}, false},
		"bad header":     {"https://a.example", "GET", []string{"x:y"}, false},
		"crlf header":    {"https://a.example", "GET", []string{"x\r\ny"}, false},
		"too many":       {"https://a.example", "GET", many, false},
	}
	for name, r := range cases {
		if err := ValidateCORSRequest(r); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
	for _, ok := range []CORSRequest{{"https://a.example", "GET", nil, false}, {"http://localhost:3000", "PUT", []string{"x-a"}, true}, {"null", "GET", nil, false}} {
		if err := ValidateCORSRequest(ok); err != nil {
			t.Errorf("%+v should pass: %v", ok, err)
		}
	}
}

func corsServer(t *testing.T, good bool) (*httptest.Server, *http.Header) {
	t.Helper()
	got := &http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "OPTIONS" {
			w.WriteHeader(405)
			return
		}
		*got = r.Header.Clone()
		if good {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT")
			w.Header().Set("Access-Control-Allow-Headers", "x-token")
			w.Header().Set("Vary", "Origin")
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestCORSCLI(t *testing.T) {
	srv, got := corsServer(t, true)
	code, out, _ := cli(t, nil, "cors", srv.URL+"/", "--origin", "https://app.example", "--request-method", "put", "--request-headers", "X-Token")
	if code != 0 || !strings.Contains(out, "PASS") {
		t.Fatalf("good preflight: %d %s", code, out)
	}
	if got.Get("Origin") != "https://app.example" || got.Get("Access-Control-Request-Method") != "PUT" || got.Get("Access-Control-Request-Headers") != "x-token" {
		t.Errorf("preflight request headers: %v", *got)
	}
	code, m := cliJSON(t, "cors", srv.URL+"/", "--origin", "https://app.example", "--request-method", "DELETE", "--json")
	if code != 1 || m["ok"] != false || len(asList(m["findings"])) == 0 {
		t.Errorf("DELETE is not allowed: %d %v", code, m)
	}
	bad, _ := corsServer(t, false)
	if code, out, _ = cli(t, nil, "cors", bad.URL+"/", "--origin", "https://app.example"); code != 1 || !strings.Contains(out, "FAIL") {
		t.Errorf("no CORS headers: %d %s", code, out)
	}
	for _, args := range [][]string{{"cors"}, {"cors", srv.URL}, {"cors", srv.URL, "--origin", "https://a.example/x"}, {"cors", srv.URL, "--origin", "https://a.example", "--request-headers", "a:b"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v should be a usage error, got %d", args, code)
		}
	}
	if code, out, _ = cli(t, nil, "cors", "http://127.0.0.1:1/", "--origin", "https://a.example", "--timeout", "1"); code != 1 || !strings.Contains(out, "no preflight answer") {
		t.Errorf("unreachable: %d %s", code, out)
	}
}
