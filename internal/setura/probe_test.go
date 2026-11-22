package setura

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func probeOpts(url string) ProbeOptions {
	o := NewProbe(url)
	o.Address = "127.0.0.1"
	return o
}

func TestHostPathAndIdentity(t *testing.T) {
	url := fixture(t, nil)
	o := probeOpts(url)
	o.Backend = "orders-v1"
	r, err := Probe(o)
	if err != nil || !r.OK {
		t.Fatalf("%v %+v", err, r)
	}
	is(t, r.Step("dns").State(), "overridden")
}

func TestNegativeRoute(t *testing.T) {
	url := fixture(t, nil)
	o := probeOpts(strings.Replace(url, "checkout", "wrong", 1))
	o.Status = 404
	if r, _ := Probe(o); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestWrongBackend(t *testing.T) {
	o := probeOpts(fixture(t, nil))
	o.Backend = "orders-v2"
	r, _ := Probe(o)
	is(t, r.Step("backend").State(), "failed")
	contains(t, asStr(r.Step("backend").Get("reason")), "expected 'orders-v2', received 'orders-v1'")
}

func TestHTTPMismatchLeavesBackendUntested(t *testing.T) {
	o := probeOpts(fixture(t, nil))
	o.Status, o.Backend = 204, "orders-v1"
	r, _ := Probe(o)
	is(t, r.Step("http").Get("status"), 200)
	is(t, r.Step("backend").State(), "untested")
}

func TestDNSFailure(t *testing.T) {
	old := lookupIP
	lookupIP = func(string) ([]string, error) { return nil, errors.New("no DNS") }
	defer func() { lookupIP = old }()
	r, err := Probe(NewProbe("https://orders.mactra.test"))
	if err != nil {
		t.Fatal(err)
	}
	is(t, r.Step("dns").State(), "failed")
	is(t, r.Step("tcp").State(), "untested")
}

func TestRefusedTCP(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	r, _ := Probe(NewProbe("https://127.0.0.1:" + strconv.Itoa(port)))
	is(t, r.Step("tcp").State(), "failed")
	is(t, r.Step("tls").State(), "untested")
}

func TestTLSTrustAndHostname(t *testing.T) {
	cfg, ca := selfSigned(t)
	url := fixture(t, cfg)
	o := probeOpts(url)
	o.CA = ca
	if rep, _ := Probe(o); !rep.OK {
		t.Fatalf("trusted CA should pass: %+v", rep.Steps["tls"])
	}
	is(t, tlsState(t, probeOpts(url)), "failed") // system trust must reject it
	bad := probeOpts(strings.Replace(url, "orders.mactra", "other.mactra", 1))
	bad.CA = ca
	is(t, tlsState(t, bad), "failed") // hostname mismatch
}

func tlsState(t *testing.T, o ProbeOptions) string {
	rep, err := Probe(o)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Step("tls").State()
}

func TestMissingCAFileFailsTLSStep(t *testing.T) {
	cfg, _ := selfSigned(t)
	o := probeOpts(fixture(t, cfg))
	o.CA = filepath.Join(t.TempDir(), "missing.pem")
	rep, _ := Probe(o)
	is(t, rep.Step("tls").State(), "failed")
}

func TestInvalidInput(t *testing.T) {
	for _, u := range []string{"file:///tmp/x", "http://a@localhost/", "http://localhost:0", "http://localhost/a b", "http://localhost/#frag", "ftp://x"} {
		if _, err := Probe(NewProbe(u)); err == nil {
			t.Errorf("%s: expected an error", u)
		}
	}
	o := NewProbe("http://localhost")
	o.Timeout = 61
	if _, err := Probe(o); err == nil {
		t.Error("timeout above 60s accepted")
	}
	o = NewProbe("http://localhost")
	o.Address = "not-an-ip"
	if _, err := Probe(o); err == nil {
		t.Error("bad address accepted")
	}
	o = NewProbe("http://localhost")
	o.Status = 99
	if _, err := Probe(o); err == nil {
		t.Error("bad status accepted")
	}
}

func TestCheckExitCodes(t *testing.T) {
	url := fixture(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.json")
	for status, want := range map[int]int{200: 0, 418: 1} {
		body := `[{"url":"` + url + `","address":"127.0.0.1","status":` + strconv.Itoa(status) + `}]`
		os.WriteFile(path, []byte(body), 0o600)
		code, _, errs := cli(t, nil, "check", path)
		if code != want {
			t.Fatalf("status %d: exit %d, want %d (%s)", status, code, want, errs)
		}
	}
	os.WriteFile(path, []byte(`[{"url":"http://x","bogus":1}]`), 0o600)
	if code, _, _ := cli(t, nil, "check", path); code != 2 {
		t.Fatalf("invalid case exit %d, want 2", code)
	}
}

func TestExplainTextOutputOrder(t *testing.T) {
	url := fixture(t, nil)
	code, out, _ := cli(t, nil, "explain", url, "--address", "127.0.0.1", "--backend", "orders-v1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Line 0 is the URL header, line 1 is blank, then one row per stage.
	for i, want := range []string{"dns", "tcp", "tls", "http", "backend"} {
		if !strings.Contains(lines[i+2], " "+want+" ") {
			t.Fatalf("line %d = %q, want stage %q", i+1, lines[i+1], want)
		}
	}
	contains(t, lines[5], "status=200 expected=200")
}
