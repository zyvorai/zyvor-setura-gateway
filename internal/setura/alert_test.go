package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu     sync.Mutex
	bodies []map[string]any
	paths  []string
	status func(n int) int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	r.mu.Lock()
	r.bodies = append(r.bodies, m)
	r.paths = append(r.paths, req.URL.Path)
	n := len(r.bodies)
	r.mu.Unlock()
	if r.status != nil {
		w.WriteHeader(r.status(n))
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testAlerter(t *testing.T, cfg alertConfig, log io.Writer) (*alerter, *clock, *[]time.Duration) {
	t.Helper()
	a, err := newAlerter(cfg, log)
	if err != nil || a == nil {
		t.Fatalf("newAlerter: %v", err)
	}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	var mu sync.Mutex
	var sleeps []time.Duration
	a.now = clk.now
	a.sleep = func(d time.Duration) { mu.Lock(); sleeps = append(sleeps, d); mu.Unlock() }
	return a, clk, &sleeps
}

func TestAlertTransitionsOnlyNoRepeatSpam(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a, clk, _ := testAlerter(t, alertConfig{Webhook: srv.URL + "/hook", Retries: 1}, nil)
	step := func(ok bool) {
		a.observe("http://x/", ok, "http", "expected HTTP 200, received 500", 12)
		a.wait()
		clk.advance(time.Second)
	}
	step(true)  // healthy start: nothing
	step(false) // failure
	step(false) // still failing: nothing
	step(false)
	step(true) // recovery
	step(true)
	is(t, rec.count(), 2)
	is(t, rec.bodies[0]["event"], "failure")
	is(t, rec.bodies[0]["target"], "http://x/")
	is(t, rec.bodies[0]["stage"], "http")
	is(t, rec.bodies[1]["event"], "recovery")
	is(t, rec.paths[0], "/hook")
}

func TestAlertCooldownCollapsesFlap(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a, clk, _ := testAlerter(t, alertConfig{Webhook: srv.URL, Cooldown: time.Minute, Retries: 0}, nil)
	obs := func(ok bool) { a.observe("t", ok, "tcp", "refused", 1); a.wait() }
	obs(false) // sent
	clk.advance(10 * time.Second)
	obs(true) // within cooldown: held back
	clk.advance(10 * time.Second)
	obs(false) // back to the state recipients know: nothing
	is(t, rec.count(), 1)
	clk.advance(time.Minute)
	obs(true) // cooldown over: recovery goes out
	is(t, rec.count(), 2)
	is(t, rec.bodies[1]["event"], "recovery")
}

func TestAlertRetriesWithBackoffThenSucceeds(t *testing.T) {
	rec := &recorder{status: func(n int) int {
		if n < 3 {
			return 503
		}
		return 200
	}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a, _, sleeps := testAlerter(t, alertConfig{Webhook: srv.URL, Retries: 3}, nil)
	a.observe("t", false, "http", "x", 1)
	a.wait()
	is(t, rec.count(), 3)
	is(t, len(*sleeps), 2)
	if (*sleeps)[1] != 2*(*sleeps)[0] {
		t.Fatalf("backoff not exponential: %v", *sleeps)
	}
}

func TestAlertPermanentErrorNotRetriedAndRetriedLater(t *testing.T) {
	rec := &recorder{status: func(int) int { return 404 }}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	var log bytes.Buffer
	a, clk, sleeps := testAlerter(t, alertConfig{Webhook: srv.URL + "/secret-token-123", Retries: 3}, &log)
	a.observe("t", false, "http", "x", 1)
	a.wait()
	is(t, rec.count(), 1)
	is(t, len(*sleeps), 0)
	contains(t, log.String(), "HTTP 404")
	// not delivered, so the transition is attempted again on the next probe
	clk.advance(time.Second)
	a.observe("t", false, "http", "x", 1)
	a.wait()
	is(t, rec.count(), 2)
}

func TestAlertSecretsNeverLogged(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	secretURL := srv.URL + "/services/T000/B000/s3cr3t-token"
	srv.Close() // connection refused: net/http error would embed the URL
	var log bytes.Buffer
	a, _, _ := testAlerter(t, alertConfig{Slack: secretURL, Retries: 1}, &log)
	a.observe("t", false, "http", "x", 1)
	a.wait()
	out := log.String()
	if out == "" {
		t.Fatal("expected a delivery failure log line")
	}
	for _, leak := range []string{"s3cr3t-token", "T000", srv.URL, "127.0.0.1"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaks %q: %s", leak, out)
		}
	}
	contains(t, out, "slack")

	_, err := newAlerter(alertConfig{Webhook: "ftp://user:pw-secret@host/x"}, nil)
	if err == nil || strings.Contains(err.Error(), "pw-secret") {
		t.Fatalf("validation error must not echo the value: %v", err)
	}
	_, err = newAlerter(alertConfig{Slack: "%zz-hunter2"}, nil)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("validation error must not echo the value: %v", err)
	}
}

func TestSlackPayloadShape(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a, _, _ := testAlerter(t, alertConfig{Slack: srv.URL}, nil)
	a.observe("http://x/?a=1&b=<2>", false, "http", "boom", 1)
	a.wait()
	text, _ := rec.bodies[0]["text"].(string)
	contains(t, text, "rotating_light")
	contains(t, text, "&amp;")
	contains(t, text, "&lt;2&gt;")
	att := asList(rec.bodies[0]["attachments"])
	is(t, asMap(att[0])["color"], "danger")
}

func TestWatchSendsAlertsOnTransitions(t *testing.T) {
	srv, _ := flipServer(t, 2) // ok, ok, then 500s
	rec := &recorder{}
	hook := httptest.NewServer(rec)
	defer hook.Close()
	w := newWatcher([]ProbeOptions{NewProbe(srv.URL + "/")}, time.Second, io.Discard)
	w.newTick, w.count = fakeTicks(10), 5
	a, _, _ := testAlerter(t, alertConfig{Webhook: hook.URL, Cooldown: 0}, nil)
	w.alerts = a
	if _, err := w.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	is(t, rec.count(), 1) // three failing rounds, one alert
	is(t, rec.bodies[0]["event"], "failure")
}

func TestWatchCommandRejectsBadAlertURLWithoutLeaking(t *testing.T) {
	code, _, errs := cli(t, nil, "watch", "http://127.0.0.1:1/", "--count", "1", "--alert-webhook", "not-a-url-hunter2")
	is(t, code, 2)
	contains(t, errs, "--alert-webhook")
	if strings.Contains(errs, "hunter2") {
		t.Fatalf("stderr leaks the URL: %s", errs)
	}
}
