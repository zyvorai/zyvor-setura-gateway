package webui

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func state() any { return map[string]any{"schema": "x", "n": 1} }

func get(t *testing.T, h http.Handler, path string, mod func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "127.0.0.1:9090"
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestIndexAndState(t *testing.T) {
	h := New(Options{State: state})
	w := get(t, h, "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<title>Setura</title>") {
		t.Fatalf("index: %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'sha256-", "style-src 'sha256-", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing hardening headers")
	}
	w = get(t, h, "/api/state", nil)
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got["n"] != float64(1) {
		t.Fatalf("state: %v %s", err, w.Body)
	}
	if get(t, h, "/nope", nil).Code != 404 {
		t.Error("unknown path should 404")
	}
	if get(t, h, "/healthz", nil).Code != 200 {
		t.Error("healthz")
	}
}

func TestNotReady(t *testing.T) {
	h := New(Options{State: func() any { return nil }})
	if c := get(t, h, "/api/state", nil).Code; c != http.StatusServiceUnavailable {
		t.Fatalf("got %d", c)
	}
}

func TestReadOnly(t *testing.T) {
	h := New(Options{State: state})
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		r := httptest.NewRequest(m, "/api/state", strings.NewReader("{}"))
		r.Host = "127.0.0.1:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d", m, w.Code)
		}
	}
}

func TestLoopbackHostRequiredWithoutToken(t *testing.T) {
	h := New(Options{State: state})
	for host, want := range map[string]int{
		"127.0.0.1:9090": 200, "localhost:9090": 200, "[::1]:9090": 200, "LOCALHOST": 200,
		"evil.example:9090": 403, "10.0.0.5:9090": 403, "127.0.0.1.evil.test": 403,
	} {
		if got := get(t, h, "/api/state", func(r *http.Request) { r.Host = host }).Code; got != want {
			t.Errorf("Host %q: got %d want %d", host, got, want)
		}
	}
}

func TestTokenRules(t *testing.T) {
	h := New(Options{State: state, Token: "s3cret"})
	remote := func(r *http.Request) { r.Host = "dash.internal:9090" } // any host is fine with a token
	if c := get(t, h, "/api/state", remote).Code; c != 401 {
		t.Fatalf("no token: %d", c)
	}
	w := get(t, h, "/api/state", func(r *http.Request) { remote(r); r.Header.Set("Authorization", "Bearer wrong") })
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("wrong token: %d", w.Code)
	}
	if c := get(t, h, "/api/state", func(r *http.Request) { remote(r); r.Header.Set("Authorization", "Bearer s3cret") }).Code; c != 200 {
		t.Fatalf("bearer: %d", c)
	}
	// The query token is accepted only on "/" and only to set a cookie.
	if c := get(t, h, "/api/state?token=s3cret", remote).Code; c != 401 {
		t.Fatalf("query token must not authorize the API: %d", c)
	}
	w = get(t, h, "/", remote)
	if w.Code != 401 || strings.Contains(w.Body.String(), "<title>Setura</title>\n<style>") || !strings.Contains(w.Body.String(), "needs a token") {
		t.Fatalf("index without token: %d", w.Code)
	}
	w = get(t, h, "/?token=s3cret", remote)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("token exchange: %d", w.Code)
	}
	ck := w.Result().Cookies()
	if len(ck) != 1 || !ck[0].HttpOnly || ck[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", ck)
	}
	if c := get(t, h, "/api/state", func(r *http.Request) { remote(r); r.AddCookie(ck[0]) }).Code; c != 200 {
		t.Fatalf("cookie auth: %d", c)
	}
	if c := get(t, h, "/?token=nope", remote).Code; c != 401 {
		t.Fatalf("bad token exchange: %d", c)
	}
	if c := get(t, h, "/healthz", remote).Code; c != 200 {
		t.Fatalf("healthz must stay open: %d", c)
	}
}

func TestNormalizeListen(t *testing.T) {
	ok := map[[2]string]string{
		{"", ""}:                     "127.0.0.1:9090",
		{":9090", ""}:                "127.0.0.1:9090",
		{"127.0.0.1:0", ""}:          "127.0.0.1:0",
		{"localhost:8080", ""}:       "localhost:8080",
		{"[::1]:8080", ""}:           "[::1]:8080",
		{"0.0.0.0:9090", "tok"}:      "0.0.0.0:9090",
		{"192.168.1.9:9090", "tok"}:  "192.168.1.9:9090",
		{"dash.internal:9090", "tk"}: "dash.internal:9090",
	}
	for in, want := range ok {
		got, err := NormalizeListen(in[0], in[1])
		if err != nil || got != want {
			t.Errorf("%v: got %q, %v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"0.0.0.0:9090", "192.168.1.9:9090", "[::]:9090", "example.com:80"} {
		if _, err := NormalizeListen(in, ""); err == nil || !strings.Contains(err.Error(), "--token") {
			t.Errorf("%s without token should be refused with a hint, got %v", in, err)
		}
	}
	for _, in := range []string{"9090", "127.0.0.1:abc", "127.0.0.1:99999"} {
		if _, err := NormalizeListen(in, ""); err == nil {
			t.Errorf("%s should be invalid", in)
		}
	}
}

func TestEventsJSONAndHub(t *testing.T) {
	hub := NewHub(3)
	for _, s := range []string{"a", "b", "c", "d"} {
		hub.Publish(Event{Kind: "probe", Text: s})
	}
	h := New(Options{State: state, Hub: hub})
	var out struct {
		Events []Event `json:"events"`
		Last   int64   `json:"last"`
		Live   bool    `json:"live"`
	}
	json.Unmarshal(get(t, h, "/api/events", nil).Body.Bytes(), &out)
	if !out.Live || len(out.Events) != 3 || out.Events[0].Text != "b" || out.Last != 4 || out.Events[0].Level != "info" {
		t.Fatalf("ring buffer: %+v", out)
	}
	out.Events = nil
	json.Unmarshal(get(t, h, "/api/events?since=3", nil).Body.Bytes(), &out)
	if len(out.Events) != 1 || out.Events[0].Text != "d" {
		t.Fatalf("since: %+v", out)
	}
	// Without a hub the endpoint says the feed is not live and returns [].
	b := get(t, New(Options{State: state}), "/api/events", nil).Body.String()
	if !strings.Contains(b, `"events":[]`) || !strings.Contains(b, `"live":false`) {
		t.Fatalf("no hub: %s", b)
	}
}

// sseReader reads SSE frames from a streaming response.
type sseFrame struct{ event, id, data string }

func readFrame(t *testing.T, br *bufio.Reader) sseFrame {
	t.Helper()
	var f sseFrame
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "" && (f.event != "" || f.data != ""):
			return f
		case strings.HasPrefix(line, "event: "):
			f.event = line[7:]
		case strings.HasPrefix(line, "id: "):
			f.id = line[4:]
		case strings.HasPrefix(line, "data: "):
			f.data = line[6:]
		}
	}
}

func TestSSEStreamsStateAndFeed(t *testing.T) {
	hub := NewHub(10)
	hub.Publish(Event{Kind: "info", Text: "before connect"})
	var n int
	h := New(Options{State: func() any { n++; return map[string]any{"n": n / 2} }, Hub: hub, Interval: 20 * time.Millisecond})
	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	br := bufio.NewReader(res.Body)
	got := map[string]bool{}
	hub.Publish(Event{Kind: "change", Level: "warn", Target: "r", Text: "live one"})
	for i := 0; i < 8 && !(got["state"] && got["replay"] && got["live"]); i++ {
		f := readFrame(t, br)
		switch {
		case f.event == "state" && strings.Contains(f.data, `"n"`):
			got["state"] = true
		case f.event == "feed" && strings.Contains(f.data, "before connect"):
			got["replay"] = true
		case f.event == "feed" && strings.Contains(f.data, "live one"):
			got["live"] = true
		}
	}
	if !got["state"] || !got["replay"] || !got["live"] {
		t.Fatalf("missing frames: %v", got)
	}
	// State changes are pushed again (n advances every two reads).
	for i := 0; i < 10; i++ {
		if f := readFrame(t, br); f.event == "state" {
			return
		}
	}
	t.Fatal("no second state frame")
}

func TestSSEHonoursLastEventID(t *testing.T) {
	hub := NewHub(10)
	hub.Publish(Event{Text: "one"})
	hub.Publish(Event{Text: "two"})
	srv := httptest.NewServer(New(Options{State: state, Hub: hub, Interval: time.Hour}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events", nil)
	req.Header.Set("Last-Event-ID", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	br := bufio.NewReader(res.Body)
	f := readFrame(t, br)
	if f.event != "feed" || !strings.Contains(f.data, "two") || strings.Contains(f.data, "one") {
		t.Fatalf("expected only the missed event, got %+v", f)
	}
}

func TestSSERequiresToken(t *testing.T) {
	h := New(Options{State: state, Token: "t", Hub: NewHub(1)})
	if c := get(t, h, "/events", func(r *http.Request) { r.Host = "x:1" }).Code; c != 401 {
		t.Fatalf("got %d", c)
	}
}

func TestServe(t *testing.T) {
	if _, _, err := Serve(context.Background(), "0.0.0.0:0", "", New(Options{})); err == nil {
		t.Fatal("non-loopback without token must be refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	addr, stop, err := Serve(ctx, "127.0.0.1:0", "", New(Options{State: state}))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	res, err := http.Get("http://" + addr + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"n"`) {
		t.Fatalf("%d %s", res.StatusCode, b)
	}
	cancel()
	time.Sleep(100 * time.Millisecond)
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Fatal("server should stop with its context")
	}
}

// The page must stay one self-contained file: nothing external, no inline
// handlers or style attributes (the CSP forbids them), no innerHTML sinks.
func TestPageIsSelfContained(t *testing.T) {
	s := string(page)
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "<link rel=\"stylesheet\"", "<script src", "@import", "fonts.googleapis", " onclick=", " style=\""} {
		if strings.Contains(s, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	for _, m := range regexp.MustCompile(`https?://[^\s"')]+`).FindAllString(s, -1) {
		if u, _ := url.Parse(m); u.Host != "www.w3.org" {
			t.Errorf("external reference %s", m)
		}
	}
	if len(scriptRe.FindAllStringSubmatch(s, -1)) != 1 || len(styleRe.FindAllStringSubmatch(s, -1)) != 1 {
		t.Error("expect exactly one inline script and one inline style (CSP hashes cover one of each)")
	}
	for _, want := range []string{"prefers-color-scheme:dark", "prefers-reduced-motion", ":focus-visible", `aria-live`, `role="log"`, "EventSource", "api/state"} {
		if !strings.Contains(s, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestConnectionsEndpointAndBroadcast(t *testing.T) {
	var gotLimit int
	var gotSince int64
	h := New(Options{State: state, Connections: func(limit int, since int64) any {
		gotLimit, gotSince = limit, since
		return map[string]any{"history": []any{}}
	}})
	w := get(t, h, "/api/connections?limit=7&since=3", nil)
	if w.Code != 200 || gotLimit != 7 || gotSince != 3 {
		t.Fatalf("code %d limit %d since %d", w.Code, gotLimit, gotSince)
	}
	if w := get(t, New(Options{State: state}), "/api/connections", nil); w.Code != 404 {
		t.Errorf("without a provider: %d, want 404", w.Code)
	}
	if w := get(t, New(Options{State: state, Token: "t", Connections: func(int, int64) any { return 1 }}), "/api/connections", nil); w.Code != 401 {
		t.Errorf("without a token: %d, want 401", w.Code)
	}
	hub := NewHub(5)
	ch, cancel := hub.subscribe()
	defer cancel()
	hub.Broadcast(Event{Kind: "conns", Data: map[string]any{"n": 1}})
	select {
	case e := <-ch:
		if e.Kind != "conns" || e.ID == 0 {
			t.Errorf("event %+v", e)
		}
	default:
		t.Fatal("subscriber got nothing")
	}
	if len(hub.Since(0)) != 0 {
		t.Error("broadcast events must not enter the replay buffer")
	}
}
