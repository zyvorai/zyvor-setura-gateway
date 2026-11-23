// Package webui serves the read-only Setura dashboard: one embedded HTML
// page, a JSON state endpoint and a Server-Sent Events stream. It depends
// only on the standard library so both the CLI and the gateway can mount it.
package webui

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var page []byte

const cookieName = "setura_ui"

// Event is one entry of the live feed.
type Event struct {
	ID     int64  `json:"id"`
	Time   string `json:"time"`
	Kind   string `json:"kind"`   // probe, change, reload, traffic, info
	Level  string `json:"level"`  // ok, warn, info
	Target string `json:"target"` // route, URL or listener the event is about
	Text   string `json:"text"`
	// Data carries a structured payload for kinds the page handles itself
	// (for example "conns"); such events are not shown in the feed.
	Data any `json:"data,omitempty"`
}

// Hub keeps a ring buffer of recent events and fans them out to subscribers.
type Hub struct {
	mu   sync.Mutex
	cap  int
	next int64
	buf  []Event
	subs map[chan Event]struct{}
}

// NewHub returns a hub that remembers the last capacity events.
func NewHub(capacity int) *Hub {
	if capacity < 1 {
		capacity = 200
	}
	return &Hub{cap: capacity, subs: map[chan Event]struct{}{}}
}

// Publish stamps and stores an event. It never blocks on slow subscribers.
func (h *Hub) Publish(e Event) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	e.ID = h.next
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Level == "" {
		e.Level = "info"
	}
	h.buf = append(h.buf, e)
	if len(h.buf) > h.cap {
		h.buf = append([]Event(nil), h.buf[len(h.buf)-h.cap:]...)
	}
	for c := range h.subs {
		select {
		case c <- e:
		default:
		}
	}
	return e
}

// Broadcast fans an event out to live subscribers without keeping it in the
// replay buffer, for high-volume structured updates that a reconnecting page
// refetches from its own endpoint instead.
func (h *Hub) Broadcast(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	e.ID = h.next
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	for c := range h.subs {
		select {
		case c <- e:
		default:
		}
	}
}

// Since returns events with an ID greater than id, oldest first.
func (h *Hub) Since(id int64) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Event
	for _, e := range h.buf {
		if e.ID > id {
			out = append(out, e)
		}
	}
	return out
}

func (h *Hub) subscribe() (chan Event, func()) {
	c := make(chan Event, 64)
	h.mu.Lock()
	h.subs[c] = struct{}{}
	h.mu.Unlock()
	return c, func() {
		h.mu.Lock()
		delete(h.subs, c)
		h.mu.Unlock()
	}
}

// Options configures the handler.
type Options struct {
	// State returns the document served at /api/state. It must already be
	// free of secrets. A nil result means "not ready yet" (503).
	State func() any
	// Hub supplies the live feed; nil disables it (the UI hides the feed).
	Hub *Hub
	// Connections returns the recent-connections document served at
	// /api/connections?limit=&since=. It must not contain header values or
	// query strings. Nil hides the Connections section.
	Connections func(limit int, since int64) any
	// Changes returns the document served at /api/changes: the diff between the
	// live configuration and its previous backups, plus the rollout timeline.
	// ChangeDetail answers /api/changes/ID with the read-only "what would this
	// do" view of one timeline entry. Both are nil when no history is known;
	// the page then shows how to connect one.
	Changes      func() any
	ChangeDetail func(id string) (any, bool)
	// Inventory returns the document served at /api/inventory: the learned API
	// inventory and the contract status. Nil when the source has no learner;
	// the page then shows how to turn it on.
	Inventory func() any
	// Token, when set, is required as a Bearer token or session cookie.
	Token string
	// Interval is how often an SSE client checks for a changed state.
	Interval time.Duration
}

var (
	scriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	styleRe  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	csp      = buildCSP()
)

func buildCSP() string {
	h := func(re *regexp.Regexp) string {
		m := re.FindSubmatch(page)
		if m == nil {
			return ""
		}
		sum := sha256.Sum256(m[1])
		return " 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; script-src" + h(scriptRe) + "; style-src" + h(styleRe) +
		"; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

// New returns the dashboard handler.
func New(o Options) http.Handler {
	if o.Interval <= 0 {
		o.Interval = 2 * time.Second
	}
	s := &srv{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/state", s.guard(s.state))
	mux.HandleFunc("/api/events", s.guard(s.events))
	mux.HandleFunc("/api/connections", s.guard(s.connections))
	mux.HandleFunc("/api/palette", s.guard(s.palette))
	mux.HandleFunc("/api/inventory", s.guard(s.inventory))
	mux.HandleFunc("/api/changes", s.guard(s.changes))
	mux.HandleFunc("/api/changes/", s.guard(s.changeDetail))
	mux.HandleFunc("/events", s.guard(s.stream))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	return s.base(mux)
}

type srv struct{ o Options }

func headers(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
}

// base enforces read-only access and, without a token, a loopback Host so a
// hostile web page cannot read the dashboard through DNS rebinding.
func (s *srv) base(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "the Setura dashboard is read-only", http.StatusMethodNotAllowed)
			return
		}
		if s.o.Token == "" && !loopbackHost(r.Host) {
			http.Error(w, "forbidden host; open the dashboard via http://127.0.0.1:PORT or http://localhost:PORT", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *srv) authed(r *http.Request) bool {
	if s.o.Token == "" {
		return true
	}
	eq := func(got string) bool {
		return subtle.ConstantTimeCompare([]byte(got), []byte(s.o.Token)) == 1
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") && eq(strings.TrimPrefix(a, "Bearer ")) {
		return true
	}
	if c, err := r.Cookie(cookieName); err == nil && eq(c.Value) {
		return true
	}
	return false
}

func (s *srv) guard(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="setura"`)
			http.Error(w, "token required: send Authorization: Bearer TOKEN", http.StatusUnauthorized)
			return
		}
		f(w, r)
	}
}

const denied = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setura</title>
<body style="font:17px/1.5 -apple-system,system-ui,sans-serif;max-width:32rem;margin:18vh auto;padding:0 1.5rem;color:#1d1d1f">
<h1 style="font-weight:600;letter-spacing:-.02em">This dashboard needs a token</h1>
<p>Open it once with the token you started it with, for example <code>/?token=YOUR_TOKEN</code>. The browser then remembers it for this session.</p>`

func (s *srv) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if t := r.URL.Query().Get("token"); t != "" && s.o.Token != "" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.o.Token)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	if !s.authed(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, denied)
		return
	}
	writePage(w, r, s.renderIndex())
}

func (s *srv) snapshot() ([]byte, bool) {
	if s.o.State == nil {
		return nil, false
	}
	v := s.o.State()
	if v == nil {
		return nil, false
	}
	b, err := json.Marshal(v)
	return b, err == nil
}

func (s *srv) state(w http.ResponseWriter, r *http.Request) {
	b, ok := s.snapshot()
	if !ok {
		http.Error(w, "not ready yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (s *srv) connections(w http.ResponseWriter, r *http.Request) {
	if s.o.Connections == nil {
		http.NotFound(w, r)
		return
	}
	limit, since := 200, int64(0)
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 5000 {
		limit = n
	}
	if n, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); err == nil && n > 0 {
		since = n
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.o.Connections(limit, since))
}

func (s *srv) events(w http.ResponseWriter, r *http.Request) {
	var evs []Event
	var last int64
	if s.o.Hub != nil {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		evs = s.o.Hub.Since(since)
		last = since
		if n := len(evs); n > 0 {
			last = evs[n-1].ID
		}
	}
	if evs == nil {
		evs = []Event{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"events": evs, "last": last, "live": s.o.Hub != nil})
}

func (s *srv) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	var sub chan Event
	if s.o.Hub != nil {
		var cancel func()
		sub, cancel = s.o.Hub.subscribe()
		defer cancel()
		since, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
		for _, e := range s.o.Hub.Since(since) {
			writeEvent(w, e)
		}
	}
	var lastState string
	push := func() {
		if b, ok := s.snapshot(); ok && string(b) != lastState {
			lastState = string(b)
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		}
	}
	push()
	fl.Flush()
	tick := time.NewTicker(s.o.Interval)
	defer tick.Stop()
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-sub:
			writeEvent(w, e)
		case <-tick.C:
			push()
		case <-beat.C:
			fmt.Fprint(w, ": keepalive\n\n")
		}
		fl.Flush()
	}
}

func writeEvent(w io.Writer, e Event) {
	b, _ := json.Marshal(e)
	fmt.Fprintf(w, "id: %d\nevent: feed\ndata: %s\n\n", e.ID, b)
}

// NormalizeListen validates a listen address. A bare ":PORT" means loopback.
// Binding anything other than loopback requires a token.
func NormalizeListen(addr, token string) (string, error) {
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: want HOST:PORT, for example 127.0.0.1:9090", addr)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return "", fmt.Errorf("invalid port in %q", addr)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if !loopbackHost(host) && token == "" {
		return "", errors.New("refusing to expose the dashboard on a non-loopback address without a token; add --token VALUE (or set SETURA_UI_TOKEN), or bind 127.0.0.1")
	}
	return net.JoinHostPort(host, port), nil
}

// Serve listens on addr and serves h until ctx ends or stop is called.
// It returns the bound address.
func Serve(ctx context.Context, addr, token string, h http.Handler) (bound string, stop func(), err error) {
	addr, err = NormalizeListen(addr, token)
	if err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go hs.Serve(ln)
	var once sync.Once
	stop = func() {
		once.Do(func() {
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if hs.Shutdown(c) != nil {
				hs.Close()
			}
		})
	}
	go func() { <-ctx.Done(); stop() }()
	return ln.Addr().String(), stop, nil
}
