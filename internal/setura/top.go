package setura

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// "setura top": a live terminal view of the built-in gateway, read from its
// admin API. Sampling (topFetch, buildTopModel) and drawing (renderTop) are
// separate so the frames can be tested without a terminal.

// topHist is a cumulative Prometheus histogram. le[len-1] is +Inf.
type topHist struct {
	le  []float64
	cum []float64
}

// topEP is one backend endpoint as reported by the endpoint gauges.
type topEP struct {
	Backend  string `json:"backend"`
	Endpoint string `json:"endpoint"`
	Healthy  bool   `json:"healthy"`
	Ejected  bool   `json:"ejected"`
}

// topErr is a recent failed request from /connections.
type topErr struct {
	Time    string `json:"time"`
	Status  int    `json:"status"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Route   string `json:"route,omitempty"`
	Backend string `json:"backend,omitempty"`
	Error   string `json:"error,omitempty"`
}

// topScrape is one poll of the admin API.
type topScrape struct {
	at        time.Time
	total     int64
	unmatched int64
	routes    map[string]topCounter
	backends  map[string]topCounter
	routeH    map[string]topHist
	backendH  map[string]topHist
	eps       []topEP
	gen       int64
	open      int
	errs      []topErr
}

type topCounter struct {
	Requests int64            `json:"requests"`
	Status   map[string]int64 `json:"status"`
}

// topRow is one line of the ROUTES or BACKENDS table. Rate and the window
// error rate are -1 when unknown (a single sample, or no traffic in the window).
type topRow struct {
	Name     string           `json:"name"`
	Requests int64            `json:"requests"`
	Rate     float64          `json:"rate"`
	ErrPct   float64          `json:"error_percent"`
	P50      float64          `json:"p50_ms"`
	P95      float64          `json:"p95_ms"`
	Status   map[string]int64 `json:"status,omitempty"`
}

// topModel is what a frame shows.
type topModel struct {
	Admin      string        `json:"admin"`
	Generation int64         `json:"generation,omitempty"`
	Interval   time.Duration `json:"-"`
	HaveRate   bool          `json:"have_rate"`
	Total      int64         `json:"requests"`
	Unmatched  int64         `json:"unmatched"`
	Rate       float64       `json:"rate"`
	Routes     []topRow      `json:"routes"`
	Backends   []topRow      `json:"backends"`
	Endpoints  []topEP       `json:"endpoints,omitempty"`
	Open       int           `json:"open_connections"`
	Errors     []topErr      `json:"recent_errors"`
	Err        string        `json:"-"`
	Hint       string        `json:"-"`
}

func (m *topModel) ejected() []topEP {
	var out []topEP
	for _, e := range m.Endpoints {
		if e.Ejected || !e.Healthy {
			out = append(out, e)
		}
	}
	return out
}

// ---- parsing ----

// parseProm reads the histogram buckets and endpoint gauges we need from the
// Prometheus text format.
func parseProm(text string) (routeH, backendH map[string]topHist, eps []topEP) {
	type key struct{ metric, name string }
	buckets := map[key][][2]float64{}
	epm := map[[2]string]*topEP{}
	var order [][2]string
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, val, ok := promLine(line)
		if !ok {
			continue
		}
		switch name {
		case "setura_gateway_request_duration_seconds_bucket", "setura_gateway_backend_request_duration_seconds_bucket":
			lk := "route"
			if strings.Contains(name, "backend") {
				lk = "backend"
			}
			le := math.Inf(1)
			if labels["le"] != "+Inf" {
				f, err := strconv.ParseFloat(labels["le"], 64)
				if err != nil {
					continue
				}
				le = f
			}
			k := key{lk, labels[lk]}
			buckets[k] = append(buckets[k], [2]float64{le, val})
		case "setura_gateway_endpoint_healthy", "setura_gateway_endpoint_ejected":
			k := [2]string{labels["backend"], labels["endpoint"]}
			e := epm[k]
			if e == nil {
				e = &topEP{Backend: k[0], Endpoint: k[1]}
				epm[k] = e
				order = append(order, k)
			}
			if strings.HasSuffix(name, "healthy") {
				e.Healthy = val == 1
			} else {
				e.Ejected = val == 1
			}
		}
	}
	routeH, backendH = map[string]topHist{}, map[string]topHist{}
	for k, bs := range buckets {
		sort.Slice(bs, func(i, j int) bool { return bs[i][0] < bs[j][0] })
		h := topHist{}
		for _, b := range bs {
			h.le, h.cum = append(h.le, b[0]), append(h.cum, b[1])
		}
		if k.metric == "route" {
			routeH[k.name] = h
		} else {
			backendH[k.name] = h
		}
	}
	for _, k := range order {
		eps = append(eps, *epm[k])
	}
	sort.SliceStable(eps, func(i, j int) bool {
		if eps[i].Backend != eps[j].Backend {
			return eps[i].Backend < eps[j].Backend
		}
		return eps[i].Endpoint < eps[j].Endpoint
	})
	return
}

// promLine splits `name{a="b",c="d"} 1.5`.
func promLine(line string) (name string, labels map[string]string, val float64, ok bool) {
	labels = map[string]string{}
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return
	}
	name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		j := 1
		for j < len(rest) && rest[j] != '}' {
			eq := strings.IndexByte(rest[j:], '=')
			if eq < 0 || j+eq+1 >= len(rest) || rest[j+eq+1] != '"' {
				return
			}
			k := rest[j : j+eq]
			j += eq + 2
			var v strings.Builder
			for j < len(rest) && rest[j] != '"' {
				if rest[j] == '\\' && j+1 < len(rest) {
					j++
					if rest[j] == 'n' {
						v.WriteByte('\n')
					} else {
						v.WriteByte(rest[j])
					}
				} else {
					v.WriteByte(rest[j])
				}
				j++
			}
			j++
			labels[strings.TrimLeft(k, ", ")] = v.String()
			for j < len(rest) && rest[j] == ',' {
				j++
			}
		}
		if j >= len(rest) {
			return
		}
		rest = rest[j+1:]
	}
	f := strings.Fields(rest)
	if len(f) == 0 {
		return
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return
	}
	return name, labels, v, true
}

// quantile returns the q-quantile in milliseconds, interpolating linearly
// inside the bucket, or -1 without observations.
func quantile(h topHist, q float64) float64 {
	n := len(h.cum)
	if n == 0 || h.cum[n-1] <= 0 {
		return -1
	}
	target := q * h.cum[n-1]
	lo, prev := 0.0, 0.0
	for i, c := range h.cum {
		if c >= target {
			if math.IsInf(h.le[i], 1) {
				return lo * 1000
			}
			if c == prev {
				return h.le[i] * 1000
			}
			return (lo + (h.le[i]-lo)*(target-prev)/(c-prev)) * 1000
		}
		lo, prev = h.le[i], c
	}
	return lo * 1000
}

// diffHist subtracts an earlier cumulative histogram; ok is false when the
// bucket layouts differ or nothing was observed in between.
func diffHist(cur, old topHist) (topHist, bool) {
	if len(cur.le) != len(old.le) || len(cur.le) == 0 {
		return cur, false
	}
	out := topHist{le: cur.le, cum: make([]float64, len(cur.cum))}
	for i := range cur.cum {
		out.cum[i] = cur.cum[i] - old.cum[i]
		if out.cum[i] < 0 {
			return cur, false
		}
	}
	return out, out.cum[len(out.cum)-1] > 0
}

// ---- model ----

func buildTopModel(admin string, prev, cur *topScrape) *topModel {
	m := &topModel{Admin: admin, Generation: cur.gen, Total: cur.total, Unmatched: cur.unmatched, Open: cur.open, Errors: cur.errs, Endpoints: cur.eps, Rate: -1}
	dt := 0.0
	if prev != nil {
		dt = cur.at.Sub(prev.at).Seconds()
		m.HaveRate = dt > 0 && cur.total >= prev.total
	}
	if m.HaveRate {
		m.Rate = float64(cur.total-prev.total) / dt
	}
	rows := func(cs map[string]topCounter, hs map[string]topHist, pc map[string]topCounter, ph map[string]topHist) []topRow {
		var out []topRow
		for name, c := range cs {
			r := topRow{Name: name, Requests: c.Requests, Rate: -1, ErrPct: -1, P50: -1, P95: -1, Status: c.Status}
			h := hs[name]
			if m.HaveRate {
				old := pc[name]
				dn := c.Requests - old.Requests
				if dn >= 0 {
					r.Rate = float64(dn) / dt
					if dn > 0 {
						r.ErrPct = 100 * float64(c.Status["5xx"]-old.Status["5xx"]) / float64(dn)
					}
				}
				if w, ok := diffHist(h, ph[name]); ok {
					h = w
				}
			} else if c.Requests > 0 {
				r.ErrPct = 100 * float64(c.Status["5xx"]) / float64(c.Requests)
			}
			r.P50, r.P95 = quantile(h, .5), quantile(h, .95)
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Rate != out[j].Rate {
				return out[i].Rate > out[j].Rate
			}
			if out[i].Requests != out[j].Requests {
				return out[i].Requests > out[j].Requests
			}
			return out[i].Name < out[j].Name
		})
		return out
	}
	var pr, pb map[string]topCounter
	var phr, phb map[string]topHist
	if prev != nil {
		pr, pb, phr, phb = prev.routes, prev.backends, prev.routeH, prev.backendH
	}
	m.Routes = rows(cur.routes, cur.routeH, pr, phr)
	m.Backends = rows(cur.backends, cur.backendH, pb, phb)
	return m
}

// ---- fetching ----

type topFetchError struct {
	unauthorized bool
	msg          string
}

func (e *topFetchError) Error() string { return e.msg }

func topBase(admin string) (string, error) {
	if !strings.Contains(admin, "://") {
		admin = "http://" + admin
	}
	u, err := url.Parse(admin)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", userErrorf("--admin %q: want HOST:PORT, for example %s", admin, defaultConnAdmin)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return "", userErrorf("--admin %q: want HOST:PORT, for example %s", admin, defaultConnAdmin)
	}
	return u.Scheme + "://" + u.Host, nil
}

func topGet(ctx context.Context, c *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := c.Do(req)
	if err != nil {
		return nil, &topFetchError{msg: "cannot reach the gateway admin endpoint"}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &topFetchError{unauthorized: true, msg: "the admin endpoint refused the request (" + resp.Status + ")"}
	case resp.StatusCode != http.StatusOK:
		return nil, &topFetchError{msg: "the admin endpoint answered " + resp.Status}
	}
	return b, nil
}

// topFetch polls the admin API once. /stats is required; the other documents
// are best effort so an older gateway still shows something.
func topFetch(ctx context.Context, c *http.Client, base string, now time.Time) (*topScrape, error) {
	s := &topScrape{at: now}
	b, err := topGet(ctx, c, base+"/stats")
	if err != nil {
		return nil, err
	}
	var st struct {
		Requests  int64                 `json:"requests"`
		Unmatched int64                 `json:"unmatched"`
		Routes    map[string]topCounter `json:"routes"`
		Backends  map[string]topCounter `json:"backends"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, &topFetchError{msg: "unexpected /stats response"}
	}
	s.total, s.unmatched, s.routes, s.backends = st.Requests, st.Unmatched, st.Routes, st.Backends
	if s.routes == nil {
		s.routes = map[string]topCounter{}
	}
	if s.backends == nil {
		s.backends = map[string]topCounter{}
	}
	if b, err := topGet(ctx, c, base+"/metrics"); err == nil {
		s.routeH, s.backendH, s.eps = parseProm(string(b))
	}
	if b, err := topGet(ctx, c, base+"/status"); err == nil {
		var d struct {
			Generation int64 `json:"generation"`
		}
		if json.Unmarshal(b, &d) == nil {
			s.gen = d.Generation
		}
	}
	if b, err := topGet(ctx, c, base+"/connections?limit=200"); err == nil {
		var d connDoc
		if json.Unmarshal(b, &d) == nil {
			s.open = len(d.Open)
			for _, r := range d.History {
				code, _ := r["status"].(float64)
				if int(code) < 500 && fieldStr(r, "error") == "" {
					continue
				}
				s.errs = append(s.errs, topErr{Time: fieldStr(r, "time"), Status: int(code), Method: fieldStr(r, "method"), Path: fieldStr(r, "path"),
					Route: fieldStr(r, "route"), Backend: fieldStr(r, "backend"), Error: fieldStr(r, "error")})
				if len(s.errs) == 20 {
					break
				}
			}
		}
	}
	return s, nil
}

// ---- state and keys ----

type topState struct {
	Sel    int
	Detail bool
	Paused bool
	Quit   bool
	Once   bool // one-shot table: no footer, no selection
}

// topKey applies one key to the state. n is the number of selectable rows.
func topKey(st topState, key string, n int) topState {
	switch key {
	case "q", "ctrl-c":
		st.Quit = true
	case "j", "down":
		if st.Sel < n-1 {
			st.Sel++
		}
	case "k", "up":
		if st.Sel > 0 {
			st.Sel--
		}
	case "enter":
		st.Detail = !st.Detail && n > 0
	case "esc", "backspace":
		st.Detail = false
	case "p":
		st.Paused = !st.Paused
	}
	if st.Sel >= n {
		st.Sel = max(n-1, 0)
	}
	if n == 0 {
		st.Detail = false
	}
	return st
}

// topKeys turns one terminal read into key names.
func topKeys(b []byte) []string {
	if len(b) == 1 && b[0] == 0x1b {
		return []string{"esc"}
	}
	if len(b) >= 3 && b[0] == 0x1b && b[1] == '[' {
		switch b[2] {
		case 'A':
			return []string{"up"}
		case 'B':
			return []string{"down"}
		}
		return nil
	}
	var out []string
	for _, c := range b {
		switch c {
		case 3:
			out = append(out, "ctrl-c")
		case '\r', '\n':
			out = append(out, "enter")
		case 127, 8:
			out = append(out, "backspace")
		case 0x1b:
		default:
			out = append(out, string(rune(c)))
		}
	}
	return out
}

// ---- rendering ----

type topLine struct {
	text string
	st   func(string) string
}

func (m *topModel) all() []topRow { return append(append([]topRow{}, m.Routes...), m.Backends...) }

func fmtRate(r float64) string {
	switch {
	case r < 0:
		return "-"
	case r == 0:
		return "0"
	case r < 0.1:
		return "<0.1"
	case r < 100:
		return fmt.Sprintf("%.1f", r)
	}
	return fmt.Sprintf("%.0f", r)
}

func fmtPct(p float64) string {
	switch {
	case p < 0:
		return "-"
	case p == 0:
		return "0%"
	case p < 10:
		return fmt.Sprintf("%.1f%%", p)
	}
	return fmt.Sprintf("%.0f%%", p)
}

func fmtLat(ms float64) string {
	switch {
	case ms < 0:
		return "-"
	case ms < 10:
		return fmt.Sprintf("%.1fms", ms)
	case ms < 1000:
		return fmt.Sprintf("%.0fms", ms)
	}
	return fmt.Sprintf("%.1fs", ms/1000)
}

func clip(s string, w int, ascii bool) string {
	r := []rune(s)
	if w <= 0 {
		return ""
	}
	if len(r) <= w {
		return s
	}
	if ascii {
		if w <= 3 {
			return string(r[:w])
		}
		return string(r[:w-3]) + "..."
	}
	return string(r[:w-1]) + "…"
}

// topVerdict is the one-line summary and its severity: ok, warn or bad.
func topVerdict(m *topModel) (string, string) {
	if m.Err != "" {
		return m.Err, "bad"
	}
	worst, wn := "", 0.0
	for _, r := range m.Routes {
		if r.Rate > 0 && r.ErrPct >= 5 && r.ErrPct > wn {
			worst, wn = r.Name, r.ErrPct
		}
	}
	ej := len(m.ejected())
	var v, sev string
	switch {
	case worst != "":
		v, sev = fmt.Sprintf("Errors rising on route %s (%s of requests)", worst, fmtPct(wn)), "bad"
	case !m.HaveRate && m.Total == 0:
		v, sev = "All quiet: no requests yet", "ok"
	case !m.HaveRate:
		e := int64(0)
		for _, r := range m.Routes {
			e += r.Status["5xx"]
		}
		v, sev = fmt.Sprintf("%s so far, %s", plural(int(m.Total), "request", "requests"), plural(int(e), "server error", "server errors")), "ok"
	case m.Rate == 0:
		v, sev = "All quiet", "ok"
	default:
		e := 0.0
		for _, r := range m.Routes {
			if r.Rate > 0 && r.ErrPct > 0 {
				e += r.Rate * r.ErrPct / 100
			}
		}
		v, sev = fmt.Sprintf("%s req/s, %s server errors/s", fmtRate(m.Rate), fmtRate(e)), "ok"
	}
	if ej > 0 {
		v += "; " + plural(ej, "endpoint", "endpoints") + " ejected or down"
		if sev == "ok" {
			sev = "warn"
		}
	}
	return v, sev
}

// renderTop draws one frame as at most h lines of at most w cells (zero
// means unlimited).
func renderTop(m *topModel, st topState, w, h int, u *ui) string {
	var ls []topLine
	add := func(text string, f func(string) string) { ls = append(ls, topLine{text, f}) }
	mode := "LIVE"
	if st.Paused {
		mode = "PAUSED"
	}
	dot := u.sym("·", "-")
	head := "  setura top  " + m.Admin
	if m.Generation > 0 {
		head += fmt.Sprintf(" %s generation %d", dot, m.Generation)
	}
	if !st.Once {
		if m.Interval > 0 {
			head += fmt.Sprintf(" %s every %s", dot, m.Interval)
		}
		head += " " + dot + " " + mode
	}
	add(head, u.bold)
	add("", nil)
	v, sev := topVerdict(m)
	paint := u.green
	switch sev {
	case "warn":
		paint = u.amber
	case "bad":
		paint = u.red
	}
	mark := map[string]string{"ok": u.sym("●", "*"), "warn": u.sym("▲", "!"), "bad": u.sym("✗", "x")}[sev]
	add("  "+mark+" "+v, paint)
	switch {
	case m.Err != "":
		if m.Hint != "" {
			add("  Next: "+m.Hint, nil)
		}
	case st.Detail && st.Sel < len(m.all()):
		ls = append(ls, topDetail(m, st, u)...)
	default:
		if !m.HaveRate {
			add("  Single sample: showing totals since the gateway started. Rates need the live view.", u.gray)
		}
		ls = append(ls, topTable("ROUTES", m.Routes, 0, st, m.HaveRate, w, u)...)
		ls = append(ls, topTable("BACKENDS", m.Backends, len(m.Routes), st, m.HaveRate, w, u)...)
		if ej := m.ejected(); len(ej) > 0 {
			add("", nil)
			add("  EJECTED ENDPOINTS", u.gray)
			for _, e := range ej {
				why := "ejected"
				if !e.Ejected {
					why = "unhealthy"
				}
				add(fmt.Sprintf("  %s %s  %s  %s", u.sym("▲", "!"), e.Backend, e.Endpoint, why), u.amber)
			}
		}
		add("", nil)
		add("  Open connections  "+strconv.Itoa(m.Open), nil)
		if len(m.Errors) > 0 {
			add("", nil)
			add("  RECENT ERRORS", u.gray)
			for i, e := range m.Errors {
				if i == 6 {
					break
				}
				add("  "+topErrLine(e), nil)
			}
		}
	}
	foot := ""
	if !st.Once {
		foot = "  q quit  j/k select  enter details  p pause"
		if st.Detail {
			foot = "  q quit  esc back  p pause"
		}
	}
	body := ls
	if h > 0 {
		room := h
		if foot != "" {
			room--
		}
		if len(body) > room {
			body = body[:max(room, 0)]
		}
	}
	var b strings.Builder
	for i, l := range body {
		b.WriteString(topPaint(l, w, u))
		if i < len(body)-1 || foot != "" {
			b.WriteByte('\n')
		}
	}
	if foot != "" {
		b.WriteString(topPaint(topLine{foot, u.gray}, w, u))
	}
	return b.String()
}

func topPaint(l topLine, w int, u *ui) string {
	t := l.text
	if w > 0 {
		t = clip(t, w, u.ascii)
	}
	if l.st != nil && t != "" {
		return l.st(t)
	}
	return t
}

func topErrLine(e topErr) string {
	t := e.Time
	if len(t) >= 19 && t[10] == 'T' {
		t = t[11:19]
	}
	s := fmt.Sprintf("%s %d %s %s", t, e.Status, e.Method, e.Path)
	if e.Route != "" {
		s += "  " + e.Route
	}
	if e.Backend != "" {
		s += " -> " + e.Backend
	}
	if e.Error != "" {
		s += "  " + e.Error
	}
	return strings.TrimSpace(s)
}

func topTable(title string, rows []topRow, offset int, st topState, rate bool, w int, u *ui) []topLine {
	first := "req/s"
	if !rate {
		first = "requests"
	}
	nameW := 24
	if w > 0 {
		nameW = min(max(w-2-4*9-1, 8), 40)
	}
	hdr := func(n, a, b, c, d string) string {
		return "  " + pad(n, nameW) + " " + fmt.Sprintf("%9s%9s%9s%9s", a, b, c, d)
	}
	ls := []topLine{{}, {hdr(title, first, "err%", "p50", "p95"), u.gray}}
	if len(rows) == 0 {
		return append(ls, topLine{"  nothing yet: no traffic has been counted", u.gray})
	}
	for i, r := range rows {
		a := fmtRate(r.Rate)
		if !rate {
			a = strconv.FormatInt(r.Requests, 10)
		}
		text := hdr(clip(r.Name, nameW, u.ascii), a, fmtPct(r.ErrPct), fmtLat(r.P50), fmtLat(r.P95))
		var f func(string) string
		switch {
		case !st.Once && st.Sel == offset+i:
			f = func(s string) string { return u.sgr("7", s) }
		case r.ErrPct >= 5 && r.Rate != 0:
			f = u.red
		}
		ls = append(ls, topLine{text, f})
	}
	return ls
}

func topDetail(m *topModel, st topState, u *ui) []topLine {
	rows := m.all()
	r := rows[st.Sel]
	kind := "Route"
	if st.Sel >= len(m.Routes) {
		kind = "Backend"
	}
	var ls []topLine
	add := func(t string, f func(string) string) { ls = append(ls, topLine{t, f}) }
	add("", nil)
	add("  "+kind+"  "+r.Name, u.bold)
	add("", nil)
	add(fmt.Sprintf("  Requests      %d", r.Requests), nil)
	add("  Rate          "+fmtRate(r.Rate)+" req/s", nil)
	add("  Error rate    "+fmtPct(r.ErrPct), nil)
	add("  Latency       p50 "+fmtLat(r.P50)+"   p95 "+fmtLat(r.P95), nil)
	var cls []string
	for _, k := range sortedKeys(r.Status) {
		cls = append(cls, fmt.Sprintf("%s %d", k, r.Status[k]))
	}
	add("  Status        "+strings.Join(cls, "   "), nil)
	if kind == "Backend" {
		add("", nil)
		add("  ENDPOINTS", u.gray)
		n := 0
		for _, e := range m.Endpoints {
			if e.Backend != r.Name {
				continue
			}
			n++
			state := "healthy"
			if e.Ejected {
				state = "ejected"
			} else if !e.Healthy {
				state = "unhealthy"
			}
			add("  "+pad(e.Endpoint, 28)+" "+state, nil)
		}
		if n == 0 {
			add("  no endpoint gauges reported", u.gray)
		}
	}
	add("", nil)
	add("  RECENT ERRORS", u.gray)
	n := 0
	for _, e := range m.Errors {
		if e.Route == r.Name || e.Backend == r.Name {
			add("  "+topErrLine(e), nil)
			n++
		}
	}
	if n == 0 {
		add("  none in the recent window", u.gray)
	}
	return ls
}

// ---- command ----

// topFailure words a fetch failure as a verdict and a next step.
func topFailure(err error, admin string) (string, string) {
	var fe *topFetchError
	if errors.As(err, &fe) && fe.unauthorized {
		return "The gateway admin endpoint at " + admin + " needs a token", "export SETURA_ADMIN_TOKEN=... (the value given to --admin-token), then run setura top again."
	}
	if errors.As(err, &fe) && !strings.HasPrefix(fe.msg, "cannot reach") {
		return "Unexpected answer from " + admin + ": " + fe.msg, "check that --admin points at a Setura gateway admin listener."
	}
	return "Cannot reach the gateway admin endpoint at " + admin, "start the gateway with `setura gateway run --config FILE` (admin listens on " + defaultConnAdmin + " by default), or pass --admin HOST:PORT; set SETURA_ADMIN_TOKEN if it uses --admin-token."
}

func runTop(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) (int, error) {
	admin := fs.String("admin", defaultConnAdmin, "gateway admin address")
	interval := fs.Duration("interval", time.Second, "refresh interval (at least 200ms)")
	once := fs.Bool("once", false, "print one frame and exit")
	format := fs.String("format", "auto", "auto (live on a terminal, table when piped), table or json")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		fmt.Fprintln(stderr, "setura top: unexpected arguments")
		exampleHint(stderr, "top")
		return 2, usageError{"arguments"}
	}
	switch *format {
	case "auto", "table", "json":
	default:
		return 2, userErrorf("--format must be auto, table or json, got %q", *format)
	}
	if *interval < 200*time.Millisecond {
		return 2, userErrorf("--interval must be at least 200ms")
	}
	base, err := topBase(*admin)
	if err != nil {
		return 2, err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	live := stdoutTTY && isTTY(os.Stdin) && !*once && *format == "auto"
	if !live {
		s, err := topFetch(ctx, client, base, time.Now())
		if err != nil {
			verdict, hint := topFailure(err, *admin)
			fmt.Fprintf(stderr, "\n  %s %s\n  %s %s\n\n", u.failSym(), u.bold(verdict), u.blue("Next:"), hint)
			return 1, nil
		}
		m := buildTopModel(*admin, nil, s)
		if *format == "json" {
			return 0, writeJSON(stdout, m)
		}
		fmt.Fprint(stdout, "\n"+renderTop(m, topState{Once: true}, 0, 0, u)+"\n\n")
		return 0, nil
	}
	return topLive(ctx, client, base, *admin, *interval, stdout, u)
}

func sttyRun(args ...string) (string, error) {
	c := exec.Command("stty", args...)
	c.Stdin = os.Stdin
	b, err := c.Output()
	return strings.TrimSpace(string(b)), err
}

func termSize() (w, h int) {
	w, h = 100, 30
	if s, err := sttyRun("size"); err == nil {
		var r, c int
		if n, _ := fmt.Sscanf(s, "%d %d", &r, &c); n == 2 && r > 0 && c > 0 {
			return c, r
		}
	}
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		w = c
	}
	if l, err := strconv.Atoi(os.Getenv("LINES")); err == nil && l > 0 {
		h = l
	}
	return
}

func topLive(ctx context.Context, client *http.Client, base, admin string, interval time.Duration, stdout io.Writer, u *ui) (int, error) {
	saved, serr := sttyRun("-g")
	if serr == nil {
		_, serr = sttyRun("-icanon", "-echo", "min", "1", "time", "0")
	}
	fmt.Fprint(stdout, "\x1b[?1049h\x1b[?25l")
	defer func() {
		fmt.Fprint(stdout, "\x1b[?25h\x1b[?1049l")
		if serr == nil {
			sttyRun(saved)
		}
	}()
	keys := make(chan string, 16)
	if serr == nil { // without stty only Ctrl-C (a signal) can quit
		go func() {
			buf := make([]byte, 16)
			for {
				n, err := os.Stdin.Read(buf)
				if err != nil {
					return
				}
				for _, k := range topKeys(buf[:n]) {
					select {
					case keys <- k:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	var prev, cur *topScrape
	model := &topModel{Admin: admin}
	st := topState{}
	fetch := func() {
		s, err := topFetch(ctx, client, base, time.Now())
		if err != nil {
			verdict, hint := topFailure(err, admin)
			model = &topModel{Admin: admin, Interval: interval, Err: verdict, Hint: hint}
			return
		}
		prev, cur = cur, s
		model = buildTopModel(admin, prev, cur)
		model.Interval = interval
	}
	draw := func() {
		w, h := termSize()
		st = topKey(st, "", len(model.all()))
		frame := renderTop(model, st, w, h, u)
		fmt.Fprint(stdout, "\x1b[H"+strings.ReplaceAll(frame, "\n", "\x1b[K\n")+"\x1b[K\x1b[J")
	}
	fetch()
	draw()
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, nil
		case <-tk.C:
			if !st.Paused {
				fetch()
				draw()
			}
		case k := <-keys:
			st = topKey(st, k, len(model.all()))
			if st.Quit {
				return 0, nil
			}
			draw()
		}
	}
}
