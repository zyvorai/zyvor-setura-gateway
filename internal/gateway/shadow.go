package gateway

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

const (
	shadowRingSize    = 200 // recent mismatches kept
	shadowDeltaWindow = 512 // latency deltas kept per route
	shadowMaxInflight = 64  // concurrent comparisons; more are dropped
	shadowPrimaryWait = 30 * time.Second
	shadowTimeout     = 10 * time.Second
	shadowSchema      = "setura.shadow/v1"
)

// shadowState holds comparison results. The zero value is ready to use.
type shadowState struct {
	mu       sync.Mutex
	routes   map[string]*shadowRoute
	ring     []shadowEntry
	head     int
	total    shadowRoute
	lastErr  string
	inflight int
	limit    int // test hook, default shadowMaxInflight
}

type shadowRoute struct {
	Sampled, Compared, Matched, Mismatched, Errors, Dropped, Skipped int64
	Cat                                                              map[string]int64
	deltas                                                           []float64
	dn                                                               int
}

func (r *shadowRoute) cat(c string) {
	if r.Cat == nil {
		r.Cat = map[string]int64{}
	}
	r.Cat[c]++
}

// shadowSide describes one response in a mismatch entry.
type shadowSide struct {
	Backend string  `json:"backend"`
	Status  int     `json:"status"`
	Ms      float64 `json:"ms"`
}

// shadowDetail is the minimal diff excerpt.
type shadowDetail struct {
	Where   string `json:"where"`
	Primary string `json:"primary"`
	Shadow  string `json:"shadow"`
}

// shadowEntry is one recorded mismatch.
type shadowEntry struct {
	Time     string       `json:"time"`
	Route    string       `json:"route"`
	Category string       `json:"category"`
	Method   string       `json:"method"`
	Path     string       `json:"path"`
	Detail   shadowDetail `json:"detail"`
	Primary  shadowSide   `json:"primary"`
	Shadow   shadowSide   `json:"shadow"`
	DeltaMs  float64      `json:"deltaMs"`
}

func (s *shadowState) route(key string) *shadowRoute {
	if s.routes == nil {
		s.routes = map[string]*shadowRoute{}
	}
	r := s.routes[key]
	if r == nil {
		r = &shadowRoute{}
		s.routes[key] = r
	}
	return r
}

func (s *shadowState) acquire(route string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lim := s.limit
	if lim <= 0 {
		lim = shadowMaxInflight
	}
	if s.inflight >= lim {
		s.route(route).Dropped++
		s.total.Dropped++
		return false
	}
	s.inflight++
	s.route(route).Sampled++
	s.total.Sampled++
	return true
}

func (s *shadowState) release() {
	s.mu.Lock()
	s.inflight--
	s.mu.Unlock()
}

// skip counts a request whose body was over the maxBody ceiling and therefore
// not compared.
func (s *shadowState) skip(route string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.route(route).Skipped++
	s.total.Skipped++
}

func (s *shadowState) fail(route, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.route(route).Errors++
	s.total.Errors++
	s.lastErr = msg
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// record stores the outcome of one comparison.
func (s *shadowState) record(route, method, path string, p, sh *respCapture, mm []shadowMismatch, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delta := ms(sh.dur - p.dur)
	for _, r := range []*shadowRoute{s.route(route), &s.total} {
		r.Compared++
		if len(mm) == 0 {
			r.Matched++
		} else {
			r.Mismatched++
		}
		for _, m := range mm {
			r.cat(m.Category)
		}
	}
	rt := s.route(route)
	if len(rt.deltas) < shadowDeltaWindow {
		rt.deltas = append(rt.deltas, delta)
	} else {
		rt.deltas[rt.dn%shadowDeltaWindow] = delta
	}
	rt.dn++
	for _, m := range mm {
		e := shadowEntry{Time: now.UTC().Format(time.RFC3339), Route: route, Category: m.Category, Method: method, Path: path,
			Detail:  shadowDetail{Where: m.Where, Primary: m.Primary, Shadow: m.Shadow},
			Primary: shadowSide{p.backend, p.status, ms(p.dur)}, Shadow: shadowSide{sh.backend, sh.status, ms(sh.dur)}, DeltaMs: delta}
		if len(s.ring) < shadowRingSize {
			s.ring = append(s.ring, e)
		} else {
			s.ring[s.head] = e
			s.head = (s.head + 1) % shadowRingSize
		}
	}
}

// ShadowRouteSummary is the per-route part of the /shadow document.
type ShadowRouteSummary struct {
	Sampled    int64            `json:"sampled"`
	Compared   int64            `json:"compared"`
	Matched    int64            `json:"matched"`
	Mismatched int64            `json:"mismatched"`
	Errors     int64            `json:"errors"`
	Dropped    int64            `json:"dropped"`
	Skipped    int64            `json:"skipped"`
	ByCategory map[string]int64 `json:"byCategory"`
	MatchRate  *float64         `json:"matchRate,omitempty"`
	P50DeltaMs float64          `json:"p50DeltaMs"`
	P95DeltaMs float64          `json:"p95DeltaMs"`
}

// ShadowSummary is the /shadow document.
type ShadowSummary struct {
	Schema string `json:"schema"`
	ShadowRouteSummary
	Routes    map[string]ShadowRouteSummary `json:"routes"`
	Recent    []shadowEntry                 `json:"recent"`
	LastError string                        `json:"lastError,omitempty"`
}

func rate(r *shadowRoute) *float64 {
	if r.Compared == 0 {
		return nil
	}
	v := float64(r.Matched) * 100 / float64(r.Compared)
	return &v
}

func percentile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q*float64(len(sorted))+0.999999) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func summarize(r *shadowRoute, deltas []float64) ShadowRouteSummary {
	sort.Float64s(deltas)
	cat := map[string]int64{"status": 0, "header": 0, "body": 0, "latency": 0}
	for k, v := range r.Cat {
		cat[k] = v
	}
	return ShadowRouteSummary{Sampled: r.Sampled, Compared: r.Compared, Matched: r.Matched, Mismatched: r.Mismatched, Errors: r.Errors,
		Dropped: r.Dropped, Skipped: r.Skipped, ByCategory: cat, MatchRate: rate(r), P50DeltaMs: percentile(deltas, .5), P95DeltaMs: percentile(deltas, .95)}
}

// Summary returns a copy of the current results, newest mismatches first.
func (s *shadowState) Summary() ShadowSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []float64
	out := ShadowSummary{Schema: shadowSchema, Routes: map[string]ShadowRouteSummary{}, LastError: s.lastErr}
	for k, r := range s.routes {
		d := append([]float64(nil), r.deltas...)
		all = append(all, d...)
		out.Routes[k] = summarize(r, d)
	}
	out.ShadowRouteSummary = summarize(&s.total, all)
	n := len(s.ring)
	out.Recent = make([]shadowEntry, 0, n)
	for i := 0; i < n; i++ {
		out.Recent = append(out.Recent, s.ring[((s.head+n-1-i)%n+n)%n])
	}
	return out
}

func (s *shadowState) active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total.Sampled+s.total.Dropped+s.total.Errors+s.total.Skipped > 0
}

// writeShadowMetrics emits setura_gateway_shadow_total.
func (s *Server) writeShadowMetrics(w io.Writer) {
	fmt.Fprint(w, "# HELP setura_gateway_shadow_total Shadow comparisons by route and result.\n# TYPE setura_gateway_shadow_total counter\n")
	st := &s.shadow
	st.mu.Lock()
	defer st.mu.Unlock()
	keys := make([]string, 0, len(st.routes))
	for k := range st.routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := st.routes[k]
		row := func(res string, n int64) {
			fmt.Fprintf(w, "setura_gateway_shadow_total{route=\"%s\",result=\"%s\"} %d\n", promLabel(k), res, n)
		}
		row("matched", r.Matched)
		row("mismatched", r.Mismatched)
		cats := map[string]bool{"status": true, "header": true, "body": true, "latency": true}
		for c := range r.Cat {
			cats[c] = true
		}
		for _, c := range sortedKeys(cats) {
			row(c, r.Cat[c])
		}
		row("error", r.Errors)
		row("dropped", r.Dropped)
		row("skipped", r.Skipped)
	}
}

// shadowReq follows one primary request that has comparing mirrors.
type shadowReq struct {
	s       *Server
	route   string
	method  string
	path    string
	backend string
	on      map[*CMirror]*CShadow
	max     int64
	grpc    bool
	start   time.Time
	done    chan struct{}
	cap     *shadowWriter
}

// shadowStart decides which mirrors compare for this request. It returns nil
// when none do, which leaves the request path untouched.
func (s *Server) shadowStart(r *http.Request, route, backend string, mirrors []*CMirror) *shadowReq {
	var req *shadowReq
	for _, m := range mirrors {
		on, sample := m.Shadow.effective(s.opts.ShadowDiff)
		if !on || (sample < 100 && s.intn(100) >= sample) {
			continue
		}
		if req == nil {
			req = &shadowReq{s: s, route: route, method: r.Method, path: r.URL.Path, backend: backend, on: map[*CMirror]*CShadow{}, done: make(chan struct{})}
		}
		req.on[m] = m.Shadow
		if mx := m.Shadow.max(); mx > req.max {
			req.max = mx
		}
	}
	return req
}

// wrap captures what the client receives. Nil-safe.
func (q *shadowReq) wrap(w http.ResponseWriter) http.ResponseWriter {
	if q == nil {
		return w
	}
	q.start = time.Now()
	q.cap = &shadowWriter{ResponseWriter: w, bc: bodyCap{max: q.max}}
	return q.cap
}

// finish releases waiting comparisons once the primary response is complete.
func (q *shadowReq) finish() {
	if q != nil && q.cap != nil {
		q.cap.dur = time.Since(q.start)
		if q.grpc {
			q.cap.trailer = finalTrailers(q.cap.ResponseWriter.Header())
		}
		close(q.done)
	}
}

// submit hands the mirror request to the bounded comparison pool. It reports
// false when the mirror is not compared or the pool is full, in which case the
// caller sends the plain fire-and-forget copy instead.
func (q *shadowReq) submit(m *CMirror, req *http.Request, client *http.Client) bool {
	if q == nil || q.cap == nil {
		return false
	}
	cfg, ok := q.on[m]
	if !ok {
		return false
	}
	return q.launch(m, cfg, req, client)
}

func (q *shadowReq) launch(m *CMirror, cfg *CShadow, req *http.Request, client *http.Client) bool {
	s := q.s
	if !s.shadow.acquire(q.route) {
		return false
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = shadowTimeout
	s.mirrorWG.Add(1)
	go func() {
		defer s.mirrorWG.Done()
		defer s.shadow.release()
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			s.shadow.fail(q.route, "shadow request failed")
			return
		}
		bc := &bodyCap{max: cfg.max()}
		_, rerr := io.Copy(bc, io.LimitReader(resp.Body, bc.max+1))
		sh := &respCapture{status: resp.StatusCode, hdr: resp.Header, trailer: resp.Trailer.Clone(), dur: time.Since(t0), backend: m.B.Key}
		resp.Body.Close()
		bc.fill(sh)
		if rerr != nil {
			s.shadow.fail(q.route, "shadow response read failed")
			return
		}
		select {
		case <-q.done:
		case <-time.After(shadowPrimaryWait):
			s.shadow.fail(q.route, "primary response did not complete")
			return
		}
		p := &respCapture{status: q.cap.status, hdr: q.cap.hdr, trailer: q.cap.trailer, dur: q.cap.dur, backend: q.backend}
		q.cap.bc.fill(p)
		if p.status == 0 {
			p.status = http.StatusOK
		}
		if p.hdr == nil {
			p.hdr = http.Header{}
		}
		var mm []shadowMismatch
		if q.grpc {
			mm = compareGRPC(p, sh, cfg)
		} else {
			mm = compareCaptures(p, sh, cfg)
		}
		if bodiesSkipped(p, sh) {
			s.shadow.skip(q.route)
		}
		s.shadow.record(q.route, q.method, q.path, p, sh, mm, time.Now())
	}()
	return true
}

// shadowWriter copies the response head and streams the body through bodyCap.
type shadowWriter struct {
	http.ResponseWriter
	bc      bodyCap
	status  int
	hdr     http.Header
	trailer http.Header
	dur     time.Duration
}

func (w *shadowWriter) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == 101) {
		w.status, w.hdr = code, w.ResponseWriter.Header().Clone()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *shadowWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status, w.hdr = http.StatusOK, w.ResponseWriter.Header().Clone()
	}
	w.bc.Write(p)
	return w.ResponseWriter.Write(p)
}

func (w *shadowWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach Hijack for upgrades.
func (w *shadowWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
