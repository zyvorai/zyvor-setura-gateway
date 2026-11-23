package gateway

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Response compression: gzip and deflate (zlib, as HTTP means by "deflate")
// from the standard library, negotiated with Accept-Encoding. Brotli and zstd
// are not in the standard library and are not offered (docs/traffic-shaping.md).

// CompressKey is the rule extension and the listener extension that tune
// compression; the --compress flags set the gateway wide default.
const CompressKey = "setura.zyvor.dev/compress"

// CompressConfig is one level of compression settings (rule, listener or the
// gateway flags). Unset members inherit from the level above: rule over
// listener over gateway over the built-in defaults.
type CompressConfig struct {
	Enabled   *bool      `json:"enabled,omitempty"`
	Encodings []string   `json:"encodings,omitempty"` // gzip, deflate; the order is the preference when the client ranks them equally
	Types     []string   `json:"types,omitempty"`     // text/*, application/json, */*+json ...
	MinSize   flexString `json:"minSize,omitempty"`   // smallest body worth compressing, bytes or 1KB (default 1KB)
	Level     *int       `json:"level,omitempty"`     // 1 (fast) to 9 (small), default 6
}

// DefaultCompressTypes are compressed unless a block names its own.
var DefaultCompressTypes = []string{
	"text/*", "application/json", "application/javascript", "application/x-javascript", "application/xml",
	"application/xhtml+xml", "application/rss+xml", "application/atom+xml", "application/manifest+json",
	"application/graphql", "image/svg+xml", "*/*+json", "*/*+xml",
}

const (
	defaultCompressMin   = 1024
	defaultCompressLevel = 6
)

var supportedEncodings = []string{"gzip", "deflate"}

func (c *CompressConfig) validate() error {
	for _, e := range c.Encodings {
		if !inList(supportedEncodings, strings.ToLower(e)) {
			return fmt.Errorf("%s: encoding %q: the standard library offers gzip and deflate (brotli and zstd are not available)", CompressKey, e)
		}
	}
	for _, t := range c.Types {
		if !validMediaPattern(t) {
			return fmt.Errorf("%s: type %q: want type/subtype, type/* or */*+suffix", CompressKey, t)
		}
	}
	if c.MinSize != "" {
		if _, err := parseBodyLimit(string(c.MinSize)); err != nil {
			return fmt.Errorf("%s: minSize: %w", CompressKey, err)
		}
	}
	if c.Level != nil && (*c.Level < 1 || *c.Level > 9) {
		return fmt.Errorf("%s: level %d: want 1 to 9", CompressKey, *c.Level)
	}
	return nil
}

func inList(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func validMediaPattern(t string) bool {
	typ, sub, ok := strings.Cut(strings.TrimSpace(t), "/")
	if !ok || typ == "" || sub == "" || strings.ContainsAny(t, " ;,") {
		return false
	}
	if typ == "*" && !strings.HasPrefix(sub, "*+") {
		return false
	}
	return true
}

// ParseCompressBlock decodes and validates a compress block.
func ParseCompressBlock(raw []byte) (*CompressConfig, error) {
	var c CompressConfig
	if err := strictDecode(CompressKey, raw, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// compressPolicy is a fully resolved policy.
type compressPolicy struct {
	enabled   bool
	encodings []string
	types     []string
	min       int64
	level     int
}

// CompressOptions are the gateway wide defaults (--compress ...).
type CompressOptions struct {
	Enabled   bool
	Encodings []string
	Types     []string
	MinSize   int64
	Level     int
}

func (o CompressOptions) config() *CompressConfig {
	c := &CompressConfig{Encodings: o.Encodings, Types: o.Types}
	en := o.Enabled
	c.Enabled = &en
	if o.MinSize > 0 {
		c.MinSize = flexString(strconv.FormatInt(o.MinSize, 10))
	}
	if o.Level > 0 {
		lv := o.Level
		c.Level = &lv
	}
	return c
}

// resolveCompress layers the levels: gateway flags, then the listener, then the rule.
func resolveCompress(levels ...*CompressConfig) compressPolicy {
	p := compressPolicy{encodings: supportedEncodings, types: DefaultCompressTypes, min: defaultCompressMin, level: defaultCompressLevel}
	for _, c := range levels {
		if c == nil {
			continue
		}
		if c.Enabled != nil {
			p.enabled = *c.Enabled
		}
		if len(c.Encodings) > 0 {
			p.encodings = p.encodings[:0:0]
			for _, e := range c.Encodings {
				p.encodings = append(p.encodings, strings.ToLower(e))
			}
		}
		if len(c.Types) > 0 {
			p.types = c.Types
		}
		if c.MinSize != "" {
			p.min, _ = parseBodyLimit(string(c.MinSize))
		}
		if c.Level != nil {
			p.level = *c.Level
		}
	}
	return p
}

// matchType reports whether a Content-Type is on the list.
func (p compressPolicy) matchType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	typ, sub, _ := strings.Cut(ct, "/")
	for _, pat := range p.types {
		pat = strings.ToLower(strings.TrimSpace(pat))
		pt, ps, _ := strings.Cut(pat, "/")
		switch {
		case pat == ct:
			return true
		case ps == "*" && pt == typ:
			if ct == "text/event-stream" && pat == "text/*" {
				continue // an event stream is not worth buffering: it must be listed by name
			}
			return true
		case pt == "*" && strings.HasPrefix(ps, "*+") && strings.HasSuffix(sub, ps[1:]):
			return true
		}
	}
	return false
}

// negotiate picks the encoding for an Accept-Encoding header, "" for none.
func (p compressPolicy) negotiate(ae string) string {
	if ae == "" {
		return ""
	}
	q := map[string]float64{}
	star := -1.0
	for _, part := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		w := 1.0
		if params != "" {
			k, v, _ := strings.Cut(strings.TrimSpace(params), "=")
			if strings.EqualFold(strings.TrimSpace(k), "q") {
				f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
				if err != nil {
					f = 0
				}
				w = f
			}
		}
		switch name {
		case "x-gzip":
			name = "gzip"
		case "*":
			star = w
			continue
		}
		if _, seen := q[name]; !seen {
			q[name] = w
		}
	}
	best, bestQ := "", 0.0
	for _, e := range p.encodings {
		w, ok := q[e]
		if !ok {
			if star < 0 {
				continue
			}
			w = star
		}
		if w > bestQ {
			best, bestQ = e, w
		}
	}
	return best
}

var (
	gzPools [10]sync.Pool // by level
	zlPools [10]sync.Pool
)

type encWriter interface {
	io.WriteCloser
	Flush() error
}

func getEncoder(enc string, level int, w io.Writer) encWriter {
	if level < 1 || level > 9 {
		level = defaultCompressLevel
	}
	if enc == "gzip" {
		if v := gzPools[level].Get(); v != nil {
			zw := v.(*gzip.Writer)
			zw.Reset(w)
			return zw
		}
		zw, _ := gzip.NewWriterLevel(w, level)
		return zw
	}
	if v := zlPools[level].Get(); v != nil {
		zw := v.(*zlib.Writer)
		zw.Reset(w)
		return zw
	}
	zw, _ := zlib.NewWriterLevel(w, level)
	return zw
}

func putEncoder(enc string, level int, zw encWriter) {
	if level < 1 || level > 9 {
		level = defaultCompressLevel
	}
	if enc == "gzip" {
		gzPools[level].Put(zw)
	} else {
		zlPools[level].Put(zw)
	}
}

// countWriter counts the bytes that left the encoder.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type cwState int

const (
	cwUndecided cwState = iota
	cwPass
	cwEncode
	cwDiscard // HEAD: the headers say encoded, there is no body
)

// compressWriter compresses the response body when the policy and the
// response allow it. It decides at the first Write, Flush or Close, once the
// headers are final, and buffers up to the minimum size when the length is
// not declared.
type compressWriter struct {
	http.ResponseWriter
	req    *http.Request
	pol    compressPolicy
	enc    string // negotiated, "" when the client accepts none
	route  string
	stats  *shapeStats
	state  cwState
	status int
	buf    []byte
	zw     encWriter
	out    countWriter
	in     int64
}

// newCompressWriter returns nil when compression does not apply to the request.
func newCompressWriter(w http.ResponseWriter, r *http.Request, pol compressPolicy, route string, stats *shapeStats) *compressWriter {
	if !pol.enabled || len(pol.encodings) == 0 {
		return nil
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil
	}
	c := &compressWriter{ResponseWriter: w, req: r, pol: pol, route: route, stats: stats}
	// A ranged request wants bytes of the identity representation: leave it alone.
	if r.Header.Get("Range") == "" {
		c.enc = pol.negotiate(r.Header.Get("Accept-Encoding"))
	}
	return c
}

func (c *compressWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *compressWriter) WriteHeader(code int) {
	if c.state != cwUndecided || c.status != 0 {
		return
	}
	if code >= 100 && code < 200 {
		c.ResponseWriter.WriteHeader(code) // interim and upgrade responses go straight out
		return
	}
	c.status = code
}

func hasToken(h http.Header, name, tok string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), tok) {
				return true
			}
		}
	}
	return false
}

func addVary(h http.Header, v string) {
	if hasToken(h, "Vary", v) || hasToken(h, "Vary", "*") {
		return
	}
	h.Add("Vary", v)
}

// bodyless reports statuses that carry no body.
func bodyless(code int) bool { return code == 204 || code == 304 || (code >= 100 && code < 200) }

// mustBuffer: the decision needs the first bytes (unknown length or type).
func (c *compressWriter) mustBuffer() bool {
	h := c.Header()
	if c.enc == "" || bodyless(c.status) || c.status == http.StatusPartialContent || h.Get("Content-Encoding") != "" {
		return false
	}
	if h.Get("Content-Length") != "" && h.Get("Content-Type") != "" {
		return false
	}
	return c.pol.min > 0 || h.Get("Content-Type") == ""
}

// commit decides, writes the header and flushes what was buffered. flush says
// the handler asked for the bytes to go out now (a stream), so a short body
// is compressed rather than waited for.
func (c *compressWriter) commit(flush bool) {
	h := c.Header()
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if h.Get("Content-Type") == "" && h.Get("Content-Encoding") == "" && len(c.buf) > 0 && !bodyless(c.status) {
		h.Set("Content-Type", http.DetectContentType(c.buf))
	}
	ct := h.Get("Content-Type")
	encoded := h.Get("Content-Encoding") != "" && !strings.EqualFold(h.Get("Content-Encoding"), "identity")
	eligible := !encoded && !bodyless(c.status) && c.status != http.StatusPartialContent && c.pol.matchType(ct)
	if eligible {
		addVary(h, "Accept-Encoding") // the representation depends on it whether or not this client got gzip
	}
	do := eligible && c.enc != "" && h.Get("Content-Range") == "" &&
		!hasToken(h, "Cache-Control", "no-transform")
	if do {
		if cl := h.Get("Content-Length"); cl != "" {
			n, err := strconv.ParseInt(cl, 10, 64)
			do = err == nil && n >= c.pol.min
		} else if c.req.Method == http.MethodHead {
			do = true // no length to judge by and no body to measure: answer as a streamed GET would
		} else if !flush {
			do = int64(len(c.buf)) >= c.pol.min && len(c.buf) > 0
		}
	}
	if do {
		h.Set("Content-Encoding", c.enc)
		h.Del("Content-Length")
		h.Del("Accept-Ranges")
		h.Del("Content-Md5")
		if et := h.Get("Etag"); et != "" && !strings.HasPrefix(et, "W/") {
			h.Set("Etag", "W/"+et)
		}
		if c.req.Method == http.MethodHead {
			c.state = cwDiscard
		} else {
			c.out = countWriter{w: c.ResponseWriter}
			c.zw = getEncoder(c.enc, c.pol.level, &c.out)
			c.state = cwEncode
		}
	} else {
		c.state = cwPass
	}
	c.ResponseWriter.WriteHeader(c.status)
	if len(c.buf) > 0 {
		b := c.buf
		c.buf = nil
		c.write(b)
	}
}

func (c *compressWriter) write(p []byte) (int, error) {
	switch c.state {
	case cwEncode:
		c.in += int64(len(p))
		return c.zw.Write(p)
	case cwDiscard:
		return len(p), nil
	}
	return c.ResponseWriter.Write(p)
}

func (c *compressWriter) Write(p []byte) (int, error) {
	if c.state == cwUndecided {
		if c.status == 0 {
			c.status = http.StatusOK
		}
		if c.mustBuffer() {
			c.buf = append(c.buf, p...)
			if int64(len(c.buf)) < c.pol.min || len(c.buf) == 0 {
				return len(p), nil
			}
			c.commit(false)
			return len(p), nil
		}
		c.commit(false)
	}
	return c.write(p)
}

func (c *compressWriter) Flush() {
	if c.state == cwUndecided {
		c.commit(true)
	}
	if c.state == cwEncode {
		c.zw.Flush()
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Close ends the encoded stream and releases the encoder. It must run before
// the handler returns.
func (c *compressWriter) Close() {
	if c.state == cwUndecided && (c.status != 0 || len(c.buf) > 0) {
		c.commit(false)
	} else if c.state == cwUndecided {
		return // the handler wrote nothing: net/http sends its default response untouched
	}
	if c.state == cwEncode {
		c.zw.Close()
		putEncoder(c.enc, c.pol.level, c.zw)
		c.zw = nil
		c.stats.compressed(c.route, c.enc, c.in, c.out.n)
		c.state = cwPass
	}
}

// ---- metrics ----

// shapeStats counts what the traffic-shaping features did, by bounded labels.
type shapeStats struct {
	mu   sync.Mutex
	vals map[string]map[string]int64 // family -> label string -> value
}

func (s *shapeStats) add(family, labels string, n int64) {
	s.mu.Lock()
	if s.vals == nil {
		s.vals = map[string]map[string]int64{}
	}
	if s.vals[family] == nil {
		s.vals[family] = map[string]int64{}
	}
	s.vals[family][labels] += n
	s.mu.Unlock()
}

func (s *shapeStats) compressed(route, enc string, in, out int64) {
	s.add("compress_responses", fmt.Sprintf(`route="%s",encoding="%s"`, esc(route), enc), 1)
	s.add("compress_bytes", fmt.Sprintf(`route="%s",direction="in"`, esc(route)), in)
	s.add("compress_bytes", fmt.Sprintf(`route="%s",direction="out"`, esc(route)), out)
}

func (s *shapeStats) snapshot(family string) (keys []string, vals map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vals = map[string]int64{}
	for k, v := range s.vals[family] {
		vals[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return
}
