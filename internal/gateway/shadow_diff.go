package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ShadowDiffKey is the extension key on a RequestMirror filter that turns the
// mirror into a comparison.
const ShadowDiffKey = "setura.zyvor.dev/shadow-diff"

const (
	// defaultShadowMaxBody is the ceiling (bytes) up to which a body is compared:
	// byte for byte or structurally up to shadowWindow, by streaming SHA-256 and
	// length above it. Larger bodies are skipped.
	defaultShadowMaxBody = 16 << 20
	// shadowWindow is the most of each body kept in memory for detailed diffs.
	shadowWindow  = 1 << 20
	shadowContext = 80
)

// ShadowDiff is the opt-in comparison block on a RequestMirror filter.
type ShadowDiff struct {
	Compare            *bool    `json:"compare,omitempty"`
	Sample             *int     `json:"sample,omitempty"` // percent of requests, default: --shadow-diff or 100
	Headers            []string `json:"headers,omitempty"`
	IgnoreHeaders      []string `json:"ignoreHeaders,omitempty"`
	IgnoreJSONPaths    []string `json:"ignoreJSONPaths,omitempty"`
	MaxBody            int      `json:"maxBody,omitempty"`            // ceiling in bytes, default 16 MiB
	LatencyThresholdMs int      `json:"latencyThresholdMs,omitempty"` // 0 records the delta without flagging it
	// gRPC routes: frame indexes (0-based) left out of the comparison, and how
	// frame payloads are compared: "bytes" (default) or "json".
	IgnoreFrames []int  `json:"ignoreFrames,omitempty"`
	FrameFormat  string `json:"frameFormat,omitempty"`

	annErr error // set when an annotation value could not be decoded
}

// CShadow is a validated ShadowDiff.
type CShadow struct {
	compare   *bool
	sample    *int
	headers   []string
	ignore    map[string]bool
	paths     []*jsonPath
	maxBody   int
	latencyMs int
	frames    map[int]bool
	frameJSON bool
}

var defaultCompareHeaders = []string{"Content-Type", "Cache-Control", "Location"}

// alwaysIgnored headers differ between any two healthy backends.
var alwaysIgnored = map[string]bool{"date": true, "server": true, "set-cookie": true, "x-request-id": true, "via": true,
	"traceparent": true, "tracestate": true, "b3": true, "x-b3-traceid": true, "x-b3-spanid": true, "x-b3-parentspanid": true,
	"x-b3-sampled": true, "x-cloud-trace-context": true, "x-amzn-trace-id": true}

func compileShadow(d *ShadowDiff) (*CShadow, error) {
	c := &CShadow{ignore: map[string]bool{}, maxBody: defaultShadowMaxBody}
	if d == nil {
		return c, nil
	}
	if d.annErr != nil {
		return nil, d.annErr
	}
	if d.Sample != nil && (*d.Sample < 0 || *d.Sample > 100) {
		return nil, fmt.Errorf("%s: sample %d is not a percentage", ShadowDiffKey, *d.Sample)
	}
	if d.MaxBody < 0 || d.LatencyThresholdMs < 0 {
		return nil, fmt.Errorf("%s: maxBody and latencyThresholdMs must not be negative", ShadowDiffKey)
	}
	c.compare, c.sample, c.latencyMs = d.Compare, d.Sample, d.LatencyThresholdMs
	if d.MaxBody > 0 {
		c.maxBody = d.MaxBody
	}
	switch d.FrameFormat {
	case "", "bytes":
	case "json":
		c.frameJSON = true
	default:
		return nil, fmt.Errorf("%s: frameFormat %q: want bytes or json", ShadowDiffKey, d.FrameFormat)
	}
	for _, i := range d.IgnoreFrames {
		if i < 0 {
			return nil, fmt.Errorf("%s: ignoreFrames index %d is negative", ShadowDiffKey, i)
		}
		if c.frames == nil {
			c.frames = map[int]bool{}
		}
		c.frames[i] = true
	}
	for _, h := range d.Headers {
		c.headers = append(c.headers, http.CanonicalHeaderKey(strings.TrimSpace(h)))
	}
	for _, h := range d.IgnoreHeaders {
		c.ignore[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, p := range d.IgnoreJSONPaths {
		jp, err := parseJSONPath(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ShadowDiffKey, err)
		}
		c.paths = append(c.paths, jp)
	}
	return c, nil
}

// effective resolves the mirror's block against the --shadow-diff default.
func (c *CShadow) effective(global int) (on bool, sample int) {
	if c == nil {
		c = &CShadow{}
	}
	switch {
	case c.compare != nil && !*c.compare:
		return false, 0
	case c.compare == nil && global <= 0:
		return false, 0
	}
	sample = 100
	if global > 0 {
		sample = global
	}
	if c.sample != nil {
		sample = *c.sample
	}
	return sample > 0, sample
}

func (c *CShadow) max() int64 {
	if c == nil || c.maxBody <= 0 {
		return defaultShadowMaxBody
	}
	return int64(c.maxBody)
}

// respCapture is one finished response.
type respCapture struct {
	status  int
	hdr     http.Header
	trailer http.Header
	body    []byte // the first shadowWindow bytes
	n       int64  // total length, valid unless over
	sum     string // hex SHA-256 of the whole body, valid unless over
	over    bool   // the body exceeded the maxBody ceiling and was not compared
	dur     time.Duration
	backend string
}

// shadowMismatch is one difference found between primary and shadow.
type shadowMismatch struct {
	Category string
	Where    string
	Primary  string
	Shadow   string
}

func ignoredHeader(name string, c *CShadow) bool {
	n := strings.ToLower(name)
	if alwaysIgnored[n] || strings.HasPrefix(n, "x-setura-") || strings.HasPrefix(n, "x-b3-") || (c != nil && c.ignore[n]) {
		return true
	}
	return false
}

// compareCaptures lists every difference between the primary and shadow
// responses. An empty result means they match.
func compareCaptures(p, s *respCapture, c *CShadow) []shadowMismatch {
	if c == nil {
		c = &CShadow{}
	}
	var out []shadowMismatch
	if p.status != s.status {
		out = append(out, shadowMismatch{Category: "status", Where: "status", Primary: strconv.Itoa(p.status), Shadow: strconv.Itoa(s.status)})
	}
	seen := map[string]bool{}
	for _, h := range append(append([]string(nil), defaultCompareHeaders...), c.headers...) {
		if seen[h] || ignoredHeader(h, c) {
			continue
		}
		seen[h] = true
		pv, sv := strings.Join(p.hdr.Values(h), ", "), strings.Join(s.hdr.Values(h), ", ")
		if pv != sv {
			out = append(out, shadowMismatch{Category: "header", Where: h, Primary: excerpt(pv), Shadow: excerpt(sv)})
		}
	}
	if m := compareBodies(p, s, c); m != nil {
		out = append(out, *m)
	}
	return append(out, latencyMismatch(p, s, c)...)
}

func latencyMismatch(p, s *respCapture, c *CShadow) []shadowMismatch {
	if c.latencyMs > 0 {
		if d := s.dur - p.dur; d > time.Duration(c.latencyMs)*time.Millisecond {
			return []shadowMismatch{{Category: "latency", Where: "latency",
				Primary: p.dur.Round(time.Millisecond).String(), Shadow: s.dur.Round(time.Millisecond).String()}}
		}
	}
	return nil
}

// bodyCap sees a body once, as it streams by: it keeps the first shadowWindow
// bytes, the length and a SHA-256, and stops hashing at the ceiling.
type bodyCap struct {
	max  int64
	n    int64
	over bool
	buf  []byte
	h    hash.Hash
}

func (b *bodyCap) Write(p []byte) (int, error) {
	if b.over {
		return len(p), nil
	}
	if b.n+int64(len(p)) > b.max {
		b.over, b.h, b.buf = true, nil, nil
		return len(p), nil
	}
	if b.h == nil {
		b.h = sha256.New()
	}
	b.h.Write(p)
	b.n += int64(len(p))
	if room := shadowWindow - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// fill copies the result into a capture.
func (b *bodyCap) fill(c *respCapture) {
	c.body, c.n, c.over = b.buf, b.n, b.over
	if !b.over {
		h := b.h
		if h == nil {
			h = sha256.New()
		}
		c.sum = hex.EncodeToString(h.Sum(nil))
	}
}

// bodiesSkipped reports whether a body was over the ceiling on either side.
func bodiesSkipped(p, s *respCapture) bool { return p.over || s.over }

func compareBodies(p, s *respCapture, c *CShadow) *shadowMismatch {
	if bodiesSkipped(p, s) || (p.n == s.n && p.sum == s.sum) {
		return nil
	}
	pb, sb := p.body, s.body
	small := p.n <= shadowWindow && s.n <= shadowWindow
	if small {
		if pv, ok1 := decodeJSON(pb); ok1 {
			if sv, ok2 := decodeJSON(sb); ok2 {
				for _, jp := range c.paths {
					pv, sv = jp.prune(pv), jp.prune(sv)
				}
				path, a, b, differ := firstJSONDiff(pv, sv, "$")
				if !differ {
					return nil
				}
				return &shadowMismatch{Category: "body", Where: path, Primary: valueExcerpt(path, a), Shadow: valueExcerpt(path, b)}
			}
		}
	}
	off := 0
	for off < len(pb) && off < len(sb) && pb[off] == sb[off] {
		off++
	}
	where := fmt.Sprintf("offset %d (primary %d bytes, shadow %d bytes)", off, p.n, s.n)
	if !small {
		where = fmt.Sprintf("length %d vs %d, sha256 %.12s vs %.12s", p.n, s.n, p.sum, s.sum)
		if off >= len(pb) || off >= len(sb) {
			return &shadowMismatch{Category: "body", Where: where, Primary: "(beyond the first 1 MiB)", Shadow: "(beyond the first 1 MiB)"}
		}
	}
	// Redact a generous neighbourhood first so a secret cut by the excerpt
	// window is still recognised, then show the window of the redacted text.
	rp, rs := redactSlice(pb, off), redactSlice(sb, off)
	roff := 0
	for roff < len(rp) && roff < len(rs) && rp[roff] == rs[roff] {
		roff++
	}
	if rp == rs {
		return &shadowMismatch{Category: "body", Where: where, Primary: "[redacted]", Shadow: "[redacted]"}
	}
	return &shadowMismatch{Category: "body", Where: where, Primary: window(rp, roff), Shadow: window(rs, roff)}
}

func decodeJSON(b []byte) (any, bool) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || (b[0] != '{' && b[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

func jsonKeyPath(base, key string) string {
	ident := key != ""
	for _, r := range key {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			ident = false
		}
	}
	if ident {
		return base + "." + key
	}
	return base + "['" + strings.ReplaceAll(key, "'", `\'`) + "']"
}

// firstJSONDiff walks both values in a stable order and returns the first
// differing path with the values found there.
func firstJSONDiff(a, b any, path string) (string, any, any, bool) {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return path, a, b, true
		}
		keys := map[string]bool{}
		for k := range av {
			keys[k] = true
		}
		for k := range bv {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			x, okx := av[k]
			y, oky := bv[k]
			kp := jsonKeyPath(path, k)
			switch {
			case !okx:
				return kp, missing{}, y, true
			case !oky:
				return kp, x, missing{}, true
			}
			if p, x2, y2, d := firstJSONDiff(x, y, kp); d {
				return p, x2, y2, true
			}
		}
		return "", nil, nil, false
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return path, a, b, true
		}
		for i := 0; i < len(av) && i < len(bv); i++ {
			if p, x, y, d := firstJSONDiff(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i)); d {
				return p, x, y, true
			}
		}
		if len(av) != len(bv) {
			return path + "[]", fmt.Sprintf("%d items", len(av)), fmt.Sprintf("%d items", len(bv)), true
		}
		return "", nil, nil, false
	case json.Number:
		bv, ok := b.(json.Number)
		if !ok {
			return path, a, b, true
		}
		x, e1 := strconv.ParseFloat(string(av), 64)
		y, e2 := strconv.ParseFloat(string(bv), 64)
		if e1 == nil && e2 == nil && (x == y || math.Abs(x-y) < 1e-12*math.Max(math.Abs(x), math.Abs(y))) {
			return "", nil, nil, false
		}
		return path, a, b, string(av) != string(bv)
	default:
		if a != b {
			return path, a, b, true
		}
		return "", nil, nil, false
	}
}

type missing struct{}

var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|session)`)

func valueExcerpt(path string, v any) string {
	if _, ok := v.(missing); ok {
		return "(missing)"
	}
	if secretKey.MatchString(path[strings.LastIndexAny(path, ".["):]) {
		return "[redacted]"
	}
	if s, ok := v.(string); ok && strings.HasPrefix(s, "[") == false && strings.HasSuffix(s, " items") {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return excerpt(string(b))
}

var redactions = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(?i)("?[\w.-]*(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|session)[\w.-]*"?\s*[:=]\s*)("[^"]*"?|(?:(?:bearer|basic)\s+)?[^\s,&;}\]]*)`), `${1}"[redacted]"`},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`), `$1 [redacted]`},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`), `[redacted-jwt]`},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), `[redacted-key]`},
	{regexp.MustCompile(`\b[A-Fa-f0-9]{40,}\b`), `[redacted-hex]`},
	{regexp.MustCompile(`\b(?:sk|pk|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{16,}`), `[redacted-key]`},
}

// redactSecrets masks obvious credentials in a diff excerpt.
func redactSecrets(s string) string {
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.with)
	}
	return s
}

func printable(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, s)
}

// excerpt redacts and truncates one value to the context length.
func excerpt(s string) string {
	s = printable(redactSecrets(s))
	if utf8.RuneCountInString(s) > shadowContext {
		r := []rune(s)
		s = string(r[:shadowContext]) + "..."
	}
	return s
}

// redactSlice returns the redacted text within 512 bytes of off.
func redactSlice(b []byte, off int) string {
	lo, hi := off-512, off+512
	if lo < 0 {
		lo = 0
	}
	if hi > len(b) {
		hi = len(b)
	}
	if lo > hi {
		lo = hi
	}
	return redactSecrets(string(b[lo:hi]))
}

// window shows shadowContext bytes of s around offset off. s is already redacted.
func window(s string, off int) string {
	start := off - 16
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		start = len(s)
	}
	end := start + shadowContext
	if end > len(s) {
		end = len(s)
	}
	pre, post := "", ""
	if start > 0 {
		pre = "..."
	}
	if end < len(s) {
		post = "..."
	}
	return pre + printable(s[start:end]) + post
}
