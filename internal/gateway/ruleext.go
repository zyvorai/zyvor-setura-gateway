package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Rule extensions of the data-plane limits track. Like setura.zyvor.dev/auth
// each is a field of a rule in a snapshot and a route annotation, either
// route wide (KEY) or for one rule (KEY.rule-N, 1-based, wins).
const (
	DirectResponseKey = "setura.zyvor.dev/direct-response"
	RateLimitKey      = "setura.zyvor.dev/rate-limit"
	LimitsKey         = "setura.zyvor.dev/limits"
)

// RuleExtKeys are the annotation keys of the rule extensions of this file.
var RuleExtKeys = []string{DirectResponseKey, RateLimitKey, LimitsKey}

// flexString is a JSON string or number kept as text, so rate and size
// fields may be written 100, "100/s", 1048576 or "1MB".
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("want a string or a number")
	}
	*f = flexString(n.String())
	return nil
}

// DirectResponse answers a rule's requests with a fixed response and no backend.
type DirectResponse struct {
	Status  int               `json:"status"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// RouteRateLimit is a token bucket scoped to one rule.
type RouteRateLimit struct {
	Rate  flexString `json:"rate"`
	Burst int        `json:"burst,omitempty"`
	Key   string     `json:"key,omitempty"` // route, client-ip (default) or header:NAME
}

// RuleLimits overrides the gateway-wide limits for one rule.
type RuleLimits struct {
	MaxRequestBody    flexString `json:"maxRequestBody,omitempty"`    // bytes or 10MB; 0 or unlimited lifts the gateway limit
	StreamIdleTimeout string     `json:"streamIdleTimeout,omitempty"` // 0 lifts the gateway limit
}

const maxDirectBody = 64 << 10

// strictDecode decodes one JSON object, refusing unknown fields and trailing data.
func strictDecode(key string, raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	if _, err := dec.Token(); err == nil {
		return fmt.Errorf("%s: trailing data after the JSON object", key)
	}
	return nil
}

func validHeaderName(n string) bool {
	if n == "" {
		return false
	}
	for _, c := range n {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return false
		}
	}
	return true
}

func (d *DirectResponse) validate() error {
	if d.Status < 200 || d.Status > 599 {
		return fmt.Errorf("%s: status %d: want 200-599", DirectResponseKey, d.Status)
	}
	if (d.Status == http.StatusNoContent || d.Status == http.StatusNotModified) && d.Body != "" {
		return fmt.Errorf("%s: status %d cannot carry a body", DirectResponseKey, d.Status)
	}
	if len(d.Body) > maxDirectBody {
		return fmt.Errorf("%s: body is %d bytes, the limit is %d", DirectResponseKey, len(d.Body), maxDirectBody)
	}
	for k, v := range d.Headers {
		switch strings.ToLower(k) {
		case "content-length", "transfer-encoding", "connection", "host", "keep-alive", "upgrade", "trailer", "te":
			return fmt.Errorf("%s: header %q is managed by the gateway", DirectResponseKey, k)
		}
		if !validHeaderName(k) {
			return fmt.Errorf("%s: invalid header name %q", DirectResponseKey, k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%s: header %q has a control character in its value", DirectResponseKey, k)
		}
	}
	return nil
}

// ParseDirectResponseBlock decodes and validates a direct-response block.
func ParseDirectResponseBlock(raw []byte) (*DirectResponse, error) {
	var d DirectResponse
	if err := strictDecode(DirectResponseKey, raw, &d); err != nil {
		return nil, err
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ParseRateLimitBlock decodes and validates a per-rule rate-limit block.
func ParseRateLimitBlock(raw []byte) (*RouteRateLimit, error) {
	var r RouteRateLimit
	if err := strictDecode(RateLimitKey, raw, &r); err != nil {
		return nil, err
	}
	if _, err := r.config(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ParseLimitsBlock decodes and validates a per-rule limits block.
func ParseLimitsBlock(raw []byte) (*RuleLimits, error) {
	var l RuleLimits
	if err := strictDecode(LimitsKey, raw, &l); err != nil {
		return nil, err
	}
	if _, _, err := l.compile(); err != nil {
		return nil, err
	}
	return &l, nil
}

func (r *RouteRateLimit) config() (RateLimitConfig, error) {
	if strings.TrimSpace(string(r.Rate)) == "" {
		return RateLimitConfig{}, fmt.Errorf("%s: rate is required (for example \"100/s\")", RateLimitKey)
	}
	rate, per, err := ParseRate(string(r.Rate))
	if err != nil {
		return RateLimitConfig{}, fmt.Errorf("%s: %w", RateLimitKey, err)
	}
	key := r.Key
	switch {
	case key == "" || key == "client-ip" || key == "ip":
		key = "ip"
	case key == "route":
	case strings.HasPrefix(key, "header:") && len(key) > len("header:"):
	default:
		return RateLimitConfig{}, fmt.Errorf("%s: key %q: want route, client-ip or header:NAME", RateLimitKey, r.Key)
	}
	c := RateLimitConfig{Rate: rate, Per: per, Burst: r.Burst, Key: key}
	if err := c.validate(); err != nil {
		return c, fmt.Errorf("%s: %w", RateLimitKey, err)
	}
	return c, nil
}

// parseBodyLimit reads a size: a byte count, 10MB, 0 or "unlimited" (= 0).
func parseBodyLimit(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "unlimited") {
		return 0, nil
	}
	n, err := ParseSize(v)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("size %q must not be negative", v)
	}
	return n, nil
}

// compile returns the body limit and idle timeout, nil when the rule leaves
// the gateway-wide value alone.
func (l *RuleLimits) compile() (body *int64, idle *time.Duration, err error) {
	if l.MaxRequestBody != "" {
		n, e := parseBodyLimit(string(l.MaxRequestBody))
		if e != nil {
			return nil, nil, fmt.Errorf("%s: maxRequestBody: %w", LimitsKey, e)
		}
		body = &n
	}
	if l.StreamIdleTimeout != "" {
		d, e := time.ParseDuration(l.StreamIdleTimeout)
		if e != nil || d < 0 {
			return nil, nil, fmt.Errorf("%s: streamIdleTimeout %q: want a duration such as 30s", LimitsKey, l.StreamIdleTimeout)
		}
		idle = &d
	}
	return body, idle, nil
}

// RuleExtAnnotation targets rule n (1-based) with the annotation key base.
func RuleExtAnnotation(base string, n int) string { return base + ".rule-" + strconv.Itoa(n) }

// annotateExt gives every rule that has no block of its own the block of its
// annotation. A value that cannot be decoded is remembered on the rule, so
// the route turns invalid instead of silently serving without the setting.
func annotateExt(rules []Rule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		r := &rules[i]
		pick := func(base string) (string, string, bool) {
			key := RuleExtAnnotation(base, i+1)
			if v, ok := ann[key]; ok {
				return key, v, true
			}
			v, ok := ann[base]
			return base, v, ok
		}
		fail := func(key string, err error) {
			if r.extErr == nil {
				r.extErr = fmt.Errorf("annotation %s: %w", key, err)
			}
		}
		if key, v, ok := pick(DirectResponseKey); ok && r.DirectResponse == nil {
			if d, err := ParseDirectResponseBlock([]byte(v)); err != nil {
				fail(key, err)
			} else {
				r.DirectResponse = d
			}
		}
		if key, v, ok := pick(RateLimitKey); ok && r.RateLimit == nil {
			if d, err := ParseRateLimitBlock([]byte(v)); err != nil {
				fail(key, err)
			} else {
				r.RateLimit = d
			}
		}
		if key, v, ok := pick(LimitsKey); ok && r.Limits == nil {
			if d, err := ParseLimitsBlock([]byte(v)); err != nil {
				fail(key, err)
			} else {
				r.Limits = d
			}
		}
	}
}

// OrphanRuleAnnotations lists annotation keys of one extension (base) that no
// rule uses: a malformed rule-N suffix or a rule number beyond the route's rules.
func OrphanRuleAnnotations(ann map[string]string, base string, rules int) []string {
	var out []string
	for k := range ann {
		if k == base || !strings.HasPrefix(k, base) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, base+".rule-"))
		if !strings.HasPrefix(k, base+".rule-") || err != nil || n < 1 || n > rules {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// compileExt validates and compiles the extensions of a rule onto cr.
func (cr *CRule) compileExt(rule *Rule) error {
	if rule.extErr != nil {
		return rule.extErr
	}
	if d := rule.DirectResponse; d != nil {
		if err := d.validate(); err != nil {
			return err
		}
		if len(rule.BackendRefs) > 0 {
			return fmt.Errorf("%s: a direct-response rule answers by itself and must have no backendRefs", DirectResponseKey)
		}
		for _, f := range rule.Filters {
			switch f.Type {
			case "RequestRedirect", "RequestMirror", "ExternalAuth":
				return fmt.Errorf("%s: a direct-response rule cannot also have a %s filter", DirectResponseKey, f.Type)
			}
		}
		cr.Direct = d
	}
	if rl := rule.RateLimit; rl != nil {
		c, err := rl.config()
		if err != nil {
			return err
		}
		cr.Limit = newLimiter(c, nil)
	}
	if l := rule.Limits; l != nil {
		var err error
		if cr.MaxBody, cr.StreamIdle, err = l.compile(); err != nil {
			return err
		}
	}
	return nil
}

// serveDirect answers a direct-response rule: header modifiers and CORS
// filters of the rule first, then the rule's own headers, status and body.
func serveDirect(rec *recorder, r *http.Request, rule *CRule) {
	d := rule.Direct
	h := rec.Header()
	shapeResponse(h, r, rule.Rule.Filters)
	for k, v := range d.Headers {
		h.Set(k, v)
	}
	if d.Body != "" && h.Get("Content-Type") == "" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	h.Set("Content-Length", strconv.Itoa(len(d.Body)))
	rec.WriteHeader(d.Status)
	if r.Method != http.MethodHead && d.Body != "" {
		io.WriteString(rec, d.Body)
	}
}
