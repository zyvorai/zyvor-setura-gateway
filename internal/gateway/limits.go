package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Data-plane limits, path normalisation and TLS version bounds. Everything
// here is off (or Go's own default) unless a flag or a setting asks for it.

// Listener TLS option keys (listener.tls.options) for the version bounds.
const (
	TLSMinVersionOption = "setura.zyvor.dev/tls-min-version"
	TLSMaxVersionOption = "setura.zyvor.dev/tls-max-version"
	// TLSCipherSuitesOption is a comma separated list of TLS 1.2 cipher suite
	// names; TLSSessionResumptionOption is "on" or "off" (session tickets).
	TLSCipherSuitesOption      = "setura.zyvor.dev/tls-cipher-suites"
	TLSSessionResumptionOption = "setura.zyvor.dev/tls-session-resumption"
)

// DefaultHeaderReadTimeout is how long a client may take to send request headers.
const DefaultHeaderReadTimeout = 10 * time.Second

// LimitsOptions are the gateway-wide limits and timeouts. Zero means the
// default (no limit, except HeaderReadTimeout and MaxHeaderBytes which keep
// Go's defaults of 10s and 1MB).
type LimitsOptions struct {
	MaxBodyBytes      int64         // request body limit, answered with 413
	MaxHeaderBytes    int           // request header size limit, answered with 431
	HeaderReadTimeout time.Duration // time to read the request headers
	IdleTimeout       time.Duration // idle keep-alive connections are closed after this
	StreamIdleTimeout time.Duration // a response that sends no byte for this long is cut
}

// PathOptions are the request path normalisations applied before routing.
type PathOptions struct {
	Normalize            bool // remove . and .. segments (RFC 3986 section 5.2.4)
	MergeSlashes         bool // collapse // into /
	RejectEscapedSlashes bool // answer 400 for %2F and %5C in the path
}

func (p PathOptions) active() bool { return p.Normalize || p.MergeSlashes || p.RejectEscapedSlashes }

// TLSOptions bound the TLS version of HTTPS and terminating TLS listeners
// (0 = Go's default floor of 1.2, and no ceiling), restrict the TLS 1.2
// cipher suites (empty: Go's secure defaults; TLS 1.3 suites are not
// configurable) and switch session resumption (session tickets) on or off
// ("" keeps Go's default, which is on).
type TLSOptions struct {
	Min, Max   uint16
	Ciphers    []uint16
	Resumption string
}

// ParseCipherSuites reads a comma separated list of cipher suite names as Go
// spells them (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256). Insecure suites and
// the TLS 1.3 suites (which Go does not let you choose) are refused.
func ParseCipherSuites(list string) ([]uint16, error) {
	secure := map[string]uint16{}
	for _, c := range tls.CipherSuites() {
		secure[c.Name] = c.ID
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := secure[name]
		switch {
		case !ok:
			for _, c := range tls.InsecureCipherSuites() {
				if c.Name == name {
					return nil, fmt.Errorf("cipher suite %s is insecure and not allowed", name)
				}
			}
			return nil, fmt.Errorf("unknown cipher suite %q (use a name from Go's crypto/tls, such as TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)", name)
		case strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_"):
			return nil, fmt.Errorf("cipher suite %s is a TLS 1.3 suite; Go does not let you choose those (they are always enabled)", name)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no cipher suite named")
	}
	return out, nil
}

// ParseResumption reads "on" or "off".
func ParseResumption(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "enabled":
		return "on", nil
	case "off", "false", "disabled":
		return "off", nil
	}
	return "", fmt.Errorf("session resumption %q: want on or off", v)
}

// ListenerLimits is the limits block of a listener in a snapshot.
type ListenerLimits struct {
	MaxRequestBody flexString `json:"maxRequestBody,omitempty"`
}

// ParseTLSVersion reads "1.2" or "1.3" (also "TLS1.2", "tls1.3").
func ParseTLSVersion(v string) (uint16, error) {
	switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "tls") {
	case "1.2", "v1.2":
		return tls.VersionTLS12, nil
	case "1.3", "v1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("TLS version %q: want 1.2 or 1.3", v)
}

func (o TLSOptions) validate() error {
	if o.Min != 0 && o.Max != 0 && o.Min > o.Max {
		return errors.New("the minimum TLS version is higher than the maximum")
	}
	return nil
}

// apply sets the bounds on cfg, an unset bound keeping cfg's value.
func (o TLSOptions) apply(cfg *tls.Config) {
	if o.Min != 0 {
		cfg.MinVersion = o.Min
	}
	if o.Max != 0 {
		cfg.MaxVersion = o.Max
	}
	if len(o.Ciphers) > 0 {
		cfg.CipherSuites = append([]uint16(nil), o.Ciphers...)
	}
	switch o.Resumption {
	case "off":
		cfg.SessionTicketsDisabled = true
	case "on":
		cfg.SessionTicketsDisabled = false
	}
}

// custom reports whether the options change anything from Go's defaults.
func (o TLSOptions) custom() bool {
	return o.Min != 0 || o.Max != 0 || len(o.Ciphers) > 0 || o.Resumption != ""
}

// tlsFor returns the TLS bounds of a listener: its own options over the gateway's.
func (s *Server) tlsFor(l *RTListener) TLSOptions {
	o := s.opts.TLS
	if l != nil {
		if l.TLSMin != 0 {
			o.Min = l.TLSMin
		}
		if l.TLSMax != 0 {
			o.Max = l.TLSMax
		}
		if len(l.TLSCiphers) > 0 {
			o.Ciphers = l.TLSCiphers
		}
		if l.TLSResumption != "" {
			o.Resumption = l.TLSResumption
		}
	}
	return o
}

// resolveLimits reads the extension settings of a listener; a bad value
// makes the listener invalid (the error text is returned).
func (l *RTListener) resolveLimits() error {
	if o := l.L.TLS; o != nil {
		if v := o.Options[TLSMinVersionOption]; v != "" {
			n, err := ParseTLSVersion(v)
			if err != nil {
				return fmt.Errorf("tls.options %s: %w", TLSMinVersionOption, err)
			}
			l.TLSMin = n
		}
		if v := o.Options[TLSMaxVersionOption]; v != "" {
			n, err := ParseTLSVersion(v)
			if err != nil {
				return fmt.Errorf("tls.options %s: %w", TLSMaxVersionOption, err)
			}
			l.TLSMax = n
		}
		if v := o.Options[TLSCipherSuitesOption]; v != "" {
			ids, err := ParseCipherSuites(v)
			if err != nil {
				return fmt.Errorf("tls.options %s: %w", TLSCipherSuitesOption, err)
			}
			l.TLSCiphers = ids
		}
		if v := o.Options[TLSSessionResumptionOption]; v != "" {
			r, err := ParseResumption(v)
			if err != nil {
				return fmt.Errorf("tls.options %s: %w", TLSSessionResumptionOption, err)
			}
			l.TLSResumption = r
		}
		if err := (TLSOptions{Min: l.TLSMin, Max: l.TLSMax}).validate(); err != nil {
			return fmt.Errorf("tls.options: %w", err)
		}
	}
	if b := l.L.Limits; b != nil && b.MaxRequestBody != "" {
		n, err := parseBodyLimit(string(b.MaxRequestBody))
		if err != nil {
			return fmt.Errorf("%s: maxRequestBody: %w", LimitsKey, err)
		}
		l.MaxBody = &n
	}
	return nil
}

// bodyLimit is the request body limit that applies: rule, then listener, then the gateway.
func (s *Server) bodyLimit(l *RTListener, rule *CRule) int64 {
	switch {
	case rule != nil && rule.MaxBody != nil:
		return *rule.MaxBody
	case l != nil && l.MaxBody != nil:
		return *l.MaxBody
	}
	return s.opts.Limits.MaxBodyBytes
}

// idleLimit is the response idle timeout that applies.
func (s *Server) idleLimit(rule *CRule) time.Duration {
	if rule != nil && rule.StreamIdle != nil {
		return *rule.StreamIdle
	}
	return s.opts.Limits.StreamIdleTimeout
}

// limitReader fails with errBodyTooLarge once more than max bytes were read.
type limitReader struct {
	rc       io.ReadCloser
	max, n   int64
	exceeded atomic.Bool
}

var errBodyTooLarge = errors.New("request body exceeds the configured limit")

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n >= l.max {
		// Distinguish "exactly max" from "more than max" by reading one byte.
		var b [1]byte
		n, err := l.rc.Read(b[:])
		if n > 0 {
			l.exceeded.Store(true)
			return 0, errBodyTooLarge
		}
		return 0, err
	}
	if rem := l.max - l.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := l.rc.Read(p)
	l.n += int64(n)
	return n, err
}

func (l *limitReader) Close() error { return l.rc.Close() }

// limitBody enforces the request body limit: a declared Content-Length over
// the limit is refused at once, an undeclared (chunked) body fails while it
// streams. It reports whether the request was answered with 413.
func (s *Server) limitBody(w http.ResponseWriter, r *http.Request, st *reqState, max int64) (*limitReader, bool) {
	if max <= 0 || r.Body == nil || r.Body == http.NoBody {
		return nil, false
	}
	if r.ContentLength > max {
		st.errMsg = fmt.Sprintf("request body of %d bytes exceeds the limit of %d", r.ContentLength, max)
		w.Header().Set("Connection", "close")
		plain(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, true
	}
	lr := &limitReader{rc: r.Body, max: max}
	r.Body = lr
	return lr, false
}

// idleBody cuts a response that stops sending: if no byte was read from the
// body for d, the request context is cancelled, which ends the transfer.
type idleBody struct {
	rc     io.ReadCloser
	d      time.Duration
	cancel context.CancelCauseFunc
	mu     sync.Mutex
	t      *time.Timer
	fired  atomic.Bool
}

var errStreamIdle = errors.New("response idle timeout")

func newIdleBody(rc io.ReadCloser, d time.Duration, cancel context.CancelCauseFunc) *idleBody {
	b := &idleBody{rc: rc, d: d, cancel: cancel}
	b.t = time.AfterFunc(d, b.fire)
	return b
}

func (b *idleBody) fire() {
	b.fired.Store(true)
	b.cancel(errStreamIdle)
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.mu.Lock()
	if err != nil {
		b.t.Stop()
	} else if n > 0 && !b.fired.Load() {
		b.t.Reset(b.d)
	}
	b.mu.Unlock()
	if err != nil && b.fired.Load() && !errors.Is(err, io.EOF) {
		return n, errStreamIdle
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.mu.Lock()
	b.t.Stop()
	b.mu.Unlock()
	return b.rc.Close()
}

// ---- path normalisation ----

// removeDotSegments implements RFC 3986 section 5.2.4 on an absolute path.
// Empty segments are kept, so "//" survives unless MergeSlashes is on.
func removeDotSegments(p string) string {
	if !strings.Contains(p, "/.") {
		return p
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	res := strings.Join(out, "/")
	if res == "" {
		return "/"
	}
	return res
}

func mergeSlashes(p string) string {
	if !strings.Contains(p, "//") {
		return p
	}
	var b strings.Builder
	prev := byte(0)
	for i := 0; i < len(p); i++ {
		if p[i] == '/' && prev == '/' {
			continue
		}
		b.WriteByte(p[i])
		prev = p[i]
	}
	return b.String()
}

// normalizePath applies the path options to r in place, before routing. It
// returns a message when the request must be refused with 400.
func (p PathOptions) normalizePath(r *http.Request) string {
	if !p.active() || r.URL == nil {
		return ""
	}
	if p.RejectEscapedSlashes {
		raw := r.URL.RawPath
		if raw == "" {
			raw = r.URL.EscapedPath()
		}
		raw = strings.ToLower(raw)
		if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
			return "the request path contains an escaped slash"
		}
	}
	path := r.URL.Path
	if p.Normalize {
		path = removeDotSegments(path)
	}
	if p.MergeSlashes {
		path = mergeSlashes(path)
	}
	if path != r.URL.Path {
		r.URL.Path, r.URL.RawPath = path, ""
	}
	return ""
}

// ---- flags ----

type limitFlags struct {
	maxBody, maxHeader                 string
	headerRead, idle, streamIdle       time.Duration
	normalize, mergeSlashes, rejectEsc bool
	tlsMin, tlsMax                     string
	tlsCiphers, tlsResumption          string
}

func addLimitFlags(fs *flag.FlagSet, f *limitFlags) {
	fs.StringVar(&f.maxBody, "max-request-body", "", "refuse request bodies over this size with 413 (100, 64k, 10MB; default no limit)")
	fs.StringVar(&f.maxHeader, "max-header-bytes", "", "refuse request headers over this size with 431 (default 1MB)")
	fs.DurationVar(&f.headerRead, "header-read-timeout", 0, "time a client has to send the request headers (default 10s)")
	fs.DurationVar(&f.idle, "idle-timeout", 0, "close idle keep-alive connections after this long (default off)")
	fs.DurationVar(&f.streamIdle, "stream-idle-timeout", 0, "cut a response that sends no byte for this long (default off)")
	fs.BoolVar(&f.normalize, "normalize-path", false, "remove . and .. path segments before routing (default off)")
	fs.BoolVar(&f.mergeSlashes, "merge-slashes", false, "collapse // in the request path before routing (default off)")
	fs.BoolVar(&f.rejectEsc, "reject-escaped-slashes", false, "answer 400 to request paths containing %2F or %5C (default off)")
	fs.StringVar(&f.tlsMin, "tls-min-version", "", "lowest TLS version of HTTPS listeners: 1.2 or 1.3 (default 1.2)")
	fs.StringVar(&f.tlsMax, "tls-max-version", "", "highest TLS version of HTTPS listeners: 1.2 or 1.3 (default 1.3)")
	fs.StringVar(&f.tlsCiphers, "tls-cipher-suites", "", "comma separated TLS 1.2 cipher suites HTTPS listeners accept, Go names (default Go's secure set; TLS 1.3 suites are not configurable)")
	fs.StringVar(&f.tlsResumption, "tls-session-resumption", "", "TLS session resumption (session tickets) of HTTPS listeners: on or off (default on)")
}

func (f *limitFlags) apply(o *Options) error {
	if f.maxBody != "" {
		n, err := ParseSize(f.maxBody)
		if err != nil || n <= 0 {
			return fmt.Errorf("--max-request-body %q: want a positive size such as 10MB", f.maxBody)
		}
		o.Limits.MaxBodyBytes = n
	}
	if f.maxHeader != "" {
		n, err := ParseSize(f.maxHeader)
		if err != nil || n <= 0 || n > 1<<30 {
			return fmt.Errorf("--max-header-bytes %q: want a positive size such as 16k", f.maxHeader)
		}
		o.Limits.MaxHeaderBytes = int(n)
	}
	for name, d := range map[string]time.Duration{"--header-read-timeout": f.headerRead, "--idle-timeout": f.idle, "--stream-idle-timeout": f.streamIdle} {
		if d < 0 {
			return fmt.Errorf("%s %s: must not be negative", name, d)
		}
	}
	o.Limits.HeaderReadTimeout, o.Limits.IdleTimeout, o.Limits.StreamIdleTimeout = f.headerRead, f.idle, f.streamIdle
	o.Path = PathOptions{Normalize: f.normalize, MergeSlashes: f.mergeSlashes, RejectEscapedSlashes: f.rejectEsc}
	var err error
	if f.tlsMin != "" {
		if o.TLS.Min, err = ParseTLSVersion(f.tlsMin); err != nil {
			return fmt.Errorf("--tls-min-version: %w", err)
		}
	}
	if f.tlsMax != "" {
		if o.TLS.Max, err = ParseTLSVersion(f.tlsMax); err != nil {
			return fmt.Errorf("--tls-max-version: %w", err)
		}
	}
	if f.tlsCiphers != "" {
		if o.TLS.Ciphers, err = ParseCipherSuites(f.tlsCiphers); err != nil {
			return fmt.Errorf("--tls-cipher-suites: %w", err)
		}
	}
	if f.tlsResumption != "" {
		if o.TLS.Resumption, err = ParseResumption(f.tlsResumption); err != nil {
			return fmt.Errorf("--tls-session-resumption: %w", err)
		}
	}
	if err := o.TLS.validate(); err != nil {
		return fmt.Errorf("--tls-min-version/--tls-max-version: %w", err)
	}
	return nil
}

// ParseListenerLimitsBlock decodes and validates the limits block of a listener.
func ParseListenerLimitsBlock(raw []byte) (*ListenerLimits, error) {
	var l ListenerLimits
	if err := strictDecode(LimitsKey, raw, &l); err != nil {
		return nil, err
	}
	if l.MaxRequestBody != "" {
		if _, err := parseBodyLimit(string(l.MaxRequestBody)); err != nil {
			return nil, fmt.Errorf("%s: maxRequestBody: %w", LimitsKey, err)
		}
	}
	return &l, nil
}
