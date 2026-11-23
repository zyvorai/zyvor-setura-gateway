package gateway

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// gRPC-web bridge. A browser cannot speak gRPC (no access to HTTP/2 trailers
// and framing), so it sends application/grpc-web or application/grpc-web-text
// (the same frames, base64 encoded) over HTTP/1.1 or HTTP/2. A rule that opts
// in with setura.zyvor.dev/grpc-web translates such a call to gRPC towards the
// backend and the answer back: the HTTP/2 trailers become a final frame with
// the 0x80 flag inside the body, as the gRPC-web protocol specifies.
// Retries, mirroring and unary-only limits do not apply to bridged calls.

// GRPCWebConfig is the setura.zyvor.dev/grpc-web block of a rule.
type GRPCWebConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
	// AllowOrigins answers browser preflights and adds Access-Control-Allow-Origin
	// for these origins (* or scheme://host[:port], one leading *. wildcard). Leave
	// it empty when the rule carries a CORS filter that does this.
	AllowOrigins []string `json:"allowOrigins,omitempty"`
	MaxAge       int      `json:"maxAge,omitempty"` // seconds a preflight may be cached (default 600)
}

func (g *GRPCWebConfig) on() bool { return g != nil && (g.Enabled == nil || *g.Enabled) }

func (g *GRPCWebConfig) validate() error {
	if g.MaxAge < 0 {
		return fmt.Errorf("%s: maxAge must not be negative", GRPCWebKey)
	}
	if err := (&CORS{AllowOrigins: g.AllowOrigins}).validate(); err != nil {
		return fmt.Errorf("%s: %s", GRPCWebKey, strings.TrimPrefix(err.Error(), "cors."))
	}
	return nil
}

// ParseGRPCWebBlock decodes and validates a grpc-web block.
func ParseGRPCWebBlock(raw []byte) (*GRPCWebConfig, error) {
	var g GRPCWebConfig
	if err := strictDecode(GRPCWebKey, raw, &g); err != nil {
		return nil, err
	}
	if err := g.validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

const (
	grpcUnknown  = 2
	grpcInternal = 13
)

// grpcWebAllowHeaders are what browser gRPC-web clients send.
const grpcWebAllowHeaders = "content-type, x-grpc-web, x-user-agent, grpc-timeout, x-accept-content-transfer-encoding, x-accept-response-streaming, authorization, x-requested-with"

// grpcWebExposeHeaders must be readable by the browser's JavaScript.
const grpcWebExposeHeaders = "grpc-status, grpc-message, grpc-status-details-bin, x-request-id"

// grpcWebMode classifies a request Content-Type: ok is false for anything
// that is not gRPC-web; suffix is "" or "+proto" / "+json".
func grpcWebMode(ct string) (text bool, suffix string, ok bool) {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	rest, found := strings.CutPrefix(ct, "application/grpc-web")
	if !found {
		return false, "", false
	}
	if t, isText := strings.CutPrefix(rest, "-text"); isText {
		rest, text = t, true
	}
	if rest != "" && !strings.HasPrefix(rest, "+") {
		return false, "", false
	}
	return text, rest, true
}

// b64Reader decodes a base64 stream in 4 character groups. Unlike
// base64.NewDecoder it accepts padded groups in the middle of the stream
// (a client may send several separately encoded chunks).
type b64Reader struct {
	src  io.Reader
	pend []byte // undecoded characters
	out  []byte // decoded, not yet read
	err  error
}

func (b *b64Reader) Read(p []byte) (int, error) {
	for len(b.out) == 0 {
		if b.err != nil {
			return 0, b.err
		}
		var buf [4096]byte
		n, err := b.src.Read(buf[:])
		for _, c := range buf[:n] {
			if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
				b.pend = append(b.pend, c)
			}
		}
		b.err = err
		if derr := b.decode(err != nil); derr != nil {
			b.err = derr
		}
	}
	n := copy(p, b.out)
	b.out = b.out[n:]
	return n, nil
}

func (b *b64Reader) decode(final bool) error {
	whole := len(b.pend) / 4 * 4
	for i := 0; i < whole; i += 4 {
		var d [3]byte
		n, err := base64.StdEncoding.Decode(d[:], b.pend[i:i+4])
		if err != nil {
			return errors.New("grpc-web-text: invalid base64")
		}
		b.out = append(b.out, d[:n]...)
	}
	b.pend = append(b.pend[:0], b.pend[whole:]...)
	if final && len(b.pend) > 0 {
		var d [3]byte
		n, err := base64.RawStdEncoding.Decode(d[:], b.pend)
		if err != nil {
			return errors.New("grpc-web-text: truncated base64")
		}
		b.out = append(b.out, d[:n]...)
		b.pend = nil
	}
	return nil
}

// b64Writer encodes a stream as one base64 text: whole groups of three bytes
// go out at once, the remainder waits for the next write or Close.
type b64Writer struct {
	w    io.Writer
	rest []byte
}

func (b *b64Writer) Write(p []byte) (int, error) {
	data := append(b.rest, p...)
	whole := len(data) / 3 * 3
	if whole > 0 {
		enc := make([]byte, base64.StdEncoding.EncodedLen(whole))
		base64.StdEncoding.Encode(enc, data[:whole])
		if _, err := b.w.Write(enc); err != nil {
			return 0, err
		}
	}
	b.rest = append(b.rest[:0], data[whole:]...)
	return len(p), nil
}

func (b *b64Writer) Close() error {
	if len(b.rest) == 0 {
		return nil
	}
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(b.rest)))
	base64.StdEncoding.Encode(enc, b.rest)
	b.rest = nil
	_, err := b.w.Write(enc)
	return err
}

// trailerFrame is the gRPC-web trailer frame: flag 0x80, a 4 byte length and
// "name: value" lines.
func trailerFrame(h http.Header) []byte {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	var body strings.Builder
	for _, k := range keys {
		for _, v := range h.Values(k) {
			body.WriteString(k + ": " + strings.NewReplacer("\r", " ", "\n", " ").Replace(v) + "\r\n")
		}
	}
	frame := make([]byte, 5, 5+body.Len())
	frame[0] = 0x80
	binary.BigEndian.PutUint32(frame[1:], uint32(body.Len()))
	return append(frame, body.String()...)
}

func statusTrailers(code int, msg string) http.Header {
	h := http.Header{}
	h.Set("grpc-status", strconv.Itoa(code))
	if msg != "" {
		h.Set("grpc-message", msg)
	}
	return h
}

func mergeToken(h http.Header, name, tokens string) {
	cur := h.Get(name)
	have := map[string]bool{}
	for _, t := range strings.Split(cur, ",") {
		have[strings.ToLower(strings.TrimSpace(t))] = true
	}
	var add []string
	for _, t := range strings.Split(tokens, ",") {
		if t = strings.TrimSpace(t); t != "" && !have[strings.ToLower(t)] {
			add = append(add, t)
		}
	}
	if len(add) == 0 {
		return
	}
	if cur != "" {
		add = append([]string{cur}, add...)
	}
	h.Set(name, strings.Join(add, ", "))
}

func (g *GRPCWebConfig) originAllowed(origin string) bool {
	for _, o := range g.AllowOrigins {
		if originMatches(o, origin) {
			return true
		}
	}
	return false
}

// grpcWebPreflight answers a browser preflight for a gRPC-web rule that
// lists allowOrigins. It reports whether it answered.
func (s *Server) grpcWebPreflight(rec *recorder, r *http.Request, g *GRPCWebConfig) bool {
	origin := r.Header.Get("Origin")
	if r.Method != http.MethodOptions || origin == "" || r.Header.Get("Access-Control-Request-Method") == "" || len(g.AllowOrigins) == 0 {
		return false
	}
	h := rec.Header()
	addVary(h, "Origin")
	if g.originAllowed(origin) {
		if inList(g.AllowOrigins, "*") {
			h.Set("Access-Control-Allow-Origin", "*")
		} else {
			h.Set("Access-Control-Allow-Origin", origin)
		}
		h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", grpcWebAllowHeaders)
		age := g.MaxAge
		if age == 0 {
			age = 600
		}
		h.Set("Access-Control-Max-Age", strconv.Itoa(age))
	}
	rec.WriteHeader(http.StatusNoContent)
	return true
}

func (s *Server) grpcWebDone(route string, text bool, result string) {
	mode := "binary"
	if text {
		mode = "text"
	}
	s.shape.add("grpcweb", fmt.Sprintf(`route="%s",mode="%s",result="%s"`, esc(route), mode, result), 1)
}

// serveGRPCWeb bridges one gRPC-web call to the rule's backend.
func (s *Server) serveGRPCWeb(rec *recorder, r *http.Request, st *reqState, rule *CRule, e *Entry, pg *PortGroup, text bool, suffix string) {
	g := rule.GRPCWeb
	h := rec.Header()
	respCT := "application/grpc-web" + suffix
	if text {
		respCT = "application/grpc-web-text" + suffix
	}
	fail := func(code int, msg string) {
		st.errMsg = msg
		h.Set("Content-Type", respCT)
		h.Set("Grpc-Status", strconv.Itoa(code)) // Trailers-Only: status in the headers and in a trailer frame
		h.Set("Grpc-Message", msg)
		s.grpcWebHeaders(rec, r, g, rule, nil)
		rec.WriteHeader(http.StatusOK)
		frame := trailerFrame(statusTrailers(code, msg))
		if text {
			rec.Write([]byte(base64.StdEncoding.EncodeToString(frame)))
		} else {
			rec.Write(frame)
		}
		s.grpcWebDone(st.route, text, "error")
	}
	if r.Method != http.MethodPost {
		h.Set("Allow", "POST, OPTIONS")
		plain(rec, http.StatusMethodNotAllowed, "gRPC-web calls are POST requests")
		s.grpcWebDone(st.route, text, "error")
		return
	}
	ref := s.pickRef(rule)
	if ref == nil || ref.B == nil {
		fail(grpcUnavailable, "no valid backend for this route")
		return
	}
	ep := ref.B.choose(s.res.now(), nil)
	st.backend, st.weight = ref.B.Key, ref.Weight
	st.markRoute()
	if hasExternalAuth(requestFilters(rule, ref)) {
		ar, v := s.runAuthFilters(r, rule, requestFilters(rule, ref), pg.TLS)
		if v != nil {
			s.ext.authOutcome(st.route, "denied", "external")
			st.errMsg = v.why
			shapeResponse(h, r, requestFilters(rule, ref))
			writeAuthDenied(rec, v)
			return
		}
		r = ar
	}
	if s.grpcTr.get(ep.URL.Scheme, ref.B.Insecure) == nil {
		fail(grpcUnavailable, "cleartext HTTP/2 backends need Go 1.24 or newer")
		return
	}
	ctx := r.Context()
	timeout := rule.Timeout
	if bt := ref.B.Timeout; bt > 0 && (timeout == 0 || bt < timeout) {
		timeout = bt
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	u := *ep.URL
	u.Path, u.RawPath, u.RawQuery = r.URL.Path, r.URL.RawPath, r.URL.RawQuery
	var body io.Reader = r.Body
	if text {
		body = &b64Reader{src: r.Body}
	}
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		fail(grpcInternal, "cannot build the upstream request")
		return
	}
	out.Header = r.Header.Clone()
	stripHopHeaders(out.Header)
	for _, k := range []string{"Content-Length", "X-Grpc-Web", "Accept", "Origin", "Referer", "X-Accept-Content-Transfer-Encoding", "X-Accept-Response-Streaming"} {
		out.Header.Del(k)
	}
	out.Header.Set("Content-Type", "application/grpc"+suffix)
	out.Header.Set("Te", "trailers")
	if text {
		out.ContentLength = -1
	} else {
		out.ContentLength = r.ContentLength
	}
	shapeUpstream(out, r, remoteIP(r), pg.TLS, requestFilters(rule, ref), e.Match, true, st.reqID, st.listener, st.claims())
	out.Header.Set("Te", "trailers")
	s.chainForwardedFor(r, out)
	injectTrace(out, st)
	rt := &grpcTransport{s: s, b: ref.B, first: ep, tried: map[*Endpoint]bool{}, st: st}
	resp, err := rt.RoundTrip(out)
	if err != nil {
		code := grpcUnavailable
		if errors.Is(err, context.DeadlineExceeded) {
			code = grpcDeadlineExceeded
		}
		fail(code, "upstream error")
		st.errMsg = err.Error()
		return
	}
	defer resp.Body.Close()
	st.backend = ref.B.Key
	for k, vv := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Type", "Content-Length", "Connection", "Keep-Alive", "Transfer-Encoding", "Te", "Trailer", "Upgrade", RequestIDHeader:
			continue
		}
		for _, v := range vv {
			h.Add(k, v)
		}
	}
	h.Set("Content-Type", respCT)
	h.Set(BackendHeader, ref.Name)
	if s.opts.Shape.RequestID == RequestIDUpstream {
		if up := resp.Header.Get(RequestIDHeader); validRequestID(up) {
			st.reqID = up
		}
	}
	h.Set(RequestIDHeader, st.reqID)
	s.grpcWebHeaders(rec, r, g, rule, ref)
	rec.WriteHeader(http.StatusOK)

	var w io.Writer = rec
	var tw *b64Writer
	if text {
		tw = &b64Writer{w: rec}
		w = tw
	}
	buf := make([]byte, 32<<10)
	var readErr error
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // the browser went away
			}
			rec.Flush()
		}
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
	}
	var tr http.Header
	switch {
	case readErr != nil && errors.Is(readErr, context.DeadlineExceeded):
		tr, st.errMsg = statusTrailers(grpcDeadlineExceeded, "deadline exceeded"), readErr.Error()
	case readErr != nil:
		tr, st.errMsg = statusTrailers(grpcUnavailable, "upstream stream failed"), readErr.Error()
	default:
		tr = resp.Trailer.Clone()
		if tr == nil || tr.Get("Grpc-Status") == "" {
			// Trailers-Only answer: the status came in the headers.
			if tr == nil {
				tr = http.Header{}
			}
			for _, k := range []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"} {
				if v := resp.Header.Get(k); v != "" && tr.Get(k) == "" {
					tr.Set(k, v)
				}
			}
		}
		if tr.Get("Grpc-Status") == "" {
			tr = statusTrailers(grpcUnknown, "upstream sent no grpc-status")
		}
	}
	w.Write(trailerFrame(tr))
	if tw != nil {
		tw.Close()
	}
	rec.Flush()
	result := "ok"
	if readErr != nil {
		result = "error"
	}
	s.grpcWebDone(st.route, text, result)
}

// grpcWebHeaders adds the CORS related headers every bridged response needs.
func (s *Server) grpcWebHeaders(rec *recorder, r *http.Request, g *GRPCWebConfig, rule *CRule, ref *CRef) {
	h := rec.Header()
	filters := rule.Rule.Filters
	if ref != nil {
		filters = requestFilters(rule, ref)
	}
	shapeResponse(h, r, filters)
	if origin := r.Header.Get("Origin"); origin != "" && len(g.AllowOrigins) > 0 && g.originAllowed(origin) && h.Get("Access-Control-Allow-Origin") == "" {
		if inList(g.AllowOrigins, "*") {
			h.Set("Access-Control-Allow-Origin", "*")
		} else {
			h.Set("Access-Control-Allow-Origin", origin)
			addVary(h, "Origin")
		}
	}
	mergeToken(h, "Access-Control-Expose-Headers", grpcWebExposeHeaders)
}
