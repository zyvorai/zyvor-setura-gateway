package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExternalAuth is the HTTPRoute ExternalAuth filter (Gateway API 1.5): the
// gateway asks an authorization service whether to let a request through.
// The HTTP protocol forwards the request to BackendRef; the GRPC protocol
// speaks Envoy's envoy.service.auth.v3.Authorization/Check.
type ExternalAuth struct {
	Protocol   string      `json:"protocol"`
	BackendRef BackendRef  `json:"backendRef"`
	GRPC       *GRPCAuth   `json:"grpc,omitempty"`
	HTTP       *HTTPAuth   `json:"http,omitempty"`
	Forward    *ForwardRef `json:"forwardBody,omitempty"`
}

// GRPCAuth configures the gRPC authorization protocol.
type GRPCAuth struct {
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
}

// HTTPAuth configures the HTTP authorization protocol.
type HTTPAuth struct {
	// Path is a prefix added to the original request path.
	Path string `json:"path,omitempty"`
	// AllowedHeaders are the client headers sent to the service (all when empty;
	// Host, Method, Path, Content-Length and Authorization are always sent).
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
	// AllowedResponseHeaders are copied from an allowing response onto the
	// upstream request (replacing the client's).
	AllowedResponseHeaders []string `json:"allowedResponseHeaders,omitempty"`
}

// ForwardRef is forwardBody: send up to MaxSize bytes of the request body.
type ForwardRef struct {
	MaxSize int `json:"maxSize"`
}

const (
	defaultAuthTimeout = 5 * time.Second
	maxAuthResponse    = 1 << 20
	grpcAuthPath       = "/envoy.service.auth.v3.Authorization/Check"
	authPreviewValue   = "<from auth service>"
)

func (a *ExternalAuth) validate() error {
	switch a.Protocol {
	case "HTTP":
		if a.GRPC != nil {
			return fmt.Errorf("externalAuth: protocol HTTP cannot carry a grpc block")
		}
	case "GRPC":
		if a.HTTP != nil {
			return fmt.Errorf("externalAuth: protocol GRPC cannot carry an http block")
		}
	default:
		return fmt.Errorf("externalAuth: protocol must be HTTP or GRPC, got %q", a.Protocol)
	}
	if a.BackendRef.Name == "" {
		return fmt.Errorf("externalAuth: backendRef is required")
	}
	if a.Forward != nil && a.Forward.MaxSize < 0 {
		return fmt.Errorf("externalAuth: forwardBody.maxSize must not be negative")
	}
	if a.HTTP != nil && a.HTTP.Path != "" && !strings.HasPrefix(a.HTTP.Path, "/") {
		return fmt.Errorf("externalAuth: http.path must start with /")
	}
	return nil
}

func (a *ExternalAuth) responseHeaders() []string {
	if a.HTTP != nil {
		return a.HTTP.AllowedResponseHeaders
	}
	return nil
}

func (a *ExternalAuth) describe() string {
	s := "ask the " + a.Protocol + " authorization service " + a.BackendRef.Name + " before forwarding"
	if h := a.responseHeaders(); len(h) > 0 {
		s += "; headers from an allowing answer replace the request's: " + commaJoin(h)
	}
	return s
}

func hasExternalAuth(fs []Filter) bool {
	for _, f := range fs {
		if f.Type == "ExternalAuth" && f.ExternalAuth != nil {
			return true
		}
	}
	return false
}

// authTargets maps each ExternalAuth filter of a rule to its resolved backend.
type authTargets map[*ExternalAuth]*Backend

type authCtxKey struct{}

// authHeaders are the headers allowing answers asked to set on the upstream
// request, per filter. A preview marks an explanation, where nothing is asked.
type authHeaders map[*ExternalAuth]http.Header
type authPreview struct{}

// applyAuthToRequest is the ExternalAuth step of shapeUpstream: it puts the
// headers the authorization service returned (or, when explaining, a
// placeholder for each one it may return) on the upstream request.
func applyAuthToRequest(out, in *http.Request, a *ExternalAuth) {
	switch v := in.Context().Value(authCtxKey{}).(type) {
	case authHeaders:
		for k, vals := range v[a] {
			out.Header[k] = append([]string(nil), vals...)
		}
	case authPreview:
		for _, n := range a.responseHeaders() {
			out.Header.Set(n, authPreviewValue)
		}
	}
}

// authVerdict is the outcome of one authorization call.
type authVerdict struct {
	allow  bool
	status int         // status to answer with when denying
	hdr    http.Header // headers to answer with when denying
	body   []byte
	set    http.Header // headers to put on the upstream request when allowing
	why    string
}

// runAuthFilters evaluates every ExternalAuth filter of the request in order.
// It returns the request to forward (its context carries the headers the
// services asked to set) or the verdict that stops it.
func (s *Server) runAuthFilters(r *http.Request, rule *CRule, filters []Filter, tlsPort bool) (*http.Request, *authVerdict) {
	set := authHeaders{}
	for _, f := range filters {
		if f.Type != "ExternalAuth" || f.ExternalAuth == nil {
			continue
		}
		b := rule.Auth[f.ExternalAuth]
		if b == nil {
			return r, &authVerdict{status: http.StatusInternalServerError, why: "authorization backend is not resolved"}
		}
		v := s.callAuth(r, f.ExternalAuth, b, tlsPort)
		if !v.allow {
			return r, v
		}
		set[f.ExternalAuth] = v.set
	}
	if len(set) == 0 {
		return r, nil
	}
	return r.WithContext(context.WithValue(r.Context(), authCtxKey{}, set)), nil
}

func (s *Server) callAuth(r *http.Request, a *ExternalAuth, b *Backend, tlsPort bool) *authVerdict {
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = defaultAuthTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var body []byte
	if a.Forward != nil && a.Forward.MaxSize > 0 && r.Body != nil && r.Body != http.NoBody {
		buf, _ := io.ReadAll(io.LimitReader(r.Body, int64(a.Forward.MaxSize)))
		body = buf
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	}
	var v *authVerdict
	var err error
	if a.Protocol == "GRPC" {
		v, err = s.callGRPCAuth(ctx, r, a, b, body, tlsPort)
	} else {
		v, err = s.callHTTPAuth(ctx, r, a, b, body, tlsPort)
	}
	if err != nil {
		return &authVerdict{status: http.StatusForbidden, why: "authorization service failed, denying (fail closed): " + err.Error()}
	}
	return v
}

func canonSet(names []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[http.CanonicalHeaderKey(n)] = true
	}
	return m
}

var authNeverCopy = map[string]bool{"Host": true, "Content-Length": true, "Content-Type": true, "Date": true, "Server": true,
	"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true}

var authAlwaysSent = []string{"Authorization", "Content-Length", "Content-Type"}

// authRequestHeaders picks the client headers an authorization call carries.
// With an empty list the gRPC protocol sends every header; the HTTP protocol
// sends only Authorization, Content-Length and Content-Type (Host, method and
// path travel on the request itself), as the spec says.
func authRequestHeaders(in http.Header, allowed []string, grpc bool) http.Header {
	out := http.Header{}
	all := len(allowed) == 0 && grpc
	want := canonSet(allowed)
	for _, n := range authAlwaysSent {
		want[n] = true
	}
	for k, vals := range in {
		if all || want[k] {
			out[k] = append([]string(nil), vals...)
		}
	}
	stripHopHeaders(out)
	return out
}

func (s *Server) callHTTPAuth(ctx context.Context, r *http.Request, a *ExternalAuth, b *Backend, body []byte, tlsPort bool) (*authVerdict, error) {
	ep := b.choose(s.res.now(), nil)
	if ep == nil {
		return nil, errors.New("no endpoints")
	}
	path := r.URL.EscapedPath()
	if a.HTTP != nil {
		path = strings.TrimSuffix(a.HTTP.Path, "/") + path
	}
	target := ep.URL.Scheme + "://" + ep.URL.Host + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target, rd)
	if err != nil {
		return nil, err
	}
	var allowed []string
	if a.HTTP != nil {
		allowed = a.HTTP.AllowedHeaders
	}
	req.Header = authRequestHeaders(r.Header, allowed, a.Protocol == "GRPC")
	if len(body) == 0 {
		req.Header.Del("Content-Length")
	}
	req.Host = r.Host
	setForwarded(req.Header, remoteIP(r), r.Host, tlsPort)
	client := &http.Client{Transport: s.backendTransport(b), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponse))
	switch {
	case resp.StatusCode == http.StatusOK:
		set := http.Header{}
		names := canonSet(a.responseHeaders())
		for k, vals := range resp.Header {
			if len(names) > 0 && !names[k] {
				continue
			}
			if len(names) == 0 && authNeverCopy[k] {
				continue // no list: everything but the headers that describe the auth response itself
			}
			set[k] = append([]string(nil), vals...)
		}
		return &authVerdict{allow: true, set: set}, nil
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	h := resp.Header.Clone()
	stripHopHeaders(h)
	h.Del("Content-Length")
	return &authVerdict{status: resp.StatusCode, hdr: h, body: data, why: fmt.Sprintf("authorization service answered %d", resp.StatusCode)}, nil
}

// ---- gRPC (envoy.service.auth.v3) ----

func (s *Server) callGRPCAuth(ctx context.Context, r *http.Request, a *ExternalAuth, b *Backend, body []byte, tlsPort bool) (*authVerdict, error) {
	ep := b.choose(s.res.now(), nil)
	if ep == nil {
		return nil, errors.New("no endpoints")
	}
	var allowed []string
	if a.GRPC != nil {
		allowed = a.GRPC.AllowedHeaders
	}
	msg := encodeCheckRequest(r, authRequestHeaders(r.Header, allowed, a.Protocol == "GRPC"), body, tlsPort)
	frame := append([]byte{0, 0, 0, 0, 0}, msg...)
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL.Scheme+"://"+ep.URL.Host+grpcAuthPath, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := (&http.Client{Transport: s.grpcTransport(b, ep.URL.Scheme)}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponse))
	if err != nil {
		return nil, err
	}
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	if resp.StatusCode != http.StatusOK || (status != "" && status != "0") {
		return nil, fmt.Errorf("authorization call failed (HTTP %d, grpc-status %q)", resp.StatusCode, status)
	}
	if len(data) < 5 {
		return nil, errors.New("empty authorization response")
	}
	return decodeCheckResponse(data[5:])
}

func pbBytes(b []byte, field int, v []byte) []byte {
	b = pbVarint(b, uint64(field)<<3|2)
	b = pbVarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbString(b []byte, field int, v string) []byte {
	if v == "" {
		return b
	}
	return pbBytes(b, field, []byte(v))
}

type pbField struct {
	num int
	i   uint64
	b   []byte
}

func pbParse(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		tag, n := binaryUvarint(b)
		if n <= 0 {
			return nil, errors.New("bad protobuf tag")
		}
		b = b[n:]
		f := pbField{num: int(tag >> 3)}
		switch tag & 7 {
		case 0:
			v, n := binaryUvarint(b)
			if n <= 0 {
				return nil, errors.New("bad protobuf varint")
			}
			f.i, b = v, b[n:]
		case 2:
			l, n := binaryUvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("bad protobuf length")
			}
			f.b, b = b[n:n+int(l)], b[n+int(l):]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("bad protobuf fixed64")
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("bad protobuf fixed32")
			}
			b = b[4:]
		default:
			return nil, errors.New("unsupported protobuf wire type")
		}
		out = append(out, f)
	}
	return out, nil
}

func binaryUvarint(b []byte) (uint64, int) { return binary.Uvarint(b) }

// encodeCheckRequest builds a CheckRequest{attributes{source, request{http}}}.
func encodeCheckRequest(r *http.Request, hdr http.Header, body []byte, tlsPort bool) []byte {
	var http_ []byte
	http_ = pbString(http_, 2, r.Method)
	for k, vals := range hdr {
		var entry []byte
		entry = pbString(entry, 1, strings.ToLower(k))
		entry = pbString(entry, 2, strings.Join(vals, ","))
		http_ = pbBytes(http_, 3, entry)
	}
	http_ = pbString(http_, 4, r.URL.RequestURI())
	http_ = pbString(http_, 5, r.Host)
	scheme := "http"
	if tlsPort {
		scheme = "https"
	}
	http_ = pbString(http_, 6, scheme)
	http_ = pbString(http_, 10, r.Proto)
	if len(body) > 0 {
		http_ = pbBytes(http_, 12, body)
	}
	req := pbBytes(nil, 2, http_)
	var attrs []byte
	if ip := remoteIP(r); ip != "" {
		sock := pbString(nil, 2, ip)
		addr := pbBytes(nil, 1, sock)
		attrs = pbBytes(attrs, 1, pbBytes(nil, 1, addr))
	}
	attrs = pbBytes(attrs, 4, req)
	return pbBytes(nil, 1, attrs)
}

func parseHeaderValueOptions(raw [][]byte) http.Header {
	h := http.Header{}
	for _, opt := range raw {
		fs, _ := pbParse(opt)
		for _, f := range fs {
			if f.num != 1 {
				continue
			}
			var k, v string
			kv, _ := pbParse(f.b)
			for _, x := range kv {
				switch x.num {
				case 1:
					k = string(x.b)
				case 2:
					v = string(x.b)
				}
			}
			if k != "" {
				h.Add(k, v)
			}
		}
	}
	return h
}

// decodeCheckResponse reads a CheckResponse.
func decodeCheckResponse(b []byte) (*authVerdict, error) {
	fs, err := pbParse(b)
	if err != nil {
		return nil, err
	}
	code := uint64(0)
	var denied, ok []byte
	for _, f := range fs {
		switch f.num {
		case 1:
			sf, _ := pbParse(f.b)
			for _, x := range sf {
				if x.num == 1 {
					code = x.i
				}
			}
		case 2:
			denied = f.b
		case 3:
			ok = f.b
		}
	}
	if code == 0 {
		set := http.Header{}
		okf, _ := pbParse(ok)
		var opts [][]byte
		for _, f := range okf {
			if f.num == 2 {
				opts = append(opts, f.b)
			}
		}
		for k, vals := range parseHeaderValueOptions(opts) {
			set[k] = vals
		}
		return &authVerdict{allow: true, set: set}, nil
	}
	v := &authVerdict{status: http.StatusForbidden, why: fmt.Sprintf("authorization service denied (rpc code %d)", code)}
	df, _ := pbParse(denied)
	var opts [][]byte
	for _, f := range df {
		switch f.num {
		case 1:
			sf, _ := pbParse(f.b)
			for _, x := range sf {
				if x.num == 1 && x.i >= 100 && x.i < 600 {
					v.status = int(x.i)
				}
			}
		case 2:
			opts = append(opts, f.b)
		case 3:
			v.body = f.b
		}
	}
	v.hdr = parseHeaderValueOptions(opts)
	return v, nil
}

// writeAuthDenied answers a request the authorization service refused.
func writeAuthDenied(w http.ResponseWriter, v *authVerdict) {
	h := w.Header()
	for k, vals := range v.hdr {
		h[k] = vals
	}
	if len(v.body) == 0 && h.Get("Content-Type") == "" {
		plain(w, v.status, v.why)
		return
	}
	w.WriteHeader(v.status)
	w.Write(v.body)
}

// compileAuth resolves the ExternalAuth filters among fs for rule cr.
func (t *Table) compileAuth(r *Route, cr *CRule, fs []Filter, note func(fact)) error {
	for _, f := range fs {
		if f.Type != "ExternalAuth" {
			continue
		}
		if f.ExternalAuth == nil {
			return fmt.Errorf("ExternalAuth filter has no externalAuth block")
		}
		if err := f.ExternalAuth.validate(); err != nil {
			return err
		}
		b, fc := t.backend(r, f.ExternalAuth.BackendRef)
		note(fc)
		if b != nil {
			if cr.Auth == nil {
				cr.Auth = authTargets{}
			}
			cr.Auth[f.ExternalAuth] = b
		}
	}
	return nil
}
