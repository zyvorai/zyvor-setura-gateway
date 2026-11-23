package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// RequestIDHeader carries the request id to the backend and back to the client.
const RequestIDHeader = "X-Request-Id"

// traceInfo is the W3C trace context of one request as seen by this hop.
type traceInfo struct {
	TraceID  string // 32 lowercase hex
	SpanID   string // 16 hex, new for this hop
	ParentID string // incoming span id, empty when the trace starts here
	Flags    string // 2 hex, "01" means sampled
	State    string // tracestate, passed through untouched
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool { return strings.Trim(s, "0") == "" }

// parseTraceparent validates version 00 headers (and tolerates higher
// versions with extra fields, as the spec asks).
func parseTraceparent(h string) (traceID, parent, flags string, ok bool) {
	p := strings.Split(strings.TrimSpace(h), "-")
	if len(p) < 4 || len(p[0]) != 2 || !isHex(p[0]) || p[0] == "ff" {
		return
	}
	if p[0] == "00" && len(p) != 4 {
		return
	}
	if len(p[1]) != 32 || !isHex(p[1]) || allZero(p[1]) || len(p[2]) != 16 || !isHex(p[2]) || allZero(p[2]) || len(p[3]) != 2 || !isHex(p[3]) {
		return
	}
	return p[1], p[2], p[3], true
}

// newTrace continues the incoming trace (new span id) or starts one.
func newTrace(h http.Header) traceInfo {
	t := traceInfo{SpanID: randHex(8), State: h.Get("Tracestate")}
	if id, parent, flags, ok := parseTraceparent(h.Get("Traceparent")); ok {
		t.TraceID, t.ParentID, t.Flags = id, parent, flags
		return t
	}
	t.TraceID, t.Flags, t.State = randHex(16), "01", ""
	return t
}

func (t traceInfo) header() string { return "00-" + t.TraceID + "-" + t.SpanID + "-" + t.Flags }

func validRequestID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// beginTrace assigns trace context and request id and echoes the id.
func (s *Server) beginTrace(w http.ResponseWriter, r *http.Request, st *reqState) {
	st.trace = newTrace(r.Header)
	var client string
	st.reqID, client = s.requestID(r.Header)
	if client != "" {
		r.Header.Set("X-Client-Request-Id", client)
	}
	w.Header().Set(RequestIDHeader, st.reqID)
}

// injectTrace stamps the outgoing request with this hop's span.
func injectTrace(out *http.Request, st *reqState) {
	out.Header.Set("Traceparent", st.trace.header())
	if st.trace.State == "" {
		out.Header.Del("Tracestate")
	}
	out.Header.Set(RequestIDHeader, st.reqID)
}
