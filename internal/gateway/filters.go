package gateway

import (
	"net"
	"net/http"
	"strings"
)

// This file is the single implementation of "what the upstream request looks
// like". The data path (proxy.go, grpcroute.go) calls shapeUpstream from the
// ReverseProxy Rewrite hook, and the explainer (explain.go) calls the same
// function to render the request a backend would receive, so a filter type
// added here is applied by both.

// requestFilters returns the filters that apply to a request, in order: the
// rule's own first, then the chosen backendRef's.
func requestFilters(rule *CRule, ref *CRef) []Filter {
	return append(append([]Filter(nil), rule.Rule.Filters...), ref.Filters...)
}

// remoteIP is the client address the gateway sees on the connection, or "".
func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return h
}

// setForwarded stamps X-Forwarded-For/-Host/-Proto. Whatever the client sent
// in these headers (and in Forwarded) was already dropped by ReverseProxy
// before Rewrite runs, so the gateway never trusts or appends to a client
// supplied chain: X-Forwarded-For is exactly the connection's remote address.
func setForwarded(out http.Header, clientIP, host string, tlsPort bool) {
	if clientIP != "" {
		out.Set("X-Forwarded-For", clientIP)
	} else {
		out.Del("X-Forwarded-For")
	}
	out.Set("X-Forwarded-Host", host)
	if tlsPort {
		out.Set("X-Forwarded-Proto", "https")
	} else {
		out.Set("X-Forwarded-Proto", "http")
	}
}

// shapeUpstream turns the inbound request in into the outbound request out
// (whose URL scheme and host the caller has already pointed at the endpoint):
// forwarded headers, Host, the original path, then every filter in order.
// gRPC calls take header modifiers only; URLRewrite does not apply to them.
func shapeUpstream(out, in *http.Request, clientIP string, tlsPort bool, filters []Filter, m *CMatch, grpc bool, reqID, listener string, claims map[string]any) {
	out.Host = in.Host
	scheme := "http"
	if tlsPort {
		scheme = "https"
	}
	vars := &headerVars{clientIP: clientIP, requestID: reqID, host: in.Host, scheme: scheme, listener: listener, claims: claims}
	setForwarded(out.Header, clientIP, in.Host, tlsPort)
	out.URL.Path, out.URL.RawPath = in.URL.Path, in.URL.RawPath
	for _, f := range filters {
		switch {
		case f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil:
			applyHeaderModVars(out.Header, f.RequestHeaderModifier, vars)
		case f.Type == "ExternalAuth" && f.ExternalAuth != nil && !grpc:
			applyAuthToRequest(out, in, f.ExternalAuth)
		case f.Type == "URLRewrite" && f.URLRewrite != nil && !grpc:
			if f.URLRewrite.Hostname != "" {
				out.Host = f.URLRewrite.Hostname
			}
			if p := f.URLRewrite.Path; p != nil {
				out.URL.Path, out.URL.RawPath = rewritePath(out.URL.Path, p, m), ""
			}
		}
	}
}

// headerVars are the values a request HeaderModifier can refer to as
// {client_ip}, {request_id}, {host}, {scheme}, {listener} and {claim:NAME}:
// things the gateway knows and Gateway API cannot express. client_ip is the
// TCP peer, not X-Forwarded-For, so a header set from it cannot be spoofed.
// {claim:NAME} is a claim of the JWT or OIDC session the gateway verified
// itself (dotted names reach into objects: {claim:realm_access.roles}).
type headerVars struct {
	clientIP, requestID, host, scheme, listener string
	claims                                      map[string]any
}

// HeaderVarNames lists the supported variables, for docs and lint.
// claim:NAME takes any claim name.
var HeaderVarNames = []string{"client_ip", "request_id", "host", "scheme", "listener", "claim:NAME"}

// ClaimVarPrefix starts a claim variable.
const ClaimVarPrefix = "{claim:"

// ClaimVars lists the claim names a header value refers to.
func ClaimVars(s string) []string {
	var out []string
	for {
		i := strings.Index(s, ClaimVarPrefix)
		if i < 0 {
			return out
		}
		s = s[i+len(ClaimVarPrefix):]
		j := strings.IndexByte(s, '}')
		if j < 0 {
			return out
		}
		out = append(out, s[:j])
		s = s[j+1:]
	}
}

func cleanHeaderValue(s string) string {
	return strings.Map(func(c rune) rune {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return -1
		}
		return c
	}, s)
}

// expand replaces the known variables in s; an unknown {name} stays as written.
func (v *headerVars) expand(s string) string {
	out, _ := v.expandHdr(s)
	return out
}

// expandHdr is expand that also reports whether a {claim:NAME} has no value
// (no verified claims, or the claim is absent or empty). A header whose value
// refers to such a claim is not sent, so an unauthenticated request never
// carries an empty identity and a client's own value is not passed through.
func (v *headerVars) expandHdr(s string) (string, bool) {
	if v == nil || !strings.Contains(s, "{") {
		return s, false
	}
	s = strings.NewReplacer("{client_ip}", cleanHeaderValue(v.clientIP), "{request_id}", cleanHeaderValue(v.requestID),
		"{host}", cleanHeaderValue(v.host), "{scheme}", v.scheme, "{listener}", cleanHeaderValue(v.listener)).Replace(s)
	missing := false
	for _, name := range ClaimVars(s) {
		val := ""
		if c, ok := claimAt(v.claims, name); ok {
			val = claimHeaderValue(c)
		}
		if val == "" {
			missing = true
		}
		s = strings.Replace(s, ClaimVarPrefix+name+"}", val, 1)
	}
	return s, missing
}

// shapeResponse is the response-side counterpart of shapeUpstream: every
// ResponseHeaderModifier and CORS filter, in order, applied to the headers h
// of a response to the inbound request in. The proxy runs it on upstream
// responses, redirects and authorization denials; the explainer runs it on a
// blank header set to show what the client would receive.
func shapeResponse(h http.Header, in *http.Request, filters []Filter) {
	for _, f := range filters {
		switch {
		case f.Type == "ResponseHeaderModifier" && f.ResponseHeaderModifier != nil:
			applyHeaderMod(h, f.ResponseHeaderModifier)
		case f.Type == "CORS" && f.CORS != nil:
			f.CORS.applyResponse(h, in)
		}
	}
}

// hopHeaders are removed by net/http/httputil.ReverseProxy before it calls
// Rewrite (hop-by-hop headers plus the forwarding headers). The explainer
// applies the same removal to the headers it was given.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}

func stripHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// previewTrace stamps the trace headers the way injectTrace does on the data
// path, with placeholders where the gateway generates random ids.
func previewTrace(out *http.Request, in http.Header) {
	st := &reqState{reqID: in.Get(RequestIDHeader)}
	if !validRequestID(st.reqID) {
		st.reqID = "<generated>"
	}
	st.trace = traceInfo{SpanID: "<new-span-id>", State: in.Get("Tracestate")}
	if id, parent, flags, ok := parseTraceparent(in.Get("Traceparent")); ok {
		st.trace.TraceID, st.trace.ParentID, st.trace.Flags = id, parent, flags
	} else {
		st.trace.TraceID, st.trace.Flags, st.trace.State = "<generated-trace-id>", "01", ""
	}
	injectTrace(out, st)
}
