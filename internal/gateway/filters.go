package gateway

import (
	"net"
	"net/http"
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
func shapeUpstream(out, in *http.Request, clientIP string, tlsPort bool, filters []Filter, m *CMatch, grpc bool) {
	out.Host = in.Host
	setForwarded(out.Header, clientIP, in.Host, tlsPort)
	out.URL.Path, out.URL.RawPath = in.URL.Path, in.URL.RawPath
	for _, f := range filters {
		switch {
		case f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil:
			applyHeaderMod(out.Header, f.RequestHeaderModifier)
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
