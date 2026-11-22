package gateway

import (
	"fmt"
	"net/http"
	"strings"
)

// This file models what Gateway API 1.5 features add to a trace: CORS
// answers, external authorization, backend request timeouts, session
// persistence and backend TLS. Each piece runs the same shared helpers the
// data path runs (shapeResponse, applyAuthToRequest, corsOf, preflightTarget).

func flatten(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// explainExtras fills the Gateway API 1.5 parts of the winner.
func (tr *Trace) explainExtras(w *TraceWinner, e *Entry, r *http.Request) {
	rule := e.Rule
	if rule.Rule.Name != "" {
		w.RuleName = rule.Rule.Name
	}
	if rule.BackendTimeout > 0 {
		w.BackendTimeout = rule.BackendTimeout.String()
	}
	if rule.Redirect != nil {
		w.ResponseHeaders = respHeadersFor(r, rule.Rule.Filters)
	}
	if rule.Session != nil {
		w.Session = describeSession(rule.Session)
	}
	for i := range w.Backends {
		if i >= len(rule.Refs) {
			break
		}
		ref := rule.Refs[i]
		w.Backends[i].ResponseHeaders = respHeadersFor(r, requestFilters(rule, ref))
		if ref.Session != nil && rule.Session == nil {
			w.Notes = append(w.Notes, "backendRef "+ref.Name+": "+describeSession(ref.Session))
		}
		if ref.B != nil && ref.B.TLS != nil {
			w.Backends[i].BackendTLS = ref.B.TLS.describe()
		}
	}
	for _, f := range requestFilters(rule, firstRef(rule)) {
		if f.Type == "ExternalAuth" && f.ExternalAuth != nil && f.ExternalAuth.Protocol == "GRPC" {
			w.Notes = append(w.Notes, "ExternalAuth over gRPC: the headers the service sets on the request are only known when it answers")
		}
	}
}

func firstRef(rule *CRule) *CRef {
	if len(rule.Refs) > 0 {
		return rule.Refs[0]
	}
	return &CRef{}
}

// respHeadersFor is what the gateway itself puts on the response: response
// header modifiers and CORS headers, through shapeResponse.
func respHeadersFor(r *http.Request, fs []Filter) map[string]string {
	h := http.Header{}
	shapeResponse(h, r, fs)
	return flatten(h)
}

// explainPreflight turns the trace of a CORS preflight into the answer the
// gateway itself gives (no backend is contacted).
func (tr *Trace) explainPreflight(w *TraceWinner, c *CORS, r *http.Request) {
	w.Preflight = flatten(c.preflightHeaders(r))
	w.Notes = append(w.Notes, fmt.Sprintf("this is a CORS preflight: the gateway answers 200 itself and the backend is not contacted (%s)", describeCORS(c)))
}
