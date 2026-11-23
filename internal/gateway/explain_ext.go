package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"time"
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
	if rule.Direct != nil {
		w.Notes = append(w.Notes, "direct response: the gateway answers itself and no backend is contacted")
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

// explainL4 explains a TCP or UDP listener: nothing is matched, the oldest
// route's first rule with a backend takes every connection or client.
func (tr *Trace) explainL4(t *Table, l *RTListener, now time.Time) {
	e := l.l4Pick()
	if e == nil {
		tr.Verdict = VerdictNoRoute
		tr.Reason = fmt.Sprintf("listener %s (%s) has no %s attached with a backendRef, so connections are closed", l.Key, l.L.Protocol, protocolKinds(l.L.Protocol)[0])
		return
	}
	kind := protocolKinds(l.L.Protocol)[0]
	w := &TraceWinner{Route: e.RouteKey, Kind: kind, Rule: e.Index() + 1, Summary: "every " + strings.ToLower(l.L.Protocol) + " connection or client on port " + fmt.Sprint(l.L.Port), RuleName: e.Name}
	w.Backends = t.distribution(tr.Request, kind, e.RouteKey, e.Refs, e.Total, nil, nil, now, nil)
	if l.L.Protocol == "UDP" {
		w.Notes = append(w.Notes, "UDP: the backend is chosen once per client address; the session ends after the idle timeout (--udp-idle-timeout)")
	}
	tr.Winner = w
	tr.finishBackends(w)
}

// Index is the 0-based rule position of the entry.
func (e *L4Entry) Index() int { return e.Rule }

// explainPreflight turns the trace of a CORS preflight into the answer the
// gateway itself gives (no backend is contacted).
func (tr *Trace) explainPreflight(w *TraceWinner, c *CORS, r *http.Request) {
	w.Preflight = flatten(c.preflightHeaders(r))
	w.Notes = append(w.Notes, fmt.Sprintf("this is a CORS preflight: the gateway answers 200 itself and the backend is not contacted (%s)", describeCORS(c)))
}
