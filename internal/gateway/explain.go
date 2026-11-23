package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file is the routing-decision explainer. It never re-implements the
// matching rules: Explain drives the very functions the data path uses
// (pickListenerT, selectEntryT, selectTLST, matchesWhy, hostMatches, ...)
// with a *Trace attached. The data path passes a nil *Trace, so recording costs
// it one nil check per decision and no allocation.

// Trace verdicts.
const (
	VerdictRouted     = "routed"
	VerdictRedirect   = "redirect"
	VerdictDirect     = "direct-response"
	VerdictBadRequest = "bad-request"
	VerdictNoListener = "no-listener"
	VerdictNoRoute    = "no-route"
	VerdictNoBackend  = "no-backend"
)

// ExplainRequest is a request to explain. Build one with ParseExplainRequest.
type ExplainRequest struct {
	Method   string      `json:"method"`
	Scheme   string      `json:"scheme"`
	Host     string      `json:"host"` // Host header, with the port when one was given
	Port     int         `json:"port"` // spec port the request arrives on
	Path     string      `json:"path"`
	RawPath  string      `json:"raw_path,omitempty"` // the path as sent, when it has escapes
	RawQuery string      `json:"query,omitempty"`
	Header   http.Header `json:"headers,omitempty"`
	GRPC     string      `json:"grpc,omitempty"` // "service/method": a gRPC call over HTTP/2
	SNI      string      `json:"sni,omitempty"`  // TLS passthrough: route by server name

	// Live says the table's endpoint health is real (a running gateway), so
	// ejected and unhealthy endpoints are reported and excluded. Now overrides
	// the clock when set.
	Live bool      `json:"-"`
	Now  time.Time `json:"-"`

	// Remote is the client address (X-Forwarded-For, rate-limit key); empty
	// renders as <client-ip>. Server carries the gateway-wide policy that is
	// not part of the route config: rate limit, retry budget, shadow default.
	Remote string        `json:"remote,omitempty"`
	Server ExplainServer `json:"-"`
}

// ParseExplainRequest validates the inputs of "setura why" and /why.
// headers are "Name: value" strings.
func ParseExplainRequest(method, rawURL string, headers []string, grpc, sni string) (ExplainRequest, error) {
	req := ExplainRequest{Method: strings.ToUpper(strings.TrimSpace(method)), Header: http.Header{}, SNI: strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sni), "."))}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return req, fmt.Errorf("URL %q: want scheme://host[:port]/path", rawURL)
	}
	req.Scheme = strings.ToLower(u.Scheme)
	switch req.Scheme {
	case "http", "https", "tls":
	default:
		return req, fmt.Errorf("URL scheme %q: want http, https or tls", u.Scheme)
	}
	req.Host = u.Host
	if p := u.Port(); p != "" {
		if req.Port, err = strconv.Atoi(p); err != nil || req.Port < 1 || req.Port > 65535 {
			return req, fmt.Errorf("URL port %q is out of range", p)
		}
	} else if req.Scheme == "http" {
		req.Port = 80
	} else {
		req.Port = 443
	}
	req.Path, req.RawPath, req.RawQuery = u.Path, u.RawPath, u.RawQuery
	if req.Path == "" {
		req.Path = "/"
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return req, fmt.Errorf("header %q: want \"Name: value\"", h)
		}
		req.Header.Add(name, strings.TrimSpace(value))
	}
	if grpc != "" {
		svc, meth, ok := strings.Cut(strings.Trim(grpc, "/"), "/")
		if !ok || svc == "" || meth == "" {
			return req, fmt.Errorf("--grpc %q: want service/method, for example helloworld.Greeter/SayHello", grpc)
		}
		req.GRPC = svc + "/" + meth
		req.Method, req.Path = "POST", "/"+req.GRPC
		req.Header.Set("Content-Type", "application/grpc")
	}
	if req.SNI != "" && req.GRPC != "" {
		return req, fmt.Errorf("--sni and --grpc cannot be combined: TLS passthrough does not look inside the connection")
	}
	return req, nil
}

// httpRequest builds the request the data path would see.
func (q ExplainRequest) httpRequest() *http.Request {
	h := q.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	host := q.Host
	if v := h.Get("Host"); v != "" {
		host = v
		h.Del("Host")
	}
	remote := q.Remote
	if remote == "" {
		remote = "<client-ip>"
	}
	r := &http.Request{Method: q.Method, URL: &url.URL{Path: q.Path, RawPath: q.RawPath, RawQuery: q.RawQuery}, Header: h, Host: host, RemoteAddr: net.JoinHostPort(remote, "0"), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	if q.GRPC != "" {
		r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	}
	return r
}

// Trace is everything Explain considered, in order, with the verdict.
type Trace struct {
	Request    ExplainRequest   `json:"request"`
	Verdict    string           `json:"verdict"`
	Reason     string           `json:"reason"`
	Listeners  []TraceListener  `json:"listeners"`
	Routes     []TraceRoute     `json:"routes,omitempty"`
	Candidates []TraceCandidate `json:"candidates,omitempty"`
	Winner     *TraceWinner     `json:"winner,omitempty"`
	// NormalizedPath is the path routing used, when path normalisation changed it.
	NormalizedPath string `json:"normalized_path,omitempty"`

	// recorders, filled by the match code when a Trace is attached
	lrec   []listenerRec
	chosen *RTListener
	// credHeaders and credQuery name where the winning rule's auth policy reads
	// credentials, so the echoed request can hide them.
	credHeaders, credQuery []string
	authRes                *authResult // outcome of the winning rule's policy, for plan resolution
	erec                   []entryRec
	trec                   []tlsRec
}

type listenerRec struct {
	l      *RTListener
	hostOK bool
}

type entryRec struct {
	e      *Entry
	s      score
	ok     bool
	reason string
}

type tlsRec struct {
	e       *TLSEntry
	matched bool
	rank    int
}

// TraceListener is one listener and what became of it.
type TraceListener struct {
	Listener string `json:"listener"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname,omitempty"`
	Verdict  string `json:"verdict"` // chosen, lost or rejected
	Reason   string `json:"reason"`
}

// TraceRoute is a route and whether it is attached to the chosen listener.
type TraceRoute struct {
	Route    string `json:"route"` // StatusKey: ns/name or Kind/ns/name
	Kind     string `json:"kind"`
	Created  string `json:"created,omitempty"`
	Attached bool   `json:"attached"`
	Reason   string `json:"reason"`
}

// TraceCandidate is one (route, rule, match) considered on the chosen listener.
type TraceCandidate struct {
	Route   string   `json:"route"`
	Kind    string   `json:"kind"`
	Rule    int      `json:"rule"`  // 1-based
	Match   int      `json:"match"` // 1-based within the rule
	Summary string   `json:"summary"`
	Hosts   []string `json:"hosts,omitempty"`
	Verdict string   `json:"verdict"` // winner, lost or rejected
	Reason  string   `json:"reason"`
}

// TraceFilter is one filter and its effect.
type TraceFilter struct {
	Scope  string `json:"scope"` // "rule" or "backendRef NAME"
	Type   string `json:"type"`
	Effect string `json:"effect"`
}

// TraceEndpoint is one upstream address and its known state.
type TraceEndpoint struct {
	URL   string `json:"url"`
	State string `json:"state"` // up, unhealthy, ejected or unknown
}

// TraceUpstream is the request a backend would receive.
type TraceUpstream struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

// TraceBackend is one backendRef of the winning rule.
type TraceBackend struct {
	Name      string          `json:"name"`
	Key       string          `json:"key,omitempty"`
	Weight    int             `json:"weight"`
	Percent   float64         `json:"percent"`
	Status    string          `json:"status"` // ok, excluded or unresolved
	Reason    string          `json:"reason,omitempty"`
	Endpoints []TraceEndpoint `json:"endpoints,omitempty"`
	Request   *TraceUpstream  `json:"request,omitempty"`
	// ResponseHeaders are the headers the gateway itself adds to the response
	// (header modifiers, CORS), whatever the backend sends.
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	BackendTLS      string            `json:"backend_tls,omitempty"`
}

// TraceRedirect is the answer of a RequestRedirect rule.
type TraceRedirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
}

// TraceDirect is the answer of a direct-response rule.
type TraceDirect struct {
	Status  int               `json:"status"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// TraceWinner is the rule that took the request.
type TraceWinner struct {
	Route    string         `json:"route"`
	Kind     string         `json:"kind"`
	Rule     int            `json:"rule"`
	Match    int            `json:"match"`
	Summary  string         `json:"summary"`
	Filters  []TraceFilter  `json:"filters,omitempty"`
	Redirect *TraceRedirect `json:"redirect,omitempty"`
	Direct   *TraceDirect   `json:"direct_response,omitempty"`
	Backends []TraceBackend `json:"backends,omitempty"`
	Mirrors  []string       `json:"mirrors,omitempty"`
	Timeout  string         `json:"timeout,omitempty"`
	Passthru bool           `json:"passthrough,omitempty"`

	MirrorTargets []TraceMirror   `json:"mirror_targets,omitempty"`
	Retry         *TraceRetry     `json:"retry,omitempty"`
	RateLimit     *TraceRateLimit `json:"rate_limit,omitempty"`
	RouteLimit    *TraceRateLimit `json:"route_rate_limit,omitempty"` // the rule's own limiter
	Auth          *TraceAuth      `json:"auth,omitempty"`
	Plan          *TracePlan      `json:"plan,omitempty"`
	AI            *TraceAI        `json:"ai,omitempty"`
	Notes         []string        `json:"notes,omitempty"`
	Faults        []TraceFault    `json:"faults,omitempty"`

	// Gateway API 1.5 additions (explain_ext.go).
	RuleName        string            `json:"rule_name,omitempty"`
	BackendTimeout  string            `json:"backend_timeout,omitempty"`
	Session         string            `json:"session_persistence,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"` // redirect rules
	Preflight       map[string]string `json:"preflight,omitempty"`        // CORS preflight answer
}

// ---- recorders, called from the match code with a non-nil Trace ----

func (tr *Trace) noteListener(l *RTListener, hostOK bool) {
	tr.lrec = append(tr.lrec, listenerRec{l, hostOK})
}

func (tr *Trace) chooseListener(l *RTListener) { tr.chosen = l }

func (tr *Trace) noteEntry(e *Entry, s score, ok bool, reason string) {
	tr.erec = append(tr.erec, entryRec{e, s, ok, reason})
}

func (tr *Trace) noteTLS(e *TLSEntry, matched bool, rank int) {
	tr.trec = append(tr.trec, tlsRec{e, matched, rank})
}

// ---- shared rules (also used when building the table) ----

func kindMismatchReason(grpc bool) string {
	if grpc {
		return "this rule belongs to a GRPCRoute and the request is not a gRPC call (HTTP/2 with content-type application/grpc)"
	}
	return "this rule belongs to an HTTPRoute and the request is a gRPC call; gRPC calls only match GRPCRoutes"
}

func hostList(hosts []string) string {
	q := make([]string, len(hosts))
	for i, h := range hosts {
		if h == "" {
			h = "(any)"
		}
		q[i] = strconv.Quote(h)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// allowedWhy returns "" when the listener lets routes of kind in routeNS
// attach, and the plain-language reason otherwise. allowedNamespace is its
// boolean form.
func (c *Config) allowedWhy(kind string, l *RTListener, routeNS string) string {
	if !l.allowsKind(kind) {
		carried := false
		for _, k := range protocolKinds(l.L.Protocol) {
			carried = carried || k == kind
		}
		if !carried {
			return fmt.Sprintf("listener %s has protocol %s, which does not carry %s (it carries %s)", l.Key, l.L.Protocol, kind, strings.Join(protocolKinds(l.L.Protocol), ", "))
		}
		var names []string
		for _, k := range l.L.AllowedRoutes.Kinds {
			names = append(names, k.Kind)
		}
		return fmt.Sprintf("listener %s allowedRoutes.kinds is [%s], which does not include %s", l.Key, strings.Join(names, ", "), kind)
	}
	var ns *RouteNamespaces
	if l.L.AllowedRoutes != nil {
		ns = l.L.AllowedRoutes.Namespaces
	}
	from := "Same"
	if ns != nil && ns.From != "" {
		from = ns.From
	}
	switch from {
	case "All":
		return ""
	case "Same":
		if routeNS == l.ownerNS() {
			return ""
		}
		return fmt.Sprintf("listener %s allows routes from the %s namespace only (allowedRoutes.namespaces.from is Same) and the route lives in %s", l.Key, l.ownerNS(), routeNS)
	case "Selector":
		if ns.Selector == nil {
			return fmt.Sprintf("listener %s has allowedRoutes.namespaces.from Selector without a selector (fails closed)", l.Key)
		}
		if why := selectorWhy(ns.Selector.MatchLabels, ns.Selector.MatchExpressions, c.Namespaces[routeNS]); why != "" {
			return fmt.Sprintf("listener %s selects namespaces by %s and namespace %s does not match", l.Key, why, routeNS)
		}
		return ""
	}
	return fmt.Sprintf("listener %s has unknown allowedRoutes.namespaces.from %q", l.Key, from)
}

// How a route's parentRef relates to one listener.
const (
	fitSkip       = iota // the parentRef does not name this listener
	fitNotAllowed        // named, but the listener is not serving or does not allow the route
	fitNoHost            // allowed, but hostnames do not intersect
	fitOK
)

// parentFit decides whether a route attaches to listener l through parentRef p
// of gateway gw. It is the single rule BuildTable uses to attach routes.
func (t *Table) parentFit(kind, routeNS string, p ParentRef, gw *Gateway, hostnames []string, l *RTListener) (hosts []string, fit int, why string) {
	switch {
	case l.GW != gw:
		return nil, fitSkip, "parentRef names another Gateway"
	case p.Kind == "ListenerSet" && (l.LS == nil || l.LS.Name != p.Name || l.LS.NS != parentNS(p, routeNS)):
		return nil, fitSkip, "parentRef names a ListenerSet that does not hold this listener"
	case p.Kind != "ListenerSet" && p.SectionName != "" && l.LS != nil:
		return nil, fitSkip, "parentRef sectionName names a listener of the Gateway itself, not of a ListenerSet"
	case p.SectionName != "" && l.L.Name != p.SectionName:
		return nil, fitSkip, fmt.Sprintf("parentRef sectionName %q names a different listener", p.SectionName)
	case p.Port != 0 && l.L.Port != p.Port:
		return nil, fitSkip, fmt.Sprintf("parentRef port %d differs from the listener port %d", p.Port, l.L.Port)
	}
	if !l.Serving {
		return nil, fitNotAllowed, "listener " + l.Key + " is not serving: " + l.notServing()
	}
	if w := t.Cfg.allowedWhy(kind, l, routeNS); w != "" {
		return nil, fitNotAllowed, w
	}
	hosts = effectiveHosts(hostnames, l.Host)
	if len(hosts) == 0 {
		return nil, fitNoHost, fmt.Sprintf("route hostnames %s do not intersect the listener hostname %q", hostList(hostnames), l.Host)
	}
	return hosts, fitOK, ""
}

// notServing says why a listener does not serve.
func (l *RTListener) notServing() string {
	switch {
	case !l.Accepted.OK:
		return l.Accepted.Reason + ": " + l.Accepted.Message
	case l.Conflicted.OK:
		return l.Conflicted.Reason + ": " + l.Conflicted.Message
	case !l.Resolved.OK:
		return l.Resolved.Reason + ": " + l.Resolved.Message
	}
	return "not accepted"
}

// ---- Explain ----

func rankName(rank int) string {
	switch {
	case rank <= 0:
		return "no hostname"
	case rank >= 1<<20:
		return "an exact hostname"
	}
	return "a wildcard hostname"
}

// whyLost names the Gateway API precedence rule by which winner beat other.
func whyLost(w, o *Entry, ws, os score) string {
	switch {
	case ws.host != os.host:
		return fmt.Sprintf("precedence rule 1, hostname specificity: it matched through %s, the winner through %s (exact beats wildcard beats none)", rankName(os.host), rankName(ws.host))
	case ws.pathKind != os.pathKind:
		return fmt.Sprintf("precedence rule 2, path type: %s loses to %s (Exact beats RegularExpression beats PathPrefix)", pathKindName(os.pathKind), pathKindName(ws.pathKind))
	case ws.pathLen != os.pathLen:
		return fmt.Sprintf("precedence rule 3, longest path prefix wins: %q (%d characters) loses to %q (%d characters)", o.Match.PathValue, os.pathLen, w.Match.PathValue, ws.pathLen)
	case ws.method != os.method:
		return "precedence rule 4, a rule with a method match beats one without"
	case ws.headers != os.headers:
		return fmt.Sprintf("precedence rule 5, most header matches wins: %d header match(es) loses to %d", os.headers, ws.headers)
	case ws.query != os.query:
		return fmt.Sprintf("precedence rule 6, most query parameter matches wins: %d loses to %d", os.query, ws.query)
	}
	// Dead heat: the table order is the tie-break.
	wr, or := w.Route, o.Route
	if wr == or {
		return "tied on every precedence rule; the earlier rule and match in the same route wins"
	}
	switch {
	case !wr.Created.Equal(or.Created):
		note := ""
		if wr.Created.IsZero() || or.Created.IsZero() {
			note = " (a route without a creationTimestamp counts as oldest)"
		}
		return fmt.Sprintf("tied on every precedence rule; tie-break 1, the oldest creationTimestamp wins: %s (created %s) is older than %s (created %s)%s", routeLabel(wr), fmtTime(wr.Created), routeLabel(or), fmtTime(or.Created), note)
	case wr.Created.IsZero():
		return fmt.Sprintf("tied on every precedence rule; neither route has a creationTimestamp (set metadata.creationTimestamp in the file to use creation time), so tie-break 2, name order, decides: %s sorts before %s", routeLabel(wr), routeLabel(or))
	}
	return fmt.Sprintf("tied on every precedence rule and created at the same time (%s); tie-break 2, name order, decides: %s sorts before %s", fmtTime(wr.Created), routeLabel(wr), routeLabel(or))
}

func pathKindName(k int) string {
	switch k {
	case kindExact:
		return "Exact"
	case kindRegex:
		return "RegularExpression"
	}
	return "PathPrefix"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "no creationTimestamp"
	}
	return t.UTC().Format(time.RFC3339)
}

func routeLabel(r *Route) string { return r.StatusKey() }

// summary renders a compiled match.
func (m *CMatch) summary() string {
	parts := []string{m.PathType + " " + m.PathValue}
	if m.Method != "" {
		parts = append(parts, "method "+m.Method)
	}
	for _, h := range m.Headers {
		parts = append(parts, "header "+h.Name+valueOp(h))
	}
	for _, q := range m.Query {
		parts = append(parts, "query "+q.Name+valueOp(q))
	}
	return strings.Join(parts, ", ")
}

func valueOp(v cvm) string {
	if v.Re != nil {
		return "~" + strings.TrimSuffix(strings.TrimPrefix(v.Re.String(), "^(?:"), ")$")
	}
	return "=" + v.Value
}

// Explain walks the real matching code of the built-in gateway for one request
// against a routing table and records every listener, route, rule and match it
// considered, with a reason for each decision.
func Explain(t *Table, q ExplainRequest) *Trace {
	tr := &Trace{Request: q}
	defer tr.redactRequest()
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	pg := t.Ports[q.Port]
	r := q.httpRequest()
	if msg := q.Server.Path.normalizePath(r); msg != "" {
		tr.Verdict, tr.Reason = VerdictBadRequest, msg+"; the gateway answers 400 before routing (--reject-escaped-slashes)"
		return tr
	}
	if r.URL.Path != q.Path {
		tr.NormalizedPath = r.URL.Path
	}
	host := hostOnly(r.Host)
	passthrough := q.SNI != ""
	if passthrough {
		host = q.SNI
	}

	// Listener selection runs through the same pickListenerT as the data path.
	var l *RTListener
	switch {
	case pg == nil:
	case pg.L4 != "":
		l = pg.pickListenerT(host, tr)
	case pg.Passthrough && !passthrough:
		tr.Verdict, tr.Reason = VerdictNoListener, fmt.Sprintf("port %d is a TLS passthrough port (TLSRoute); give the server name with --sni", q.Port)
	case !pg.Passthrough && passthrough:
		tr.Verdict, tr.Reason = VerdictNoListener, fmt.Sprintf("port %d serves HTTP, not TLS passthrough; --sni only applies to TLS listeners", q.Port)
	case pg.TLS && q.Scheme == "http":
		tr.Verdict, tr.Reason = VerdictNoListener, fmt.Sprintf("port %d serves HTTPS but the URL scheme is http; use https://", q.Port)
	case !pg.TLS && !pg.Passthrough && q.Scheme == "https":
		tr.Verdict, tr.Reason = VerdictNoListener, fmt.Sprintf("port %d serves plain HTTP but the URL scheme is https; use http://", q.Port)
	default:
		l = pg.pickListenerT(host, tr)
	}
	tr.fillListeners(t, q.Port, host, l)
	if tr.Verdict == "" && l == nil {
		tr.Verdict = VerdictNoListener
		switch {
		case pg == nil:
			tr.Reason = fmt.Sprintf("no serving listener is on port %d (%s)", q.Port, tr.portsHint(t))
		default:
			tr.Reason = fmt.Sprintf("no listener on port %d has a hostname that matches %q; the gateway answers 404", q.Port, host)
		}
	}
	if l == nil {
		return tr
	}
	tr.fillRoutes(t, l, passthrough)
	if l.L4Entries != nil || (pg != nil && pg.L4 != "") {
		tr.explainL4(t, l, now)
		return tr
	}

	if passthrough {
		tr.explainTLS(t, l, host, now)
		return tr
	}
	r.URL.RawQuery = q.RawQuery
	e := l.selectEntryT(r, host, tr)
	pe, pcors := l.preflightTarget(r, host)
	if pe != nil {
		e = pe
	}
	tr.fillCandidates(l, e)
	if e == nil {
		tr.Verdict = VerdictNoRoute
		tr.Reason = tr.noRouteReason(l, host)
		return tr
	}
	tr.explainWinner(t, pg, e, r, now)
	if pe != nil {
		tr.explainPreflight(tr.Winner, pcors, r)
	}
	return tr
}

func (tr *Trace) portsHint(t *Table) string {
	var ports []int
	for p := range t.Ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) == 0 {
		return "the table serves no ports"
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return "the table serves " + strings.Join(s, ", ")
}

func (tr *Trace) fillListeners(t *Table, port int, host string, chosen *RTListener) {
	hostOK := map[*RTListener]bool{}
	seen := map[*RTListener]bool{}
	for _, lr := range tr.lrec {
		hostOK[lr.l], seen[lr.l] = lr.hostOK, true
	}
	for _, l := range t.Listeners {
		tl := TraceListener{Listener: l.Key, Port: l.L.Port, Protocol: l.L.Protocol, Hostname: l.Host}
		switch {
		case l == chosen:
			tl.Verdict = "chosen"
			tl.Reason = fmt.Sprintf("hostname %s matches %q", hostLabel(l.Host), host)
			if len(tr.lrec) > 1 {
				tl.Reason += ", and it is the most specific of the listeners that match"
			}
		case !l.Serving:
			tl.Verdict, tl.Reason = "rejected", "not serving: "+l.notServing()
		case l.L.Port != port:
			tl.Verdict, tl.Reason = "rejected", fmt.Sprintf("listens on port %d, the request is for port %d", l.L.Port, port)
		case !seen[l]:
			tl.Verdict, tl.Reason = "rejected", "not considered"
		case !hostOK[l]:
			tl.Verdict, tl.Reason = "rejected", fmt.Sprintf("host mismatch: listener hostname %s does not match %q", hostLabel(l.Host), host)
		default:
			tl.Verdict = "lost"
			tl.Reason = fmt.Sprintf("hostname %s matches, but listener %s has a more specific hostname %s (exact beats wildcard beats none)", hostLabel(l.Host), chosenKey(chosen), hostLabel(chosenHost(chosen)))
		}
		tr.Listeners = append(tr.Listeners, tl)
	}
}

func hostLabel(h string) string {
	if h == "" {
		return "(any)"
	}
	return strconv.Quote(h)
}

func chosenKey(l *RTListener) string {
	if l == nil {
		return "(none)"
	}
	return l.Key
}

func chosenHost(l *RTListener) string {
	if l == nil {
		return ""
	}
	return l.Host
}

// fillRoutes records, for every route of the table, whether it attached to the
// chosen listener and why not when it did not.
func (tr *Trace) fillRoutes(t *Table, l *RTListener, passthrough bool) {
	attached := map[*Route]bool{}
	for _, e := range l.Entries {
		attached[e.Route] = true
	}
	tlsAttached := map[string]bool{}
	for _, e := range l.TLSEntries {
		tlsAttached[e.RouteKey] = true
	}
	for _, e := range l.L4Entries {
		tlsAttached[e.RouteKey] = true
	}
	gateways := map[string]*Gateway{}
	for _, g := range t.Cfg.Gateways {
		gateways[g.Key()] = g
	}
	for _, rr := range t.routes {
		r := rr.Route
		kind := r.Kind
		if kind == "" {
			kind = "HTTPRoute"
		}
		tro := TraceRoute{Route: r.StatusKey(), Kind: kind}
		if !r.Created.IsZero() {
			tro.Created = fmtTime(r.Created)
		}
		if attached[r] || tlsAttached[r.StatusKey()] {
			tro.Attached, tro.Reason = true, "attached to listener "+l.Key
		} else {
			tro.Reason = whyNotAttached(t, rr, kind, l, gateways)
		}
		tr.Routes = append(tr.Routes, tro)
	}
}

func whyNotAttached(t *Table, rr *routeResult, kind string, l *RTListener, gateways map[string]*Gateway) string {
	r := rr.Route
	if len(rr.Parents) == 0 {
		return "the route has no parentRefs"
	}
	var reasons []string
	for _, pr := range rr.Parents {
		if !pr.Accepted.OK && (pr.Accepted.Reason == "UnsupportedValue" || pr.Accepted.Reason == "NoMatchingParent") {
			reasons = append(reasons, pr.Accepted.Reason+": "+pr.Accepted.Message)
			continue
		}
		ns := pr.Ref.Namespace
		if ns == "" {
			ns = r.NS
		}
		gw := gateways[ns+"/"+pr.Ref.Name]
		if gw == nil {
			reasons = append(reasons, fmt.Sprintf("Gateway %s/%s not found", ns, pr.Ref.Name))
			continue
		}
		_, fit, why := t.parentFit(kind, r.NS, pr.Ref, gw, r.Hostnames, l)
		if fit != fitOK {
			reasons = append(reasons, why)
		}
	}
	if len(reasons) == 0 {
		return "not attached"
	}
	return strings.Join(reasons, "; ")
}

// fillCandidates turns the recorded entries into the candidate list.
func (tr *Trace) fillCandidates(l *RTListener, winner *Entry) {
	var wrec *entryRec
	for i := range tr.erec {
		if tr.erec[i].e == winner {
			wrec = &tr.erec[i]
		}
	}
	matchIdx := map[*CRule]int{}
	for _, rec := range tr.erec {
		e := rec.e
		matchIdx[e.Rule]++
		kind := e.Route.Kind
		if kind == "" {
			kind = "HTTPRoute"
		}
		c := TraceCandidate{Route: e.Route.StatusKey(), Kind: kind, Rule: e.Rule.Index + 1, Match: matchIdx[e.Rule], Summary: e.Match.summary(), Hosts: e.Hosts}
		switch {
		case !rec.ok:
			c.Verdict, c.Reason = "rejected", rec.reason
		case e == winner:
			c.Verdict, c.Reason = "winner", "matches and ranks highest under the Gateway API precedence rules"
			if n := tr.matching(); n == 1 {
				c.Reason = "the only rule that matches"
			}
		default:
			c.Verdict = "lost"
			c.Reason = "matches, but " + whyLost(winner, e, wrec.s, rec.s)
		}
		tr.Candidates = append(tr.Candidates, c)
	}
}

func (tr *Trace) matching() int {
	n := 0
	for _, r := range tr.erec {
		if r.ok {
			n++
		}
	}
	return n
}

func (tr *Trace) noRouteReason(l *RTListener, host string) string {
	if len(l.Entries) == 0 && len(l.TLSEntries) == 0 {
		return fmt.Sprintf("no route is attached to listener %s; the gateway answers 404 (see the routes below for why each was not attached)", l.Key)
	}
	return fmt.Sprintf("none of the %d rule match(es) on listener %s accepted the request; the gateway answers 404", len(tr.erec), l.Key)
}

// explainTLS routes a passthrough connection by SNI.
func (tr *Trace) explainTLS(t *Table, l *RTListener, host string, now time.Time) {
	e := l.selectTLST(host, tr)
	idx := map[string]int{}
	for _, rec := range tr.trec {
		idx[rec.e.RouteKey]++
		c := TraceCandidate{Route: rec.e.RouteKey, Kind: "TLSRoute", Rule: idx[rec.e.RouteKey], Match: 1, Summary: "SNI " + hostList(rec.e.Hosts), Hosts: rec.e.Hosts}
		switch {
		case !rec.matched:
			c.Verdict, c.Reason = "rejected", fmt.Sprintf("host mismatch: server name %q does not match route hostnames %s", host, hostList(rec.e.Hosts))
		case rec.e == e:
			c.Verdict, c.Reason = "winner", "server name matches with "+rankName(rec.rank)+", the most specific"
		default:
			c.Verdict, c.Reason = "lost", "matches with "+rankName(rec.rank)+", but a more specific hostname matches (exact beats wildcard); on a tie the oldest route, then the first rule wins"
		}
		tr.Candidates = append(tr.Candidates, c)
	}
	if e == nil {
		tr.Verdict, tr.Reason = VerdictNoRoute, fmt.Sprintf("no TLSRoute on listener %s matches server name %q; the connection is closed", l.Key, host)
		return
	}
	w := &TraceWinner{Route: e.RouteKey, Kind: "TLSRoute", Rule: idx[e.RouteKey], Match: 1, Summary: "SNI " + hostList(e.Hosts), Passthru: true}
	for i, c := range tr.Candidates {
		if c.Verdict == "winner" {
			w.Rule = tr.Candidates[i].Rule
		}
	}
	var defs []BackendRef
	for _, tl := range t.Cfg.TLSRoutes {
		if (&Route{Kind: "TLSRoute", NS: tl.NS, Name: tl.Name}).StatusKey() == e.RouteKey && w.Rule-1 < len(tl.Rules) {
			defs = tl.Rules[w.Rule-1].BackendRefs
		}
	}
	w.Backends = t.distribution(tr.Request, "TLSRoute", e.RouteKey, e.Refs, e.Total, defs, nil, now, nil)
	tr.Winner = w
	tr.finishBackends(w)
}

func (tr *Trace) finishBackends(w *TraceWinner) {
	usable := false
	for _, b := range w.Backends {
		if b.Status == "ok" {
			usable = true
		}
	}
	switch {
	case w.Direct != nil:
		tr.Verdict = VerdictDirect
		tr.Reason = fmt.Sprintf("rule %d of %s answers with a fixed %d response; no backend is contacted", w.Rule, w.Route, w.Direct.Status)
	case w.Redirect != nil:
		tr.Verdict = VerdictRedirect
		tr.Reason = fmt.Sprintf("rule %d of %s answers with a %d redirect to %s", w.Rule, w.Route, w.Redirect.Status, w.Redirect.Location)
	case !usable:
		tr.Verdict = VerdictNoBackend
		tr.Reason = fmt.Sprintf("rule %d of %s won, but it has no backend that can take traffic (weights are 0 or no backend resolved); the gateway answers 500", w.Rule, w.Route)
	default:
		tr.Verdict = VerdictRouted
		tr.Reason = fmt.Sprintf("rule %d of %s won", w.Rule, w.Route)
	}
}

// explainWinner describes filters, backends and the final upstream request.
func (tr *Trace) explainWinner(t *Table, pg *PortGroup, e *Entry, r *http.Request, now time.Time) {
	rule := e.Rule
	kind := e.Route.Kind
	if kind == "" {
		kind = "HTTPRoute"
	}
	w := &TraceWinner{Route: e.Route.StatusKey(), Kind: kind, Rule: rule.Index + 1, Summary: e.Match.summary(), Timeout: durLabel(rule.Timeout)}
	for _, c := range tr.Candidates {
		if c.Verdict == "winner" {
			w.Match = c.Match
		}
	}
	for _, f := range rule.Rule.Filters {
		w.Filters = append(w.Filters, describeFilter("rule", f, e.Match, r, pg.TLS))
	}
	tr.Winner = w
	tr.explainPolicy(w, e, tr.Request, r)
	if !e.GRPC {
		w.Faults = tr.Request.Server.describeFaults(t, rule, now)
	}
	if rule.Redirect != nil {
		code := rule.Redirect.StatusCode
		if code == 0 {
			code = http.StatusFound
		}
		w.Redirect = &TraceRedirect{Status: code, Location: redirectURL(r, rule.Redirect, e.Match, pg.TLS)}
		tr.explainExtras(w, e, r)
		tr.finishBackends(w)
		return
	}
	if d := rule.Direct; d != nil {
		w.Direct = &TraceDirect{Status: d.Status, Body: d.Body, Headers: respHeadersFor(r, rule.Rule.Filters)}
		if w.Direct.Headers == nil && len(d.Headers) > 0 {
			w.Direct.Headers = map[string]string{}
		}
		for k, v := range d.Headers {
			w.Direct.Headers[http.CanonicalHeaderKey(k)] = v
		}
		tr.explainExtras(w, e, r)
		tr.finishBackends(w)
		return
	}
	if rule.AI != nil {
		tr.Verdict, tr.Reason = VerdictRouted, fmt.Sprintf("rule %d of %s won: an AI route", w.Rule, w.Route)
		if len(w.AI.Providers) == 0 || w.AI.Primary == "" {
			tr.Verdict, tr.Reason = VerdictNoBackend, fmt.Sprintf("rule %d of %s won, but %s", w.Rule, w.Route, w.AI.Why)
		}
		return
	}
	defs := t.refDefs(e)
	w.Backends = t.distribution(tr.Request, kind, w.Route, rule.Refs, rule.Total, defs, e, now, r)
	for _, b := range rule.Refs {
		for _, f := range b.Filters {
			w.Filters = append(w.Filters, describeFilter("backendRef "+b.Name, f, e.Match, r, pg.TLS))
		}
	}
	for i := range w.Backends {
		if w.Backends[i].Status == "ok" || w.Backends[i].Status == "unavailable" {
			w.Backends[i].Request = upstreamRequest(tr.Request, r, e, rule.Refs[i], w.Backends[i].Endpoints, pg.TLS, tr.chosen.Key, tr.claims())
		}
	}
	tr.explainExtras(w, e, r)
	tr.finishBackends(w)
}

func durLabel(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

// refDefs finds the BackendRef declarations of the winning rule (CRef does not
// keep the namespace and port needed to explain an unresolved reference).
func (t *Table) refDefs(e *Entry) []BackendRef {
	idx := e.Rule.Index
	if !e.GRPC {
		if idx < len(e.Route.Rules) {
			return e.Route.Rules[idx].BackendRefs
		}
		return nil
	}
	for _, g := range t.Cfg.GRPCRoutes {
		if g.stub().StatusKey() == e.Route.StatusKey() && idx < len(g.Rules) {
			return g.Rules[idx].BackendRefs
		}
	}
	return nil
}

// distribution mirrors Server.pickRef: weight-0 refs never get traffic, and
// when health is known, backends without a usable endpoint drop out and the
// remaining weights renormalise.
func (t *Table) distribution(q ExplainRequest, kind, routeKey string, refs []*CRef, total int, defs []BackendRef, e *Entry, now time.Time, r *http.Request) []TraceBackend {
	routeNS := ""
	if parts := strings.Split(routeKey, "/"); len(parts) >= 2 {
		routeNS = parts[len(parts)-2]
	}
	out := make([]TraceBackend, len(refs))
	live := func(c *CRef) bool { return c.B == nil || !q.Live || c.B.available(now) }
	sum := 0
	for _, c := range refs {
		if live(c) {
			sum += c.Weight
		}
	}
	all := sum == 0
	if all {
		sum = total
	}
	for i, c := range refs {
		tb := TraceBackend{Name: c.Name, Weight: c.Weight, Status: "ok"}
		if c.B != nil {
			tb.Key = c.B.Key
			tb.Endpoints = c.B.endpointStates(now, q.Live)
		}
		switch {
		case c.Weight == 0:
			tb.Status, tb.Reason = "excluded", "weight 0: this backendRef never receives traffic"
		case !all && !live(c):
			tb.Status, tb.Reason = "excluded", "every endpoint is unhealthy or ejected, so its share goes to the other backends"
		default:
			if sum > 0 {
				tb.Percent = float64(c.Weight) * 100 / float64(sum)
			}
			if c.B == nil {
				tb.Status = "unresolved"
				tb.Reason = "the backend does not resolve; requests drawn for it get a 500"
				if i < len(defs) {
					if _, f := t.backendFor(kind, routeNS, defs[i]); !f.OK {
						tb.Reason = f.Reason + ": " + f.Message + "; requests drawn for it get a 500"
					}
				}
			} else if all && !live(c) {
				tb.Status, tb.Reason = "unavailable", "no endpoint is healthy; the gateway still attempts it because no backend is"
			}
		}
		out[i] = tb
	}
	return out
}

// endpointStates reports each endpoint. With live false the health is not
// known (a static config), and every endpoint is "unknown".
func (b *Backend) endpointStates(now time.Time, live bool) []TraceEndpoint {
	b.hmu.Lock()
	defer b.hmu.Unlock()
	out := make([]TraceEndpoint, len(b.Eps))
	for i, ep := range b.Eps {
		st := "unknown"
		if live {
			switch {
			case !ep.healthy.Load():
				st = "unhealthy"
			case now.Before(ep.st.until):
				st = "ejected"
			default:
				st = "up"
			}
		}
		out[i] = TraceEndpoint{URL: ep.URL.String(), State: st}
	}
	return out
}

// describeFilter says what a filter does to this request.
func describeFilter(scope string, f Filter, m *CMatch, r *http.Request, tlsPort bool) TraceFilter {
	tf := TraceFilter{Scope: scope, Type: f.Type}
	switch {
	case f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil:
		tf.Effect = describeHeaderMod(f.RequestHeaderModifier) + " on the request"
	case f.Type == "ResponseHeaderModifier" && f.ResponseHeaderModifier != nil:
		tf.Effect = describeHeaderMod(f.ResponseHeaderModifier) + " on the response"
	case f.Type == "URLRewrite" && f.URLRewrite != nil:
		var parts []string
		if f.URLRewrite.Hostname != "" {
			parts = append(parts, "Host becomes "+f.URLRewrite.Hostname)
		}
		if p := f.URLRewrite.Path; p != nil {
			np := rewritePath(r.URL.Path, p, m)
			parts = append(parts, fmt.Sprintf("path %s becomes %s (%s)", r.URL.Path, np, p.Type))
		}
		tf.Effect = strings.Join(parts, ", ")
	case f.Type == "RequestRedirect" && f.RequestRedirect != nil:
		code := f.RequestRedirect.StatusCode
		if code == 0 {
			code = http.StatusFound
		}
		tf.Effect = fmt.Sprintf("answer %d with Location %s", code, redirectURL(r, f.RequestRedirect, m, tlsPort))
	case f.Type == "RequestMirror" && f.RequestMirror != nil:
		tf.Effect = "mirror a copy to " + f.RequestMirror.BackendRef.Name
	case f.Type == "CORS" && f.CORS != nil:
		tf.Effect = describeCORS(f.CORS)
	case f.Type == "ExternalAuth" && f.ExternalAuth != nil:
		tf.Effect = f.ExternalAuth.describe()
	}
	if tf.Effect == "" {
		tf.Effect = "no effect"
	}
	return tf
}

func describeHeaderMod(h *HeaderMod) string {
	var parts []string
	for _, nv := range h.Set {
		parts = append(parts, "set "+nv.Name+": "+nv.Value)
	}
	for _, nv := range h.Add {
		parts = append(parts, "add "+nv.Name+": "+nv.Value)
	}
	for _, n := range h.Remove {
		parts = append(parts, "remove "+n)
	}
	if len(parts) == 0 {
		return "no header changes"
	}
	return strings.Join(parts, ", ")
}

// upstreamRequest applies the winning rule's filters and the backendRef's own
// filters to the request, through the same shapeUpstream the proxy runs, and
// returns what the backend would receive.
func upstreamRequest(q ExplainRequest, in *http.Request, e *Entry, ref *CRef, eps []TraceEndpoint, tlsPort bool, listener string, claims map[string]any) *TraceUpstream {
	out := &http.Request{Method: in.Method, URL: &url.URL{}, Header: in.Header.Clone()}
	if out.Header == nil {
		out.Header = http.Header{}
	}
	stripHopHeaders(out.Header) // httputil.ReverseProxy does this before Rewrite
	out.URL.RawQuery = in.URL.RawQuery
	in = in.WithContext(context.WithValue(in.Context(), authCtxKey{}, authPreview{}))
	reqID := in.Header.Get(RequestIDHeader)
	if !validRequestID(reqID) {
		reqID = "<generated>"
	}
	shapeUpstream(out, in, remoteIP(in), tlsPort, requestFilters(e.Rule, ref), e.Match, e.GRPC, reqID, listener, claims)
	if !e.GRPC {
		previewTrace(out, in.Header)
	}
	target := "<endpoint>"
	if ref.B != nil && len(ref.B.Eps) > 0 {
		u := ref.B.Eps[0].URL
		target = u.Scheme + "://" + u.Host
		if len(ref.B.Eps) > 1 {
			target = u.Scheme + "://<one of " + strconv.Itoa(len(ref.B.Eps)) + " endpoints>"
		}
	}
	u := target + out.URL.EscapedPath()
	if out.URL.RawQuery != "" {
		u += "?" + redactQuery(out.URL.RawQuery)
	}
	hdr := map[string]string{}
	for k, v := range redactedHeaders(out.Header) {
		hdr[k] = strings.Join(v, ",")
	}
	return &TraceUpstream{Method: out.Method, URL: u, Host: out.Host, Headers: hdr}
}

// ---- admin endpoint ----

// handleWhy serves /why?method=&url=&header=...&grpc=&sni=&client= : the same JSON
// trace "setura why" prints, without sending any traffic.
func (s *Server) handleWhy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		plain(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	t := s.Table()
	if t == nil {
		plain(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	q := r.URL.Query()
	req, err := ParseExplainRequest(q.Get("method"), q.Get("url"), q["header"], q.Get("grpc"), q.Get("sni"))
	if err != nil {
		plain(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Live, req.Now = true, s.res.now()
	req.Remote, req.Server = strings.TrimSpace(q.Get("client")), s.liveServerPolicy()
	tr := Explain(t, req)
	w.Header().Set("Content-Type", "application/json")
	writeIndented(w, tr)
}

func writeIndented(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
