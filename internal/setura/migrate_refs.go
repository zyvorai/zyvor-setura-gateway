package setura

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- GRPCRoute matches ---------------------------------------------------

// hdrMatch is one header match of a route match.
type hdrMatch struct{ Name, Value, Type string }

func (h hdrMatch) String() string {
	if h.Type == "RegularExpression" {
		return h.Name + "~" + h.Value
	}
	return h.Name + "=" + h.Value
}

// headerMatches reads the header matches of one HTTPRoute or GRPCRoute match,
// as "name=value" (Exact) or "name~regex" strings, sorted.
func headerMatches(m any) []string {
	var out []string
	for _, h := range asList(dig(m, "headers")) {
		hm := asMap(h)
		out = append(out, hdrMatch{Name: asStr(hm["name"]), Value: asStr(hm["value"]), Type: str(hm, "type", "Exact")}.String())
	}
	sort.Strings(out)
	return out
}

// expectedGRPCHeaders is what the Ingress implies for header matches. A plain
// Ingress path never matches on headers; a canary Ingress with
// canary-by-header does. Values are "name=value", "name~regex" or, when the
// annotation sets no value, "name" (any value).
func expectedGRPCHeaders(ir *ingressRule) []string {
	ann := ir.Annotations
	if !strings.EqualFold(ann[nginxPrefix+"canary"], "true") {
		return nil
	}
	name := ann[nginxPrefix+"canary-by-header"]
	if name == "" {
		return nil
	}
	switch {
	case ann[nginxPrefix+"canary-by-header-value"] != "":
		return []string{name + "=" + ann[nginxPrefix+"canary-by-header-value"]}
	case ann[nginxPrefix+"canary-by-header-pattern"] != "":
		return []string{name + "~" + ann[nginxPrefix+"canary-by-header-pattern"]}
	}
	return []string{name}
}

func headerNameOf(m string) string {
	if i := strings.IndexAny(m, "=~"); i >= 0 {
		return strings.ToLower(m[:i])
	}
	return strings.ToLower(m)
}

// lowerName lowercases the header name of a "name=value" or "name~regex" match.
func lowerName(m string) string {
	if i := strings.IndexAny(m, "=~"); i >= 0 {
		return strings.ToLower(m[:i]) + m[i:]
	}
	return strings.ToLower(m)
}

// grpcMatchDiffs compares the method and header matches an Ingress rule
// implies with those of a GRPCRoute rule whose service/method path already
// agrees.
func grpcMatchDiffs(ir *ingressRule, rr *routeRule) []string {
	var diffs []string
	switch {
	case ir.Regex && rr.Type != "RegularExpression":
		diffs = append(diffs, "Ingress uses regular expressions but the GRPCRoute method match is not RegularExpression")
	case !ir.Regex && rr.Type == "RegularExpression":
		diffs = append(diffs, "Ingress path is a literal gRPC service/method but the GRPCRoute method match is a RegularExpression")
	}
	want := expectedGRPCHeaders(ir)
	have := map[string]string{}
	for _, h := range rr.Headers {
		have[headerNameOf(h)] = h
	}
	seen := map[string]bool{}
	for _, w := range want {
		n := headerNameOf(w)
		seen[n] = true
		h, ok := have[n]
		switch {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("Ingress canary-by-header expects a GRPCRoute header match %s, the matching rule has none", w))
		case strings.ContainsAny(w, "=~") && lowerName(h) != lowerName(w): // a value or pattern was given and differs
			diffs = append(diffs, fmt.Sprintf("GRPCRoute header match %s differs from the Ingress canary header %s", h, w))
		}
	}
	for _, h := range rr.Headers {
		if !seen[headerNameOf(h)] {
			diffs = append(diffs, fmt.Sprintf("GRPCRoute rule requires header match %s that the Ingress rule does not; requests without it would not be routed here", h))
		}
	}
	return diffs
}

// grpcMethodPath splits an Ingress or route path into a gRPC service and
// method. kind is "method" for /pkg.Service/Method, "service" for /pkg.Service
// and "" for anything else.
func grpcMethodPath(path string) (service, method, kind string) {
	p := strings.Trim(path, "/")
	if p == "" || !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.ContainsAny(p, "*^$()[]{}+?|\\ ") {
		return "", "", ""
	}
	parts := strings.Split(p, "/")
	switch len(parts) {
	case 1:
		return parts[0], "", "service"
	case 2:
		if parts[1] != "" {
			return parts[0], parts[1], "method"
		}
	}
	return "", "", ""
}

// ---- backends: Services, endpoints, ExternalName ---------------------------

func portOf(svc *migService, port int) *svcPort {
	for i := range svc.Ports {
		if svc.Ports[i].Port == port {
			return &svc.Ports[i]
		}
	}
	return nil
}

func (p *svcPort) target() string {
	if p.TargetPort != "" {
		return p.TargetPort
	}
	return strconv.Itoa(p.Port)
}

func portList(svc *migService) string {
	var have []string
	for _, p := range svc.Ports {
		have = append(have, fmt.Sprintf("%s=%d", p.Name, p.Port))
	}
	return strings.Join(have, ", ")
}

// targetPortDiff explains, for a named Ingress port whose number differs from
// the route backend's, which targetPort each side ends up at.
func targetPortDiff(ir *ingressRule, rr *routeRule) string {
	if ir.svc == nil || !ir.PortIsName {
		return ""
	}
	var parts []string
	for _, b := range rr.Backends {
		if b.Name != ir.Svc || !sameNS(b.NS, ir.NS) {
			continue
		}
		bp := portOf(ir.svc, b.Port)
		switch {
		case bp == nil:
			parts = append(parts, fmt.Sprintf("port %d is not a port of Service %s (ports: %s)", b.Port, ir.Svc, portList(ir.svc)))
		case ir.port != nil:
			parts = append(parts, fmt.Sprintf("Ingress port %s reaches targetPort %s, %s port %d reaches targetPort %s", ir.Port, ir.port.target(), rr.Kind, b.Port, bp.target()))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

type epPort struct {
	Ready, NotReady int
	Targets         map[int]bool
}

type epEntry struct {
	NS, Name string
	Ports    map[string]*epPort
}

// epIndex holds what EndpointSlice and Endpoints objects say per Service.
type epIndex struct {
	have    bool
	entries []*epEntry
}

func (x *epIndex) find(ns, name string) *epEntry {
	if x == nil {
		return nil
	}
	for _, e := range x.entries {
		if e.Name == name && sameNS(e.NS, ns) {
			return e
		}
	}
	return nil
}

func (x *epIndex) entry(ns, name string) *epEntry {
	if e := x.find(ns, name); e != nil && e.NS == ns {
		return e
	}
	e := &epEntry{NS: ns, Name: name, Ports: map[string]*epPort{}}
	x.entries = append(x.entries, e)
	return e
}

func (e *epEntry) port(name string) *epPort {
	if p := e.Ports[name]; p != nil {
		return p
	}
	p := &epPort{Targets: map[int]bool{}}
	e.Ports[name] = p
	return p
}

// extractEndpoints indexes EndpointSlice (by the kubernetes.io/service-name
// label) and Endpoints objects.
func extractEndpoints(objs []obj, have bool) *epIndex {
	x := &epIndex{have: have}
	for _, o := range objs {
		name, ns := metaOf(o)
		switch asStr(o["kind"]) {
		case "EndpointSlice":
			svc := annotationLabel(o, "kubernetes.io/service-name")
			if svc == "" {
				continue
			}
			e := x.entry(ns, svc)
			ready, notReady := 0, 0
			for _, ep := range asList(o["endpoints"]) {
				if c, ok := dig(ep, "conditions", "ready").(bool); ok && !c {
					notReady++
				} else {
					ready++
				}
			}
			for _, p := range asList(o["ports"]) {
				pm := asMap(p)
				ep := e.port(asStr(pm["name"]))
				ep.Ready += ready
				ep.NotReady += notReady
				if n, ok := num(pm["port"]); ok {
					ep.Targets[int(n)] = true
				}
			}
		case "Endpoints":
			e := x.entry(ns, name)
			for _, s := range asList(o["subsets"]) {
				sm := asMap(s)
				for _, p := range asList(sm["ports"]) {
					pm := asMap(p)
					ep := e.port(asStr(pm["name"]))
					ep.Ready += len(asList(sm["addresses"]))
					ep.NotReady += len(asList(sm["notReadyAddresses"]))
					if n, ok := num(pm["port"]); ok {
						ep.Targets[int(n)] = true
					}
				}
			}
		}
	}
	return x
}

func annotationLabel(o obj, key string) string {
	return asStr(dig(o, "metadata", "labels", key))
}

// describeExternalName says where an ExternalName Service points, resolving
// in-cluster names (name.namespace.svc[.cluster.local]) against loaded Services.
func describeExternalName(svc *migService, svcs []migService) string {
	host := strings.TrimSuffix(svc.ExternalName, ".")
	msg := fmt.Sprintf("backend Service %s is an ExternalName Service pointing at %s", svc.Name, host)
	if host == "" {
		return msg[:len(msg)-len(" pointing at ")] + " with no externalName"
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 3 && parts[2] == "svc" {
		if t := findService(svcs, parts[1], parts[0]); t != nil && t.NS == parts[1] {
			msg += fmt.Sprintf(" (the in-cluster Service %s/%s, %s", t.NS, t.Name, portsOrType(t))
			return msg + "); it has no endpoints of its own to inspect"
		}
		msg += fmt.Sprintf(" (an in-cluster name; Service %s/%s is not among the loaded Services)", parts[1], parts[0])
	}
	return msg + "; it has no endpoints to inspect, and ExternalName backends are implementation-specific in Gateway API"
}

func portsOrType(t *migService) string {
	if t.Type == "ExternalName" {
		return "itself an ExternalName Service"
	}
	if len(t.Ports) == 0 {
		return "no ports"
	}
	return "ports " + portList(t)
}

// inspectBackend records facts about the Service behind a rule: ExternalName
// targets and, for named ports, whether the port's endpoints are ready.
func (r *ingressRule) inspectBackend(svcs []migService, eps *epIndex) {
	if r.Resource {
		return
	}
	svc := findService(svcs, r.NS, r.Svc)
	if svc == nil {
		return
	}
	r.svc = svc
	if svc.Type == "ExternalName" {
		r.info = append(r.info, describeExternalName(svc, svcs))
		return
	}
	if !r.PortIsName || r.resolvedPort == "" {
		return
	}
	for i := range svc.Ports {
		if svc.Ports[i].Name == r.Port {
			r.port = &svc.Ports[i]
		}
	}
	if r.port == nil || eps == nil || !eps.have {
		return
	}
	label := fmt.Sprintf("named port %q (Service port %d, targetPort %s)", r.Port, r.port.Port, r.port.target())
	e := eps.find(r.NS, r.Svc)
	if e == nil {
		r.epWarn = append(r.epWarn, label+" has no ready endpoints: no EndpointSlice or Endpoints found for Service "+r.Svc)
		return
	}
	ep := e.Ports[r.Port]
	if ep == nil {
		var names []string
		for n := range e.Ports {
			names = append(names, strconv.Quote(n))
		}
		sort.Strings(names)
		r.epWarn = append(r.epWarn, fmt.Sprintf("%s has no ready endpoints: the endpoints of Service %s list no port with that name (they list %s)", label, r.Svc, strings.Join(names, ", ")))
		return
	}
	if ep.Ready == 0 {
		r.epWarn = append(r.epWarn, fmt.Sprintf("%s has no ready endpoints (%d not ready)", label, ep.NotReady))
		return
	}
	if n, err := strconv.Atoi(r.port.target()); err == nil && len(ep.Targets) > 0 && !ep.Targets[n] {
		var got []string
		for t := range ep.Targets {
			got = append(got, strconv.Itoa(t))
		}
		sort.Strings(got)
		r.epWarn = append(r.epWarn, fmt.Sprintf("%s: the endpoints serve port %s, not the Service targetPort", label, strings.Join(got, ", ")))
	}
}

// ---- IngressClass default ------------------------------------------------

// defaultIngressClass returns the name of the IngressClass annotated with
// ingressclass.kubernetes.io/is-default-class: "true", or "". With several
// defaults the first by name is used and a note says so.
func defaultIngressClass(classes []obj, notes *[]string) string {
	var defaults []string
	for _, c := range classes {
		if n, _ := metaOf(c); n != "" && annotationsOf(c)["ingressclass.kubernetes.io/is-default-class"] == "true" {
			defaults = append(defaults, n)
		}
	}
	sort.Strings(defaults)
	switch len(defaults) {
	case 0:
		return ""
	case 1:
		return defaults[0]
	}
	if notes != nil {
		*notes = append(*notes, fmt.Sprintf("several IngressClasses are marked default (%s); Ingresses without a class are attributed to %s, but controllers may ignore them", strings.Join(defaults, ", "), defaults[0]))
	}
	return defaults[0]
}

// ---- ReferenceGrants -----------------------------------------------------

const gatewayGroup = "gateway.networking.k8s.io"

// grantFinding is a cross-namespace reference that no ReferenceGrant allows.
type grantFinding struct {
	Status    string `json:"status"`
	Namespace string `json:"namespace"` // where the grant has to live (the target's namespace)
	From      string `json:"from"`
	To        string `json:"to"`
	Fix       string `json:"fix"` // the ReferenceGrant that allows the reference
}

type xref struct {
	FromGroup, FromKind, FromNS, FromName string
	ToGroup, ToKind, ToNS, ToName         string
}

func (x xref) from() string { return x.FromKind + " " + x.FromNS + "/" + x.FromName }
func (x xref) to() string   { return x.ToKind + " " + x.ToNS + "/" + x.ToName }

// crossRefs lists the cross-namespace backendRefs of route rules and
// certificateRefs of Gateway listeners.
func crossRefs(rules []*routeRule, ls []migListener) []xref {
	seen := map[xref]bool{}
	var out []xref
	add := func(x xref) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	for _, rr := range rules {
		if rr.other {
			continue
		}
		for _, b := range rr.Backends {
			if b.NS != "" && rr.NS != "" && b.NS != rr.NS {
				add(xref{gatewayGroup, rr.Kind, rr.NS, rr.Route, b.Group, b.Kind, b.NS, b.Name})
			}
		}
	}
	for _, l := range ls {
		for _, c := range l.CertRefs {
			if c.NS != "" && l.NS != "" && c.NS != l.NS {
				add(xref{gatewayGroup, "Gateway", l.NS, l.Gateway, c.Group, c.Kind, c.NS, c.Name})
			}
		}
	}
	return out
}

// grantTargetNamespaces lists the namespaces whose ReferenceGrants matter for
// the given route and Gateway objects.
func grantTargetNamespaces(routes, gateways []obj) []string {
	var rules []*routeRule
	for _, rt := range routes {
		rules = append(rules, extractRouteRules(rt)...)
	}
	var ls []migListener
	for _, gw := range gateways {
		ls = append(ls, extractListeners(gw)...)
	}
	set := map[string]bool{}
	for _, x := range crossRefs(rules, ls) {
		set[x.ToNS] = true
	}
	return sortedKeys(set)
}

type grantSpec struct {
	NS   string
	From []xref
	To   []xref
}

func parseGrants(objs []obj) []grantSpec {
	var out []grantSpec
	for _, o := range objs {
		if !kindOf(o, "ReferenceGrant") {
			continue
		}
		_, ns := metaOf(o)
		g := grantSpec{NS: ns}
		for _, f := range asList(dig(o, "spec", "from")) {
			fm := asMap(f)
			g.From = append(g.From, xref{FromGroup: asStr(fm["group"]), FromKind: asStr(fm["kind"]), FromNS: asStr(fm["namespace"])})
		}
		for _, t := range asList(dig(o, "spec", "to")) {
			tm := asMap(t)
			g.To = append(g.To, xref{ToGroup: asStr(tm["group"]), ToKind: asStr(tm["kind"]), ToName: asStr(tm["name"])})
		}
		out = append(out, g)
	}
	return out
}

func (g grantSpec) allows(x xref) bool {
	if g.NS != x.ToNS {
		return false
	}
	from, to := false, false
	for _, f := range g.From {
		from = from || f.FromGroup == x.FromGroup && f.FromKind == x.FromKind && f.FromNS == x.FromNS
	}
	for _, t := range g.To {
		to = to || t.ToGroup == x.ToGroup && t.ToKind == x.ToKind && (t.ToName == "" || t.ToName == x.ToName)
	}
	return from && to
}

func grantName(x xref) string {
	n := strings.ToLower(fmt.Sprintf("allow-%s-%s-%s-to-%s", x.FromKind, x.FromNS, x.FromName, x.ToName))
	n = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, n)
	if len(n) > 63 {
		n = strings.TrimRight(n[:63], "-.")
	}
	return n
}

func (x xref) grantYAML() string {
	q := func(s string) string {
		if s == "" {
			return `""`
		}
		return s
	}
	return fmt.Sprintf(`apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: %s
  namespace: %s
spec:
  from:
  - group: %s
    kind: %s
    namespace: %s
  to:
  - group: %s
    kind: %s
    name: %s
`, grantName(x), x.ToNS, q(x.FromGroup), x.FromKind, x.FromNS, q(x.ToGroup), x.ToKind, x.ToName)
}

// checkReferenceGrants returns one finding per cross-namespace reference that
// no available ReferenceGrant allows. References into namespaces whose grants
// were not available are not reported, only counted in a note.
func checkReferenceGrants(rules []*routeRule, ls []migListener, in migrateInput, notes *[]string) []grantFinding {
	refs := crossRefs(rules, ls)
	if len(refs) == 0 {
		return nil
	}
	grants := parseGrants(in.Grants)
	var out []grantFinding
	unknown := map[string]bool{}
	for _, x := range refs {
		if !in.GrantsAll && !in.GrantNS[x.ToNS] {
			unknown[x.ToNS] = true
			continue
		}
		ok := false
		for _, g := range grants {
			ok = ok || g.allows(x)
		}
		if !ok {
			out = append(out, grantFinding{Status: "missing", Namespace: x.ToNS, From: x.from(), To: x.to(), Fix: x.grantYAML()})
		}
	}
	if len(unknown) > 0 {
		*notes = append(*notes, fmt.Sprintf("cross-namespace references into %s were not checked: no ReferenceGrants available for them (pass --objects FILE or read from the cluster)", strings.Join(sortedKeys(unknown), ", ")))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

// ---- live gRPC probe -----------------------------------------------------

var grpcCodeNames = []string{"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
	"PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL",
	"UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"}

func grpcCodeName(c int) string {
	if c >= 0 && c < len(grpcCodeNames) {
		return fmt.Sprintf("%d %s", c, grpcCodeNames[c])
	}
	return strconv.Itoa(c)
}

const (
	grpcUnimplemented = 12
	grpcUnavailable   = 14
)

// grpcEmptyFrame is a gRPC message frame holding an empty protobuf message:
// uncompressed flag 0 and a zero length.
const grpcEmptyFrame = "\x00\x00\x00\x00\x00"

// observeGRPC makes one unary call with an empty message to /service/method
// over HTTP/2 (TLS with ALPN h2 for https, prior-knowledge h2c for http).
func (lo *liveOptions) observeGRPC(t *liveTarget, host, path string) *probeObs {
	raw := t.urlFor(host, path)
	obs := &probeObs{URL: raw}
	u, err := url.Parse(raw)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	addr := t.address
	if addr == "" {
		addr = u.Hostname()
	}
	timeout := time.Duration(lo.timeout * float64(time.Second))
	var protos http.Protocols
	cfg := &tls.Config{ServerName: u.Hostname()}
	if u.Scheme == "https" {
		protos.SetHTTP2(true)
		if lo.ca != "" {
			pem, err := os.ReadFile(lo.ca)
			if err != nil {
				obs.Error = err.Error()
				return obs
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				obs.Error = "no certificates found in " + lo.ca
				return obs
			}
			cfg.RootCAs = pool
		}
	} else {
		protos.SetUnencryptedHTTP2(true)
	}
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Protocols:       &protos,
		TLSClientConfig: cfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, net.JoinHostPort(addr, port))
		},
		ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(grpcEmptyFrame))
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", "zyvor-setura")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	defer resp.Body.Close()
	obs.Status = resp.StatusCode
	obs.Backend = strings.Join(resp.Header.Values("X-Setura-Backend"), ", ")
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)); err != nil {
		obs.Error = err.Error()
		return obs
	}
	// Trailers are populated once the body is read; a trailers-only response
	// carries grpc-status in the headers.
	gs, gm := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if gs == "" {
		gs, gm = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if gs != "" {
		code, err := strconv.Atoi(gs)
		if err != nil {
			obs.Error = fmt.Sprintf("invalid grpc-status %q", gs)
			return obs
		}
		obs.GRPCStatus, obs.GRPCMessage = &code, gm
	}
	return obs
}

// diffGRPC probes /service/method through both targets and compares the
// results. notes holds observations that are not differences.
func (lo *liveOptions) diffGRPC(host, path string) (pd *probeDiff, notes []string) {
	pd = &probeDiff{Ingress: lo.observeGRPC(lo.ingress, host, path), Gateway: lo.observeGRPC(lo.gateway, host, path)}
	a, b := pd.Ingress, pd.Gateway
	if a.Error != "" || b.Error != "" {
		if a.Error != "" {
			pd.Diffs = append(pd.Diffs, "ingress probe failed: "+a.Error)
		}
		if b.Error != "" {
			pd.Diffs = append(pd.Diffs, "gateway probe failed: "+b.Error)
		}
		return pd, nil
	}
	pd.Diffs, notes = compareGRPC(a, b)
	return pd, notes
}

// compareGRPC compares two gRPC probe observations. An empty message is a
// poor request, so INVALID_ARGUMENT, OK or UNKNOWN are all "reached a
// backend"; what matters is whether both sides route the method (UNIMPLEMENTED
// and UNAVAILABLE mean no route or no backend) and whether they answer alike.
func compareGRPC(a, b *probeObs) (diffs, notes []string) {
	if a.Status != b.Status {
		diffs = append(diffs, fmt.Sprintf("HTTP status %d via Ingress, %d via Gateway", a.Status, b.Status))
	}
	switch {
	case a.GRPCStatus == nil && b.GRPCStatus == nil:
		if a.Status == b.Status {
			notes = append(notes, fmt.Sprintf("neither target answered with a grpc-status (HTTP %d); the call is not served as gRPC on either side", a.Status))
		}
	case a.GRPCStatus == nil || b.GRPCStatus == nil:
		diffs = append(diffs, fmt.Sprintf("grpc-status %s via Ingress, %s via Gateway", grpcStatusText(a), grpcStatusText(b)))
	default:
		x, y := *a.GRPCStatus, *b.GRPCStatus
		switch {
		case x == y && x == grpcUnimplemented:
			notes = append(notes, "both targets answer UNIMPLEMENTED: the method is not routed or not served on either side, so the probe cannot tell the two apart")
		case x == y:
		case (x == grpcUnimplemented) != (y == grpcUnimplemented):
			diffs = append(diffs, fmt.Sprintf("method answered grpc-status %s via Ingress but %s via Gateway (UNIMPLEMENTED means the route or method is not served there)", grpcCodeName(x), grpcCodeName(y)))
		case x == grpcUnavailable || y == grpcUnavailable:
			diffs = append(diffs, fmt.Sprintf("grpc-status %s via Ingress, %s via Gateway (UNAVAILABLE means no reachable backend)", grpcCodeName(x), grpcCodeName(y)))
		default:
			diffs = append(diffs, fmt.Sprintf("both targets reached a backend but answered differently: grpc-status %s via Ingress, %s via Gateway", grpcCodeName(x), grpcCodeName(y)))
		}
	}
	if a.Backend != b.Backend {
		diffs = append(diffs, fmt.Sprintf("backend identity %q via Ingress, %q via Gateway", a.Backend, b.Backend))
	}
	return diffs, notes
}

func grpcStatusText(o *probeObs) string {
	if o.GRPCStatus == nil {
		return "none"
	}
	return grpcCodeName(*o.GRPCStatus)
}

// probeGRPCRule probes one gRPC rule and records the outcome on the result.
func (lo *liveOptions) probeGRPCRule(r *ruleResult, regex bool) {
	_, _, kind := grpcMethodPath(r.Path)
	switch {
	case regex || regexMeta(r.Path, `()*+?[]{}\^$|`):
		r.Details = append(r.Details, "live probe skipped: path looks like a regular expression")
		return
	case kind != "method":
		r.Details = append(r.Details, "live probe skipped: the path is not a /service/method (a service prefix cannot be called without choosing a method)")
		return
	}
	pd, notes := lo.diffGRPC(r.Host, r.Path)
	r.Probe = pd
	for _, n := range notes {
		r.Details = append(r.Details, "live: "+n)
	}
	lo.record(r)
}
