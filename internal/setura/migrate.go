package setura

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Rule statuses reported by `setura migrate check`.
const (
	statusEquivalent = "equivalent"
	statusDifferent  = "different"
	statusMissing    = "missing-in-gateway"
	statusExtra      = "extra-in-gateway"
	// statusUnresolved: everything that could be compared agrees, but a named
	// Ingress backend port could not be resolved against a Service.
	statusUnresolved = "unresolved"
)

// Route kinds an Ingress rule can convert to.
const (
	kindHTTPRoute = "HTTPRoute"
	kindGRPCRoute = "GRPCRoute"
	kindTLSRoute  = "TLSRoute"
)

// ingressRule is one (host, path, backend) triple of an Ingress.
type ingressRule struct {
	Ingress, NS   string
	Host, Path    string
	PathType      string // Exact, Prefix or ImplementationSpecific
	Svc, Port     string // Port is a number or a port name
	PortIsName    bool
	TLS           bool
	TLSSecret     string
	Default       bool   // spec.defaultBackend
	Resource      bool   // backend.resource instead of a Service
	Regex         bool   // nginx use-regex
	Class         string // ingress class (spec.ingressClassName or the legacy annotation)
	Kind          string // route kind this rule converts to
	Passthrough   bool   // nginx ssl-passthrough
	Annotations   map[string]string
	expectedRoute string
	// Named port resolution against the Service.
	resolvedPort string // port number a named port maps to
	unresolved   string // why a named port could not be resolved
	badPort      string // the Service has no port with that name
	// Backend inspection (see migrate_refs.go).
	svc          *migService
	port         *svcPort // the Service port a named port resolved to
	info         []string // facts about the backend worth showing (ExternalName, ...)
	epWarn       []string // the backend cannot serve traffic as far as the endpoints show
	classDefault bool     // Class comes from the default IngressClass
}

// svcPort is one port of a Service. TargetPort is the raw spec value (a
// number or a container port name); empty means "same as Port".
type svcPort struct {
	Name       string
	Port       int
	TargetPort string
}

type migParent struct{ NS, Name, Section string }

type routeBackend struct {
	Name, NS    string
	Port        int
	Weight      int
	Group, Kind string // empty group and kind Service by default
}

// routeRule is one (hostname, path match) pair of an HTTPRoute rule.
type routeRule struct {
	Route, NS string
	Host      string
	Path      string
	Type      string // Exact, PathPrefix or RegularExpression
	Backends  []routeBackend
	Filters   map[string]bool
	Redirect  string // description of a RequestRedirect filter
	Parents   []migParent
	Kind      string   // HTTPRoute, GRPCRoute or TLSRoute
	Headers   []string // header matches of the match this rule came from, "name=value" or "name~regex"
	matched   bool
	other     bool // belongs to an Ingress of another class
}

type migListener struct {
	Gateway, NS, Name, Protocol, Hostname string
	TLSMode                               string
	CertRefs                              []migCert
}

// ruleResult is one reported line.
type ruleResult struct {
	Status        string     `json:"status"`
	Ingress       string     `json:"ingress,omitempty"`
	Route         string     `json:"route,omitempty"`
	ExpectedRoute string     `json:"expected_route,omitempty"`
	Host          string     `json:"host"`
	Path          string     `json:"path"`
	PathType      string     `json:"path_type"`
	Backend       string     `json:"backend,omitempty"`
	IngressClass  string     `json:"ingress_class,omitempty"`
	ClassDefault  bool       `json:"ingress_class_default,omitempty"`
	Kind          string     `json:"kind,omitempty"`
	RouteKind     string     `json:"route_kind,omitempty"`
	TLS           bool       `json:"tls,omitempty"`
	Details       []string   `json:"details,omitempty"`
	Probe         *probeDiff `json:"probe,omitempty"`
	ingress       *ingressRule
	extra         *routeRule // set for extra-in-gateway results
}

// probeObs is what one live probe saw.
type probeObs struct {
	URL      string            `json:"url"`
	Status   int               `json:"status,omitempty"`
	Location string            `json:"redirect,omitempty"`
	Backend  string            `json:"backend,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Error    string            `json:"error,omitempty"`
	// gRPC probes: the grpc-status of the call and its message.
	GRPCStatus  *int   `json:"grpc_status,omitempty"`
	GRPCMessage string `json:"grpc_message,omitempty"`
}

type probeDiff struct {
	Ingress *probeObs `json:"ingress"`
	Gateway *probeObs `json:"gateway"`
	Diffs   []string  `json:"differences,omitempty"`
}

type migrateReport struct {
	OK          bool                `json:"ok"`
	Summary     map[string]int      `json:"summary"`
	Rules       []*ruleResult       `json:"rules"`
	Annotations []annotationFinding `json:"annotations"`
	Grants      []grantFinding      `json:"reference_grants,omitempty"`
	Notes       []string            `json:"notes,omitempty"`
}

// ---- reading -------------------------------------------------------------

// loadManifestObjects reads YAML or JSON from a file or a directory and
// returns every Kubernetes object in it, expanding List kinds.
func loadManifestObjects(path string) ([]obj, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				switch strings.ToLower(filepath.Ext(p)) {
				case ".yaml", ".yml", ".json":
					files = append(files, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	var out []obj
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		docs, err := decodeManifests(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, d := range docs {
			out = append(out, flattenList(d)...)
		}
	}
	return out, nil
}

func flattenList(v any) []obj {
	if items, ok := v.([]any); ok {
		var out []obj
		for _, it := range items {
			out = append(out, flattenList(it)...)
		}
		return out
	}
	m := asMap(v)
	if m == nil {
		return nil
	}
	if items := asList(m["items"]); items != nil && strings.HasSuffix(asStr(m["kind"]), "List") {
		var out []obj
		for _, it := range items {
			out = append(out, flattenList(it)...)
		}
		return out
	}
	return []obj{m}
}

func itemsOf(o obj) []obj {
	var out []obj
	for _, it := range asList(o["items"]) {
		if m := asMap(it); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func kindOf(o obj, kind string) bool { return asStr(o["kind"]) == kind }

// ---- normalising ---------------------------------------------------------

func metaOf(o obj) (name, ns string) {
	return asStr(dig(o, "metadata", "name")), asStr(dig(o, "metadata", "namespace"))
}

// nameFromHost mirrors ingress2gateway's route naming.
func nameFromHost(host string) string {
	if host == "" {
		return "all-hosts"
	}
	h := strings.ReplaceAll(host, "*", "wildcard")
	return strings.ToLower(strings.ReplaceAll(h, ".", "-"))
}

// ingress2gatewayName is the route name ingress2gateway generates for a host.
func ingress2gatewayName(ingress, host string) string {
	return ingress + "-" + nameFromHost(host)
}

func portString(p obj) (string, bool) {
	if n, ok := num(p["number"]); ok {
		return strconv.Itoa(int(n)), false
	}
	return asStr(p["name"]), true
}

// ingressClassOf returns the class an Ingress selects: spec.ingressClassName,
// or the legacy kubernetes.io/ingress.class annotation.
func ingressClassOf(ing obj) string {
	if c := asStr(dig(ing, "spec", "ingressClassName")); c != "" {
		return c
	}
	return annotationsOf(ing)["kubernetes.io/ingress.class"]
}

// routeKindFor picks the route kind an Ingress converts to: TLS passthrough
// becomes a TLSRoute (nginx ignores the backend protocol then), a GRPC or
// GRPCS backend protocol a GRPCRoute, everything else an HTTPRoute.
func routeKindFor(ann map[string]string) (kind string, passthrough bool) {
	if strings.EqualFold(ann[nginxPrefix+"ssl-passthrough"], "true") {
		return kindTLSRoute, true
	}
	switch strings.ToUpper(ann[nginxPrefix+"backend-protocol"]) {
	case "GRPC", "GRPCS":
		return kindGRPCRoute, false
	}
	return kindHTTPRoute, false
}

func extractIngressRules(ing obj, notes *[]string) []*ingressRule {
	name, ns := metaOf(ing)
	ann := annotationsOf(ing)
	regex := strings.EqualFold(ann[nginxPrefix+"use-regex"], "true")
	class := ingressClassOf(ing)
	kind, passthrough := routeKindFor(ann)
	tlsHosts := map[string]string{}
	for _, t := range asList(dig(ing, "spec", "tls")) {
		tm := asMap(t)
		hosts := asList(tm["hosts"])
		if len(hosts) == 0 {
			tlsHosts[""] = asStr(tm["secretName"])
		}
		for _, h := range hosts {
			tlsHosts[strings.ToLower(asStr(h))] = asStr(tm["secretName"])
		}
	}
	newRule := func(host, path, pt string, backend obj) *ingressRule {
		r := &ingressRule{Ingress: name, NS: ns, Host: strings.ToLower(host), Path: path, PathType: pt, Regex: regex,
			Annotations: ann, Class: class, Kind: kind, Passthrough: passthrough}
		if secret, ok := tlsHosts[r.Host]; ok {
			r.TLS, r.TLSSecret = true, secret
		}
		if svc := asMap(backend["service"]); svc != nil {
			r.Svc = asStr(svc["name"])
			r.Port, r.PortIsName = portString(asMap(svc["port"]))
		} else {
			r.Resource = true
		}
		r.expectedRoute = ingress2gatewayName(name, r.Host)
		return r
	}
	var out []*ingressRule
	if db := asMap(dig(ing, "spec", "defaultBackend")); db != nil {
		r := newRule("", "/", "Prefix", db)
		r.Default = true
		out = append(out, r)
	}
	for _, rl := range asList(dig(ing, "spec", "rules")) {
		rm := asMap(rl)
		for _, p := range asList(dig(rm, "http", "paths")) {
			pm := asMap(p)
			path := str(pm, "path", "/")
			pt := str(pm, "pathType", "ImplementationSpecific")
			out = append(out, newRule(asStr(rm["host"]), path, pt, asMap(pm["backend"])))
		}
	}
	return out
}

// extractServices reads the ports of Service objects.
func extractServices(objs []obj) []migService {
	var out []migService
	for _, o := range objs {
		if !kindOf(o, "Service") {
			continue
		}
		name, ns := metaOf(o)
		s := migService{NS: ns, Name: name, Type: str(asMap(o["spec"]), "type", "ClusterIP"), ExternalName: asStr(dig(o, "spec", "externalName"))}
		for _, p := range asList(dig(o, "spec", "ports")) {
			pm := asMap(p)
			n, _ := num(pm["port"])
			sp := svcPort{Name: asStr(pm["name"]), Port: int(n)}
			switch tp := pm["targetPort"].(type) {
			case string:
				sp.TargetPort = tp
			case float64:
				sp.TargetPort = strconv.Itoa(int(tp))
			}
			s.Ports = append(s.Ports, sp)
		}
		out = append(out, s)
	}
	return out
}

type migService struct {
	NS, Name     string
	Ports        []svcPort
	Type         string // ClusterIP, ExternalName, ...
	ExternalName string
}

func findService(svcs []migService, ns, name string) *migService {
	for i := range svcs {
		if svcs[i].Name == name && sameNS(svcs[i].NS, ns) {
			return &svcs[i]
		}
	}
	return nil
}

// resolvePort maps a named Ingress backend port to the Service port number.
// svcs == nil means no Service source was available at all.
func (r *ingressRule) resolvePort(svcs []migService, available bool) {
	if !r.PortIsName || r.Resource {
		return
	}
	svc := findService(svcs, r.NS, r.Svc)
	switch {
	case svc == nil && available:
		r.unresolved = fmt.Sprintf("named port %q unresolved: Service %s/%s was not found in the loaded Services", r.Port, r.NS, r.Svc)
	case svc == nil:
		r.unresolved = fmt.Sprintf("named port %q unresolved: no Service objects available (pass --services FILE or read from the cluster)", r.Port)
	default:
		var have []string
		for _, p := range svc.Ports {
			if p.Name == r.Port {
				r.resolvedPort = strconv.Itoa(p.Port)
				return
			}
			have = append(have, fmt.Sprintf("%s=%d", p.Name, p.Port))
		}
		if svc.Type == "ExternalName" && len(svc.Ports) == 0 {
			r.unresolved = fmt.Sprintf("named port %q unresolved: Service %s is an ExternalName Service (%s) and defines no ports", r.Port, r.Svc, svc.ExternalName)
			return
		}
		r.badPort = fmt.Sprintf("Service %s has no port named %q (ports: %s)", r.Svc, r.Port, strings.Join(have, ", "))
	}
}

func parentsOf(rt obj, ns string) []migParent {
	var out []migParent
	for _, p := range asList(dig(rt, "spec", "parentRefs")) {
		pm := asMap(p)
		out = append(out, migParent{NS: str(pm, "namespace", ns), Name: asStr(pm["name"]), Section: asStr(pm["sectionName"])})
	}
	return out
}

func extractRouteRules(rt obj) []*routeRule {
	name, ns := metaOf(rt)
	kind := asStr(rt["kind"])
	parents := parentsOf(rt, ns)
	hosts := []string{""}
	if hs := asList(dig(rt, "spec", "hostnames")); len(hs) > 0 {
		hosts = nil
		for _, h := range hs {
			hosts = append(hosts, strings.ToLower(asStr(h)))
		}
	}
	var out []*routeRule
	for _, rl := range asList(dig(rt, "spec", "rules")) {
		rm := asMap(rl)
		var backends []routeBackend
		filters := map[string]bool{}
		redirect := ""
		addFilters := func(list []any) {
			for _, f := range list {
				fm := asMap(f)
				t := asStr(fm["type"])
				filters[t] = true
				if t == "RequestRedirect" {
					rr := asMap(fm["requestRedirect"])
					redirect = "redirect"
					if s := asStr(rr["scheme"]); s != "" {
						redirect += " to " + s
					}
					if c, ok := num(rr["statusCode"]); ok {
						redirect += " " + strconv.Itoa(int(c))
					}
				}
			}
		}
		addFilters(asList(rm["filters"]))
		for _, b := range asList(rm["backendRefs"]) {
			bm := asMap(b)
			port, _ := num(bm["port"])
			w, ok := num(bm["weight"])
			if !ok {
				w = 1
			}
			backends = append(backends, routeBackend{Name: asStr(bm["name"]), NS: str(bm, "namespace", ns), Port: int(port), Weight: int(w),
				Group: asStr(bm["group"]), Kind: str(bm, "kind", "Service")})
			addFilters(asList(bm["filters"]))
		}
		var hdrs []string
		add := func(path, typ string) {
			for _, h := range hosts {
				out = append(out, &routeRule{Route: name, NS: ns, Host: h, Path: path, Type: typ,
					Backends: backends, Filters: filters, Redirect: redirect, Parents: parents, Kind: kind, Headers: hdrs})
			}
		}
		switch kind {
		case kindTLSRoute:
			add("", "TLS")
		case kindGRPCRoute:
			matches := asList(rm["matches"])
			if len(matches) == 0 {
				add("/", "GRPCMethod")
			}
			for _, m := range matches {
				hdrs = headerMatches(m)
				method := asMap(dig(m, "method"))
				path, typ := "/", "GRPCMethod"
				if svc := asStr(method["service"]); svc != "" {
					path = "/" + svc
					if mt := asStr(method["method"]); mt != "" {
						path += "/" + mt
					}
				} else if mt := asStr(method["method"]); mt != "" {
					path = "/*/" + mt
				}
				if asStr(method["type"]) == "RegularExpression" {
					typ = "RegularExpression"
				}
				add(path, typ)
			}
		default:
			matches := asList(rm["matches"])
			if len(matches) == 0 {
				matches = []any{obj{}}
			}
			for _, m := range matches {
				path := asMap(dig(m, "path"))
				add(str(path, "value", "/"), str(path, "type", "PathPrefix"))
			}
		}
	}
	return out
}

func extractListeners(gw obj) []migListener {
	name, ns := metaOf(gw)
	var out []migListener
	for _, l := range asList(dig(gw, "spec", "listeners")) {
		lm := asMap(l)
		ml := migListener{Gateway: name, NS: ns, Name: asStr(lm["name"]), Protocol: asStr(lm["protocol"]), Hostname: strings.ToLower(asStr(lm["hostname"])),
			TLSMode: str(asMap(lm["tls"]), "mode", "Terminate")}
		for _, c := range asList(dig(lm, "tls", "certificateRefs")) {
			cm := asMap(c)
			ml.CertRefs = append(ml.CertRefs, migCert{NS: asStr(cm["namespace"]), Name: asStr(cm["name"]), Group: asStr(cm["group"]), Kind: str(cm, "kind", "Secret")})
		}
		out = append(out, ml)
	}
	return out
}

type migCert struct{ NS, Name, Group, Kind string }

// ---- comparing -----------------------------------------------------------

func normPath(p string, regex bool) string {
	if regex {
		return p
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

func sameNS(a, b string) bool { return a == "" || b == "" || a == b }

func hostCovers(listener, host string) bool {
	if listener == "" || listener == host {
		return true
	}
	if strings.HasPrefix(listener, "*.") {
		return strings.HasSuffix(host, listener[1:]) && host != listener[2:]
	}
	return false
}

// effectivePort is the port number an Ingress backend means, or "" when a
// named port could not be resolved.
func (r *ingressRule) effectivePort() string {
	if r.PortIsName {
		return r.resolvedPort
	}
	return r.Port
}

func (r *ingressRule) backendString() string {
	switch {
	case r.Resource:
		return "resource"
	case r.PortIsName && r.resolvedPort != "":
		return r.Svc + ":" + r.Port + "(" + r.resolvedPort + ")"
	}
	return r.Svc + ":" + r.Port
}

func wantedType(r *ingressRule) string {
	switch {
	case r.Regex:
		return "RegularExpression"
	case r.PathType == "Exact":
		return "Exact"
	}
	return "PathPrefix"
}

func (r *ingressRule) kindReason() string {
	switch r.Kind {
	case kindTLSRoute:
		return "ssl-passthrough"
	case kindGRPCRoute:
		return "backend-protocol " + strings.ToUpper(r.Annotations[nginxPrefix+"backend-protocol"])
	}
	return "default"
}

// migCtx is what rule comparison needs besides the two rules.
type migCtx struct {
	listeners []migListener
	haveGW    bool
}

// listenersFor returns the listeners of the parent Gateways of a route rule
// (narrowed by sectionName) and whether any parent Gateway was loaded.
func (c *migCtx) listenersFor(rr *routeRule) (sel []migListener, found bool) {
	for _, p := range rr.Parents {
		for _, l := range c.listeners {
			if l.Gateway != p.Name || !sameNS(l.NS, p.NS) {
				continue
			}
			found = true
			if p.Section == "" || p.Section == l.Name {
				sel = append(sel, l)
			}
		}
	}
	return sel, found
}

func certNames(l migListener) string {
	var n []string
	for _, c := range l.CertRefs {
		n = append(n, c.Name)
	}
	if len(n) == 0 {
		return "none"
	}
	return strings.Join(n, ", ")
}

// diffRule lists how a route rule differs from an Ingress rule. unres lists
// parts that could not be verified.
func diffRule(ir *ingressRule, rr *routeRule, ctx *migCtx) (diffs, notes, unres []string) {
	if rr.Kind != ir.Kind {
		diffs = append(diffs, fmt.Sprintf("Ingress rule converts to a %s (%s) but the matching rule is in a %s", ir.Kind, ir.kindReason(), rr.Kind))
	} else {
		switch ir.Kind {
		case kindHTTPRoute:
			if want := wantedType(ir); rr.Type != want {
				diffs = append(diffs, fmt.Sprintf("path type %s in Ingress, %s in HTTPRoute", ir.PathType, rr.Type))
			}
		case kindGRPCRoute:
			diffs = append(diffs, grpcMatchDiffs(ir, rr)...)
		}
	}
	switch {
	case ir.Resource:
		diffs = append(diffs, "Ingress backend is a resource reference, which has no direct "+ir.Kind+" equivalent")
	default:
		found, nameOnly := false, false
		for _, b := range rr.Backends {
			if b.Name != ir.Svc || !sameNS(b.NS, ir.NS) {
				continue
			}
			switch {
			case ir.PortIsName && ir.resolvedPort == "":
				found = true // port unknown or invalid; reported below
			case strconv.Itoa(b.Port) == ir.effectivePort():
				found = true
			default:
				nameOnly = true
			}
			if found {
				break
			}
		}
		if ir.PortIsName && ir.unresolved != "" {
			unres = append(unres, ir.unresolved)
		}
		unres = append(unres, ir.epWarn...)
		if ir.badPort != "" {
			diffs = append(diffs, ir.badPort)
		}
		if !found {
			var have []string
			for _, b := range rr.Backends {
				have = append(have, b.Name+":"+strconv.Itoa(b.Port))
			}
			switch {
			case nameOnly:
				diffs = append(diffs, fmt.Sprintf("backend port differs: Ingress %s, %s %s", ir.backendString(), rr.Kind, strings.Join(have, ", "))+targetPortDiff(ir, rr))
			case rr.Redirect != "" && len(have) == 0:
				diffs = append(diffs, rr.Kind+" rule does "+rr.Redirect+" instead of forwarding to "+ir.backendString())
			default:
				diffs = append(diffs, fmt.Sprintf("backend differs: Ingress %s, %s %s", ir.backendString(), rr.Kind, strings.Join(have, ", ")))
			}
		}
	}
	if !ctx.haveGW || (!ir.TLS && !ir.Passthrough) {
		return diffs, notes, unres
	}
	sel, found := ctx.listenersFor(rr)
	if !found {
		return diffs, append(notes, "parent Gateway not found in the loaded objects; TLS not verified"), unres
	}
	if ir.Passthrough {
		covered := false
		for _, l := range sel {
			if l.Protocol == "TLS" && l.TLSMode == "Passthrough" && hostCovers(l.Hostname, ir.Host) {
				covered = true
			}
		}
		if !covered {
			diffs = append(diffs, "Ingress passes TLS through for this host but no TLS listener with tls.mode Passthrough of the parent Gateway covers it")
		}
		return diffs, notes, unres
	}
	var covering []migListener
	for _, l := range sel {
		if (l.Protocol == "HTTPS" || l.Protocol == "TLS") && l.TLSMode != "Passthrough" && hostCovers(l.Hostname, ir.Host) {
			covering = append(covering, l)
		}
	}
	switch {
	case len(covering) == 0:
		diffs = append(diffs, "Ingress terminates TLS for this host but no HTTPS listener of the parent Gateway covers it")
	case ir.TLSSecret == "":
		notes = append(notes, "Ingress tls has no secretName (controller default certificate); listener certificate not compared")
	default:
		match := false
		var have []string
		for _, l := range covering {
			have = append(have, l.Name+": "+certNames(l))
			for _, c := range l.CertRefs {
				if c.Name == ir.TLSSecret && sameNS(c.NS, ir.NS) {
					match = true
				}
			}
		}
		if !match {
			diffs = append(diffs, fmt.Sprintf("TLS secret %q in Ingress is not in the certificateRefs of the covering listener (%s)", ir.TLSSecret, strings.Join(have, "; ")))
		}
	}
	return diffs, notes, unres
}

// migrateInput is everything compareMigration reads.
type migrateInput struct {
	Ingresses, Routes, Gateways []obj
	HaveGW                      bool
	Services                    []migService
	HaveServices                bool  // a Service source was available (even if it held no match)
	OtherIngresses              []obj // Ingresses of other classes: their routes are not reported as extra
	Classes                     []obj // IngressClass objects, for the default class
	Endpoints                   []obj // EndpointSlice and Endpoints objects
	HaveEndpoints               bool
	Grants                      []obj // ReferenceGrant objects
	GrantsAll                   bool  // Grants is complete for every namespace
	GrantNS                     map[string]bool
}

func compareMigration(in migrateInput) *migrateReport {
	rep := &migrateReport{Summary: map[string]int{}, Rules: []*ruleResult{}, Annotations: []annotationFinding{}}
	var iRules []*ingressRule
	var ingNames []string
	annotationsByIng := map[string]map[string]string{}
	apiOK := func(ing obj) bool {
		if v := asStr(ing["apiVersion"]); v != "" && v != "networking.k8s.io/v1" {
			n, _ := metaOf(ing)
			rep.Notes = append(rep.Notes, fmt.Sprintf("skipped Ingress %s: apiVersion %s is not networking.k8s.io/v1", n, v))
			return false
		}
		return true
	}
	for _, ing := range in.Ingresses {
		if !apiOK(ing) {
			continue
		}
		rs := extractIngressRules(ing, &rep.Notes)
		name, ns := metaOf(ing)
		key := ns + "/" + name
		ingNames = append(ingNames, key)
		annotationsByIng[key] = annotationsOf(ing)
		iRules = append(iRules, rs...)
	}
	defaultClass := defaultIngressClass(in.Classes, &rep.Notes)
	eps := extractEndpoints(in.Endpoints, in.HaveEndpoints)
	namedPorts := false
	for _, ir := range iRules {
		if ir.Class == "" && defaultClass != "" {
			ir.Class, ir.classDefault = defaultClass, true
		}
		ir.resolvePort(in.Services, in.HaveServices)
		ir.inspectBackend(in.Services, eps)
		namedPorts = namedPorts || ir.PortIsName
	}
	if namedPorts && !in.HaveEndpoints {
		rep.Notes = append(rep.Notes, "endpoints were not inspected for named ports: no EndpointSlice or Endpoints objects were available (pass --objects FILE or read from the cluster)")
	}
	var rRules []*routeRule
	for _, rt := range in.Routes {
		rRules = append(rRules, extractRouteRules(rt)...)
	}
	var listeners []migListener
	for _, gw := range in.Gateways {
		listeners = append(listeners, extractListeners(gw)...)
	}
	ctx := &migCtx{listeners: listeners, haveGW: in.HaveGW}
	needTLS := false
	for _, r := range iRules {
		needTLS = needTLS || r.TLS || r.Passthrough
	}
	if !in.HaveGW && needTLS {
		rep.Notes = append(rep.Notes, "TLS was not verified: no Gateway objects were loaded")
	}

	candidate := func(ir *ingressRule, rr *routeRule) bool {
		if !sameNS(rr.NS, ir.NS) || rr.Host != ir.Host {
			return false
		}
		if rr.Kind == kindTLSRoute || ir.Kind == kindTLSRoute {
			return rr.Kind == ir.Kind // SNI routing has no path
		}
		return normPath(rr.Path, ir.Regex) == normPath(ir.Path, ir.Regex)
	}

	matchedBy := map[string][]*routeRule{} // ingress key -> matched route rules
	for _, ir := range iRules {
		res := &ruleResult{Ingress: ir.Ingress, ExpectedRoute: ir.expectedRoute, Host: ir.Host, Path: ir.Path, PathType: ir.PathType,
			Backend: ir.backendString(), IngressClass: ir.Class, ClassDefault: ir.classDefault, Kind: ir.Kind, TLS: ir.TLS || ir.Passthrough, ingress: ir}
		if ir.classDefault {
			res.Details = append(res.Details, fmt.Sprintf("no ingress class set: %q is the default IngressClass", ir.Class))
		}
		res.Details = append(res.Details, ir.info...)
		if ir.Default {
			res.Details = append(res.Details, "default backend")
		}
		if ir.Kind == kindHTTPRoute && ir.PathType == "ImplementationSpecific" {
			res.Details = append(res.Details, "pathType ImplementationSpecific is compared as a prefix match")
		}
		if ir.Kind == kindTLSRoute {
			res.Details = append(res.Details, "TLS passthrough routes on SNI only; the Ingress path is not compared")
		}
		var best *routeRule
		var bestDiffs, bestNotes, bestUnres []string
		for _, rr := range rRules {
			if !candidate(ir, rr) {
				continue
			}
			d, n, u := diffRule(ir, rr, ctx)
			better := best == nil || len(d) < len(bestDiffs) ||
				len(d) == len(bestDiffs) && rr.Route == ir.expectedRoute && best.Route != ir.expectedRoute
			if better {
				best, bestDiffs, bestNotes, bestUnres = rr, d, n, u
			}
		}
		if best == nil {
			res.Status = statusMissing
			res.Details = append(res.Details, "no "+ir.Kind+" rule matches this host"+map[bool]string{true: "", false: " and path"}[ir.Kind == kindTLSRoute])
		} else {
			best.matched = true
			matchedBy[ir.NS+"/"+ir.Ingress] = append(matchedBy[ir.NS+"/"+ir.Ingress], best)
			res.Route, res.RouteKind = best.Route, best.Kind
			res.Details = append(res.Details, bestNotes...)
			switch {
			case len(bestDiffs) > 0:
				res.Status = statusDifferent
				res.Details = append(res.Details, bestDiffs...)
				res.Details = append(res.Details, bestUnres...)
			case len(bestUnres) > 0:
				res.Status = statusUnresolved
				res.Details = append(res.Details, bestUnres...)
			default:
				res.Status = statusEquivalent
			}
			if best.Kind == kindHTTPRoute && ir.Kind == kindHTTPRoute && best.Route != ir.expectedRoute {
				res.Details = append(res.Details, fmt.Sprintf("route name %q differs from the ingress2gateway convention %q", best.Route, ir.expectedRoute))
			}
		}
		rep.Rules = append(rep.Rules, res)
	}

	// Routes that belong to Ingresses of other classes are neither matched
	// nor extra.
	otherRoutes := 0
	for _, ing := range in.OtherIngresses {
		if !apiOK(ing) {
			continue
		}
		for _, ir := range extractIngressRules(ing, &rep.Notes) {
			for _, rr := range rRules {
				if !rr.matched && candidate(ir, rr) {
					rr.matched, rr.other = true, true
					otherRoutes++
				}
			}
		}
	}
	if otherRoutes > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d route rules belong to Ingresses of other classes and are not reported", otherRoutes))
	}
	for _, rr := range rRules {
		if rr.matched {
			continue
		}
		res := &ruleResult{Status: statusExtra, Route: rr.Route, RouteKind: rr.Kind, Host: rr.Host, Path: rr.Path, PathType: rr.Type}
		var bs []string
		for _, b := range rr.Backends {
			bs = append(bs, b.Name+":"+strconv.Itoa(b.Port))
		}
		res.Backend = strings.Join(bs, ", ")
		if rr.Redirect != "" {
			res.Details = append(res.Details, rr.Redirect)
		}
		res.Details = append(res.Details, "no Ingress rule maps to this "+rr.Kind+" rule")
		rep.Rules = append(rep.Rules, res)
		res.extra = rr
	}

	rep.Grants = checkReferenceGrants(rRules, listeners, in, &rep.Notes)

	sort.Strings(ingNames)
	for _, key := range ingNames {
		filters := map[string]bool{}
		for _, rr := range matchedBy[key] {
			for f := range rr.Filters {
				filters[f] = true
			}
			filters["kind:"+rr.Kind] = true
		}
		_, name, _ := strings.Cut(key, "/")
		rep.Annotations = append(rep.Annotations, classifyAnnotations(name, annotationsByIng[key], filters)...)
	}
	rep.finish()
	return rep
}

func (r *migrateReport) finish() {
	r.Summary = map[string]int{statusEquivalent: 0, statusDifferent: 0, statusMissing: 0, statusExtra: 0, statusUnresolved: 0, "annotations_flagged": 0, "grants_missing": len(r.Grants)}
	for _, x := range r.Rules {
		r.Summary[x.Status]++
	}
	for _, a := range r.Annotations {
		if a.Flagged() {
			r.Summary["annotations_flagged"]++
		}
	}
	r.OK = r.Summary[statusDifferent]+r.Summary[statusMissing]+r.Summary[statusExtra]+r.Summary[statusUnresolved]+r.Summary["annotations_flagged"]+r.Summary["grants_missing"] == 0
}

// ---- live probing --------------------------------------------------------

type liveTarget struct {
	base    *url.URL
	address string
}

func newLiveTarget(raw, address string) (*liveTarget, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, userErrorf("expected an absolute HTTP(S) base URL, got %s", pyRepr(raw))
	}
	t := &liveTarget{base: u, address: address}
	if t.address == "" {
		if net.ParseIP(u.Hostname()) != nil {
			t.address = u.Hostname()
		} else if addrs, err := lookupIP(u.Hostname()); err == nil && len(addrs) > 0 {
			t.address = addrs[0]
		}
	}
	return t, nil
}

func (t *liveTarget) urlFor(host, path string) string {
	if host == "" {
		host = t.base.Hostname()
	}
	host = strings.ReplaceAll(host, "*", "setura-probe")
	port := t.base.Port()
	if port == "" || (t.base.Scheme == "http" && port == "80") || (t.base.Scheme == "https" && port == "443") {
		port = ""
	} else {
		host += ":" + port
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return t.base.Scheme + "://" + host + path
}

type liveOptions struct {
	ingress, gateway *liveTarget
	ca               string
	timeout          float64
	headers          []string
}

var defaultCompareHeaders = []string{"Content-Type", "Cache-Control", "Strict-Transport-Security", "Access-Control-Allow-Origin"}

func (lo *liveOptions) observe(t *liveTarget, host, path string) *probeObs {
	o := NewProbe(t.urlFor(host, path))
	o.Address, o.CA, o.Timeout = t.address, lo.ca, lo.timeout
	obs := &probeObs{URL: o.URL, Headers: map[string]string{}}
	o.capture = func(resp *http.Response) {
		obs.Location = resp.Header.Get("Location")
		obs.Backend = strings.Join(resp.Header.Values("X-Setura-Backend"), ", ")
		for _, h := range lo.headers {
			if v := resp.Header.Values(h); len(v) > 0 {
				obs.Headers[http.CanonicalHeaderKey(h)] = strings.Join(v, ", ")
			}
		}
	}
	rep, err := Probe(o)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	if st, ok := num(rep.Step("http").Get("status")); ok {
		obs.Status = int(st)
		return obs
	}
	name, step := failedStage(rep)
	obs.Error = name + ": " + stageReason(step)
	return obs
}

func (lo *liveOptions) diff(host, path string) *probeDiff {
	pd := &probeDiff{Ingress: lo.observe(lo.ingress, host, path), Gateway: lo.observe(lo.gateway, host, path)}
	a, b := pd.Ingress, pd.Gateway
	switch {
	case a.Error != "" || b.Error != "":
		if a.Error != "" {
			pd.Diffs = append(pd.Diffs, "ingress probe failed: "+a.Error)
		}
		if b.Error != "" {
			pd.Diffs = append(pd.Diffs, "gateway probe failed: "+b.Error)
		}
		return pd
	}
	if a.Status != b.Status {
		pd.Diffs = append(pd.Diffs, fmt.Sprintf("status %d via Ingress, %d via Gateway", a.Status, b.Status))
	}
	if a.Location != b.Location {
		pd.Diffs = append(pd.Diffs, fmt.Sprintf("redirect target %q via Ingress, %q via Gateway", a.Location, b.Location))
	}
	if a.Backend != b.Backend {
		pd.Diffs = append(pd.Diffs, fmt.Sprintf("backend identity %q via Ingress, %q via Gateway", a.Backend, b.Backend))
	}
	for _, h := range sortedKeys(mergeKeys(a.Headers, b.Headers)) {
		if a.Headers[h] != b.Headers[h] {
			pd.Diffs = append(pd.Diffs, fmt.Sprintf("header %s: %q via Ingress, %q via Gateway", h, a.Headers[h], b.Headers[h]))
		}
	}
	return pd
}

func mergeKeys(a, b map[string]string) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

var regexMeta = strings.ContainsAny

// apply probes every Ingress rule and, with probeExtra, the rules that exist
// only in the Gateway as well.
func (lo *liveOptions) apply(rep *migrateReport, probeExtra bool) {
	for _, r := range rep.Rules {
		var regex bool
		switch {
		case r.ingress != nil:
			regex = r.ingress.Regex
			if r.ingress.Kind == kindGRPCRoute {
				lo.probeGRPCRule(r, regex)
				continue
			}
		case r.extra != nil && probeExtra:
			regex = r.extra.Type == "RegularExpression"
			if r.extra.Kind == kindGRPCRoute {
				lo.probeGRPCRule(r, regex)
				continue
			}
		default:
			continue
		}
		path := r.Path
		if path == "" {
			path = "/"
		}
		if regex || regexMeta(path, `()*+?[]{}\^$|`) {
			r.Details = append(r.Details, "live probe skipped: path looks like a regular expression")
			continue
		}
		r.Probe = lo.diff(r.Host, path)
		lo.record(r)
	}
	rep.finish()
}

// record turns the differences of a probe into details and, for rules that
// were otherwise fine, a different status.
func (lo *liveOptions) record(r *ruleResult) {
	if len(r.Probe.Diffs) == 0 {
		return
	}
	if r.Status == statusEquivalent || r.Status == statusUnresolved {
		r.Status = statusDifferent
	}
	for _, d := range r.Probe.Diffs {
		r.Details = append(r.Details, "live: "+d)
	}
}

// ---- rendering -----------------------------------------------------------

func (u *ui) MigratePretty(rep *migrateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n\n", u.bold("setura migrate check"))
	sym := func(s string) string {
		switch s {
		case statusEquivalent:
			return u.okSym()
		case statusExtra, statusUnresolved:
			return u.warnSym()
		}
		return u.failSym()
	}
	hostW, pathW, beW, clsW := 4, 4, 7, 5
	for _, r := range rep.Rules {
		hostW = max(hostW, len([]rune(hostLabel(r.Host))))
		pathW = max(pathW, len([]rune(r.Path)))
		beW = max(beW, len([]rune(r.Backend)))
		clsW = max(clsW, len([]rune(r.IngressClass)))
	}
	fmt.Fprintf(&b, "    %s  %s  %s  %s  %s  %s\n", pad("", 1), u.gray(pad("HOST", hostW)), u.gray(pad("PATH", pathW)), u.gray(pad("BACKEND", beW)), u.gray(pad("CLASS", clsW)), u.gray("STATUS / ROUTE"))
	for _, r := range rep.Rules {
		tail := r.Status
		if r.Route != "" {
			tail += " " + u.arrow() + " " + r.Route
			if r.RouteKind != "" && r.RouteKind != kindHTTPRoute {
				tail += " (" + r.RouteKind + ")"
			}
		}
		class := r.IngressClass
		if class == "" {
			class = "-"
		}
		fmt.Fprintf(&b, "    %s  %s  %s  %s  %s  %s\n", sym(r.Status), pad(hostLabel(r.Host), hostW), pad(r.Path, pathW), pad(r.Backend, beW), pad(class, clsW), tail)
		for _, d := range r.Details {
			fmt.Fprintf(&b, "         %s\n", u.gray(d))
		}
	}
	if len(rep.Rules) == 0 {
		fmt.Fprintf(&b, "    %s no Ingress rules or HTTPRoutes found\n", u.skipSym())
	}
	var flagged []annotationFinding
	for _, a := range rep.Annotations {
		if a.Support != supportIgnored {
			flagged = append(flagged, a)
		}
	}
	if len(flagged) > 0 {
		fmt.Fprintf(&b, "\n  %s\n", u.blue("Annotations"))
		for _, a := range flagged {
			s := u.failSym()
			if a.Handled {
				s = u.okSym()
			}
			fmt.Fprintf(&b, "    %s  %s  %s  %s\n", s, a.Ingress, strings.TrimPrefix(a.Annotation, nginxPrefix), u.gray("["+a.Support+"]"))
			fmt.Fprintf(&b, "         %s\n", u.gray(a.Hint))
		}
	}
	if len(rep.Grants) > 0 {
		fmt.Fprintf(&b, "\n  %s\n", u.blue("ReferenceGrants"))
		for _, g := range rep.Grants {
			fmt.Fprintf(&b, "    %s  %s -> %s  %s\n", u.failSym(), g.From, g.To, u.gray("missing in namespace "+g.Namespace+"; this grant would allow it:"))
			for _, l := range strings.Split(strings.TrimRight(g.Fix, "\n"), "\n") {
				fmt.Fprintf(&b, "         %s\n", u.gray(l))
			}
		}
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "\n  %s %s", u.warnSym(), n)
	}
	s := rep.Summary
	verdict := u.green("equivalent")
	if !rep.OK {
		verdict = u.red("differences found")
	}
	fmt.Fprintf(&b, "\n\n  %s: %d equivalent, %d different, %d missing in Gateway, %d extra in Gateway, %d unresolved, %d annotations need attention, %d ReferenceGrants missing\n\n",
		verdict, s[statusEquivalent], s[statusDifferent], s[statusMissing], s[statusExtra], s[statusUnresolved], s["annotations_flagged"], s["grants_missing"])
	return b.String()
}

func hostLabel(h string) string {
	if h == "" {
		return "*"
	}
	return h
}

// MigrateAnnotations renders GitHub Actions workflow commands.
func MigrateAnnotations(rep *migrateReport, file string) string {
	var b strings.Builder
	for _, r := range rep.Rules {
		if r.Status == statusEquivalent {
			continue
		}
		level := "error"
		if r.Status == statusExtra || r.Status == statusUnresolved {
			level = "warning"
		}
		msg := fmt.Sprintf("%s%s: %s", hostLabel(r.Host), r.Path, r.Status)
		if len(r.Details) > 0 {
			msg += " (" + strings.Join(r.Details, "; ") + ")"
		}
		b.WriteString(annotation(level, "setura migrate "+r.Status, file, 0, msg))
	}
	for _, g := range rep.Grants {
		b.WriteString(annotation("error", "setura migrate reference grant", file, 0,
			fmt.Sprintf("%s -> %s needs a ReferenceGrant in namespace %s: from %s to %s", g.From, g.To, g.Namespace, g.From, g.To)))
	}
	for _, a := range rep.Annotations {
		if a.Flagged() {
			b.WriteString(annotation("warning", "setura migrate annotation", file, 0,
				fmt.Sprintf("%s: %s is %s: %s", a.Ingress, a.Annotation, a.Support, a.Hint)))
		}
	}
	return b.String()
}

// ---- command -------------------------------------------------------------

func runMigrate(cluster *Cluster, fs *flag.FlagSet, args []string, stdout, stderr io.Writer, u *ui, tty bool) (int, error) {
	if len(args) > 0 && args[0] == "convert" {
		return runMigrateConvert(cluster, fs, args, stdout, stderr, u, tty)
	}
	var ns string
	fs.StringVar(&ns, "n", "default", "namespace to read from the cluster")
	fs.StringVar(&ns, "namespace", "default", "namespace to read from the cluster")
	all := fs.Bool("A", false, "read all namespaces from the cluster")
	ingressPath := fs.String("ingress", "", "read Ingress objects from this YAML/JSON file or directory instead of the cluster")
	routesPath := fs.String("routes", "", "read HTTPRoutes, GRPCRoutes, TLSRoutes (and Gateways) from this YAML/JSON file or directory instead of the cluster")
	servicesPath := fs.String("services", "", "read Services (to resolve named backend ports) from this YAML/JSON file or directory; Service objects in --ingress/--routes inputs are used too")
	objectsPath := fs.String("objects", "", "read supporting objects (Services, EndpointSlices, Endpoints, ReferenceGrants, IngressClasses) from this YAML/JSON file or directory")
	ingressClass := fs.String("ingress-class", "", "only analyse Ingresses of this class (spec.ingressClassName or kubernetes.io/ingress.class); default: all")
	probeExtra := fs.Bool("probe-extra", false, "also probe routes that exist only in the Gateway, HTTP and gRPC (needs --ingress-url and --gateway-url)")
	ingressURL := fs.String("ingress-url", "", "base URL of the Ingress controller for live comparison: GET for HTTP rules, an empty unary call over h2/h2c for gRPC rules (needs --gateway-url)")
	gatewayURL := fs.String("gateway-url", "", "base URL of the Gateway data plane for live comparison (needs --ingress-url)")
	address := fs.String("address", "", "connect both live targets to this numeric IP, preserving Host and TLS identity")
	ingressAddr := fs.String("ingress-address", "", "connect the Ingress target to this numeric IP")
	gatewayAddr := fs.String("gateway-address", "", "connect the Gateway target to this numeric IP")
	ca := fs.String("ca", "", "trusted PEM CA bundle for live HTTPS probes")
	timeout := fs.Float64("timeout", 4, "per-operation timeout in seconds for live probes")
	var headers stringList
	fs.Var(&headers, "header", "response header to compare in live probes; repeatable (defaults: Content-Type, Cache-Control, Strict-Transport-Security, Access-Control-Allow-Origin)")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty, json or github (workflow annotations)")

	if len(args) > 0 && args[0] == "check" {
		args = args[1:]
	} else if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(stderr, "setura migrate: unknown subcommand %q (expected check or convert)\n", args[0])
		exampleHint(stderr, "migrate")
		return 2, usageError{"subcommand"}
	}
	pos, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	if len(pos) > 0 {
		fmt.Fprintln(stderr, "setura migrate check: takes flags only")
		exampleHint(stderr, "migrate")
		return 2, usageError{"arguments"}
	}
	fail := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura migrate check: %s\n", msg)
		exampleHint(stderr, "migrate")
		return 2, usageError{msg}
	}
	pretty := false
	if *format != "github" {
		if pretty, err = wantPretty(*format, tty); err != nil {
			return 2, err
		}
	}
	if (*ingressURL == "") != (*gatewayURL == "") {
		return fail("--ingress-url and --gateway-url must be given together")
	}
	live := *ingressURL != ""
	if !live && *probeExtra {
		return fail("--probe-extra needs --ingress-url and --gateway-url")
	}
	if !live && (*address != "" || *ingressAddr != "" || *gatewayAddr != "" || *ca != "" || len(headers) > 0) {
		return fail("--address, --ingress-address, --gateway-address, --ca and --header need --ingress-url and --gateway-url")
	}

	// Load objects.
	var ingresses, routes, gateways, services, classes, endpoints, grants []obj
	haveGW := false
	scope := []string{}
	if *all {
		scope = []string{"-A"}
	}
	list := func(resource string) ([]obj, error) {
		v, err := cluster.getMap(ns, resource, scope...)
		if err != nil {
			return nil, err
		}
		return itemsOf(v), nil
	}
	listKind := func(resource, kind string) ([]obj, error) {
		items, err := list(resource)
		var out []obj
		for _, o := range items {
			if kindOf(o, kind) {
				out = append(out, o)
			}
		}
		return out, err
	}
	var fileObjs []obj
	for _, p := range []string{*ingressPath, *routesPath, *servicesPath, *objectsPath} {
		if p == "" {
			continue
		}
		objs, err := loadManifestObjects(p)
		if err != nil {
			return 0, err
		}
		fileObjs = append(fileObjs, objs...)
	}
	for _, o := range fileObjs {
		switch {
		case kindOf(o, "Ingress"):
			ingresses = append(ingresses, o)
		case kindOf(o, "HTTPRoute"), kindOf(o, "GRPCRoute"), kindOf(o, "TLSRoute"):
			routes = append(routes, o)
		case kindOf(o, "Gateway"):
			gateways = append(gateways, o)
			haveGW = true
		case kindOf(o, "Service"):
			services = append(services, o)
		case kindOf(o, "IngressClass"):
			classes = append(classes, o)
		case kindOf(o, "EndpointSlice"), kindOf(o, "Endpoints"):
			endpoints = append(endpoints, o)
		case kindOf(o, "ReferenceGrant"):
			grants = append(grants, o)
		}
	}
	var notes []string
	anyCluster := *ingressPath == "" || *routesPath == ""
	if *ingressPath == "" {
		if ingresses, err = list("ingresses.networking.k8s.io"); err != nil {
			return 0, err
		}
		// The default IngressClass (annotation is-default-class) decides which
		// class an Ingress without one belongs to.
		if cs, cerr := listKind("ingressclasses.networking.k8s.io", "IngressClass"); cerr == nil {
			classes = append(classes, cs...)
		} else if *ingressClass != "" {
			notes = append(notes, "could not read IngressClasses (the default class is unknown): "+cerr.Error())
		}
	}
	needKind := map[string]bool{}
	needNamedPort := false
	for _, ing := range ingresses {
		if ingressClassWanted(ing, classes, *ingressClass) {
			k, _ := routeKindFor(annotationsOf(ing))
			needKind[k] = true
			for _, ir := range extractIngressRules(ing, nil) {
				needNamedPort = needNamedPort || ir.PortIsName
			}
		}
	}
	if *routesPath == "" {
		if routes, err = listKind("httproutes.gateway.networking.k8s.io", kindHTTPRoute); err != nil {
			return 0, err
		}
		if gws, gerr := listKind("gateways.gateway.networking.k8s.io", "Gateway"); gerr == nil {
			gateways, haveGW = gws, true
		} else {
			notes = append(notes, "could not read Gateways: "+gerr.Error())
		}
		for _, kr := range [][2]string{{"grpcroutes.gateway.networking.k8s.io", kindGRPCRoute}, {"tlsroutes.gateway.networking.k8s.io", kindTLSRoute}} {
			rs, rerr := listKind(kr[0], kr[1])
			routes = append(routes, rs...)
			if rerr != nil && needKind[kr[1]] {
				notes = append(notes, "could not read "+kr[1]+"s: "+rerr.Error())
			}
		}
	}
	haveSvc := len(services) > 0 || *servicesPath != ""
	if !haveSvc && anyCluster {
		if svcs, serr := listKind("services", "Service"); serr == nil {
			services, haveSvc = svcs, true
		} else {
			notes = append(notes, "could not read Services: "+serr.Error())
		}
	}
	haveEps := len(endpoints) > 0 || *objectsPath != ""
	if !haveEps && needNamedPort && anyCluster {
		es, eerr := listKind("endpointslices.discovery.k8s.io", "EndpointSlice")
		if eerr != nil {
			var oerr error
			if es, oerr = listKind("endpoints", "Endpoints"); oerr != nil {
				notes = append(notes, "could not read EndpointSlices or Endpoints: "+eerr.Error())
			} else {
				eerr = nil
			}
		}
		if eerr == nil {
			endpoints, haveEps = es, true
		}
	}
	// ReferenceGrants: from the input files when any were given, otherwise
	// from the cluster, one read per namespace a cross-namespace reference
	// points into.
	grantsAll := len(grants) > 0 || *objectsPath != ""
	grantNS := map[string]bool{}
	if !grantsAll && anyCluster {
		for _, tns := range grantTargetNamespaces(routes, gateways) {
			if list, gerr := cluster.getMap(tns, "referencegrants.gateway.networking.k8s.io"); gerr == nil {
				grants = append(grants, itemsOf(list)...)
				grantNS[tns] = true
			} else {
				notes = append(notes, "could not read ReferenceGrants in namespace "+tns+": "+gerr.Error())
			}
		}
	}
	if len(ingresses) == 0 {
		return 0, userError("no Ingress objects found; nothing to migrate")
	}
	var others []obj
	if *ingressClass != "" {
		var kept []obj
		for _, ing := range ingresses {
			if ingressClassWanted(ing, classes, *ingressClass) {
				kept = append(kept, ing)
			} else {
				others = append(others, ing)
			}
		}
		if len(kept) == 0 {
			return 0, userErrorf("no Ingress objects of class %q found (%d of other classes skipped)", *ingressClass, len(others))
		}
		if len(others) > 0 {
			notes = append(notes, fmt.Sprintf("skipped %d Ingress objects not of class %q", len(others), *ingressClass))
		}
		ingresses = kept
	}
	if *routesPath != "" && len(routes) == 0 {
		return 0, userErrorf("no HTTPRoute, GRPCRoute or TLSRoute objects found in %s", *routesPath)
	}

	rep := compareMigration(migrateInput{Ingresses: ingresses, Routes: routes, Gateways: gateways, HaveGW: haveGW,
		Services: extractServices(services), HaveServices: haveSvc, OtherIngresses: others,
		Classes: classes, Endpoints: endpoints, HaveEndpoints: haveEps, Grants: grants, GrantsAll: grantsAll, GrantNS: grantNS})
	rep.Notes = append(rep.Notes, notes...)
	if live {
		lo := &liveOptions{ca: *ca, timeout: *timeout, headers: append(append([]string{}, defaultCompareHeaders...), headers...)}
		pick := func(specific string) string {
			if specific != "" {
				return specific
			}
			return *address
		}
		if lo.ingress, err = newLiveTarget(*ingressURL, pick(*ingressAddr)); err != nil {
			return 0, err
		}
		if lo.gateway, err = newLiveTarget(*gatewayURL, pick(*gatewayAddr)); err != nil {
			return 0, err
		}
		lo.apply(rep, *probeExtra)
	}

	switch {
	case *format == "github":
		fmt.Fprint(stdout, MigrateAnnotations(rep, firstNonEmpty(*ingressPath, *routesPath)))
	case pretty:
		fmt.Fprint(stdout, u.MigratePretty(rep))
	default:
		if err := writeJSON(stdout, rep); err != nil {
			return 0, err
		}
	}
	return boolExit(!rep.OK), nil
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// ingressClassWanted reports whether an Ingress belongs to the selected class.
// An empty selection keeps everything. An Ingress without a class belongs to
// the selected class when a loaded IngressClass of that name is the default.
func ingressClassWanted(ing obj, classes []obj, want string) bool {
	if want == "" {
		return true
	}
	if c := ingressClassOf(ing); c != "" {
		return c == want
	}
	for _, c := range classes {
		if n, _ := metaOf(c); n == want && annotationsOf(c)["ingressclass.kubernetes.io/is-default-class"] == "true" {
			return true
		}
	}
	return false
}
