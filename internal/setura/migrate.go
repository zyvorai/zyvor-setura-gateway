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
	Default       bool // spec.defaultBackend
	Resource      bool // backend.resource instead of a Service
	Regex         bool // nginx use-regex
	Annotations   map[string]string
	expectedRoute string
}

type routeBackend struct {
	Name, NS string
	Port     int
	Weight   int
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
	Parents   []string
	matched   bool
}

type migListener struct {
	Gateway, NS, Name, Protocol, Hostname string
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
	TLS           bool       `json:"tls,omitempty"`
	Details       []string   `json:"details,omitempty"`
	Probe         *probeDiff `json:"probe,omitempty"`
	ingress       *ingressRule
}

// probeObs is what one live probe saw.
type probeObs struct {
	URL      string            `json:"url"`
	Status   int               `json:"status,omitempty"`
	Location string            `json:"redirect,omitempty"`
	Backend  string            `json:"backend,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Error    string            `json:"error,omitempty"`
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

func extractIngressRules(ing obj, notes *[]string) []*ingressRule {
	name, ns := metaOf(ing)
	ann := annotationsOf(ing)
	regex := strings.EqualFold(ann[nginxPrefix+"use-regex"], "true")
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
		r := &ingressRule{Ingress: name, NS: ns, Host: strings.ToLower(host), Path: path, PathType: pt, Regex: regex, Annotations: ann}
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

func extractRouteRules(rt obj) []*routeRule {
	name, ns := metaOf(rt)
	var parents []string
	for _, p := range asList(dig(rt, "spec", "parentRefs")) {
		pm := asMap(p)
		parents = append(parents, str(pm, "namespace", ns)+"/"+asStr(pm["name"]))
	}
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
			backends = append(backends, routeBackend{Name: asStr(bm["name"]), NS: str(bm, "namespace", ns), Port: int(port), Weight: int(w)})
			addFilters(asList(bm["filters"]))
		}
		matches := asList(rm["matches"])
		if len(matches) == 0 {
			matches = []any{obj{}}
		}
		for _, m := range matches {
			path := asMap(dig(m, "path"))
			typ, val := str(path, "type", "PathPrefix"), str(path, "value", "/")
			for _, h := range hosts {
				out = append(out, &routeRule{Route: name, NS: ns, Host: h, Path: val, Type: typ,
					Backends: backends, Filters: filters, Redirect: redirect, Parents: parents})
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
		out = append(out, migListener{Gateway: name, NS: ns, Name: asStr(lm["name"]), Protocol: asStr(lm["protocol"]), Hostname: strings.ToLower(asStr(lm["hostname"]))})
	}
	return out
}

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

func (r *ingressRule) backendString() string {
	if r.Resource {
		return "resource"
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

// diffRule lists how a route rule differs from an Ingress rule.
func diffRule(ir *ingressRule, rr *routeRule, gws []migListener, haveGW bool) (diffs, notes []string) {
	if want := wantedType(ir); rr.Type != want {
		diffs = append(diffs, fmt.Sprintf("path type %s in Ingress, %s in HTTPRoute", ir.PathType, rr.Type))
	}
	switch {
	case ir.Resource:
		diffs = append(diffs, "Ingress backend is a resource reference, which has no direct HTTPRoute equivalent")
	default:
		found, nameOnly := false, false
		for _, b := range rr.Backends {
			if b.Name != ir.Svc || !sameNS(b.NS, ir.NS) {
				continue
			}
			if ir.PortIsName || strconv.Itoa(b.Port) == ir.Port {
				found = true
				if ir.PortIsName {
					notes = append(notes, fmt.Sprintf("backend port name %q was not resolved against the Service", ir.Port))
				}
				break
			}
			nameOnly = true
		}
		if !found {
			var have []string
			for _, b := range rr.Backends {
				have = append(have, b.Name+":"+strconv.Itoa(b.Port))
			}
			switch {
			case nameOnly:
				diffs = append(diffs, fmt.Sprintf("backend port differs: Ingress %s, HTTPRoute %s", ir.backendString(), strings.Join(have, ", ")))
			case rr.Redirect != "" && len(have) == 0:
				diffs = append(diffs, "HTTPRoute rule does "+rr.Redirect+" instead of forwarding to "+ir.backendString())
			default:
				diffs = append(diffs, fmt.Sprintf("backend differs: Ingress %s, HTTPRoute %s", ir.backendString(), strings.Join(have, ", ")))
			}
		}
	}
	if ir.TLS && haveGW {
		var found, covered bool
		for _, p := range rr.Parents {
			for _, l := range gws {
				if l.NS+"/"+l.Gateway != p && l.Gateway != strings.TrimPrefix(p, rr.NS+"/") {
					continue
				}
				found = true
				if (l.Protocol == "HTTPS" || l.Protocol == "TLS") && hostCovers(l.Hostname, ir.Host) {
					covered = true
				}
			}
		}
		switch {
		case !found:
			notes = append(notes, "parent Gateway not found in the loaded objects; TLS not verified")
		case !covered:
			diffs = append(diffs, "Ingress terminates TLS for this host but no HTTPS listener of the parent Gateway covers it")
		}
	}
	return diffs, notes
}

func compareMigration(ingresses, routes, gateways []obj, haveGW bool) *migrateReport {
	rep := &migrateReport{Summary: map[string]int{}, Rules: []*ruleResult{}, Annotations: []annotationFinding{}}
	var iRules []*ingressRule
	byIngress := map[string][]*ingressRule{}
	var ingNames []string
	annotationsByIng := map[string]map[string]string{}
	for _, ing := range ingresses {
		if v := asStr(ing["apiVersion"]); v != "" && v != "networking.k8s.io/v1" {
			n, _ := metaOf(ing)
			rep.Notes = append(rep.Notes, fmt.Sprintf("skipped Ingress %s: apiVersion %s is not networking.k8s.io/v1", n, v))
			continue
		}
		rs := extractIngressRules(ing, &rep.Notes)
		name, ns := metaOf(ing)
		key := ns + "/" + name
		ingNames = append(ingNames, key)
		annotationsByIng[key] = annotationsOf(ing)
		byIngress[key] = rs
		iRules = append(iRules, rs...)
	}
	var rRules []*routeRule
	for _, rt := range routes {
		rRules = append(rRules, extractRouteRules(rt)...)
	}
	var listeners []migListener
	for _, gw := range gateways {
		listeners = append(listeners, extractListeners(gw)...)
	}
	if !haveGW && func() bool {
		for _, r := range iRules {
			if r.TLS {
				return true
			}
		}
		return false
	}() {
		rep.Notes = append(rep.Notes, "TLS was not verified: no Gateway objects were loaded")
	}

	matchedBy := map[string][]*routeRule{} // ingress key -> matched route rules
	for _, ir := range iRules {
		res := &ruleResult{Ingress: ir.Ingress, ExpectedRoute: ir.expectedRoute, Host: ir.Host, Path: ir.Path, PathType: ir.PathType,
			Backend: ir.backendString(), TLS: ir.TLS, ingress: ir}
		if ir.Default {
			res.Details = append(res.Details, "default backend")
		}
		if ir.PathType == "ImplementationSpecific" {
			res.Details = append(res.Details, "pathType ImplementationSpecific is compared as a prefix match")
		}
		var best *routeRule
		var bestDiffs, bestNotes []string
		for _, rr := range rRules {
			if !sameNS(rr.NS, ir.NS) || rr.Host != ir.Host || normPath(rr.Path, ir.Regex) != normPath(ir.Path, ir.Regex) {
				continue
			}
			d, n := diffRule(ir, rr, listeners, haveGW)
			better := best == nil || len(d) < len(bestDiffs) ||
				len(d) == len(bestDiffs) && rr.Route == ir.expectedRoute && best.Route != ir.expectedRoute
			if better {
				best, bestDiffs, bestNotes = rr, d, n
			}
		}
		if best == nil {
			res.Status = statusMissing
			res.Details = append(res.Details, "no HTTPRoute rule matches this host and path")
		} else {
			best.matched = true
			matchedBy[ir.NS+"/"+ir.Ingress] = append(matchedBy[ir.NS+"/"+ir.Ingress], best)
			res.Route = best.Route
			res.Details = append(res.Details, bestNotes...)
			if len(bestDiffs) == 0 {
				res.Status = statusEquivalent
			} else {
				res.Status = statusDifferent
				res.Details = append(res.Details, bestDiffs...)
			}
			if best.Route != ir.expectedRoute {
				res.Details = append(res.Details, fmt.Sprintf("route name %q differs from the ingress2gateway convention %q", best.Route, ir.expectedRoute))
			}
		}
		rep.Rules = append(rep.Rules, res)
	}
	for _, rr := range rRules {
		if rr.matched {
			continue
		}
		res := &ruleResult{Status: statusExtra, Route: rr.Route, Host: rr.Host, Path: rr.Path, PathType: rr.Type}
		var bs []string
		for _, b := range rr.Backends {
			bs = append(bs, b.Name+":"+strconv.Itoa(b.Port))
		}
		res.Backend = strings.Join(bs, ", ")
		if rr.Redirect != "" {
			res.Details = append(res.Details, rr.Redirect)
		}
		res.Details = append(res.Details, "no Ingress rule maps to this HTTPRoute rule")
		rep.Rules = append(rep.Rules, res)
	}

	sort.Strings(ingNames)
	for _, key := range ingNames {
		filters := map[string]bool{}
		for _, rr := range matchedBy[key] {
			for f := range rr.Filters {
				filters[f] = true
			}
		}
		_, name, _ := strings.Cut(key, "/")
		rep.Annotations = append(rep.Annotations, classifyAnnotations(name, annotationsByIng[key], filters)...)
	}
	rep.finish()
	return rep
}

func (r *migrateReport) finish() {
	r.Summary = map[string]int{statusEquivalent: 0, statusDifferent: 0, statusMissing: 0, statusExtra: 0, "annotations_flagged": 0}
	for _, x := range r.Rules {
		r.Summary[x.Status]++
	}
	for _, a := range r.Annotations {
		if a.Flagged() {
			r.Summary["annotations_flagged"]++
		}
	}
	r.OK = r.Summary[statusDifferent]+r.Summary[statusMissing]+r.Summary[statusExtra]+r.Summary["annotations_flagged"] == 0
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

func (lo *liveOptions) apply(rep *migrateReport) {
	for _, r := range rep.Rules {
		if r.ingress == nil {
			continue
		}
		if r.ingress.Regex || regexMeta(r.Path, `()*+?[]{}\^$|`) {
			r.Details = append(r.Details, "live probe skipped: path looks like a regular expression")
			continue
		}
		r.Probe = lo.diff(r.Host, r.Path)
		if len(r.Probe.Diffs) > 0 {
			if r.Status == statusEquivalent {
				r.Status = statusDifferent
			}
			for _, d := range r.Probe.Diffs {
				r.Details = append(r.Details, "live: "+d)
			}
		}
	}
	rep.finish()
}

// ---- rendering -----------------------------------------------------------

func (u *ui) MigratePretty(rep *migrateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n\n", u.bold("setura migrate check"))
	sym := func(s string) string {
		switch s {
		case statusEquivalent:
			return u.okSym()
		case statusExtra:
			return u.warnSym()
		}
		return u.failSym()
	}
	hostW, pathW, beW := 4, 4, 7
	for _, r := range rep.Rules {
		hostW = max(hostW, len([]rune(hostLabel(r.Host))))
		pathW = max(pathW, len([]rune(r.Path)))
		beW = max(beW, len([]rune(r.Backend)))
	}
	fmt.Fprintf(&b, "    %s  %s  %s  %s  %s\n", pad("", 1), u.gray(pad("HOST", hostW)), u.gray(pad("PATH", pathW)), u.gray(pad("BACKEND", beW)), u.gray("STATUS / ROUTE"))
	for _, r := range rep.Rules {
		tail := r.Status
		if r.Route != "" {
			tail += " " + u.arrow() + " " + r.Route
		}
		fmt.Fprintf(&b, "    %s  %s  %s  %s  %s\n", sym(r.Status), pad(hostLabel(r.Host), hostW), pad(r.Path, pathW), pad(r.Backend, beW), tail)
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
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "\n  %s %s", u.warnSym(), n)
	}
	s := rep.Summary
	verdict := u.green("equivalent")
	if !rep.OK {
		verdict = u.red("differences found")
	}
	fmt.Fprintf(&b, "\n\n  %s: %d equivalent, %d different, %d missing in Gateway, %d extra in Gateway, %d annotations need attention\n\n",
		verdict, s[statusEquivalent], s[statusDifferent], s[statusMissing], s[statusExtra], s["annotations_flagged"])
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
		if r.Status == statusExtra {
			level = "warning"
		}
		msg := fmt.Sprintf("%s%s: %s", hostLabel(r.Host), r.Path, r.Status)
		if len(r.Details) > 0 {
			msg += " (" + strings.Join(r.Details, "; ") + ")"
		}
		b.WriteString(annotation(level, "setura migrate "+r.Status, file, 0, msg))
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
	var ns string
	fs.StringVar(&ns, "n", "default", "namespace to read from the cluster")
	fs.StringVar(&ns, "namespace", "default", "namespace to read from the cluster")
	all := fs.Bool("A", false, "read all namespaces from the cluster")
	ingressPath := fs.String("ingress", "", "read Ingress objects from this YAML/JSON file or directory instead of the cluster")
	routesPath := fs.String("routes", "", "read HTTPRoutes (and Gateways) from this YAML/JSON file or directory instead of the cluster")
	ingressURL := fs.String("ingress-url", "", "base URL of the Ingress controller for live comparison (needs --gateway-url)")
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
		fmt.Fprintf(stderr, "setura migrate: unknown subcommand %q (expected check)\n", args[0])
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
	if !live && (*address != "" || *ingressAddr != "" || *gatewayAddr != "" || *ca != "" || len(headers) > 0) {
		return fail("--address, --ingress-address, --gateway-address, --ca and --header need --ingress-url and --gateway-url")
	}

	// Load objects.
	var ingresses, routes, gateways []obj
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
	var fileObjs []obj
	for _, p := range []string{*ingressPath, *routesPath} {
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
		case kindOf(o, "HTTPRoute"):
			routes = append(routes, o)
		case kindOf(o, "Gateway"):
			gateways = append(gateways, o)
			haveGW = true
		}
	}
	var notes []string
	if *ingressPath == "" {
		if ingresses, err = list("ingresses.networking.k8s.io"); err != nil {
			return 0, err
		}
	}
	if *routesPath == "" {
		if routes, err = list("httproutes.gateway.networking.k8s.io"); err != nil {
			return 0, err
		}
		if gws, gerr := list("gateways.gateway.networking.k8s.io"); gerr == nil {
			gateways, haveGW = gws, true
		} else {
			notes = append(notes, "could not read Gateways: "+gerr.Error())
		}
	}
	if len(ingresses) == 0 {
		return 0, userError("no Ingress objects found; nothing to migrate")
	}
	if *routesPath != "" && len(routes) == 0 {
		return 0, userErrorf("no HTTPRoute objects found in %s", *routesPath)
	}

	rep := compareMigration(ingresses, routes, gateways, haveGW)
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
		lo.apply(rep)
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
