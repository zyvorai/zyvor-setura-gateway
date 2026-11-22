package setura

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ingress-nginx Ingress to Gateway + HTTPRoute / GRPCRoute / TLSRoute.
// Naming follows ingress2gateway: the Gateway is named after the Ingress
// class, routes are "<ingress>-<host with . as ->".

// ingCtx is the state of converting one Ingress.
type ingCtx struct {
	src       string
	name, ns  string
	ing       obj
	ann       map[string]string // annotation name without the nginx prefix
	used      map[string]bool
	todos     []string // comment lines for every route of this Ingress
	kind      string
	class     string
	tlsSecret map[string]string // host -> secretName for hosts under spec.tls
	tlsHosts  map[string]bool
}

func (ic *ingCtx) get(name string) (string, bool) {
	v, ok := ic.ann[name]
	if ok {
		ic.used[name] = true
	}
	return v, ok
}

func (ic *ingCtx) truthy(name string) bool {
	v, _ := ic.get(name)
	return strings.EqualFold(v, "true")
}

// pendRoute is one route (one host of one Ingress) before it is written.
type pendRoute struct {
	ic          *ingCtx
	host        string
	hosts       []string // host and its server-alias names
	kind        string
	rules       []*cvRule
	gw          *gwBuild
	redirect    bool   // add a route that sends HTTP clients to HTTPS
	appRoot     string // app-root target path
	todos       []string
	tlsBackends map[string]bool // Services reached over TLS
	entry       string          // "http" or "https" to attach to one listener kind only; "" for both
}

type mainRef struct {
	rule *cvRule
	pr   *pendRoute
}

func (c *converter) newIngCtx(ing obj) *ingCtx {
	name, ns := metaOf(ing)
	ic := &ingCtx{src: "Ingress " + ns + "/" + name, name: name, ns: ns, ing: ing, ann: map[string]string{}, used: map[string]bool{},
		tlsSecret: map[string]string{}, tlsHosts: map[string]bool{}}
	for k, v := range annotationsOf(ing) {
		if strings.HasPrefix(k, nginxPrefix) {
			ic.ann[strings.TrimPrefix(k, nginxPrefix)] = v
		}
	}
	ic.kind, _ = routeKindFor(annotationsOf(ing))
	ic.class = ingressClassOf(ing)
	if ic.class == "" {
		ic.class = "nginx"
	}
	for _, t := range asList(dig(ing, "spec", "tls")) {
		tm := asMap(t)
		hosts := asList(tm["hosts"])
		for _, h := range hosts {
			ic.tlsHosts[strings.ToLower(asStr(h))] = true
			ic.tlsSecret[strings.ToLower(asStr(h))] = asStr(tm["secretName"])
		}
		if len(hosts) == 0 {
			ic.tlsHosts[""] = true
			ic.tlsSecret[""] = asStr(tm["secretName"])
		}
	}
	return ic
}

func (ic *ingCtx) fullKey(name string) string {
	if name == "ingress.class" {
		return "kubernetes.io/ingress.class"
	}
	return nginxPrefix + name
}

// convertIngresses converts every Ingress; canary Ingresses are folded into
// the rule of the Ingress they canary.
func (c *converter) convertIngresses(ings []obj) {
	var mains, canaries []obj
	for _, ing := range ings {
		if strings.EqualFold(annotationsOf(ing)[nginxPrefix+"canary"], "true") {
			canaries = append(canaries, ing)
		} else {
			mains = append(mains, ing)
		}
	}
	index := map[string]mainRef{}
	var pend []*pendRoute
	for _, ing := range mains {
		pend = append(pend, c.convertIngress(ing, index, "")...)
	}
	for _, ing := range canaries {
		if !c.convertCanary(ing, index) {
			pend = append(pend, c.convertIngress(ing, index, "no non-canary Ingress serves the same host and path in the inputs, so it was converted as a regular route")...)
		}
	}
	for _, pr := range pend {
		c.materialise(pr)
	}
}

func mainKey(ns, host, path string) string { return ns + "|" + host + "|" + normPath(path, false) }

func (c *converter) rulesOf(ing obj, ic *ingCtx) []*ingressRule {
	rs := extractIngressRules(ing, &c.notes)
	for _, r := range rs {
		r.resolvePort(c.svcs, c.haveSvc)
	}
	return rs
}

func (c *converter) convertIngress(ing obj, index map[string]mainRef, standaloneNote string) []*pendRoute {
	ic := c.newIngCtx(ing)
	if v := asStr(ing["apiVersion"]); v != "" && v != "networking.k8s.io/v1" {
		c.notes = append(c.notes, fmt.Sprintf("skipped %s: apiVersion %s is not networking.k8s.io/v1", ic.src, v))
		return nil
	}
	if standaloneNote != "" {
		ic.todos = append(ic.todos, c.todo(ic.src, nginxPrefix+"canary", "true", standaloneNote))
		ic.used["canary"] = true
		for _, n := range []string{"canary-weight", "canary-weight-total", "canary-by-header", "canary-by-header-value", "canary-by-header-pattern", "canary-by-cookie"} {
			if v, ok := ic.get(n); ok {
				ic.todos = append(ic.todos, c.todo(ic.src, nginxPrefix+n, v, "there is no main route to split traffic with; decide which route this canary should join"))
			}
		}
	}
	gw := c.gateway(ic.ns, ic.class)
	var order []string
	byHost := map[string][]*ingressRule{}
	for _, ir := range c.rulesOf(ing, ic) {
		if _, ok := byHost[ir.Host]; !ok {
			order = append(order, ir.Host)
		}
		byHost[ir.Host] = append(byHost[ir.Host], ir)
	}
	var out []*pendRoute
	for _, host := range order {
		pr := &pendRoute{ic: ic, host: host, hosts: []string{host}, kind: ic.kind, gw: gw, tlsBackends: map[string]bool{}}
		if v, ok := ic.get("server-alias"); ok && host != "" {
			for _, a := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				pr.hosts = append(pr.hosts, strings.ToLower(a))
			}
		}
		for _, ir := range byHost[host] {
			if ir.Resource {
				ic.todos = append(ic.todos, c.todo(ic.src, "spec.rules backend.resource", ir.Path, "the backend is a resource reference, not a Service; Gateway API routes only to Services (or a typed backendRef the controller supports)"))
				continue
			}
			cr := c.buildRule(ic, ir, pr)
			if cr == nil {
				continue
			}
			pr.rules = append(pr.rules, cr)
			if ic.kind == kindHTTPRoute || ic.kind == kindGRPCRoute {
				index[mainKey(ic.ns, host, ir.Path)] = mainRef{cr, pr}
			}
		}
		if len(pr.rules) == 0 {
			continue
		}
		out = append(out, pr)
	}
	// Ingress level annotations.
	for _, pr := range out {
		c.ingressLevel(ic, pr)
	}
	c.finishUnused(ic)
	return out
}

func (c *converter) ingressLevel(ic *ingCtx, pr *pendRoute) {
	if ic.kind == kindTLSRoute {
		ic.used["ssl-passthrough"] = true
		c.done(ic.src, nginxPrefix+"ssl-passthrough", "true", "TLSRoute with a TLS Passthrough listener")
		return
	}
	if v, ok := ic.get("app-root"); ok {
		pr.appRoot = v
	}
	// ssl redirect: nginx redirects HTTP to HTTPS for TLS hosts unless ssl-redirect is false.
	tls := false
	for _, h := range pr.hosts {
		tls = tls || ic.tlsHosts[h]
	}
	sslv, sslSet := ic.get("ssl-redirect")
	forcev, forceSet := ic.get("force-ssl-redirect")
	off := strings.EqualFold(sslv, "false") && !strings.EqualFold(forcev, "true")
	switch {
	case off:
	case tls || strings.EqualFold(forcev, "true"):
		pr.redirect = true
	}
	redirectTarget := "RequestRedirect scheme https (301) on a route attached to the HTTP listener"
	if sslSet && strings.EqualFold(sslv, "false") {
		c.done(ic.src, nginxPrefix+"ssl-redirect", sslv, "no redirect route: redirect disabled")
	} else if sslSet {
		c.done(ic.src, nginxPrefix+"ssl-redirect", sslv, redirectTarget)
	}
	if forceSet {
		if strings.EqualFold(forcev, "true") && !tls {
			ic.todos = append(ic.todos, c.todo(ic.src, nginxPrefix+"force-ssl-redirect", forcev, "the host has no entry under spec.tls, so there is no HTTPS listener to redirect to; add a tls block with a secretName (ingress-nginx would serve its default certificate)"))
			pr.redirect = false
		} else if strings.EqualFold(forcev, "true") {
			c.done(ic.src, nginxPrefix+"force-ssl-redirect", forcev, redirectTarget)
		} else {
			c.done(ic.src, nginxPrefix+"force-ssl-redirect", forcev, "no redirect route: redirect disabled")
		}
	}
	if !sslSet && !forceSet && pr.redirect {
		c.done(ic.src, nginxPrefix+"ssl-redirect (default for hosts under spec.tls)", "", redirectTarget)
	}
}

// buildRule converts one Ingress rule and its annotations.
func (c *converter) buildRule(ic *ingCtx, ir *ingressRule, pr *pendRoute) *cvRule {
	cr := &cvRule{}
	port := 0
	if ir.PortIsName {
		if ir.resolvedPort != "" {
			port, _ = strconv.Atoi(ir.resolvedPort)
		} else {
			ic.todos = append(ic.todos, c.todo(ic.src, "spec.rules backend port "+ir.Port, ir.Svc, ir.unresolved+"; set the port number on the backendRef by hand"))
		}
	} else {
		port, _ = strconv.Atoi(ir.Port)
	}
	ref := backendRef(ir.Svc, "", port, -1)
	switch ir.Kind {
	case kindTLSRoute:
		cr.backends = []any{ref}
		return cr
	case kindGRPCRoute:
		if p := strings.Trim(ir.Path, "/"); p != "" {
			svc, mth, kind := grpcMethodPath(ir.Path)
			if kind == "" {
				ic.todos = append(ic.todos, c.todo(ic.src, "spec.rules path "+ir.Path, ir.Svc, "a gRPC rule needs a path of the form /package.Service or /package.Service/Method; "+ir.Path+" cannot be turned into a GRPCRoute method match"))
				return nil
			}
			m := obj{"service": svc}
			if mth != "" {
				m["method"] = mth
			}
			if ir.Regex {
				m["type"] = "RegularExpression"
			}
			cr.matches = []any{obj{"method": m}}
		}
	default:
		typ := "PathPrefix"
		switch {
		case ir.Regex:
			typ = "RegularExpression"
		case ir.PathType == "Exact":
			typ = "Exact"
		}
		path := ir.Path
		if typ == "PathPrefix" {
			path = normPath(path, false)
		}
		cr.matches = []any{obj{"path": obj{"type": typ, "value": path}}}
	}
	cr.backends = []any{ref}
	if pr != nil && ir.Svc != "" {
		if v := ic.ann["backend-protocol"]; strings.EqualFold(v, "HTTPS") || strings.EqualFold(v, "GRPCS") {
			pr.tlsBackends[ir.Svc] = true
		}
	}
	c.ruleAnnotations(ic, ir, cr, pr)
	return cr
}

func (c *converter) ruleAnnotations(ic *ingCtx, ir *ingressRule, cr *cvRule, pr *pendRoute) {
	todo := func(name, reason string) {
		v, _ := ic.get(name)
		ic.todos = append(ic.todos, c.todo(ic.src, ic.fullKey(name), v, reason))
	}
	done := func(name, target string) {
		v, _ := ic.get(name)
		c.done(ic.src, ic.fullKey(name), v, target)
	}
	key := func(n string) string { return nginxPrefix + n }

	// backend protocol and regex
	if v, ok := ic.get("backend-protocol"); ok {
		switch strings.ToUpper(v) {
		case "HTTP":
			done("backend-protocol", "default: plain HTTP to the backend")
		case "HTTPS":
			done("backend-protocol", "BackendTLSPolicy for the Service")
			c.tlsSiblings(ic)
		case "GRPC":
			done("backend-protocol", "GRPCRoute")
		case "GRPCS":
			done("backend-protocol", "GRPCRoute and a BackendTLSPolicy for the Service")
			c.tlsSiblings(ic)
		default:
			todo("backend-protocol", "the backend protocol "+v+" has no Gateway API equivalent (supported: HTTP, HTTPS, GRPC, GRPCS)")
		}
	}
	if ic.truthy("use-regex") {
		if ir.Kind == kindHTTPRoute {
			done("use-regex", "path match type RegularExpression")
		} else {
			done("use-regex", "RegularExpression method match")
		}
	}
	if ir.Kind == kindGRPCRoute {
		// Most HTTP-only filters do not exist on GRPCRoute; the rest of the
		// annotations are handled below and refused by kind where needed.
	}

	// Rewrites.
	if v, ok := ic.get("rewrite-target"); ok {
		switch {
		case ir.Kind != kindHTTPRoute:
			todo("rewrite-target", "path rewriting is an HTTPRoute filter and this rule converts to a "+ir.Kind)
		case strings.Contains(v, "$"):
			todo("rewrite-target", "the target uses regex capture groups ($1, $2); URLRewrite has no capture groups, so rewrite by hand or restructure the path")
		case ir.Regex:
			todo("rewrite-target", "rewriting a regular expression path needs capture groups, which URLRewrite does not have")
		case !strings.HasPrefix(v, "/"):
			todo("rewrite-target", "the target is not an absolute path")
		case ir.PathType == "Exact":
			f := cr.filter("URLRewrite", "urlRewrite")
			f["path"] = obj{"type": "ReplaceFullPath", "replaceFullPath": v}
			done("rewrite-target", "URLRewrite ReplaceFullPath")
		default:
			f := cr.filter("URLRewrite", "urlRewrite")
			f["path"] = obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": v}
			done("rewrite-target", "URLRewrite ReplacePrefixMatch")
		}
	}
	if v, ok := ic.get("upstream-vhost"); ok {
		if ir.Kind == kindHTTPRoute {
			cr.filter("URLRewrite", "urlRewrite")["hostname"] = v
			done("upstream-vhost", "URLRewrite hostname")
		} else {
			todo("upstream-vhost", "the Host rewrite is an HTTPRoute filter")
		}
	}
	if v, ok := ic.get("x-forwarded-prefix"); ok {
		if ir.Kind == kindHTTPRoute {
			cr.setRequestHeader("X-Forwarded-Prefix", v)
			done("x-forwarded-prefix", "RequestHeaderModifier set X-Forwarded-Prefix")
		} else {
			todo("x-forwarded-prefix", "header modification is an HTTPRoute filter")
		}
	}
	for _, h := range []struct{ name, target string }{{"proxy-set-headers", "request"}, {"custom-headers", "response"}} {
		v, ok := ic.get(h.name)
		if !ok {
			continue
		}
		if ir.Kind != kindHTTPRoute {
			todo(h.name, "header modification is an HTTPRoute filter")
			continue
		}
		cmKey := v
		if !strings.Contains(cmKey, "/") {
			cmKey = ic.ns + "/" + cmKey
		}
		data, found := c.cms[cmKey]
		if !found {
			todo(h.name, "the headers live in ConfigMap "+cmKey+", which is not in the inputs; pass it as an input file or add the headers by hand")
			continue
		}
		for _, n := range sortedKeys(data) {
			if h.target == "request" {
				cr.setRequestHeader(n, data[n])
			} else {
				cr.setResponseHeader(n, data[n])
			}
		}
		done(h.name, map[string]string{"request": "RequestHeaderModifier", "response": "ResponseHeaderModifier"}[h.target]+" from ConfigMap "+cmKey)
	}

	// Redirects of the whole rule.
	for _, rd := range []struct {
		name string
		code int
	}{{"permanent-redirect", 301}, {"temporal-redirect", 302}} {
		v, ok := ic.get(rd.name)
		if !ok {
			continue
		}
		code := rd.code
		if cv, ok := ic.get(rd.name + "-code"); ok {
			if n, err := strconv.Atoi(cv); err == nil && (n == 301 || n == 302) {
				code = n
			} else {
				ic.todos = append(ic.todos, c.todo(ic.src, key(rd.name+"-code"), cv, "Gateway API RequestRedirect only supports status 301 and 302; "+strconv.Itoa(code)+" was used"))
			}
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || ir.Kind != kindHTTPRoute {
			todo(rd.name, "the redirect target must be an absolute http(s) URL on an HTTPRoute")
			continue
		}
		rr := obj{"scheme": u.Scheme, "hostname": u.Hostname(), "statusCode": code}
		if p := u.Port(); p != "" {
			n, _ := strconv.Atoi(p)
			rr["port"] = n
		}
		if u.Path != "" {
			rr["path"] = obj{"type": "ReplaceFullPath", "replaceFullPath": u.Path}
		}
		cr.filters = append(cr.filters, obj{"type": "RequestRedirect", "requestRedirect": rr})
		cr.backends = nil
		done(rd.name, "RequestRedirect "+strconv.Itoa(code))
	}

	// Mirroring.
	if v, ok := ic.get("mirror-target"); ok {
		if name, ns, port, _, ok := svcFromURL(v, ic.ns); ok && ir.Kind == kindHTTPRoute {
			nsOut := ""
			target := "RequestMirror"
			if ns != ic.ns {
				nsOut = ns
				c.needGrant(ns, ic.ns, kindHTTPRoute, name)
				target += " and a ReferenceGrant in " + ns
			}
			cr.filters = append(cr.filters, obj{"type": "RequestMirror", "requestMirror": obj{"backendRef": backendRef(name, nsOut, port, -1)}})
			done("mirror-target", target)
		} else {
			todo("mirror-target", "the mirror target is not a Service URL of this cluster (name[.namespace][.svc]:port)")
		}
	}
	if _, ok := ic.ann["mirror-host"]; ok {
		todo("mirror-host", "RequestMirror cannot set the Host header of the mirrored request")
	}
	if _, ok := ic.ann["mirror-request-body"]; ok {
		ic.used["mirror-request-body"] = true
		done("mirror-request-body", "RequestMirror (the request body is always mirrored)")
	}

	// Timeouts.
	var best float64
	var bestVal string
	for _, n := range []string{"proxy-read-timeout", "proxy-send-timeout"} {
		v, ok := ic.get(n)
		if !ok {
			continue
		}
		d, valid := durationOf(v)
		switch {
		case ir.Kind != kindHTTPRoute:
			todo(n, "timeouts are an HTTPRoute rule field")
		case !valid:
			todo(n, "the value is not a number of seconds or a duration")
		default:
			if s := durationSeconds(d); s >= best {
				best, bestVal = s, d
			}
			target := "timeouts.backendRequest"
			if n == "proxy-send-timeout" {
				target += " (covers the whole backend request, not only sending; the larger of read and send is used)"
			}
			done(n, target)
		}
	}
	if bestVal != "" {
		cr.timeouts = obj{"backendRequest": bestVal}
	}

	// CORS.
	c.corsAnnotations(ic, cr, ir)

	// Security.
	c.authAnnotations(ic, ir, cr)

	// Session affinity.
	if v, ok := ic.get("affinity"); ok {
		c.sessionAnnotations(ic, ir, cr, v)
	}

	// Rules out of the HTTP world.
	if ir.Kind == kindGRPCRoute {
		_ = pr
	}
}

func (c *converter) corsAnnotations(ic *ingCtx, cr *cvRule, ir *ingressRule) {
	names := []string{"enable-cors", "cors-allow-origin", "cors-allow-methods", "cors-allow-headers", "cors-allow-credentials", "cors-expose-headers", "cors-max-age"}
	present := false
	for _, n := range names {
		if _, ok := ic.ann[n]; ok {
			present = true
		}
	}
	if !present {
		return
	}
	enabled := ic.truthy("enable-cors")
	for _, n := range names[1:] {
		ic.get(n)
	}
	fk := func(n string) string { return nginxPrefix + n }
	if !enabled {
		for _, n := range names[1:] {
			if v, ok := ic.ann[n]; ok {
				c.ignore(ic.src, fk(n), v, "ignored by ingress-nginx unless enable-cors is true")
			}
		}
		return
	}
	if ir.Kind != kindHTTPRoute {
		ic.todos = append(ic.todos, c.todo(ic.src, fk("enable-cors"), "true", "the CORS filter is an HTTPRoute filter"))
		return
	}
	cors := obj{}
	origins := []string{"*"}
	if v, ok := ic.ann["cors-allow-origin"]; ok {
		origins = splitList(v)
	}
	for _, o := range origins {
		if strings.ContainsAny(o, "^$()[]\\") {
			ic.todos = append(ic.todos, c.todo(ic.src, fk("cors-allow-origin"), ic.ann["cors-allow-origin"], "regular expression origins are not part of the CORS filter; list exact origins or *.example.com wildcards"))
			return
		}
	}
	cors["allowOrigins"] = stringsToAny(origins)
	methods := []string{"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS"}
	if v, ok := ic.ann["cors-allow-methods"]; ok {
		methods = nil
		for _, m := range splitList(v) {
			methods = append(methods, strings.ToUpper(m))
		}
	}
	cors["allowMethods"] = stringsToAny(methods)
	if v, ok := ic.ann["cors-allow-headers"]; ok {
		cors["allowHeaders"] = stringsToAny(splitList(v))
	}
	if v, ok := ic.ann["cors-expose-headers"]; ok {
		cors["exposeHeaders"] = stringsToAny(splitList(v))
	}
	creds := true
	if v, ok := ic.ann["cors-allow-credentials"]; ok {
		creds = strings.EqualFold(v, "true")
	}
	cors["allowCredentials"] = creds
	if v, ok := ic.ann["cors-max-age"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cors["maxAge"] = n
		}
	}
	cr.filters = append(cr.filters, obj{"type": "CORS", "cors": cors})
	for _, n := range names {
		if v, ok := ic.ann[n]; ok {
			c.done(ic.src, fk(n), v, "CORS filter")
		}
	}
}

func (c *converter) authAnnotations(ic *ingCtx, ir *ingressRule, cr *cvRule) {
	fk := func(n string) string { return nginxPrefix + n }
	for _, n := range []string{"whitelist-source-range", "allowlist-source-range", "denylist-source-range"} {
		v, ok := ic.get(n)
		if !ok {
			continue
		}
		if ir.Kind == kindGRPCRoute || ir.Kind == kindTLSRoute {
			ic.todos = append(ic.todos, c.todo(ic.src, fk(n), v, "setura.zyvor.dev/auth policies apply to HTTPRoute rules only"))
			continue
		}
		field := "ipAllow"
		if n == "denylist-source-range" {
			field = "ipDeny"
		}
		cr.authBlock()[field] = stringsToAny(splitList(v))
		c.done(ic.src, fk(n), v, "setura.zyvor.dev/auth "+field)
	}
	if v, ok := ic.get("auth-type"); ok {
		realm, _ := ic.get("auth-realm")
		secret, _ := ic.get("auth-secret")
		ic.get("auth-secret-type")
		if !strings.EqualFold(v, "basic") || ir.Kind != kindHTTPRoute {
			ic.todos = append(ic.todos, c.todo(ic.src, fk("auth-type"), v, "only basic authentication on an HTTPRoute converts; digest has no equivalent"))
		} else {
			basic := obj{"users": []any{}}
			if realm != "" {
				basic["realm"] = realm
			}
			cr.authBlock()["basic"] = basic
			ic.todos = append(ic.todos, c.todo(ic.src, fk("auth-type"), v, "the basic auth block was generated without users: the htpasswd entries in Secret "+secret+" use bcrypt or apr1 hashes, while Setura stores pbkdf2-sha256; create each user with `setura gateway hash --kind password` and add it under basic.users"))
		}
	}
	if v, ok := ic.get("auth-url"); ok {
		name, ns, port, path, ok := svcFromURL(v, ic.ns)
		if !ok || ir.Kind != kindHTTPRoute {
			ic.todos = append(ic.todos, c.todo(ic.src, fk("auth-url"), v, "the auth URL is not a Service of this cluster (name[.namespace][.svc]:port/path); ExternalAuth needs a backendRef"))
		} else {
			nsOut := ""
			if ns != ic.ns {
				nsOut = ns
			}
			ea := obj{"protocol": "HTTP", "backendRef": backendRef(name, nsOut, port, -1)}
			http := obj{}
			if path != "" && path != "/" {
				http["path"] = path
			}
			if h, ok := ic.get("auth-response-headers"); ok {
				http["allowedResponseHeaders"] = stringsToAny(splitList(h))
				c.done(ic.src, fk("auth-response-headers"), h, "ExternalAuth http.allowedResponseHeaders")
			}
			if len(http) > 0 {
				ea["http"] = http
			}
			cr.filters = append(cr.filters, obj{"type": "ExternalAuth", "externalAuth": ea})
			target := "ExternalAuth filter"
			if nsOut != "" {
				c.needGrant(ns, ic.ns, kindHTTPRoute, name)
				target += " and a ReferenceGrant in " + ns
			}
			c.done(ic.src, fk("auth-url"), v, target)
		}
	}
	for _, n := range []string{"auth-signin", "auth-request-redirect", "auth-method", "auth-snippet", "auth-cache-key", "auth-cache-duration", "auth-always-set-cookie", "auth-proxy-set-headers"} {
		if v, ok := ic.get(n); ok {
			reason := "ExternalAuth has no equivalent for this setting"
			if n == "auth-signin" || n == "auth-request-redirect" {
				reason = "ExternalAuth answers 401/403 itself; redirecting unauthenticated users to a sign-in page needs a controller policy or an auth proxy"
			}
			ic.todos = append(ic.todos, c.todo(ic.src, fk(n), v, reason))
		}
	}
}

func (c *converter) sessionAnnotations(ic *ingCtx, ir *ingressRule, cr *cvRule, v string) {
	fk := func(n string) string { return nginxPrefix + n }
	if !strings.EqualFold(v, "cookie") || ir.Kind == kindTLSRoute {
		ic.todos = append(ic.todos, c.todo(ic.src, fk("affinity"), v, "only cookie affinity converts to sessionPersistence"))
		return
	}
	name := "INGRESSCOOKIE"
	if n, ok := ic.get("session-cookie-name"); ok {
		name = n
		c.done(ic.src, fk("session-cookie-name"), n, "sessionPersistence.sessionName")
	}
	sp := obj{"type": "Cookie", "sessionName": name}
	for _, n := range []string{"session-cookie-max-age", "session-cookie-expires"} {
		if mv, ok := ic.get(n); ok {
			if d, valid := durationOf(mv); valid {
				sp["absoluteTimeout"] = d
				sp["cookieConfig"] = obj{"lifetimeType": "Permanent"}
				c.done(ic.src, fk(n), mv, "sessionPersistence.absoluteTimeout, cookieConfig.lifetimeType Permanent")
			} else {
				ic.todos = append(ic.todos, c.todo(ic.src, fk(n), mv, "the value is not a number of seconds"))
			}
		}
	}
	for _, n := range []string{"session-cookie-path", "session-cookie-samesite", "session-cookie-secure", "session-cookie-conditional-samesite-none", "session-cookie-change-on-failure", "session-cookie-domain", "affinity-mode"} {
		if mv, ok := ic.get(n); ok {
			ic.todos = append(ic.todos, c.todo(ic.src, fk(n), mv, "sessionPersistence cookies have no attribute for this; the gateway issues a signed session cookie with its own settings"))
		}
	}
	cr.session = sp
	c.done(ic.src, fk("affinity"), v, "sessionPersistence type Cookie")
}

// convertCanary folds a canary Ingress into the rules it shadows. It returns
// false when some rule has nothing to fold into.
func (c *converter) convertCanary(ing obj, index map[string]mainRef) bool {
	ic := c.newIngCtx(ing)
	rules := c.rulesOf(ing, ic)
	if len(rules) == 0 {
		return false
	}
	for _, ir := range rules {
		if _, ok := index[mainKey(ic.ns, ir.Host, ir.Path)]; !ok || ir.Resource {
			return false
		}
	}
	ic.used["canary"] = true
	c.done(ic.src, nginxPrefix+"canary", "true", "folded into the rule of the non-canary Ingress")
	total := 100
	if v, ok := ic.get("canary-weight-total"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			total = n
		}
	}
	for _, ir := range rules {
		m := index[mainKey(ic.ns, ir.Host, ir.Path)]
		pr := m.pr
		port, _ := strconv.Atoi(ir.Port)
		if ir.PortIsName && ir.resolvedPort != "" {
			port, _ = strconv.Atoi(ir.resolvedPort)
		}
		canaryRef := backendRef(ir.Svc, "", port, -1)
		if hdr, ok := ic.get("canary-by-header"); ok {
			value, pattern := ic.ann["canary-by-header-value"], ic.ann["canary-by-header-pattern"]
			ic.get("canary-by-header-value")
			ic.get("canary-by-header-pattern")
			hm := obj{"name": hdr, "type": "Exact", "value": "always"}
			switch {
			case value != "":
				hm["value"] = value
			case pattern != "":
				hm["value"], hm["type"] = pattern, "RegularExpression"
			}
			nr := &cvRule{filters: deepCopyList(m.rule.filters), backends: []any{canaryRef}}
			for _, mt := range m.rule.matches {
				cp := deepCopy(mt).(obj)
				cp["headers"] = []any{hm}
				nr.matches = append(nr.matches, cp)
			}
			// the header rule goes before the rule it shadows
			for i, r := range pr.rules {
				if r == m.rule {
					pr.rules = append(pr.rules[:i], append([]*cvRule{nr}, pr.rules[i:]...)...)
					break
				}
			}
			c.done(ic.src, nginxPrefix+"canary-by-header", hdr, "separate rule with a header match to the canary backend")
			for _, n := range []string{"canary-by-header-value", "canary-by-header-pattern"} {
				if v, ok := ic.ann[n]; ok {
					c.done(ic.src, nginxPrefix+n, v, "header match value")
				}
			}
		}
		if v, ok := ic.get("canary-weight"); ok {
			w, err := strconv.Atoi(v)
			if err != nil || w < 0 || w > total {
				pr.todos = append(pr.todos, c.todo(ic.src, nginxPrefix+"canary-weight", v, "the weight is not a number between 0 and canary-weight-total"))
			} else {
				for _, b := range m.rule.backends {
					asMap(b)["weight"] = total - w
				}
				canaryRef["weight"] = w
				m.rule.backends = append(m.rule.backends, canaryRef)
				c.done(ic.src, nginxPrefix+"canary-weight", v, "weighted backendRefs ("+strconv.Itoa(total-w)+" to "+strconv.Itoa(w)+")")
				if t, ok := ic.get("canary-weight-total"); ok {
					c.done(ic.src, nginxPrefix+"canary-weight-total", t, "weighted backendRefs")
				}
			}
		}
		if v, ok := ic.get("canary-by-cookie"); ok {
			pr.todos = append(pr.todos, c.todo(ic.src, nginxPrefix+"canary-by-cookie", v, "HTTPRoute cannot match on cookies; route canary users by a header instead or use a controller policy"))
		}
		_ = pr
	}
	// Anything else on a canary Ingress has no effect in ingress-nginx; report it.
	for _, n := range sortedKeys(ic.ann) {
		if !ic.used[n] {
			ic.used[n] = true
			c.ignore(ic.src, nginxPrefix+n, ic.ann[n], "ingress-nginx applies only the canary annotations of a canary Ingress; the main Ingress's annotations win")
		}
	}
	return true
}

func deepCopy(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func deepCopyList(in []any) []any {
	if in == nil {
		return nil
	}
	return deepCopy(in).([]any)
}

// finishUnused records every annotation nothing consumed.
func (c *converter) finishUnused(ic *ingCtx) {
	for _, n := range sortedKeys(ic.ann) {
		if ic.used[n] {
			continue
		}
		v := ic.ann[n]
		reason := convertReason(n)
		if ic.kind == kindTLSRoute {
			reason = "the host is a TLS passthrough route: the gateway never sees the HTTP request, so this HTTP-level setting cannot apply"
		}
		ic.todos = append(ic.todos, c.todo(ic.src, nginxPrefix+n, v, reason))
	}
	if v := annotationsOf(ic.ing)["kubernetes.io/ingress.class"]; v != "" {
		c.ignore(ic.src, "kubernetes.io/ingress.class", v, "replaced by the Gateway parentRef")
	}
}

var convertReasons = map[string]string{
	"proxy-body-size":         "Gateway API has no request body limit and the Setura gateway has none per route; enforce it in the backend or in front of the gateway",
	"client-body-buffer-size": "no Gateway API equivalent; the Setura gateway streams request bodies",
	"limit-rps":               "the Setura gateway rate limit is gateway-wide (setura gateway run --rate-limit N/s), not per route; set it there or leave rate limiting to the backend",
	"limit-rpm":               "the Setura gateway rate limit is gateway-wide (setura gateway run --rate-limit N/m), not per route",
	"limit-connections":       "no per-route connection limit in Gateway API or the Setura gateway",
	"proxy-connect-timeout":   "HTTPRoute timeouts cover the request and the backend request only, not the connect phase",
	"configuration-snippet":   "arbitrary nginx configuration has no Gateway API equivalent; re-express each directive as a filter or policy by hand",
	"server-snippet":          "arbitrary nginx configuration has no Gateway API equivalent; re-express each directive as a filter or policy by hand",
	"auth-tls-secret":         "client certificate verification belongs on the Gateway listener (tls.frontend validation), not on a route",
	"auth-tls-verify-client":  "client certificate verification belongs on the Gateway listener (tls.frontend validation), not on a route",
	"proxy-ssl-secret":        "a client certificate for the backend goes on the Gateway (spec.tls.backend.clientCertificateRef), not on a route",
	"canary":                  "canary: false does nothing; remove it",
}

func convertReason(name string) string {
	if r, ok := convertReasons[name]; ok {
		return r
	}
	if r, ok := annotationTable[name]; ok {
		if r.support == supportFilter && r.filter == "" {
			return r.hint
		}
		return "no mechanical equivalent: " + strings.TrimPrefix(r.hint, "unsupported: ")
	}
	return "not recognised by Setura's annotation table; check the ingress-nginx documentation for what it does and re-express it by hand"
}

// ---- writing routes ------------------------------------------------------

func hostSlug(host string) string { return nameFromHost(host) }

func (c *converter) materialise(pr *pendRoute) {
	ic := pr.ic
	ns := ic.ns
	name := ingress2gatewayName(ic.name, pr.host)
	var hostnames []any
	for _, h := range pr.hosts {
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}
	// Listeners.
	var mainRefs, httpRefs, httpsRefs []any
	for _, h := range pr.hosts {
		slug := hostSlug(h)
		listenerBase := obj{}
		if h != "" {
			listenerBase["hostname"] = h
		}
		mk := func(suffix, proto string, port int) obj {
			l := obj{"name": slug + "-" + suffix, "port": port, "protocol": proto}
			for k, v := range listenerBase {
				l[k] = v
			}
			return l
		}
		ref := func(suffix string) obj { return obj{"name": pr.gw.name, "sectionName": slug + "-" + suffix} }
		switch {
		case pr.kind == kindTLSRoute:
			l := mk("tls", "TLS", 443)
			l["tls"] = obj{"mode": "Passthrough"}
			pr.gw.listener(slug+"-tls", l)
			mainRefs = append(mainRefs, ref("tls"))
		default:
			pr.gw.listener(slug+"-http", mk("http", "HTTP", 80))
			if ic.tlsHosts[h] || (h != "" && ic.tlsHosts[""]) {
				l := mk("https", "HTTPS", 443)
				tls := obj{"mode": "Terminate"}
				secret := ic.tlsSecret[h]
				if secret == "" {
					secret = ic.tlsSecret[""]
				}
				if secret != "" {
					tls["certificateRefs"] = []any{obj{"name": secret}}
				} else {
					pr.todos = append(pr.todos, c.todo(ic.src, "spec.tls", h, "the tls block has no secretName (ingress-nginx serves its default certificate); add certificateRefs to listener "+slug+"-https"))
				}
				l["tls"] = tls
				pr.gw.listener(slug+"-https", l)
				mainRefs = append(mainRefs, ref("https"))
				httpsRefs = append(httpsRefs, ref("https"))
				httpRefs = append(httpRefs, ref("http"))
				if !pr.redirect {
					mainRefs = append(mainRefs, ref("http"))
				}
			} else {
				mainRefs = append(mainRefs, ref("http"))
				if pr.entry == "https" {
					pr.todos = append(pr.todos, c.todo(ic.src, "entry point websecure", h, "the host has no TLS configuration, so there is no HTTPS listener; the route is attached to the HTTP listener"))
				}
			}
		}
	}
	switch {
	case pr.entry == "http" && len(httpRefs) > 0:
		mainRefs = httpRefs
	case pr.entry == "https" && len(httpsRefs) > 0:
		mainRefs = httpsRefs
	}
	mainRefs = dedupeRefs(mainRefs)
	var rules []*cvRule
	if pr.appRoot != "" {
		rules = append(rules, &cvRule{
			matches: []any{obj{"path": obj{"type": "Exact", "value": "/"}}},
			filters: []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"statusCode": 302, "path": obj{"type": "ReplaceFullPath", "replaceFullPath": pr.appRoot}}}},
		})
		c.done(ic.src, nginxPrefix+"app-root", pr.appRoot, "extra rule: Exact / with RequestRedirect 302")
		for _, h := range pr.hosts {
			c.expectedExtra[name+"|"+h+"|redirect"] = true
		}
	}
	rules = append(rules, pr.rules...)
	for _, r := range pr.rules {
		if hasFilter(r, "RequestRedirect") && len(r.backends) == 0 {
			for _, h := range pr.hosts {
				c.expectedExtra[name+"|"+h+"|redirect"] = true
			}
		}
	}
	var rl []any
	ann := map[string]any{}
	for i, r := range rules {
		for _, b := range r.backends {
			if bns := asStr(asMap(b)["namespace"]); bns != "" && bns != ns {
				c.needGrant(bns, ns, pr.kind, asStr(asMap(b)["name"]))
			}
		}
		rl = append(rl, r.obj(pr.kind))
		if len(r.auth) > 0 && pr.kind == kindHTTPRoute {
			b, _ := json.Marshal(r.auth)
			ann["setura.zyvor.dev/auth.rule-"+strconv.Itoa(i+1)] = string(b)
		}
	}
	spec := obj{"parentRefs": mainRefs, "rules": rl}
	if len(hostnames) > 0 {
		spec["hostnames"] = hostnames
	}
	o := mkObj(gatewayAPIVersion, pr.kind, ns, name)
	o["spec"] = spec
	if len(ann) > 0 {
		asMap(o["metadata"])["annotations"] = ann
	}
	res := c.add(pr.kind, ns, name, o)
	res.Comments = uniqueLines(append(append([]string{}, ic.todos...), pr.todos...))
	for _, h := range pr.hosts[1:] {
		c.expectedExtra[res.Name+"|"+h+"|all"] = true
	}
	if len(pr.hosts) > 1 {
		c.done(ic.src, nginxPrefix+"server-alias", strings.Join(pr.hosts[1:], ","), "extra route hostnames and listeners")
	}
	if pr.redirect && pr.kind != kindTLSRoute {
		ro := mkObj(gatewayAPIVersion, kindHTTPRoute, ns, res.Name+"-redirect")
		rspec := obj{"parentRefs": dedupeRefs(httpRefs), "rules": []any{obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"scheme": "https", "statusCode": 301}}}}}}
		if len(hostnames) > 0 {
			rspec["hostnames"] = hostnames
		}
		ro["spec"] = rspec
		rres := c.add(kindHTTPRoute, ns, res.Name+"-redirect", ro)
		c.redirectRoutes[rres.Name] = true
	}
	for _, svc := range sortedKeys(pr.tlsBackends) {
		c.backendTLS(ic, svc)
	}
}

func dedupeRefs(in []any) []any {
	seen := map[string]bool{}
	var out []any
	for _, r := range in {
		m := asMap(r)
		k := asStr(m["name"]) + "/" + asStr(m["sectionName"])
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

// tlsSiblings consumes the annotations that tune the TLS to the backend.
func (c *converter) tlsSiblings(ic *ingCtx) {
	if v, ok := ic.get("proxy-ssl-name"); ok {
		c.done(ic.src, nginxPrefix+"proxy-ssl-name", v, "BackendTLSPolicy validation.hostname")
	}
	if v, ok := ic.get("proxy-ssl-verify"); ok {
		c.ignore(ic.src, nginxPrefix+"proxy-ssl-verify", v, "BackendTLSPolicy always verifies; see the TODO on the policy")
	}
}

// backendTLS generates the BackendTLSPolicy for a Service reached over TLS.
func (c *converter) backendTLS(ic *ingCtx, svc string) {
	key := ic.ns + "/" + svc
	if c.tlsPolicies[key] {
		return
	}
	c.tlsPolicies[key] = true
	hostname := svc + "." + ic.ns + ".svc"
	if v, ok := ic.ann["proxy-ssl-name"]; ok {
		hostname = v
	}
	var notes []string
	caRef := obj{"group": "", "kind": "ConfigMap", "name": svc + "-ca"}
	notes = append(notes, c.todo(ic.src, "BackendTLSPolicy "+svc+"-backend-tls", "",
		"the original does not verify the backend certificate unless configured to, but BackendTLSPolicy always does; create ConfigMap "+svc+"-ca with the backend CA in ca.crt (or set wellKnownCACertificates: System) and check the hostname"))
	o := mkObj(gatewayAPIVersion, "BackendTLSPolicy", ic.ns, svc+"-backend-tls")
	o["spec"] = obj{
		"targetRefs": []any{obj{"group": "", "kind": "Service", "name": svc}},
		"validation": obj{"hostname": hostname, "caCertificateRefs": []any{caRef}},
	}
	res := c.add("BackendTLSPolicy", ic.ns, svc+"-backend-tls", o)
	res.Comments = notes
}

func uniqueLines(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range in {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
