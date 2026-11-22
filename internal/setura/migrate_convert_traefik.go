package setura

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Traefik IngressRoute / IngressRouteTCP (traefik.io and traefik.containo.us)
// and Middleware to Gateway + HTTPRoute / TLSRoute. The documented subset of
// the match language is Host, PathPrefix, Path, PathRegexp, Headers and
// Method joined with &&. Anything else is a TODO on the route it appears in.
// The entry points web and websecure mean HTTP on 80 and HTTPS on 443.

var matchTerm = regexp.MustCompile("^([A-Za-z]+)\\((.*)\\)$")
var backtickArg = regexp.MustCompile("`([^`]*)`")

type tMatch struct {
	hosts   []string
	pathTyp string
	path    string
	headers []obj
	method  string
}

// parseTraefikMatch reads a Traefik rule. The error text becomes the TODO reason.
func parseTraefikMatch(expr string) (tMatch, string) {
	var m tMatch
	if strings.Contains(expr, "||") || strings.Contains(expr, "!") || strings.Contains(expr, "(`") && strings.Count(expr, "(") != strings.Count(expr, ")") {
		return m, "the rule uses ||, ! or nested expressions; split it into one route per alternative"
	}
	for _, term := range strings.Split(expr, "&&") {
		term = strings.TrimSpace(term)
		mm := matchTerm.FindStringSubmatch(term)
		if mm == nil {
			return m, "cannot read the rule term " + term
		}
		var args []string
		for _, a := range backtickArg.FindAllStringSubmatch(mm[2], -1) {
			args = append(args, a[1])
		}
		if len(args) == 0 {
			return m, "the rule term " + term + " has no backtick-quoted argument"
		}
		switch mm[1] {
		case "Host", "HostSNI":
			for _, h := range args {
				if h == "*" && mm[1] == "HostSNI" {
					h = ""
				}
				m.hosts = append(m.hosts, strings.ToLower(h))
			}
		case "PathPrefix":
			if len(args) != 1 || m.path != "" {
				return m, "only one path matcher per rule is supported"
			}
			m.pathTyp, m.path = "PathPrefix", args[0]
		case "Path":
			if len(args) != 1 || m.path != "" {
				return m, "only one path matcher per rule is supported"
			}
			m.pathTyp, m.path = "Exact", args[0]
		case "PathRegexp":
			if len(args) != 1 || m.path != "" {
				return m, "only one path matcher per rule is supported"
			}
			m.pathTyp, m.path = "RegularExpression", args[0]
		case "Headers":
			if len(args) != 2 {
				return m, "Headers needs a name and a value"
			}
			m.headers = append(m.headers, obj{"name": args[0], "type": "Exact", "value": args[1]})
		case "HeadersRegexp":
			if len(args) != 2 {
				return m, "HeadersRegexp needs a name and a pattern"
			}
			m.headers = append(m.headers, obj{"name": args[0], "type": "RegularExpression", "value": args[1]})
		case "Method":
			if len(args) != 1 {
				return m, "only one Method per rule is supported"
			}
			m.method = strings.ToUpper(args[0])
		default:
			return m, "the matcher " + mm[1] + " has no Gateway API equivalent (supported: Host, PathPrefix, Path, PathRegexp, Headers, HeadersRegexp, Method)"
		}
	}
	return m, ""
}

type traefikCtx struct {
	c    *converter
	mws  map[string]obj // ns/name -> Middleware
	ns   string
	src  string
	ic   *ingCtx
	todo []string
}

func (c *converter) convertTraefik(objs []obj) error {
	mws := map[string]obj{}
	for _, m := range ofKind(objs, "Middleware") {
		n, ns := metaOf(m)
		mws[ns+"/"+n] = m
	}
	c.loadSupport(objs)
	var routes []obj
	for _, o := range ofKind(objs, "IngressRoute", "IngressRouteTCP") {
		if !strings.HasPrefix(asStr(o["apiVersion"]), "traefik.") {
			continue
		}
		routes = append(routes, o)
	}
	for _, o := range ofKind(objs, "IngressRouteUDP", "TraefikService", "ServersTransport", "TLSOption", "TLSStore") {
		n, ns := metaOf(o)
		c.record(convItem{Source: asStr(o["kind"]) + " " + ns + "/" + n, Key: "kind", Value: asStr(o["kind"]), Status: convTodo,
			Reason: "this Traefik kind is not converted; re-create it with Gateway API or Setura gateway settings"})
	}
	if len(routes) == 0 {
		return userError("no Traefik IngressRoute objects found; nothing to convert")
	}
	for _, o := range routes {
		c.traefikRoute(o, mws)
	}
	return nil
}

func (c *converter) traefikRoute(o obj, mws map[string]obj) {
	name, ns := metaOf(o)
	if ns == "" {
		ns = c.ns
	}
	kind := asStr(o["kind"])
	src := kind + " " + ns + "/" + name
	ic := &ingCtx{src: src, name: name, ns: ns, ann: map[string]string{}, used: map[string]bool{}, tlsSecret: map[string]string{}, tlsHosts: map[string]bool{}, kind: kindHTTPRoute}
	tc := &traefikCtx{c: c, mws: mws, ns: ns, src: src, ic: ic}
	spec := asMap(o["spec"])
	passthrough := kind == "IngressRouteTCP" && asMap(spec["tls"]) != nil && asMap(spec["tls"])["passthrough"] == true
	if kind == "IngressRouteTCP" {
		if !passthrough {
			ic.todos = append(ic.todos, c.todo(src, "spec", "", "only TLS passthrough IngressRouteTCP converts (to a TLSRoute); plain TCP routes need a TCPRoute by hand"))
			c.traefikEmitTODOOnly(ic)
			return
		}
		ic.kind = kindTLSRoute
	}
	entry := ""
	hasWeb, hasSecure := false, false
	for _, e := range asList(spec["entryPoints"]) {
		switch s := asStr(e); s {
		case "web":
			hasWeb = true
		case "websecure":
			hasSecure = true
		default:
			ic.todos = append(ic.todos, c.todo(src, "spec.entryPoints", s, "the port of entry point "+s+" is not known here; web is read as HTTP on 80 and websecure as HTTPS on 443"))
			hasWeb = true
		}
	}
	switch {
	case hasWeb && !hasSecure:
		entry = "http"
	case hasSecure && !hasWeb:
		entry = "https"
	}
	if t := asMap(spec["tls"]); t != nil {
		secret := asStr(t["secretName"])
		if asStr(t["certResolver"]) != "" {
			ic.todos = append(ic.todos, c.todo(src, "spec.tls.certResolver", asStr(t["certResolver"]), "ACME certificates from a Traefik resolver have no Gateway API field; use cert-manager and a secretName"))
		}
		ic.tlsHosts[""] = true
		ic.tlsSecret[""] = secret
		c.done(src, "spec.tls", secret, "HTTPS listener with certificateRefs")
	}
	gwName := "traefik"
	gw := c.gateway(ns, gwName)
	byHost := map[string]*pendRoute{}
	var order []string
	synthPaths := map[string][]any{}
	regexPaths := map[string][]any{}
	for ri, rt := range asList(spec["routes"]) {
		rm := asMap(rt)
		match := asStr(rm["match"])
		tm, why := parseTraefikMatch(match)
		if why != "" {
			ic.todos = append(ic.todos, c.todo(src, fmt.Sprintf("spec.routes[%d].match", ri), truncate(match, 60), why+"; the route was not converted"))
			continue
		}
		if _, ok := rm["priority"]; ok {
			ic.todos = append(ic.todos, c.todo(src, fmt.Sprintf("spec.routes[%d].priority", ri), fmt.Sprint(rm["priority"]), "Gateway API orders matches by specificity, not by an explicit priority; check which rule should win"))
		}
		hosts := tm.hosts
		if len(hosts) == 0 {
			hosts = []string{""}
		}
		for _, h := range hosts {
			cr := &cvRule{}
			if ic.kind == kindHTTPRoute {
				mt := obj{}
				if tm.path != "" {
					mt["path"] = obj{"type": tm.pathTyp, "value": tm.path}
				} else if len(tm.headers) == 0 && tm.method == "" {
					mt["path"] = obj{"type": "PathPrefix", "value": "/"}
				}
				if len(tm.headers) > 0 {
					var hs []any
					for _, x := range tm.headers {
						hs = append(hs, x)
					}
					mt["headers"] = hs
				}
				if tm.method != "" {
					mt["method"] = tm.method
				}
				cr.matches = []any{mt}
			}
			var firstSvc obj
			var weights []int
			for _, s := range asList(rm["services"]) {
				sm := asMap(s)
				if k := asStr(sm["kind"]); k != "" && k != "Service" {
					ic.todos = append(ic.todos, c.todo(src, "spec.routes.services.kind", k, "only plain Services convert; a "+k+" has no backendRef equivalent"))
					continue
				}
				svcName := asStr(sm["name"])
				port := 0
				switch p := sm["port"].(type) {
				case float64:
					port = int(p)
				case string:
					if n, err := strconv.Atoi(p); err == nil {
						port = n
					} else if sv := findService(c.svcs, ns, svcName); sv != nil {
						for _, sp := range sv.Ports {
							if sp.Name == p {
								port = sp.Port
							}
						}
					}
					if port == 0 {
						ic.todos = append(ic.todos, c.todo(src, "spec.routes.services.port", p, "the named port could not be resolved to a number (no Service "+svcName+" in the inputs); set the port by hand"))
					}
				}
				bns := ""
				if n := asStr(sm["namespace"]); n != "" && n != ns {
					bns = n
					c.done(src, "spec.routes.services.namespace", n, "backendRef namespace and a ReferenceGrant")
				}
				weight := -1
				if w, ok := num(sm["weight"]); ok {
					weight = int(w)
				}
				weights = append(weights, weight)
				br := backendRef(svcName, bns, port, weight)
				cr.backends = append(cr.backends, br)
				if firstSvc == nil {
					firstSvc = br
				}
				if sc := asStr(sm["scheme"]); sc == "https" {
					c.backendTLS(ic, svcName)
				} else if sc == "h2c" {
					ic.todos = append(ic.todos, c.todo(src, "spec.routes.services.scheme", sc, "h2c (gRPC or HTTP/2 cleartext) needs a GRPCRoute or appProtocol kubernetes.io/h2c on the Service port"))
				}
			}
			if len(cr.backends) == 1 {
				delete(asMap(cr.backends[0]), "weight")
			}
			for _, mw := range asList(rm["middlewares"]) {
				mmw := asMap(mw)
				tc.middleware(asStr(mmw["name"]), firstNonEmpty(asStr(mmw["namespace"]), ns), cr, tm, 0)
			}
			if len(cr.backends) == 0 && !hasFilter(cr, "RequestRedirect") {
				continue
			}
			if hasFilter(cr, "RequestRedirect") {
				cr.backends = nil
			}
			pr := byHost[h]
			if pr == nil {
				pr = &pendRoute{ic: ic, host: h, hosts: []string{h}, kind: ic.kind, gw: gw, tlsBackends: map[string]bool{}, entry: entry}
				if ic.kind == kindTLSRoute {
					cr.matches = nil
				}
				byHost[h] = pr
				order = append(order, h)
			}
			if ic.kind == kindTLSRoute {
				cr.filters, cr.matches = nil, nil
			}
			pr.rules = append(pr.rules, cr)
			// the synthetic Ingress the round trip compares against
			if firstSvc != nil && !hasFilter(cr, "RequestRedirect") {
				pt := map[string]string{"PathPrefix": "Prefix", "Exact": "Exact", "RegularExpression": "Prefix"}[tm.pathTyp]
				path := tm.path
				if pt == "" {
					pt, path = "Prefix", "/"
				}
				sp := obj{"number": firstSvc["port"]}
				if firstSvc["port"] == nil {
					sp = obj{"number": 0}
				}
				p := obj{"path": path, "pathType": pt, "backend": obj{"service": obj{"name": firstSvc["name"], "port": sp}}}
				if tm.pathTyp == "RegularExpression" {
					regexPaths[h] = append(regexPaths[h], p)
				} else {
					synthPaths[h] = append(synthPaths[h], p)
				}
			}
		}
	}
	for _, h := range order {
		pr := byHost[h]
		c.materialise(pr)
	}
	// Synthetic Ingress objects for the round trip: what the original means,
	// in the shape migrate check compares.
	mkSynth := func(suffix string, paths map[string][]any, regex bool) {
		var rules []any
		for _, h := range order {
			if ps := paths[h]; len(ps) > 0 {
				r := obj{"http": obj{"paths": ps}}
				if h != "" {
					r["host"] = h
				}
				rules = append(rules, r)
			}
		}
		if len(rules) == 0 {
			return
		}
		ing := mkObj("networking.k8s.io/v1", "Ingress", ns, name+suffix)
		sp := obj{"rules": rules}
		ann := obj{}
		if regex {
			ann[nginxPrefix+"use-regex"] = "true"
		}
		if len(ann) > 0 {
			asMap(ing["metadata"])["annotations"] = ann
		}
		if ic.tlsHosts[""] && ic.tlsSecret[""] != "" && entry != "http" {
			var hs []any
			for _, h := range order {
				if h != "" {
					hs = append(hs, h)
				}
			}
			sp["tls"] = []any{obj{"hosts": hs, "secretName": ic.tlsSecret[""]}}
		}
		ing["spec"] = sp
		c.synthetic = append(c.synthetic, ing)
	}
	if ic.kind == kindTLSRoute {
		pass := map[string][]any{}
		for _, h := range order {
			for _, r := range byHost[h].rules {
				b := asMap(r.backends[0])
				pass[h] = append(pass[h], obj{"path": "/", "pathType": "Prefix", "backend": obj{"service": obj{"name": b["name"], "port": obj{"number": b["port"]}}}})
			}
		}
		var rules []any
		for _, h := range order {
			for _, p := range pass[h] {
				rules = append(rules, obj{"host": h, "http": obj{"paths": []any{p}}})
			}
		}
		if len(rules) > 0 {
			ing := mkObj("networking.k8s.io/v1", "Ingress", ns, name)
			asMap(ing["metadata"])["annotations"] = obj{nginxPrefix + "ssl-passthrough": "true"}
			ing["spec"] = obj{"rules": rules}
			c.synthetic = append(c.synthetic, ing)
		}
	} else {
		mkSynth("", synthPaths, false)
		mkSynth("-regex", regexPaths, true)
	}
	// A route with nothing convertible still reports its TODOs.
	if len(order) == 0 {
		c.traefikEmitTODOOnly(ic)
	}
}

// traefikEmitTODOOnly keeps the TODO lines of a route nothing was generated
// for as a comment-only note in the report (there is no object to hold them).
func (c *converter) traefikEmitTODOOnly(ic *ingCtx) {
	c.notes = append(c.notes, fmt.Sprintf("%s produced no route; see the TODO items in the report", ic.src))
}

func hasFilter(cr *cvRule, typ string) bool {
	for _, f := range cr.filters {
		if asStr(asMap(f)["type"]) == typ {
			return true
		}
	}
	return false
}

// middleware applies one Traefik Middleware to a rule.
func (tc *traefikCtx) middleware(name, ns string, cr *cvRule, tm tMatch, depth int) {
	c := tc.c
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	m := tc.mws[ns+"/"+name]
	msrc := "Middleware " + ns + "/" + name
	if m == nil {
		tc.ic.todos = append(tc.ic.todos, c.todo(tc.src, "middlewares", name, "Middleware "+ns+"/"+name+" is not in the inputs; its effect was not converted"))
		return
	}
	todo := func(key, value, reason string) {
		tc.ic.todos = append(tc.ic.todos, c.todo(msrc, key, value, reason))
	}
	spec := asMap(m["spec"])
	for _, kind := range sortedKeys(spec) {
		body := asMap(spec[kind])
		switch kind {
		case "chain":
			if depth > 5 {
				todo("chain", "", "chains nested deeper than 5 levels are not followed")
				continue
			}
			for _, ref := range asList(body["middlewares"]) {
				rm := asMap(ref)
				tc.middleware(asStr(rm["name"]), firstNonEmpty(asStr(rm["namespace"]), ns), cr, tm, depth+1)
			}
			c.done(msrc, "chain", "", "each middleware of the chain converted in order")
		case "stripPrefix":
			if tm.pathTyp != "PathPrefix" {
				todo(kind, "", "stripPrefix converts only on a PathPrefix rule")
				continue
			}
			ok := false
			for _, p := range asList(body["prefixes"]) {
				ok = ok || strings.TrimRight(asStr(p), "/") == strings.TrimRight(tm.path, "/")
			}
			if !ok {
				todo(kind, fmt.Sprint(body["prefixes"]), "the stripped prefix differs from the rule's PathPrefix "+tm.path+"; URLRewrite can only replace the matched prefix")
				continue
			}
			cr.filter("URLRewrite", "urlRewrite")["path"] = obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}
			c.done(msrc, kind, tm.path, "URLRewrite ReplacePrefixMatch /")
		case "replacePath":
			cr.filter("URLRewrite", "urlRewrite")["path"] = obj{"type": "ReplaceFullPath", "replaceFullPath": asStr(body["path"])}
			c.done(msrc, kind, asStr(body["path"]), "URLRewrite ReplaceFullPath")
		case "redirectScheme":
			rr := obj{"scheme": asStr(body["scheme"]), "statusCode": 302}
			if body["permanent"] == true {
				rr["statusCode"] = 301
			}
			if p := asStr(body["port"]); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					rr["port"] = n
				}
			}
			cr.filters = append(cr.filters, obj{"type": "RequestRedirect", "requestRedirect": rr})
			c.done(msrc, kind, asStr(body["scheme"]), "RequestRedirect")
		case "headers":
			tc.headers(msrc, body, cr)
		case "rateLimit":
			hint := "the Setura gateway rate limit is gateway-wide (setura gateway run --rate-limit N/s), not per route"
			if n, ok := num(body["average"]); ok {
				per := asStr(body["period"])
				unit := "s"
				switch per {
				case "1m":
					unit = "m"
				case "1h":
					unit = "h"
				}
				hint += "; this middleware allows " + strconv.Itoa(int(n)) + " per " + firstNonEmpty(per, "1s") + " (--rate-limit " + strconv.Itoa(int(n)) + "/" + unit + ")"
			}
			todo(kind, "", hint)
		case "basicAuth", "digestAuth":
			if kind == "digestAuth" {
				todo(kind, "", "digest authentication has no equivalent; use basic, JWT or ExternalAuth")
				continue
			}
			b := obj{"users": []any{}}
			if r := asStr(body["realm"]); r != "" {
				b["realm"] = r
			}
			cr.authBlock()["basic"] = b
			todo(kind, asStr(body["secret"]), "the basic auth block has no users: Traefik reads htpasswd entries from Secret "+asStr(body["secret"])+" (bcrypt/apr1), Setura stores pbkdf2-sha256; create each user with `setura gateway hash --kind password`")
		case "ipAllowList", "ipWhiteList":
			if len(asMap(body["ipStrategy"])) > 0 {
				todo(kind+".ipStrategy", "", "client address depth is a gateway option: setura gateway run --trusted-proxies")
			}
			cr.authBlock()["ipAllow"] = body["sourceRange"]
			c.done(msrc, kind, fmt.Sprint(body["sourceRange"]), "setura.zyvor.dev/auth ipAllow")
		case "retry":
			retry := obj{"attempts": 4}
			if n, ok := num(body["attempts"]); ok {
				retry["attempts"] = int(n)
			}
			if d, ok := durationOf(asStr(body["initialInterval"])); ok {
				retry["backoff"] = d
			}
			cr.retry = retry
			c.done(msrc, kind, fmt.Sprint(body["attempts"]), "rule retry")
		case "forwardAuth":
			svc, sns, port, path, ok := svcFromURL(asStr(body["address"]), tc.ns)
			if !ok {
				todo(kind, asStr(body["address"]), "the address is not a Service of this cluster; ExternalAuth needs a backendRef")
				continue
			}
			nsOut := ""
			if sns != tc.ns {
				nsOut = sns
			}
			ea := obj{"protocol": "HTTP", "backendRef": backendRef(svc, nsOut, port, -1)}
			h := obj{}
			if path != "" && path != "/" {
				h["path"] = path
			}
			if hs := asList(body["authResponseHeaders"]); len(hs) > 0 {
				h["allowedResponseHeaders"] = hs
			}
			if len(h) > 0 {
				ea["http"] = h
			}
			cr.filters = append(cr.filters, obj{"type": "ExternalAuth", "externalAuth": ea})
			target := "ExternalAuth filter"
			if nsOut != "" {
				c.needGrant(nsOut, tc.ns, kindHTTPRoute, svc)
				target += " and a ReferenceGrant in " + nsOut
			}
			c.done(msrc, kind, asStr(body["address"]), target)
		default:
			todo(kind, "", "no Gateway API or Setura equivalent for this middleware")
		}
	}
}

// securityHeaders are the Headers middleware fields that are plain response
// headers.
func (tc *traefikCtx) headers(msrc string, body obj, cr *cvRule) {
	c := tc.c
	todo := func(key, reason string) {
		tc.ic.todos = append(tc.ic.todos, c.todo(msrc, "headers."+key, "", reason))
	}
	setResp := func(name, value, key string) {
		cr.setResponseHeader(name, value)
		c.done(msrc, "headers."+key, value, "ResponseHeaderModifier set "+name)
	}
	cors := obj{}
	for _, k := range sortedKeys(body) {
		switch k {
		case "customRequestHeaders":
			f := cr.filter("RequestHeaderModifier", "requestHeaderModifier")
			for _, n := range sortedKeys(asMap(body[k])) {
				v := asStr(asMap(body[k])[n])
				if v == "" {
					f["remove"] = append(asList(f["remove"]), n)
				} else {
					f["set"] = append(asList(f["set"]), obj{"name": n, "value": v})
				}
			}
			c.done(msrc, "headers."+k, "", "RequestHeaderModifier")
		case "customResponseHeaders":
			f := cr.filter("ResponseHeaderModifier", "responseHeaderModifier")
			for _, n := range sortedKeys(asMap(body[k])) {
				v := asStr(asMap(body[k])[n])
				if v == "" {
					f["remove"] = append(asList(f["remove"]), n)
				} else {
					f["set"] = append(asList(f["set"]), obj{"name": n, "value": v})
				}
			}
			c.done(msrc, "headers."+k, "", "ResponseHeaderModifier")
		case "accessControlAllowOriginList":
			cors["allowOrigins"] = body[k]
		case "accessControlAllowMethods":
			cors["allowMethods"] = body[k]
		case "accessControlAllowHeaders":
			cors["allowHeaders"] = body[k]
		case "accessControlExposeHeaders":
			cors["exposeHeaders"] = body[k]
		case "accessControlAllowCredentials":
			cors["allowCredentials"] = body[k]
		case "accessControlMaxAge":
			cors["maxAge"] = body[k]
		case "stsSeconds":
			v := "max-age=" + fmt.Sprint(int(func() float64 { n, _ := num(body[k]); return n }()))
			if body["stsIncludeSubdomains"] == true {
				v += "; includeSubDomains"
			}
			if body["stsPreload"] == true {
				v += "; preload"
			}
			setResp("Strict-Transport-Security", v, k)
		case "stsIncludeSubdomains", "stsPreload":
		case "frameDeny":
			if body[k] == true {
				setResp("X-Frame-Options", "DENY", k)
			}
		case "customFrameOptionsValue":
			setResp("X-Frame-Options", asStr(body[k]), k)
		case "contentTypeNosniff":
			if body[k] == true {
				setResp("X-Content-Type-Options", "nosniff", k)
			}
		case "browserXssFilter":
			if body[k] == true {
				setResp("X-XSS-Protection", "1; mode=block", k)
			}
		case "referrerPolicy":
			setResp("Referrer-Policy", asStr(body[k]), k)
		case "contentSecurityPolicy":
			setResp("Content-Security-Policy", asStr(body[k]), k)
		case "permissionsPolicy":
			setResp("Permissions-Policy", asStr(body[k]), k)
		default:
			todo(k, "no Gateway API equivalent (it changes redirects, host checks or proxy headers inside Traefik)")
		}
	}
	if len(cors) > 0 {
		if v, ok := cors["maxAge"]; ok {
			n, _ := num(v)
			cors["maxAge"] = int(n)
		}
		cr.filters = append(cr.filters, obj{"type": "CORS", "cors": cors})
		c.done(msrc, "headers.accessControl*", "", "CORS filter")
	}
}
