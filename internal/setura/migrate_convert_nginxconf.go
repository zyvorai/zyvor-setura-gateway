package setura

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// nginx.conf to Gateway + HTTPRoute, for the documented subset only:
//
//	http { upstream NAME { server HOST:PORT [weight=N]; }
//	       server { listen 80|443 [ssl]; server_name HOST...;
//	                location [=|^~|~] URI { proxy_pass; proxy_set_header; add_header;
//	                                         proxy_read_timeout; proxy_send_timeout;
//	                                         return 301|302 URL; allow/deny } } }
//
// Everything else is refused with its line number. Backends must be Service
// names (NAME, NAME:PORT, NAME.NAMESPACE.svc[.cluster.local]:PORT or an
// upstream of those); IP addresses and external hosts are refused.

type ngDirective struct {
	name     string
	args     []string
	line     int
	children []*ngDirective
	block    bool
}

type ngToken struct {
	text string
	line int
	punc bool // { } ;
}

func ngTokenize(src string) []ngToken {
	var toks []ngToken
	line := 1
	i := 0
	for i < len(src) {
		ch := src[i]
		switch {
		case ch == '\n':
			line++
			i++
		case ch == ' ' || ch == '\t' || ch == '\r':
			i++
		case ch == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case ch == '{' || ch == '}' || ch == ';':
			toks = append(toks, ngToken{string(ch), line, true})
			i++
		case ch == '"' || ch == '\'':
			start, startLine := i+1, line
			i++
			for i < len(src) && src[i] != ch {
				if src[i] == '\\' {
					i++
				}
				if i < len(src) && src[i] == '\n' {
					line++
				}
				i++
			}
			toks = append(toks, ngToken{src[start:min(i, len(src))], startLine, false})
			i++
		default:
			start := i
			for i < len(src) && !strings.ContainsRune(" \t\r\n;{}#", rune(src[i])) {
				i++
			}
			toks = append(toks, ngToken{src[start:i], line, false})
		}
	}
	return toks
}

func ngParse(toks []ngToken, file string, errs *[]string) []*ngDirective {
	pos := 0
	var parseList func(depth int) []*ngDirective
	parseList = func(depth int) []*ngDirective {
		var out []*ngDirective
		for pos < len(toks) {
			t := toks[pos]
			if t.punc && t.text == "}" {
				if depth == 0 {
					*errs = append(*errs, fmt.Sprintf("%s:%d: unexpected }", file, t.line))
					pos++
					continue
				}
				pos++
				return out
			}
			if t.punc {
				*errs = append(*errs, fmt.Sprintf("%s:%d: unexpected %s", file, t.line, t.text))
				pos++
				continue
			}
			d := &ngDirective{name: t.text, line: t.line}
			pos++
			for pos < len(toks) && !toks[pos].punc {
				d.args = append(d.args, toks[pos].text)
				pos++
			}
			if pos >= len(toks) {
				*errs = append(*errs, fmt.Sprintf("%s:%d: directive %s is not terminated by ; or {", file, d.line, d.name))
				return out
			}
			if toks[pos].text == "{" {
				pos++
				d.block = true
				d.children = parseList(depth + 1)
			} else if toks[pos].text == ";" {
				pos++
			} else {
				*errs = append(*errs, fmt.Sprintf("%s:%d: unexpected %s after %s", file, toks[pos].line, toks[pos].text, d.name))
				pos++
			}
			out = append(out, d)
		}
		return out
	}
	return parseList(0)
}

type ngUpstream struct {
	servers []ngServerAddr
}

type ngServerAddr struct {
	name, ns string
	port     int
	weight   int
}

type ngConv struct {
	c          *converter
	file       string
	errs       []string
	upstreams  map[string]ngUpstream
	regexRules []any // synthetic Ingress rules of regular expression locations
}

func (n *ngConv) refuse(line int, format string, a ...any) {
	n.errs = append(n.errs, fmt.Sprintf("%s:%d: %s", n.file, line, fmt.Sprintf(format, a...)))
}

var ngIgnored = map[string]bool{
	"worker_processes": true, "worker_connections": true, "error_log": true, "access_log": true, "log_format": true, "pid": true,
	"user": true, "sendfile": true, "tcp_nopush": true, "tcp_nodelay": true, "keepalive_timeout": true, "server_tokens": true,
	"default_type": true, "types_hash_max_size": true, "worker_rlimit_nofile": true, "multi_accept": true, "use": true,
}

// ngTodo are directives that parse but have no equivalent: they become TODOs
// instead of a refusal.
var ngTodo = map[string]string{
	"ssl_protocols":             "TLS versions and ciphers are listener options of the gateway, not Gateway API route fields",
	"ssl_ciphers":               "TLS versions and ciphers are listener options of the gateway, not Gateway API route fields",
	"ssl_prefer_server_ciphers": "TLS versions and ciphers are listener options of the gateway, not Gateway API route fields",
	"client_max_body_size":      "Gateway API and the Setura gateway have no per-route request body limit",
	"gzip":                      "response compression is not a Gateway API route field",
	"proxy_connect_timeout":     "HTTPRoute timeouts cover the request and the backend request, not the connect phase",
	"proxy_buffering":           "no Gateway API equivalent; the Setura gateway streams responses",
}

func (c *converter) convertNginxConf(files []namedText) []string {
	var all []string
	var ics []*ingCtx
	gw := c.gateway(c.ns, "nginx")
	_ = ics
	for _, f := range files {
		n := &ngConv{c: c, file: f.Name, upstreams: map[string]ngUpstream{}}
		toks := ngTokenize(f.Text)
		var errs []string
		tree := ngParse(toks, f.Name, &errs)
		n.errs = errs
		base := strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name))
		n.top(tree, base, gw)
		all = append(all, n.errs...)
	}
	return all
}

func (n *ngConv) top(tree []*ngDirective, base string, gw *gwBuild) {
	var servers []*ngDirective
	var walk func(ds []*ngDirective, inHTTP bool)
	walk = func(ds []*ngDirective, inHTTP bool) {
		for _, d := range ds {
			switch {
			case d.name == "events" && d.block:
			case d.name == "http" && d.block && !inHTTP:
				walk(d.children, true)
			case d.name == "upstream" && d.block:
				n.upstream(d)
			case d.name == "server" && d.block:
				servers = append(servers, d)
			case ngIgnored[d.name]:
				n.c.ignore("nginx.conf "+filepath.Base(n.file), d.name, strings.Join(d.args, " "), "does not affect routing")
			case ngTodo[d.name] != "":
				n.c.todo("nginx.conf "+filepath.Base(n.file), d.name, strings.Join(d.args, " "), ngTodo[d.name]+" (line "+strconv.Itoa(d.line)+")")
				n.c.notes = append(n.c.notes, fmt.Sprintf("%s:%d: %s has no equivalent (%s)", n.file, d.line, d.name, ngTodo[d.name]))
			case d.name == "include":
				n.refuse(d.line, "include is not followed; pass the included files as inputs too")
			default:
				n.refuse(d.line, "%s is outside the supported subset", d.name)
			}
		}
	}
	walk(tree, false)
	ic := &ingCtx{src: "nginx.conf " + filepath.Base(n.file), name: base, ns: n.c.ns, ann: map[string]string{}, used: map[string]bool{},
		tlsSecret: map[string]string{}, tlsHosts: map[string]bool{}, kind: kindHTTPRoute}
	var synthRules []any
	n.regexRules = nil
	var prs []*pendRoute
	for _, s := range servers {
		prs = append(prs, n.server(s, ic, gw, &synthRules)...)
	}
	if len(n.errs) > 0 {
		return
	}
	for _, pr := range prs {
		n.c.materialise(pr)
	}
	if len(synthRules) > 0 {
		ing := mkObj("networking.k8s.io/v1", "Ingress", n.c.ns, base)
		ing["spec"] = obj{"rules": synthRules}
		n.c.synthetic = append(n.c.synthetic, ing)
	}
	if len(n.regexRules) > 0 {
		ing := mkObj("networking.k8s.io/v1", "Ingress", n.c.ns, base+"-regex")
		asMap(ing["metadata"])["annotations"] = obj{nginxPrefix + "use-regex": "true"}
		ing["spec"] = obj{"rules": n.regexRules}
		n.c.synthetic = append(n.c.synthetic, ing)
	}
}

func (n *ngConv) upstream(d *ngDirective) {
	if len(d.args) != 1 {
		n.refuse(d.line, "upstream needs exactly one name")
		return
	}
	up := ngUpstream{}
	for _, ch := range d.children {
		if ch.name != "server" || len(ch.args) == 0 {
			n.refuse(ch.line, "%s inside an upstream is outside the supported subset (only server lines)", ch.name)
			continue
		}
		addr, ok := n.serviceAddr(ch.args[0], ch.line)
		if !ok {
			continue
		}
		addr.weight = 1
		for _, a := range ch.args[1:] {
			if v, found := strings.CutPrefix(a, "weight="); found {
				w, err := strconv.Atoi(v)
				if err != nil {
					n.refuse(ch.line, "weight=%s is not a number", v)
				}
				addr.weight = w
			} else {
				n.refuse(ch.line, "server parameter %s is outside the supported subset (only weight=N)", a)
			}
		}
		up.servers = append(up.servers, addr)
	}
	n.upstreams[d.args[0]] = up
}

// serviceAddr reads NAME[:PORT] or NAME.NS.svc[.cluster.local][:PORT].
func (n *ngConv) serviceAddr(raw string, line int) (ngServerAddr, bool) {
	host, port := raw, 80
	if i := strings.LastIndex(raw, ":"); i >= 0 {
		p, err := strconv.Atoi(raw[i+1:])
		if err != nil {
			n.refuse(line, "cannot read the port of %s", raw)
			return ngServerAddr{}, false
		}
		host, port = raw[:i], p
	}
	if strings.ContainsAny(host, "$/") || host == "" {
		n.refuse(line, "%s is not a Service name (variables and paths are not supported)", raw)
		return ngServerAddr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(host, ".cluster.local"), ".")
	var name, ns string
	switch {
	case len(parts) == 1:
		name = parts[0]
	case len(parts) == 3 && parts[2] == "svc":
		name, ns = parts[0], parts[1]
	default:
		n.refuse(line, "%s is not a Service of this cluster (use name, name.namespace.svc or an upstream of those)", raw)
		return ngServerAddr{}, false
	}
	return ngServerAddr{name: name, ns: ns, port: port}, true
}

func (n *ngConv) server(s *ngDirective, ic *ingCtx, gw *gwBuild, synth *[]any) []*pendRoute {
	c := n.c
	var hosts []string
	http, https := false, false
	for _, d := range s.children {
		switch d.name {
		case "listen":
			ssl := false
			port := 80
			for _, a := range d.args {
				switch {
				case a == "ssl":
					ssl = true
					port = 443
				case a == "default_server" || a == "http2" || a == "reuseport" || a == "quic":
				default:
					p := a
					if i := strings.LastIndex(a, ":"); i >= 0 {
						p = a[i+1:]
					}
					if v, err := strconv.Atoi(p); err == nil {
						port = v
					}
				}
			}
			if port != 80 && port != 443 {
				n.refuse(d.line, "listen port %d is not supported (only 80 and 443)", port)
			}
			if ssl || port == 443 {
				https = true
			} else {
				http = true
			}
			c.done(ic.src, "listen", strings.Join(d.args, " "), "Gateway listener")
		case "server_name":
			for _, h := range d.args {
				if strings.HasPrefix(h, "~") || strings.Contains(h, "$") {
					n.refuse(d.line, "server_name %s is a regular expression", h)
					continue
				}
				if h == "_" || h == "" {
					h = ""
				}
				hosts = append(hosts, strings.ToLower(h))
			}
		case "location", "ssl_certificate", "ssl_certificate_key":
		default:
			switch {
			case ngIgnored[d.name]:
				c.ignore(ic.src, d.name, strings.Join(d.args, " "), "does not affect routing")
			case ngTodo[d.name] != "":
				c.todo(ic.src, d.name, strings.Join(d.args, " "), ngTodo[d.name])
				c.notes = append(c.notes, fmt.Sprintf("%s:%d: %s has no equivalent (%s)", n.file, d.line, d.name, ngTodo[d.name]))
			default:
				n.refuse(d.line, "%s in a server block is outside the supported subset", d.name)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{""}
	}
	entry := ""
	switch {
	case http && !https:
		entry = "http"
	case https && !http:
		entry = "https"
	}
	var todos []string
	for _, d := range s.children {
		if d.name == "ssl_certificate" || d.name == "ssl_certificate_key" {
			todos = append(todos, c.todo(ic.src, d.name, strings.Join(d.args, " "), "create a TLS Secret from the certificate and key files (kubectl create secret tls NAME --cert=... --key=...) and name it in the listener certificateRefs"))
		}
	}
	var out []*pendRoute
	for _, h := range hosts {
		pr := &pendRoute{ic: &ingCtx{src: ic.src, name: ic.name, ns: ic.ns, ann: ic.ann, used: ic.used, kind: kindHTTPRoute,
			tlsSecret: map[string]string{}, tlsHosts: map[string]bool{}, todos: todos}, host: h, hosts: []string{h}, kind: kindHTTPRoute, gw: gw,
			tlsBackends: map[string]bool{}, entry: entry}
		if https {
			pr.ic.tlsHosts[h] = true
			pr.ic.tlsSecret[h] = hostSlug(h) + "-tls"
		}
		for _, d := range s.children {
			if d.name != "location" {
				continue
			}
			cr, path, typ, ok := n.location(d, pr)
			if !ok {
				continue
			}
			pr.rules = append(pr.rules, cr)
			pt := map[string]string{"PathPrefix": "Prefix", "Exact": "Exact", "RegularExpression": "Prefix"}[typ]
			if len(cr.backends) > 0 {
				b := asMap(cr.backends[0])
				r := obj{"http": obj{"paths": []any{obj{"path": path, "pathType": pt, "backend": obj{"service": obj{"name": b["name"], "port": obj{"number": b["port"]}}}}}}}
				if h != "" {
					r["host"] = h
				}
				if typ == "RegularExpression" {
					n.regexRules = append(n.regexRules, r)
				} else {
					*synth = append(*synth, r)
				}
			}
		}
		if len(pr.rules) > 0 {
			out = append(out, pr)
		}
	}
	return out
}

// location converts one location block.
func (n *ngConv) location(d *ngDirective, pr *pendRoute) (*cvRule, string, string, bool) {
	c := n.c
	src := pr.ic.src
	typ, path := "PathPrefix", ""
	switch len(d.args) {
	case 1:
		path = d.args[0]
	case 2:
		switch d.args[0] {
		case "=":
			typ = "Exact"
		case "^~":
		case "~":
			typ = "RegularExpression"
		default:
			n.refuse(d.line, "location modifier %s is outside the supported subset (supported: = ^~ ~)", d.args[0])
			return nil, "", "", false
		}
		path = d.args[1]
	default:
		n.refuse(d.line, "cannot read this location line")
		return nil, "", "", false
	}
	if strings.HasPrefix(path, "@") {
		n.refuse(d.line, "named location %s is outside the supported subset", path)
		return nil, "", "", false
	}
	cr := &cvRule{}
	matchPath := path
	if typ == "PathPrefix" && len(path) > 1 {
		matchPath = strings.TrimRight(path, "/")
	}
	cr.matches = []any{obj{"path": obj{"type": typ, "value": matchPath}}}
	var proxyPass string
	var allow, deny []string
	timeoutBest, timeoutVal := 0.0, ""
	ok := true
	for _, ch := range d.children {
		args := strings.Join(ch.args, " ")
		switch ch.name {
		case "proxy_pass":
			if len(ch.args) != 1 {
				n.refuse(ch.line, "proxy_pass needs one URL")
				ok = false
			}
			proxyPass = args
		case "proxy_set_header":
			if len(ch.args) != 2 {
				n.refuse(ch.line, "proxy_set_header needs a name and a value")
				ok = false
				continue
			}
			name, v := ch.args[0], ch.args[1]
			switch {
			case strings.EqualFold(name, "Host") && (v == "$host" || v == "$http_host"):
				c.done(src, "proxy_set_header Host", v, "default: the gateway preserves the Host header")
			case v == "$remote_addr" || v == "$proxy_add_x_forwarded_for" || v == "$scheme" || v == "$http_upgrade" && strings.EqualFold(name, "Upgrade") || strings.EqualFold(name, "Connection"):
				c.ignore(src, "proxy_set_header "+name, v, "the gateway sets forwarding headers itself")
			case strings.Contains(v, "$"):
				n.refuse(ch.line, "proxy_set_header %s uses the variable %s, which has no Gateway API equivalent", name, v)
				ok = false
			default:
				cr.setRequestHeader(name, v)
				c.done(src, "proxy_set_header "+name, v, "RequestHeaderModifier set")
			}
		case "add_header":
			if len(ch.args) < 2 || strings.Contains(ch.args[1], "$") {
				n.refuse(ch.line, "add_header needs a literal name and value")
				ok = false
				continue
			}
			cr.setResponseHeader(ch.args[0], ch.args[1])
			c.done(src, "add_header "+ch.args[0], ch.args[1], "ResponseHeaderModifier set")
		case "proxy_read_timeout", "proxy_send_timeout":
			d, valid := durationOf(args)
			if !valid {
				n.refuse(ch.line, "%s %s is not a duration like 60s", ch.name, args)
				ok = false
				continue
			}
			if s := durationSeconds(d); s >= timeoutBest {
				timeoutBest, timeoutVal = s, d
			}
			c.done(src, ch.name, args, "timeouts.backendRequest")
		case "proxy_http_version", "proxy_redirect", "access_log", "error_log":
			c.ignore(src, ch.name, args, "does not affect routing")
		case "proxy_connect_timeout", "proxy_buffering", "client_max_body_size", "gzip":
			c.todo(src, ch.name, args, ngTodo[ch.name])
			pr.todos = append(pr.todos, "TODO(setura) "+ch.name+": "+args+" -- "+ngTodo[ch.name])
		case "allow":
			if len(ch.args) == 1 {
				allow = append(allow, ch.args[0])
			}
		case "deny":
			if len(ch.args) == 1 {
				deny = append(deny, ch.args[0])
			}
		case "return":
			if len(ch.args) == 2 && (ch.args[0] == "301" || ch.args[0] == "302") {
				u, _ := parseRedirectURL(ch.args[1])
				if u == nil {
					n.refuse(ch.line, "return %s needs an absolute http(s) URL without variables", ch.args[0])
					ok = false
					continue
				}
				code, _ := strconv.Atoi(ch.args[0])
				rr := obj{"scheme": u.scheme, "hostname": u.host, "statusCode": code}
				if u.port > 0 {
					rr["port"] = u.port
				}
				if u.path != "" {
					rr["path"] = obj{"type": "ReplaceFullPath", "replaceFullPath": u.path}
				}
				cr.filters = append(cr.filters, obj{"type": "RequestRedirect", "requestRedirect": rr})
				c.done(src, "return "+ch.args[0], ch.args[1], "RequestRedirect")
				proxyPass = "redirect"
			} else {
				n.refuse(ch.line, "return %s is outside the supported subset (only 301 and 302 redirects)", args)
				ok = false
			}
		default:
			n.refuse(ch.line, "%s in a location block is outside the supported subset", ch.name)
			ok = false
		}
	}
	if !ok {
		return nil, "", "", false
	}
	if timeoutVal != "" {
		cr.timeouts = obj{"backendRequest": timeoutVal}
	}
	if len(allow) > 0 || len(deny) > 0 {
		switch {
		case len(allow) > 0 && len(deny) == 1 && deny[0] == "all":
			cr.authBlock()["ipAllow"] = stringsToAny(allow)
			c.done(src, "allow/deny", strings.Join(allow, ","), "setura.zyvor.dev/auth ipAllow")
		case len(allow) == 0 && deny[0] != "all":
			cr.authBlock()["ipDeny"] = stringsToAny(deny)
			c.done(src, "allow/deny", strings.Join(deny, ","), "setura.zyvor.dev/auth ipDeny")
		default:
			n.refuse(d.line, "this allow/deny combination is outside the supported subset (allow ... then deny all, or deny addresses only)")
			return nil, "", "", false
		}
	}
	if proxyPass == "redirect" {
		return cr, matchPath, typ, true
	}
	if proxyPass == "" {
		n.refuse(d.line, "location %s has no proxy_pass or return", path)
		return nil, "", "", false
	}
	rest, hasScheme := strings.CutPrefix(proxyPass, "http://")
	tls := false
	if !hasScheme {
		rest, hasScheme = strings.CutPrefix(proxyPass, "https://")
		tls = hasScheme
	}
	if !hasScheme {
		n.refuse(d.line, "proxy_pass %s must start with http:// or https://", proxyPass)
		return nil, "", "", false
	}
	hostPort, uri, hasURI := strings.Cut(rest, "/")
	uri = "/" + uri
	var servers []ngServerAddr
	if up, found := n.upstreams[hostPort]; found {
		servers = up.servers
	} else {
		addr, okAddr := n.serviceAddr(hostPort, d.line)
		if !okAddr {
			return nil, "", "", false
		}
		servers = []ngServerAddr{addr}
	}
	if len(servers) == 0 {
		n.refuse(d.line, "upstream %s has no server lines", hostPort)
		return nil, "", "", false
	}
	for _, sv := range servers {
		ns := ""
		if sv.ns != "" && sv.ns != pr.ic.ns {
			ns = sv.ns
		}
		w := -1
		if len(servers) > 1 {
			w = sv.weight
		}
		cr.backends = append(cr.backends, backendRef(sv.name, ns, sv.port, w))
		if tls {
			pr.tlsBackends[sv.name] = true
		}
	}
	switch {
	case !hasURI || (matchPath == "/" && uri == "/" && typ == "PathPrefix"):
		c.done(src, "proxy_pass", proxyPass, "backendRef")
	case typ != "PathPrefix":
		n.refuse(d.line, "proxy_pass with a URI part (%s) is only supported on prefix locations", uri)
		return nil, "", "", false
	case !strings.HasSuffix(path, "/") || !strings.HasSuffix(uri, "/"):
		n.refuse(d.line, "proxy_pass URI %s replaces the matched prefix only when both the location and the URI end in /", uri)
		return nil, "", "", false
	default:
		to := strings.TrimRight(uri, "/")
		if to == "" {
			to = "/"
		}
		cr.filter("URLRewrite", "urlRewrite")["path"] = obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": to}
		c.done(src, "proxy_pass", proxyPass, "backendRef and URLRewrite ReplacePrefixMatch "+to)
	}
	return cr, matchPath, typ, true
}

type redirectURL struct {
	scheme, host, path string
	port               int
}

func parseRedirectURL(raw string) (*redirectURL, bool) {
	if strings.Contains(raw, "$") {
		return nil, false
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || (scheme != "http" && scheme != "https") {
		return nil, false
	}
	host, path, _ := strings.Cut(rest, "/")
	if path != "" {
		path = "/" + path
	}
	r := &redirectURL{scheme: scheme, host: host, path: path}
	if h, p, found := strings.Cut(host, ":"); found {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		r.host, r.port = h, n
	}
	return r, true
}
