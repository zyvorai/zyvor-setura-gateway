package setura

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// initSchema identifies the JSON document `setura init --format json` prints.
const initSchema = "setura.init/v1"

const (
	routeResource   = "httproutes.gateway.networking.k8s.io/"
	gatewayResource = "gateways.gateway.networking.k8s.io/"
)

type initMatch struct {
	Type, Path, Method string
}

type initRule struct {
	Matches []initMatch
	Backend string // key "name:port"
}

type initRoute struct {
	Name, Host string
	Rules      []initRule
	Sample     string // path used by the generated check
}

type initBackend struct {
	Name      string
	Port      int
	Endpoints []string
}

func (b initBackend) key() string { return fmt.Sprintf("%s:%d", b.Name, b.Port) }

// initSpec is everything buildSnapshot needs; the generators fill it.
type initSpec struct {
	Name, Namespace string
	Port            int
	Routes          []initRoute
	Backends        []initBackend
}

var nonLabel = regexp.MustCompile(`[^a-z0-9-]+`)

// dnsName turns free text into a lowercase DNS label.
func dnsName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "*.", "wildcard-")
	s = strings.Trim(nonLabel.ReplaceAllString(s, "-"), "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	if s == "" {
		s = "x"
	}
	return s
}

// parseUpstream accepts host:port, http://host[:port] or https://host[:port]
// and returns the endpoint string, the host and the port.
func parseUpstream(v string) (endpoint, host string, port int, err error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", "", 0, errors.New("the upstream is empty")
	}
	scheme := "http"
	hostport := v
	if strings.Contains(v, "://") {
		u, perr := url.Parse(v)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", "", 0, fmt.Errorf("upstream %q: want host:port or an http(s) URL", v)
		}
		if p := strings.Trim(u.Path, "/"); p != "" || u.RawQuery != "" {
			return "", "", 0, fmt.Errorf("upstream %q: give only the server (host:port); put paths on the host, like host/prefix=upstream", v)
		}
		scheme, hostport = u.Scheme, u.Host
	}
	h, p, serr := net.SplitHostPort(hostport)
	if serr != nil {
		if !strings.Contains(v, "://") {
			return "", "", 0, fmt.Errorf("upstream %q: want host:port, for example 127.0.0.1:9001", v)
		}
		h, p = strings.Trim(hostport, "[]"), ""
	}
	if h == "" || strings.ContainsAny(h, " /\t") {
		return "", "", 0, fmt.Errorf("upstream %q: invalid host", v)
	}
	port = 80
	if scheme == "https" {
		port = 443
	}
	if p != "" {
		n, nerr := strconv.Atoi(p)
		if nerr != nil || n < 1 || n > 65535 {
			return "", "", 0, fmt.Errorf("upstream %q: invalid port %q", v, p)
		}
		port = n
	}
	jp := net.JoinHostPort(h, strconv.Itoa(port))
	if scheme == "https" {
		return "https://" + jp, h, port, nil
	}
	return jp, h, port, nil
}

// backendFor registers an upstream and returns its backend key. The same
// endpoint always maps to the same backend.
func (s *initSpec) backendFor(endpoint, host string, port int) string {
	for _, b := range s.Backends {
		if len(b.Endpoints) > 0 && b.Endpoints[0] == endpoint {
			return b.key()
		}
	}
	name := dnsName(host)
	for taken := true; taken; {
		taken = false
		for _, b := range s.Backends {
			if b.Name == name && b.Port == port {
				name += "-2"
				taken = true
			}
		}
	}
	b := initBackend{Name: name, Port: port, Endpoints: []string{endpoint}}
	s.Backends = append(s.Backends, b)
	return b.key()
}

func normPrefix(p string) string {
	p = "/" + strings.Trim(p, "/")
	return p
}

// fromPairs builds a spec from "host[/prefix]=upstream" pairs.
func fromPairs(pairs []string, name string, port int) (initSpec, error) {
	spec := initSpec{Name: dnsName(name), Namespace: "default", Port: port}
	if len(pairs) == 0 {
		return spec, errors.New("no routes given")
	}
	byHost := map[string]int{}
	seen := map[string]bool{}
	for _, p := range pairs {
		left, right, ok := strings.Cut(p, "=")
		if !ok {
			return spec, fmt.Errorf("route %q: want host=upstream, for example orders.example.test=127.0.0.1:9001", p)
		}
		host, prefix, _ := strings.Cut(strings.TrimSpace(left), "/")
		if host == "" || strings.ContainsAny(host, " \t") {
			return spec, fmt.Errorf("route %q: the host before '=' is empty or invalid", p)
		}
		prefix = normPrefix(prefix)
		if seen[host+prefix] {
			return spec, fmt.Errorf("route %q: %s%s is listed twice", p, host, prefix)
		}
		seen[host+prefix] = true
		ep, uh, up, err := parseUpstream(right)
		if err != nil {
			return spec, fmt.Errorf("route %q: %w", p, err)
		}
		key := spec.backendFor(ep, uh, up)
		i, have := byHost[host]
		if !have {
			i = len(spec.Routes)
			byHost[host] = i
			spec.Routes = append(spec.Routes, initRoute{Name: dnsName(host), Host: host, Sample: prefix})
		}
		spec.Routes[i].Rules = append(spec.Routes[i].Rules, initRule{Matches: []initMatch{{Type: "PathPrefix", Path: prefix}}, Backend: key})
	}
	// Longest prefixes first so the specific rule is easy to read; the
	// gateway ranks by specificity regardless.
	for i := range spec.Routes {
		r := &spec.Routes[i]
		sort.SliceStable(r.Rules, func(a, b int) bool { return len(r.Rules[a].Matches[0].Path) > len(r.Rules[b].Matches[0].Path) })
		r.Sample = r.Rules[len(r.Rules)-1].Matches[0].Path
	}
	return spec, nil
}

var openAPIMethods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

// openAPIServers returns the absolute server URLs of an OpenAPI 3 or
// Swagger 2 document.
func openAPIServers(doc obj) ([]*url.URL, error) {
	var out []*url.URL
	add := func(raw string) {
		if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			out = append(out, u)
		}
	}
	if sw := asStr(doc["swagger"]); sw != "" {
		host := asStr(doc["host"])
		if host == "" {
			return nil, nil
		}
		schemes := []string{"http"}
		if l := asList(doc["schemes"]); len(l) > 0 {
			schemes = nil
			for _, s := range l {
				schemes = append(schemes, asStr(s))
			}
		}
		for _, sc := range schemes {
			add(sc + "://" + host + asStr(doc["basePath"]))
		}
		return out, nil
	}
	for _, s := range asList(doc["servers"]) {
		m := asMap(s)
		raw := asStr(m["url"])
		for name, v := range asMap(m["variables"]) {
			raw = strings.ReplaceAll(raw, "{"+name+"}", asStr(asMap(v)["default"]))
		}
		add(raw)
	}
	return out, nil
}

// pathMatches converts an OpenAPI path and its methods into gateway matches.
// A templated segment ({id}) ends the literal part: the match becomes a
// prefix up to it.
func pathMatches(base, path string, methods []string) []initMatch {
	full := strings.TrimRight(base, "/") + path
	typ := "Exact"
	if i := strings.Index(full, "{"); i >= 0 {
		typ = "PathPrefix"
		full = full[:i]
		if j := strings.LastIndex(full, "/"); j >= 0 {
			full = full[:j]
		}
	}
	if full == "" {
		full = "/"
	}
	if typ == "PathPrefix" && len(full) > 1 {
		full = strings.TrimRight(full, "/")
	}
	if len(methods) == 0 {
		return []initMatch{{Type: typ, Path: full}}
	}
	var out []initMatch
	for _, m := range methods {
		out = append(out, initMatch{Type: typ, Path: full, Method: strings.ToUpper(m)})
	}
	return out
}

// fromOpenAPI builds a spec from an OpenAPI 3.x or Swagger 2.0 JSON document.
// upstream, when set, replaces the document's servers.
func fromOpenAPI(raw []byte, name, hostname, upstream string, port int) (initSpec, error) {
	spec := initSpec{Name: dnsName(name), Namespace: "default", Port: port}
	trim := strings.TrimSpace(string(raw))
	if trim == "" || (trim[0] != '{') {
		return spec, errors.New("the OpenAPI file is not JSON. setura init reads OpenAPI 3.x and Swagger 2.0 as JSON only; convert YAML first, for example with `yq -o=json . api.yaml > api.json`")
	}
	var doc obj
	if err := json.Unmarshal(raw, &doc); err != nil {
		return spec, fmt.Errorf("the OpenAPI file is not valid JSON: %v", err)
	}
	if asStr(doc["openapi"]) == "" && asStr(doc["swagger"]) == "" {
		return spec, errors.New("this JSON has no \"openapi\" or \"swagger\" field, so it does not look like an OpenAPI document")
	}
	paths := asMap(doc["paths"])
	if len(paths) == 0 {
		return spec, errors.New("the OpenAPI document has no paths, so there is nothing to route")
	}
	var servers []*url.URL
	if upstream != "" {
		ep, _, _, err := parseUpstream(upstream)
		if err != nil {
			return spec, err
		}
		u, _ := url.Parse("http://" + ep)
		if strings.HasPrefix(ep, "https://") {
			u, _ = url.Parse(ep)
		}
		servers = []*url.URL{u}
	} else {
		var err error
		if servers, err = openAPIServers(doc); err != nil {
			return spec, err
		}
	}
	if len(servers) == 0 {
		return spec, errors.New("the OpenAPI document has no absolute server URL (servers[].url, or host for Swagger 2). Pass --upstream HOST:PORT to say where the API runs")
	}
	primary := servers[0]
	base := ""
	if upstream == "" {
		base = strings.TrimRight(primary.Path, "/")
	}
	if hostname == "" && upstream == "" {
		if h := primary.Hostname(); h != "" && net.ParseIP(h) == nil && h != "localhost" {
			hostname = h
		}
	}
	var eps []string
	var first string
	var host string
	var bport int
	seenEp := map[string]bool{}
	for i, s := range servers {
		ep, h, p, err := parseUpstream(s.Scheme + "://" + s.Host)
		if err != nil {
			continue
		}
		if i == 0 {
			first, host, bport = ep, h, p
		}
		if !seenEp[ep] {
			seenEp[ep] = true
			eps = append(eps, ep)
		}
	}
	if first == "" {
		return spec, errors.New("could not read a usable server URL from the OpenAPI document")
	}
	key := spec.backendFor(first, host, bport)
	spec.Backends[0].Endpoints = eps
	route := initRoute{Name: dnsName(name), Host: hostname}
	var sample string
	for _, p := range sortedKeys(paths) {
		item := asMap(paths[p])
		var ms []string
		for _, m := range openAPIMethods {
			if item[m] != nil {
				ms = append(ms, m)
			}
		}
		if !strings.HasPrefix(p, "/") {
			continue
		}
		matches := pathMatches(base, p, ms)
		route.Rules = append(route.Rules, initRule{Matches: matches, Backend: key})
		if sample == "" && !strings.Contains(p, "{") && (len(ms) == 0 || item["get"] != nil) {
			sample = matches[0].Path
		}
	}
	if len(route.Rules) == 0 {
		return spec, errors.New("the OpenAPI document has no usable paths (they must start with '/')")
	}
	if sample == "" {
		sample = route.Rules[0].Matches[0].Path
	}
	route.Sample = sample
	spec.Routes = []initRoute{route}
	return spec, nil
}

// buildSnapshot renders the spec as a setura.route-specs/v1 document.
func buildSnapshot(spec initSpec) obj {
	res := obj{}
	res[gatewayResource+spec.Name] = obj{
		"gatewayClassName": "setura",
		"listeners":        []any{obj{"name": "web", "protocol": "HTTP", "port": spec.Port}},
	}
	for _, r := range spec.Routes {
		var rules []any
		for _, ru := range r.Rules {
			var ms []any
			for _, m := range ru.Matches {
				mm := obj{"path": obj{"type": m.Type, "value": m.Path}}
				if m.Method != "" {
					mm["method"] = m.Method
				}
				ms = append(ms, mm)
			}
			name, port := splitKey(ru.Backend)
			rules = append(rules, obj{"matches": ms, "backendRefs": []any{obj{"name": name, "port": port}}})
		}
		rs := obj{"parentRefs": []any{obj{"name": spec.Name, "sectionName": "web"}}, "rules": rules}
		if r.Host != "" {
			rs["hostnames"] = []any{r.Host}
		}
		res[routeResource+r.Name] = rs
	}
	backends := obj{}
	for _, b := range spec.Backends {
		eps := make([]any, len(b.Endpoints))
		for i, e := range b.Endpoints {
			eps[i] = e
		}
		backends[b.key()] = obj{"endpoints": eps, "timeout": "5s"}
	}
	return obj{"schema": snapshotSchema, "namespace": spec.Namespace, "resources": res, "backends": backends}
}

func splitKey(k string) (string, int) {
	i := strings.LastIndex(k, ":")
	n, _ := strconv.Atoi(k[i+1:])
	return k[:i], n
}

// buildChecks renders one assertion per route.
func buildChecks(spec initSpec) []obj {
	var out []obj
	for _, r := range spec.Routes {
		host := r.Host
		if host == "" || strings.HasPrefix(host, "*") {
			host = "127.0.0.1"
		}
		name, _ := splitKey(r.Rules[0].Backend)
		out = append(out, obj{"url": fmt.Sprintf("http://%s:%d%s", host, spec.Port, r.Sample), "address": "127.0.0.1", "status": 200, "backend": name})
	}
	return out
}

type initOptions struct {
	pairs    []string
	openapi  string
	upstream string
	out      string
	port     int
	hostname string
	name     string
	force    bool
	noLint   bool
	format   string
}

// initResult is the JSON document and the data behind the pretty summary.
type initResult struct {
	Schema   string   `json:"schema"`
	Dir      string   `json:"dir"`
	Files    []string `json:"files"`
	Routes   int      `json:"routes"`
	Backends int      `json:"backends"`
	Lint     obj      `json:"lint"`
	Next     []string `json:"next"`
	spec     initSpec
}

func (r *initResult) lintCounts() (int, int) {
	e, _ := num(r.Lint["errors"])
	w, _ := num(r.Lint["warnings"])
	return int(e), int(w)
}

func initFail(stderr io.Writer, u *ui, verdict, next string) (int, error) {
	fmt.Fprintf(stderr, "\n  %s %s\n", u.failSym(), u.bold(verdict))
	if next != "" {
		fmt.Fprintf(stderr, "  %s %s\n", u.blue("Next:"), next)
	}
	fmt.Fprintln(stderr)
	return 2, usageError{verdict}
}

// scaffold generates, validates and writes the files.
func scaffold(spec initSpec, o initOptions) (*initResult, error) {
	snap := buildSnapshot(spec)
	raw, _ := json.MarshalIndent(snap, "", "  ")
	raw = append(raw, '\n')
	dir := o.out
	abs, _ := filepath.Abs(dir)
	if _, err := builtin.ParseConfig(raw, abs); err != nil {
		return nil, fmt.Errorf("the generated config was rejected by the gateway parser: %w", err)
	}
	res := &initResult{Schema: initSchema, Dir: dir, Routes: len(spec.Routes), Backends: len(spec.Backends), spec: spec}
	if !o.noLint {
		var generic obj
		_ = json.Unmarshal(raw, &generic)
		rep, err := Lint(generic)
		if err != nil {
			return nil, err
		}
		res.Lint = rep
	} else {
		res.Lint = obj{"ok": true, "errors": 0, "warnings": 0, "skipped": true}
	}
	checks, _ := json.MarshalIndent(buildChecks(spec), "", "  ")
	checks = append(checks, '\n')
	cfgPath, chkPath := filepath.Join(dir, "setura.json"), filepath.Join(dir, "checks.json")
	if !o.force {
		for _, p := range []string{cfgPath, chkPath} {
			if _, err := os.Stat(p); err == nil {
				return nil, existsError{p}
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(chkPath, checks, 0o644); err != nil {
		return nil, err
	}
	res.Files = []string{cfgPath, chkPath}
	res.Next = []string{
		fmt.Sprintf("setura gateway run --config %s --ui 127.0.0.1:9090", cfgPath),
		fmt.Sprintf("setura check %s", chkPath),
	}
	return res, nil
}

type existsError struct{ path string }

func (e existsError) Error() string { return e.path + " already exists" }

// InitPretty renders the success summary.
func (u *ui) InitPretty(r *initResult) string {
	var b strings.Builder
	e, w := r.lintCounts()
	lintWords := "lint clean"
	sym := u.okSym()
	switch {
	case r.Lint["skipped"] == true:
		lintWords = "lint skipped"
	case e > 0:
		lintWords, sym = plural(e, "lint error", "lint errors"), u.warnSym()
	case w > 0:
		lintWords, sym = plural(w, "lint warning", "lint warnings"), u.warnSym()
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "  %s %s\n\n", sym, u.bold(fmt.Sprintf("Created setura.json and checks.json: %s, %s, %s",
		plural(r.Routes, "route", "routes"), plural(r.Backends, "backend", "backends"), lintWords)))
	row := func(k, v string) { fmt.Fprintf(&b, "    %s %s\n", u.gray(pad(k, 10)), v) }
	row("Folder", r.Dir)
	row("Gateway", fmt.Sprintf("%s, HTTP on port %d", r.spec.Name, r.spec.Port))
	for i, rt := range r.spec.Routes {
		k := ""
		if i == 0 {
			k = "Routes"
		}
		host := rt.Host
		if host == "" {
			host = "any host"
		}
		var targets []string
		seen := map[string]bool{}
		for _, ru := range rt.Rules {
			if !seen[ru.Backend] {
				seen[ru.Backend] = true
				targets = append(targets, ru.Backend)
			}
		}
		more := ""
		if len(rt.Rules) > 1 {
			more = fmt.Sprintf("  %s", u.gray(plural(len(rt.Rules), "rule", "rules")))
		}
		row(k, fmt.Sprintf("%s %s %s%s", host, u.arrow(), strings.Join(targets, ", "), more))
	}
	if e > 0 || w > 0 {
		b.WriteString("\n")
		n := 0
		for _, f := range asList(r.Lint["findings"]) {
			if n == 5 {
				fmt.Fprintf(&b, "    %s\n", u.gray("and more: run setura lint --snapshot "+r.Files[0]))
				break
			}
			m := asMap(f)
			fmt.Fprintf(&b, "    %s %s  %s\n", u.warnSym(), u.dim(asStr(m["id"])), m["message"])
			n++
		}
	}
	b.WriteString("\n")
	for i, n := range r.Next {
		lead := u.blue("Next:")
		if i > 0 {
			lead = "     "
		}
		fmt.Fprintf(&b, "  %s %s\n", lead, n)
	}
	b.WriteString("\n")
	return b.String()
}

// promptInit asks for routes, port and folder on stderr, reading from in.
func promptInit(in io.Reader, w io.Writer, o *initOptions) error {
	rd := bufio.NewReader(in)
	line := func(prompt string) (string, bool) {
		fmt.Fprint(w, prompt)
		s, err := rd.ReadString('\n')
		s = strings.TrimSpace(s)
		return s, err == nil || s != ""
	}
	fmt.Fprintln(w, "\n  Let's set up a gateway. Press Enter on an empty line when you are done.")
	fmt.Fprintln(w, "  Give each site as host=upstream, for example orders.example.test=127.0.0.1:9001")
	for {
		s, ok := line("  Route: ")
		if s == "" || !ok {
			break
		}
		o.pairs = append(o.pairs, s)
	}
	if len(o.pairs) == 0 {
		return errors.New("no routes entered")
	}
	if s, _ := line(fmt.Sprintf("  Listen port [%d]: ", o.port)); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q is not a valid port", s)
		}
		o.port = n
	}
	if s, _ := line(fmt.Sprintf("  Folder to write into [%s]: ", o.out)); s != "" {
		o.out = s
	}
	fmt.Fprintln(w)
	return nil
}

// runInit implements "setura init". stdinTTY says whether prompting is possible.
func runInit(fs *flag.FlagSet, rest []string, stdin io.Reader, stdinTTY bool, stdout, stderr io.Writer, u *ui, stdoutTTY bool) (int, error) {
	var o initOptions
	var routes stringList
	fs.Var(&routes, "route", "host=upstream pair, repeatable; host/prefix=upstream limits it to a path")
	fs.StringVar(&o.openapi, "openapi", "", "OpenAPI 3.x or Swagger 2.0 JSON file (JSON only, not YAML)")
	fs.StringVar(&o.upstream, "upstream", "", "with --openapi, serve the API from this HOST:PORT instead of the file's servers")
	fs.StringVar(&o.out, "out", ".", "folder to write setura.json and checks.json into")
	fs.IntVar(&o.port, "listen-port", 8080, "port the gateway listens on")
	fs.StringVar(&o.hostname, "hostname", "", "hostname for OpenAPI routes (default: the first server's host)")
	fs.StringVar(&o.name, "name", "gateway", "name of the Gateway")
	fs.BoolVar(&o.force, "force", false, "overwrite existing files")
	fs.BoolVar(&o.noLint, "no-lint", false, "skip linting the result")
	fs.StringVar(&o.format, "format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		fmt.Fprintf(stderr, "setura init: unexpected argument %q; routes are given as --route host=upstream\n", pos[0])
		exampleHint(stderr, "init")
		return 2, usageError{"arguments"}
	}
	pretty, ferr := wantPretty(o.format, stdoutTTY)
	if ferr != nil {
		return 2, ferr
	}
	if o.port < 1 || o.port > 65535 {
		return initFail(stderr, u, fmt.Sprintf("%d is not a valid listen port", o.port), "setura init --listen-port 8080 ...")
	}
	o.pairs = routes
	if len(o.pairs) > 0 && o.openapi != "" {
		return initFail(stderr, u, "Use either --route or --openapi, not both", "setura init --openapi api.json")
	}
	if len(o.pairs) == 0 && o.openapi == "" {
		if !stdinTTY || !stdoutTTY {
			return initFail(stderr, u, "Nothing to scaffold: give --route host=upstream or --openapi FILE",
				"setura init --route orders.example.test=127.0.0.1:9001")
		}
		if err := promptInit(stdin, stderr, &o); err != nil {
			return initFail(stderr, u, err.Error(), "setura init --route orders.example.test=127.0.0.1:9001")
		}
	}
	var spec initSpec
	if o.openapi != "" {
		raw, rerr := os.ReadFile(o.openapi)
		if rerr != nil {
			return initFail(stderr, u, "Cannot read "+o.openapi+": "+strings.TrimPrefix(rerr.Error(), "open "+o.openapi+": "), "Check the path, then rerun setura init --openapi FILE")
		}
		spec, err = fromOpenAPI(raw, o.name, o.hostname, o.upstream, o.port)
	} else {
		spec, err = fromPairs(o.pairs, o.name, o.port)
	}
	if err != nil {
		return initFail(stderr, u, err.Error(), "setura init --route orders.example.test=127.0.0.1:9001")
	}
	res, err := scaffold(spec, o)
	var ex existsError
	if errors.As(err, &ex) {
		return initFail(stderr, u, ex.Error()+"; nothing was changed", "Rerun with --force to overwrite, or pick another folder with --out DIR")
	}
	if err != nil {
		return 0, err
	}
	if pretty {
		fmt.Fprint(stdout, u.InitPretty(res))
	} else if err := writeJSON(stdout, res); err != nil {
		return 0, err
	}
	if e, _ := res.lintCounts(); e > 0 {
		return 1, nil
	}
	return 0, nil
}
