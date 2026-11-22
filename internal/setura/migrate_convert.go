package setura

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// `setura migrate convert` turns what people run today (ingress-nginx
// Ingresses, Envoy Gateway policies, Traefik IngressRoutes, a simple
// nginx.conf) into Gateway API objects. Nothing is dropped silently: whatever
// has no equivalent becomes a "# TODO(setura)" comment in the generated YAML
// and an entry in the report.

const gatewayAPIVersion = "gateway.networking.k8s.io/v1"

const (
	convDone    = "converted"
	convTodo    = "todo"
	convIgnored = "ignored"
)

// convItem is one decision the converter made about one input setting.
type convItem struct {
	Source string `json:"source"` // "Ingress demo/shop"
	Key    string `json:"key"`    // annotation, field or directive
	Value  string `json:"value,omitempty"`
	Status string `json:"status"` // converted, todo or ignored
	Target string `json:"target,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// convRes is one generated object.
type convRes struct {
	Kind, NS, Name string
	Obj            obj
	Comments       []string // # TODO(setura) lines placed above the object
	File           string
}

type convResource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	File      string `json:"file,omitempty"`
	Todos     int    `json:"todos,omitempty"`
}

type convCheck struct {
	Skipped bool           `json:"skipped,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	OK      bool           `json:"ok"`
	Summary map[string]int `json:"summary,omitempty"`
	Rules   []*ruleResult  `json:"rules,omitempty"`
	Notes   []string       `json:"notes,omitempty"`
}

type convReport struct {
	Source    string         `json:"source"`
	Verdict   string         `json:"verdict"` // equivalent or needs-review
	OK        bool           `json:"ok"`
	Summary   map[string]int `json:"summary"`
	Resources []convResource `json:"resources"`
	Items     []convItem     `json:"items"`
	Check     *convCheck     `json:"check,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
	Manifests []obj          `json:"manifests,omitempty"`
}

// converter collects generated resources and decisions.
type converter struct {
	from     string
	gwClass  string
	ns       string // namespace for sources that carry none (nginx.conf)
	res      []*convRes
	byKey    map[string]*convRes
	items    []convItem
	itemSeen map[string]bool
	notes    []string
	svcs     []migService
	haveSvc  bool
	cms      map[string]map[string]string // ConfigMap data by ns/name
	gws      map[string]*gwBuild
	gwOrder  []string
	// expectedExtra lists generated route rules the round trip must not call
	// extra: "<route>|<host>" for redirect routes and server aliases.
	expectedExtra map[string]bool
	// redirectRoutes are generated only to send HTTP clients to HTTPS.
	redirectRoutes map[string]bool
	// synthetic Ingress objects the check compares against (non-Ingress sources).
	synthetic []obj
	// envoyOrig are the signatures of the input route rules (envoy-gateway).
	envoyOrig []string
	// grants: ReferenceGrants needed for cross-namespace backendRefs,
	// "toNS|fromNS|fromKind" -> Service names.
	grants     map[string]map[string]bool
	grantOrder []string
	// tlsPolicies already generated, by ns/service.
	tlsPolicies map[string]bool
}

func newConverter(from, gwClass, ns string) *converter {
	return &converter{from: from, gwClass: gwClass, ns: ns, byKey: map[string]*convRes{}, itemSeen: map[string]bool{},
		cms: map[string]map[string]string{}, gws: map[string]*gwBuild{}, expectedExtra: map[string]bool{},
		redirectRoutes: map[string]bool{}, tlsPolicies: map[string]bool{}, grants: map[string]map[string]bool{}}
}

func mkObj(apiVersion, kind, ns, name string) obj {
	meta := obj{"name": name}
	if ns != "" {
		meta["namespace"] = ns
	}
	return obj{"apiVersion": apiVersion, "kind": kind, "metadata": meta}
}

// add registers a generated object under a unique name for its kind and
// namespace; a collision gets a numeric suffix and a note.
func (c *converter) add(kind, ns, name string, o obj) *convRes {
	unique := name
	for i := 2; c.byKey[kind+"|"+ns+"|"+unique] != nil; i++ {
		unique = name + "-" + strconv.Itoa(i)
	}
	if unique != name {
		c.notes = append(c.notes, fmt.Sprintf("%s name %q was taken in namespace %q; the new object is named %q", kind, name, ns, unique))
	}
	meta := asMap(o["metadata"])
	meta["name"] = unique
	r := &convRes{Kind: kind, NS: ns, Name: unique, Obj: o}
	c.byKey[kind+"|"+ns+"|"+unique] = r
	c.res = append(c.res, r)
	return r
}

func (c *converter) record(it convItem) {
	k := it.Source + "|" + it.Key + "|" + it.Status
	if c.itemSeen[k] {
		return
	}
	c.itemSeen[k] = true
	c.items = append(c.items, it)
}

func (c *converter) done(src, key, value, target string) {
	c.record(convItem{Source: src, Key: key, Value: truncate(value, 80), Status: convDone, Target: target})
}

func (c *converter) ignore(src, key, value, reason string) {
	c.record(convItem{Source: src, Key: key, Value: truncate(value, 80), Status: convIgnored, Reason: reason})
}

// todo records something a human must finish and returns the comment line.
func (c *converter) todo(src, key, value, reason string) string {
	c.record(convItem{Source: src, Key: key, Value: truncate(value, 80), Status: convTodo, Reason: reason})
	line := "TODO(setura) "
	// Policies and middlewares are attached to routes that never mention
	// them, so their comments name the source.
	for _, p := range []string{"Middleware ", "SecurityPolicy ", "BackendTrafficPolicy ", "ClientTrafficPolicy "} {
		if strings.HasPrefix(src, p) {
			line += src + " "
		}
	}
	line += key
	if v := truncate(value, 60); v != "" {
		line += ": " + v
	}
	return line + " -- " + reason
}

// ---- Gateways ------------------------------------------------------------

type gwBuild struct {
	ns, name  string
	listeners map[string]obj
}

func (c *converter) gateway(ns, name string) *gwBuild {
	key := ns + "/" + name
	if g := c.gws[key]; g != nil {
		return g
	}
	g := &gwBuild{ns: ns, name: name, listeners: map[string]obj{}}
	c.gws[key] = g
	c.gwOrder = append(c.gwOrder, key)
	return g
}

func (g *gwBuild) listener(name string, l obj) {
	if _, ok := g.listeners[name]; !ok {
		g.listeners[name] = l
	}
}

// needGrant records that routes of fromNS reach Service svc in toNS.
func (c *converter) needGrant(toNS, fromNS, fromKind, svc string) {
	k := toNS + "|" + fromNS + "|" + fromKind
	if c.grants[k] == nil {
		c.grants[k] = map[string]bool{}
		c.grantOrder = append(c.grantOrder, k)
	}
	c.grants[k][svc] = true
}

func (c *converter) finishGateways() {
	for _, k := range c.grantOrder {
		parts := strings.Split(k, "|")
		toNS, fromNS, fromKind := parts[0], parts[1], parts[2]
		var to []any
		for _, svc := range sortedKeys(c.grants[k]) {
			to = append(to, obj{"group": "", "kind": "Service", "name": svc})
		}
		name := "allow-" + fromNS + "-" + strings.ToLower(fromKind) + "s"
		o := mkObj("gateway.networking.k8s.io/v1beta1", "ReferenceGrant", toNS, name)
		o["spec"] = obj{"from": []any{obj{"group": "gateway.networking.k8s.io", "kind": fromKind, "namespace": fromNS}}, "to": to}
		c.add("ReferenceGrant", toNS, name, o)
	}
	for _, key := range c.gwOrder {
		g := c.gws[key]
		var ls []any
		for _, n := range sortedKeys(g.listeners) {
			ls = append(ls, g.listeners[n])
		}
		o := mkObj(gatewayAPIVersion, "Gateway", g.ns, g.name)
		o["spec"] = obj{"gatewayClassName": c.gwClass, "listeners": ls}
		c.add("Gateway", g.ns, g.name, o)
	}
}

// ---- rules ---------------------------------------------------------------

// cvRule is one HTTPRoute, GRPCRoute or TLSRoute rule being built.
type cvRule struct {
	matches  []any
	filters  []any
	backends []any
	timeouts obj
	retry    obj
	session  obj
	auth     obj // setura.zyvor.dev/auth block, emitted as a route annotation
	name     string
}

func (r *cvRule) obj(kind string) obj {
	o := obj{}
	if len(r.matches) > 0 {
		o["matches"] = r.matches
	}
	if len(r.filters) > 0 {
		o["filters"] = r.filters
	}
	if len(r.backends) > 0 {
		o["backendRefs"] = r.backends
	}
	if len(r.timeouts) > 0 && kind == kindHTTPRoute {
		o["timeouts"] = r.timeouts
	}
	if len(r.retry) > 0 && kind == kindHTTPRoute {
		o["retry"] = r.retry
	}
	if len(r.session) > 0 {
		o["sessionPersistence"] = r.session
	}
	if r.name != "" {
		o["name"] = r.name
	}
	return o
}

// filter returns the first filter of a type, creating it when absent.
func (r *cvRule) filter(typ, field string) obj {
	for _, f := range r.filters {
		if fm := asMap(f); asStr(fm["type"]) == typ {
			if m := asMap(fm[field]); m != nil {
				return m
			}
		}
	}
	body := obj{}
	r.filters = append(r.filters, obj{"type": typ, field: body})
	return body
}

func (r *cvRule) setRequestHeader(name, value string) {
	f := r.filter("RequestHeaderModifier", "requestHeaderModifier")
	f["set"] = append(asList(f["set"]), obj{"name": name, "value": value})
}

func (r *cvRule) setResponseHeader(name, value string) {
	f := r.filter("ResponseHeaderModifier", "responseHeaderModifier")
	f["set"] = append(asList(f["set"]), obj{"name": name, "value": value})
}

func (r *cvRule) authBlock() obj {
	if r.auth == nil {
		r.auth = obj{}
	}
	return r.auth
}

func backendRef(name, ns string, port int, weight int) obj {
	b := obj{"name": name}
	if ns != "" {
		b["namespace"] = ns
	}
	if port > 0 {
		b["port"] = port
	}
	if weight >= 0 {
		b["weight"] = weight
	}
	return b
}

func stringsToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// durationOf converts an nginx or Traefik style duration ("60", "30s", "5m")
// to a Gateway API duration.
func durationOf(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return strconv.Itoa(n) + "s", true
	}
	if len(v) > 1 {
		if n, err := strconv.Atoi(v[:len(v)-1]); err == nil && n >= 0 && strings.ContainsAny(v[len(v)-1:], "smh") {
			return v, true
		}
	}
	if strings.HasSuffix(v, "ms") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "ms")); err == nil && n >= 0 {
			return v, true
		}
	}
	return "", false
}

func durationSeconds(d string) float64 {
	switch {
	case strings.HasSuffix(d, "ms"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "ms"))
		return float64(n) / 1000
	case strings.HasSuffix(d, "h"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "h"))
		return float64(n) * 3600
	case strings.HasSuffix(d, "m"):
		n, _ := strconv.Atoi(strings.TrimSuffix(d, "m"))
		return float64(n) * 60
	}
	n, _ := strconv.Atoi(strings.TrimSuffix(d, "s"))
	return float64(n)
}

// svcFromURL reads a cluster Service out of a URL such as
// http://auth.infra.svc.cluster.local:8080/verify.
func svcFromURL(raw, defNS string) (name, ns string, port int, path string, ok bool) {
	rest := raw
	scheme := "http"
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme, rest = strings.ToLower(rest[:i]), rest[i+3:]
	}
	host := rest
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		p, err := strconv.Atoi(host[i+1:])
		if err != nil {
			return "", "", 0, "", false
		}
		host, port = host[:i], p
	} else if scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	host = strings.TrimSuffix(host, ".svc.cluster.local")
	host = strings.TrimSuffix(host, ".svc")
	parts := strings.Split(host, ".")
	switch len(parts) {
	case 1:
		name, ns = parts[0], defNS
	case 2:
		name, ns = parts[0], parts[1]
	default:
		return "", "", 0, "", false
	}
	if name == "" || strings.ContainsAny(name, "$ ") {
		return "", "", 0, "", false
	}
	return name, ns, port, path, true
}

// ---- running -------------------------------------------------------------

// toObjects renders every generated resource as an object, in a stable order.
func (c *converter) order() {
	rank := map[string]int{"Gateway": 0, "HTTPRoute": 1, "GRPCRoute": 2, "TLSRoute": 3, "BackendTLSPolicy": 4, "ReferenceGrant": 5}
	sort.SliceStable(c.res, func(i, j int) bool {
		a, b := c.res[i], c.res[j]
		if a.NS != b.NS {
			return a.NS < b.NS
		}
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		return a.Name < b.Name
	})
}

func (r *convRes) yaml() string {
	var b strings.Builder
	for _, cm := range r.Comments {
		b.WriteString("# " + cm + "\n")
	}
	b.WriteString(emitYAML(r.Obj))
	return b.String()
}

func (r *convRes) fileName(multiNS bool) string {
	n := strings.ToLower(r.Kind) + "-" + r.Name + ".yaml"
	if multiNS && r.NS != "" {
		return filepath.Join(r.NS, n)
	}
	return n
}

func (c *converter) allYAML() string {
	var parts []string
	for _, r := range c.res {
		parts = append(parts, r.yaml())
	}
	return strings.Join(parts, "---\n")
}

func (c *converter) counts() map[string]int {
	s := map[string]int{convDone: 0, convTodo: 0, convIgnored: 0, "resources": len(c.res)}
	for _, it := range c.items {
		s[it.Status]++
	}
	return s
}

// writeFiles writes one file per resource under dir. Existing files are never
// replaced unless force is set.
func writeConvertFiles(dir string, c *converter, force bool) error {
	multi := false
	for _, r := range c.res {
		if r.NS != c.res[0].NS {
			multi = true
		}
	}
	var clash []string
	for _, r := range c.res {
		r.File = r.fileName(multi)
		if _, err := os.Stat(filepath.Join(dir, r.File)); err == nil && !force {
			clash = append(clash, filepath.Join(dir, r.File))
		}
	}
	if len(clash) > 0 {
		return userErrorf("refusing to overwrite %s (use --force)", strings.Join(clash, ", "))
	}
	for _, r := range c.res {
		p := filepath.Join(dir, r.File)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(r.yaml()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func jsonCompact(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func jsonBytes(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return append(b, '\n')
}
