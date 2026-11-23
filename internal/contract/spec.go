package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

var httpMethods = []string{"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"}

// Operation is one documented method on one path.
type Operation struct {
	Method       string
	Path         string // as written in the document, without a server prefix
	Summary      string
	Deprecated   bool
	Secured      bool                // effective security requirement is non-empty
	Responses    map[string][]string // status key (200, 4XX, default) -> media types, nil entry when none documented
	RequestTypes []string            // media types of the requestBody, nil when there is none
	HasBody      bool
}

// Key is "METHOD /path".
func (o *Operation) Key() string { return o.Method + " " + o.Path }

type pathItem struct {
	segs   []string
	lits   int
	path   string
	prefix string
	ops    map[string]*Operation
}

// Spec is a parsed OpenAPI 3.x document reduced to what contract checks need.
type Spec struct {
	Version string
	Title   string
	Source  string
	Ops     []*Operation // sorted by path then method
	items   []*pathItem
	byLen   map[int][]*pathItem
}

// LoadSpecFile reads an OpenAPI 3.x document in JSON, or in the YAML subset
// described at parseYAML.
func LoadSpecFile(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ParseSpec(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.Source = path
	return s, nil
}

// ParseSpec parses an OpenAPI 3.x document.
func ParseSpec(b []byte) (*Spec, error) {
	var root any
	if t := bytes.TrimSpace(b); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		dec := json.NewDecoder(bytes.NewReader(t))
		if err := dec.Decode(&root); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	} else {
		var err error
		if root, err = parseYAML(b); err != nil {
			return nil, err
		}
	}
	doc, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("not an OpenAPI document (top level is not an object)")
	}
	ver, _ := doc["openapi"].(string)
	if ver == "" {
		if _, sw := doc["swagger"]; sw {
			return nil, errors.New("Swagger 2.0 is not supported; convert the document to OpenAPI 3.x")
		}
		return nil, errors.New("not an OpenAPI document (no \"openapi\" field)")
	}
	if !strings.HasPrefix(ver, "3.") {
		return nil, fmt.Errorf("OpenAPI %s is not supported (need 3.x)", ver)
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		return nil, errors.New("the document has no paths")
	}
	s := &Spec{Version: ver, byLen: map[int][]*pathItem{}}
	if info, ok := doc["info"].(map[string]any); ok {
		s.Title, _ = info["title"].(string)
	}
	var prefixes []string
	for _, sv := range asList(doc["servers"]) {
		m, _ := sv.(map[string]any)
		u, _ := m["url"].(string)
		if u == "" || strings.Contains(u, "{") {
			continue
		}
		if pu, err := url.Parse(u); err == nil {
			if p := "/" + strings.Trim(pu.Path, "/"); p != "/" {
				prefixes = append(prefixes, p)
			}
		}
	}
	prefixes = append([]string{""}, dedupe(prefixes)...)
	globalSec := secured(doc["security"], false)
	for _, p := range sortedKeys(paths) {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		item, _ := paths[p].(map[string]any)
		if item == nil {
			continue
		}
		item = resolveRef(doc, item)
		ops := map[string]*Operation{}
		for _, m := range httpMethods {
			raw, ok := item[strings.ToLower(m)].(map[string]any)
			if !ok {
				continue
			}
			op := &Operation{Method: m, Path: p}
			op.Summary, _ = raw["summary"].(string)
			op.Deprecated, _ = raw["deprecated"].(bool)
			op.Secured = globalSec
			if sec, has := raw["security"]; has {
				op.Secured = secured(sec, globalSec)
			}
			op.Responses = map[string][]string{}
			if rs, ok := raw["responses"].(map[string]any); ok {
				for code, rv := range rs {
					r, _ := rv.(map[string]any)
					r = resolveRef(doc, r)
					op.Responses[strings.ToUpper(code)] = contentTypes(r["content"])
				}
			}
			if rb, ok := raw["requestBody"].(map[string]any); ok {
				rb = resolveRef(doc, rb)
				op.HasBody = true
				op.RequestTypes = contentTypes(rb["content"])
			}
			ops[m] = op
			s.Ops = append(s.Ops, op)
		}
		if len(ops) == 0 {
			continue
		}
		for _, pre := range prefixes {
			full := pre + p
			segs := SplitPath(full)
			it := &pathItem{segs: segs, path: p, prefix: pre, ops: ops}
			for _, sg := range segs {
				if !isParam(sg) {
					it.lits++
				}
			}
			s.items = append(s.items, it)
		}
	}
	if len(s.Ops) == 0 {
		return nil, errors.New("the document declares no operations")
	}
	sort.SliceStable(s.Ops, func(i, j int) bool {
		if s.Ops[i].Path != s.Ops[j].Path {
			return s.Ops[i].Path < s.Ops[j].Path
		}
		return s.Ops[i].Method < s.Ops[j].Method
	})
	sort.SliceStable(s.items, func(i, j int) bool { return s.items[i].lits > s.items[j].lits })
	for _, it := range s.items {
		s.byLen[len(it.segs)] = append(s.byLen[len(it.segs)], it)
	}
	return s, nil
}

func asList(v any) []any { l, _ := v.([]any); return l }

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// secured reports whether a security requirement list demands credentials:
// absent inherits, [] or only {} entries mean none.
func secured(v any, inherit bool) bool {
	l, ok := v.([]any)
	if !ok {
		return inherit
	}
	for _, e := range l {
		if m, ok := e.(map[string]any); ok && len(m) > 0 {
			return true
		}
	}
	return false
}

// resolveRef follows a local "#/..." $ref up to a few levels.
func resolveRef(doc, m map[string]any) map[string]any {
	for i := 0; i < 4 && m != nil; i++ {
		ref, _ := m["$ref"].(string)
		if !strings.HasPrefix(ref, "#/") {
			return m
		}
		var cur any = doc
		for _, part := range strings.Split(ref[2:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			mm, ok := cur.(map[string]any)
			if !ok {
				return m
			}
			cur = mm[part]
		}
		next, ok := cur.(map[string]any)
		if !ok {
			return m
		}
		m = next
	}
	return m
}

func contentTypes(v any) []string {
	m, _ := v.(map[string]any)
	var out []string
	for k := range m {
		if t := normType(k); t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// StatusDocumented reports whether a response status is declared by op:
// exactly, as a range (4XX) or by "default". It returns the media types of
// the matching response.
func (o *Operation) StatusDocumented(status string) (types []string, ok bool) {
	status = strings.ToUpper(status)
	if t, has := o.Responses[status]; has {
		return t, true
	}
	if len(status) == 3 {
		if t, has := o.Responses[status[:1]+"XX"]; has {
			return t, true
		}
	}
	if t, has := o.Responses["DEFAULT"]; has {
		return t, true
	}
	return nil, false
}

// TypeAllowed reports whether media type t is covered by the documented list,
// honouring */* and type/* wildcards.
func TypeAllowed(documented []string, t string) bool {
	t = normType(t)
	for _, d := range documented {
		switch {
		case d == t, d == "*/*":
			return true
		case strings.HasSuffix(d, "/*") && strings.HasPrefix(t, d[:len(d)-1]):
			return true
		}
	}
	return false
}

// matchSegs matches a request or observed path against a compiled item. A
// {param} spec segment matches any segment; a literal spec segment matches
// only the same literal. When lenient, an observed {id} also matches a
// literal spec segment (used only to decide that a documented endpoint may
// have been exercised).
func matchSegs(it *pathItem, obs []string, lenient bool) bool {
	if len(it.segs) != len(obs) {
		return false
	}
	for i, sg := range it.segs {
		switch {
		case isParam(sg), sg == obs[i]:
		case lenient && obs[i] == VarSegment:
		default:
			return false
		}
	}
	return true
}

// Lookup finds the operation documented for method and path. path may be a
// raw request path or a learned template. pathKnown is true when some
// documented path matches regardless of method; allow lists that path's
// documented methods. HEAD is served by a documented GET.
func (s *Spec) Lookup(method, path string, lenient bool) (op *Operation, pathKnown bool, allow []string) {
	obs := SplitPath(path)
	method = strings.ToUpper(method)
	seen := map[string]bool{}
	for _, it := range s.byLen[len(obs)] {
		if !matchSegs(it, obs, lenient) {
			continue
		}
		pathKnown = true
		for m := range it.ops {
			if !seen[m] {
				seen[m] = true
				allow = append(allow, m)
			}
		}
		if o := it.ops[method]; o != nil {
			return o, true, nil
		}
		if method == "HEAD" && it.ops["GET"] != nil {
			return it.ops["GET"], true, nil
		}
	}
	sort.Strings(allow)
	return nil, pathKnown, allow
}

// Verdict is the result of checking one request against a Spec.
type Verdict struct {
	OK     bool
	Reason string   // "unknown_endpoint" or "unknown_method" when not OK
	Allow  []string // documented methods of the path, for a 405
}

// Check decides whether a request's method and path are documented.
func (s *Spec) Check(method, path string) Verdict {
	op, known, allow := s.Lookup(method, path, false)
	switch {
	case op != nil:
		return Verdict{OK: true}
	case known:
		return Verdict{Reason: "unknown_method", Allow: allow}
	}
	return Verdict{Reason: "unknown_endpoint"}
}
