package setura

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A deliberately small YAML reader for Kubernetes manifests (the module has no
// third-party dependencies). It supports block mappings and sequences, plain
// scalars (including ones folded across lines), single and double quoted
// scalars (including multi-line ones with escapes), flow collections that span
// lines, literal and folded block scalars with chomping and indentation
// indicators, anchors, aliases and merge keys (<<), tags, comments, directives
// and multi-document streams. Tags are honoured for !!str, !!int, !!float,
// !!bool and !!null and ignored otherwise. Numbers decode to float64 and null
// to nil, like encoding/json.
//
// Unquoted scalars follow what Kubernetes tooling (sigs.k8s.io/yaml on go-yaml
// v2) does, which is YAML 1.1: y/yes/on and n/no/off (usual spellings) are
// booleans; 0x1F, 0b101, 0o17, 0755 (octal) and 1_000 are integers; .inf,
// -.inf and .nan are floats. Quoted scalars are always strings and mapping keys
// always keep their text. Explicit keys ("? key", possibly spanning lines or
// being collections) are supported; a collection key is stored under its
// compact JSON text.

type yline struct {
	indent    int
	text      string // content after the indent, comments not yet stripped
	raw       string
	parent    int // indent of the owning "-" when the line was re-read from a sequence item
	hasParent bool
}

type yparser struct {
	lines   []yline
	pos     int
	anchors map[string]any
}

// decodeManifests decodes a YAML or JSON stream into its non-empty documents.
func decodeManifests(data []byte) ([]any, error) {
	text := strings.TrimPrefix(string(data), "\ufeff")
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var v any
		if err := json.Unmarshal([]byte(t), &v); err == nil {
			return []any{v}, nil
		} else if !strings.Contains(t, "\n") {
			return nil, err
		}
		// Multi-line and not JSON: it may be flow-style YAML; fall through.
	}
	var docs []any
	var cur []string
	flush := func() error {
		defer func() { cur = nil }()
		v, err := parseYAMLDoc(cur)
		if err != nil {
			return err
		}
		if v != nil {
			docs = append(docs, v)
		}
		return nil
	}
	hasContent := func() bool {
		for _, l := range cur {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
				return true
			}
		}
		return false
	}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case l == "---" || strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "---\t"):
			if err := flush(); err != nil {
				return nil, err
			}
			if rest := strings.TrimSpace(l[3:]); rest != "" && !strings.HasPrefix(rest, "#") {
				cur = append(cur, rest)
			}
			continue
		case l == "..." || strings.HasPrefix(l, "... "):
			continue
		case strings.HasPrefix(l, "%") && !hasContent():
			continue // %YAML / %TAG directive
		}
		cur = append(cur, l)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

func parseYAMLDoc(lines []string) (v any, err error) {
	p := &yparser{anchors: map[string]any{}}
	for _, l := range lines {
		if strings.Contains(l[:len(l)-len(strings.TrimLeft(l, " \t"))], "\t") {
			if strings.TrimSpace(l) != "" {
				return nil, fmt.Errorf("yaml: tabs are not allowed for indentation")
			}
		}
		t := strings.TrimLeft(l, " ")
		p.lines = append(p.lines, yline{indent: len(l) - len(t), text: t, raw: l})
	}
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(yamlErr); ok {
				v, err = nil, e
				return
			}
			panic(r)
		}
	}()
	if !p.skip() {
		return nil, nil
	}
	v = p.block(p.lines[p.pos].indent)
	if p.skip() {
		return nil, yamlErr(fmt.Sprintf("yaml: unexpected content %q", p.lines[p.pos].text))
	}
	return v, nil
}

type yamlErr string

func (e yamlErr) Error() string { return string(e) }

func yfail(format string, a ...any) { panic(yamlErr(fmt.Sprintf(format, a...))) }

// skip advances to the next content line and reports whether one exists.
func (p *yparser) skip() bool {
	for p.pos < len(p.lines) {
		t := strings.TrimSpace(p.lines[p.pos].text)
		if t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
		p.pos++
	}
	return false
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

// parentOf is the indent that continuation lines of a scalar on l must exceed.
func parentOf(l yline) int {
	if l.hasParent {
		return l.parent
	}
	return l.indent - 1
}

// splitProps removes leading anchor (&a) and tag (!t) properties from a value.
func splitProps(t string) (anchor, tag, rest string) {
	rest = strings.TrimSpace(t)
	for rest != "" && (rest[0] == '&' || rest[0] == '!') {
		end := strings.IndexAny(rest, " \t")
		tok := rest
		if end >= 0 {
			tok, rest = rest[:end], strings.TrimSpace(rest[end:])
		} else {
			rest = ""
		}
		if tok[0] == '&' {
			anchor = tok[1:]
		} else {
			tag = tok
		}
	}
	return anchor, tag, rest
}

func (p *yparser) block(indent int) any {
	l := p.lines[p.pos]
	_, _, rest := splitProps(stripComment(l.text))
	switch {
	case isSeqItem(l.text):
		return p.seq(indent)
	case isExplicitKey(l.text), keyColon(rest) >= 0:
		return p.mapping(indent)
	}
	p.pos++
	return p.value(parentOf(l), l.text, false)
}

func (p *yparser) seq(indent int) any {
	out := []any{}
	for p.skip() {
		l := p.lines[p.pos]
		if l.indent != indent || !isSeqItem(l.text) {
			break
		}
		rest := strings.TrimLeft(l.text[1:], " ")
		_, _, bare := splitProps(stripComment(rest))
		if isSeqItem(bare) || isExplicitKey(bare) || keyColon(bare) >= 0 {
			// Re-read the item as a line indented to where its content starts.
			// Properties in front of a key belong to the key, so drop them.
			if bare != strings.TrimSpace(stripComment(rest)) {
				rest = bare
			}
			off := len(l.text) - len(rest)
			p.lines[p.pos] = yline{indent: indent + off, text: rest, raw: l.raw, parent: indent, hasParent: true}
			out = append(out, p.block(indent+off))
			continue
		}
		p.pos++
		out = append(out, p.value(indent, rest, false))
	}
	return out
}

func (p *yparser) mapping(indent int) any {
	out := obj{}
	var merges []any
	for p.skip() {
		l := p.lines[p.pos]
		if l.indent != indent || isSeqItem(l.text) {
			break
		}
		if isExplicitKey(l.text) {
			k, v := p.explicitEntry(indent)
			if k == "<<" {
				merges = append(merges, v)
			} else {
				out[k] = v
			}
			continue
		}
		text := stripComment(l.text)
		_, _, ktext := splitProps(text)
		i := keyColon(ktext)
		if i < 0 {
			yfail("yaml: expected key: value, got %q", l.text)
		}
		rawKey := strings.TrimSpace(ktext[:i])
		val := strings.TrimSpace(ktext[i+1:])
		p.pos++
		v := p.value(indent, val, true)
		if rawKey == "<<" {
			merges = append(merges, v)
			continue
		}
		out[scalarString(rawKey)] = v
	}
	mergeInto(out, merges)
	return out
}

// isExplicitKey reports whether a line starts a "? key" entry.
func isExplicitKey(t string) bool { return t == "?" || strings.HasPrefix(t, "? ") }

// isValueMarker reports whether a line starts the ": value" of an explicit key.
func isValueMarker(t string) bool { return t == ":" || strings.HasPrefix(t, ": ") }

// nested reads the node that begins right after a "?" or ":" indicator of a
// mapping at the given indent; text is what follows the indicator on its line.
// A block collection that starts on that line is re-read as a line indented to
// where its content begins.
func (p *yparser) nested(indent int, l yline, text string, allowSeq bool) any {
	_, _, bare := splitProps(stripComment(text))
	if isSeqItem(bare) || isExplicitKey(bare) || keyColon(bare) >= 0 {
		off := len(l.text) - len(text)
		p.lines[p.pos] = yline{indent: indent + off, text: text, raw: l.raw, parent: indent, hasParent: true}
		return p.block(indent + off)
	}
	p.pos++
	return p.value(indent, text, allowSeq)
}

// explicitEntry reads "? key" and its optional ": value" at the current line.
func (p *yparser) explicitEntry(indent int) (string, any) {
	l := p.lines[p.pos]
	text := strings.TrimLeft(l.text[1:], " ")
	_, _, bare := splitProps(stripComment(text))
	var key string
	switch {
	case bare == "":
		p.pos++
		key = keyText(p.value(indent, text, false), "", false)
	case isSeqItem(bare) || isExplicitKey(bare) || keyColon(bare) >= 0 ||
		strings.ContainsRune("[{\"'|>*", rune(bare[0])):
		key = keyText(p.nested(indent, l, text, false), "", false)
	default:
		// A plain scalar key, possibly folded over several lines: keep its text.
		p.pos++
		key = p.plain(indent, bare)
	}
	var v any
	if p.skip() {
		n := p.lines[p.pos]
		if n.indent == indent && isValueMarker(n.text) {
			v = p.nested(indent, n, strings.TrimLeft(n.text[1:], " "), true)
		}
	}
	return key, v
}

// mergeInto applies YAML merge keys: explicit keys win, then earlier merges.
func mergeInto(out obj, merges []any) {
	for _, m := range merges {
		srcs, ok := m.([]any)
		if !ok {
			srcs = []any{m}
		}
		for _, s := range srcs {
			sm, ok := s.(obj)
			if !ok {
				yfail("yaml: merge key (<<) needs a mapping or a list of mappings")
			}
			for k, v := range sm {
				if _, set := out[k]; !set {
					out[k] = v
				}
			}
		}
	}
}

// value reads the value that starts with text on the line just consumed.
// parent is the indent that lines belonging to the value must exceed;
// allowSeq lets a sequence sit at the parent's own indent (mapping values).
func (p *yparser) value(parent int, text string, allowSeq bool) any {
	anchor, tag, rest := splitProps(stripComment(text))
	var v any
	raw, hasRaw := "", false
	switch {
	case rest == "":
		hasRaw = true
		if p.skip() {
			n := p.lines[p.pos]
			if n.indent > parent {
				v, hasRaw = p.block(n.indent), false
			} else if allowSeq && n.indent == parent && isSeqItem(n.text) {
				v, hasRaw = p.seq(parent), false
			}
		}
	case rest[0] == '|' || rest[0] == '>':
		v = p.blockScalar(parent, rest)
	case rest[0] == '"' || rest[0] == '\'':
		v = p.quoted(rest)
	case rest[0] == '[' || rest[0] == '{':
		v = p.flow(rest)
	case rest[0] == '*' && p.isAlias(rest):
		v = p.alias(rest)
	default:
		raw, hasRaw = p.plain(parent, rest), true
		v = plainScalar(raw)
	}
	v = applyTag(tag, v, raw, hasRaw)
	if anchor != "" {
		p.anchors[anchor] = v
	}
	return v
}

// isAlias reports whether text is an alias reference. "*.example.com" is not
// an anchor in practice but an unquoted wildcard host, so it stays a scalar.
func (p *yparser) isAlias(text string) bool {
	if len(text) < 2 || strings.ContainsAny(text, " \t") {
		return false
	}
	if _, ok := p.anchors[text[1:]]; ok {
		return true
	}
	return !strings.HasPrefix(text, "*.")
}

func (p *yparser) alias(text string) any {
	v, ok := p.anchors[text[1:]]
	if !ok {
		yfail("yaml: unknown anchor %q", text[1:])
	}
	return v
}

// plain reads a plain scalar that may continue on deeper-indented lines.
func (p *yparser) plain(parent int, first string) string {
	s := first
	blank := 0
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		t := strings.TrimSpace(l.raw)
		if t == "" {
			blank++
			p.pos++
			continue
		}
		if strings.HasPrefix(t, "#") || l.indent <= parent {
			break
		}
		piece := stripComment(t)
		if blank > 0 {
			s += strings.Repeat("\n", blank)
		} else {
			s += " "
		}
		s += piece
		blank = 0
		p.pos++
		if piece != t {
			break // a trailing comment ends the scalar
		}
	}
	return s
}

// quoted reads a quoted scalar that may continue over several lines.
func (p *yparser) quoted(first string) string {
	acc := first
	for {
		if e := quoteEnd(acc); e >= 0 {
			return unquote(acc[1:e], acc[0] == '"')
		}
		if p.pos >= len(p.lines) {
			yfail("yaml: unterminated quoted string")
		}
		acc += "\n" + p.lines[p.pos].raw
		p.pos++
	}
}

// flow reads a flow collection that may continue over several lines.
func (p *yparser) flow(first string) any {
	acc := first
	for {
		if clean, end := scanFlow(acc); end >= 0 {
			f := &flowReader{s: clean[:end+1], anchors: p.anchors}
			return f.value()
		}
		if p.pos >= len(p.lines) {
			yfail("yaml: unterminated flow collection")
		}
		acc += "\n" + p.lines[p.pos].raw
		p.pos++
	}
}

// scanFlow removes comments from s and returns the index of the bracket that
// closes the collection opened at s[0], or -1 when it is not closed yet.
func scanFlow(s string) (string, int) {
	var b strings.Builder
	depth := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			b.WriteByte(c)
			if c == '\\' && q == '"' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == q {
				if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
					b.WriteByte('\'')
				} else {
					q = 0
				}
			}
			continue
		}
		switch {
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '\n'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
			continue
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
			if depth == 0 {
				b.WriteByte(c)
				return b.String(), b.Len() - 1
			}
		}
		b.WriteByte(c)
	}
	return b.String(), -1
}

// blockScalar reads a literal (|) or folded (>) scalar whose lines are
// indented deeper than the owner.
func (p *yparser) blockScalar(parent int, header string) string {
	head := strings.Fields(header)[0]
	chomp, explicit := byte(0), 0
	for _, c := range head[1:] {
		switch {
		case c == '-' || c == '+':
			chomp = byte(c)
		case c >= '1' && c <= '9':
			explicit = int(c - '0')
		}
	}
	content := -1
	if explicit > 0 {
		content = max(parent, 0) + explicit
	}
	var body []string
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if strings.TrimSpace(l.raw) == "" {
			body = append(body, "")
			p.pos++
			continue
		}
		if l.indent <= parent {
			break
		}
		if content < 0 {
			content = l.indent
		}
		if l.indent < content {
			break
		}
		body = append(body, l.raw[content:])
		p.pos++
	}
	trailing := 0
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
		trailing++
	}
	var s string
	if head[0] == '|' {
		s = strings.Join(body, "\n")
	} else {
		s = foldLines(body)
	}
	switch {
	case chomp == '-':
	case s == "":
		if chomp == '+' {
			s = strings.Repeat("\n", trailing)
		}
	case chomp == '+':
		s += "\n" + strings.Repeat("\n", trailing)
	default:
		s += "\n"
	}
	return s
}

// foldLines implements the line folding of a ">" scalar.
func foldLines(body []string) string {
	var out strings.Builder
	blanks, started, lastMore := 0, false, false
	for _, ln := range body {
		if ln == "" {
			blanks++
			continue
		}
		more := ln[0] == ' ' || ln[0] == '\t'
		switch {
		case !started:
			out.WriteString(strings.Repeat("\n", blanks))
		case blanks == 0 && !more && !lastMore:
			out.WriteByte(' ')
		case blanks == 0:
			out.WriteByte('\n')
		case !more && !lastMore:
			out.WriteString(strings.Repeat("\n", blanks))
		default:
			out.WriteString(strings.Repeat("\n", blanks+1))
		}
		out.WriteString(ln)
		started, lastMore, blanks = true, more, 0
	}
	return out.String()
}

// stripComment removes a trailing " # comment" that is outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			if i == 0 || strings.ContainsRune(" [{,:", rune(s[i-1])) {
				q = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return strings.TrimRight(s, " \t")
}

// keyColon returns the index of the key/value separator colon, or -1.
func keyColon(s string) int {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			if i == 0 {
				q = c
			}
		case i == 0 && (c == '[' || c == '{'):
			return -1
		case c == ':' && (i+1 == len(s) || s[i+1] == ' '):
			return i
		}
	}
	return -1
}

// scalarString decodes a mapping key.
func scalarString(s string) (out string) {
	out = s
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(yamlErr); !ok {
				panic(r)
			}
		}
	}()
	f := &flowReader{s: s}
	if v, ok := f.value().(string); ok && f.i == len(f.s) {
		out = v
	}
	return out
}

var (
	yamlNumber = regexp.MustCompile(`^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$`)
	yamlInt    = regexp.MustCompile(`^[-+]?(0[xX][0-9a-fA-F_]+|0[bB][01_]+|0o[0-7_]+|[0-9][0-9_]*)$`)
	yamlUScore = regexp.MustCompile(`^[-+]?([0-9][0-9_]*\.?[0-9_]*|\.[0-9][0-9_]*)([eE][-+]?[0-9]+)?$`)
)

// yaml11Bool reports the YAML 1.1 boolean an unquoted scalar spells.
func yaml11Bool(s string) (val, ok bool) {
	switch s {
	case "true", "True", "TRUE", "y", "Y", "yes", "Yes", "YES", "on", "On", "ON":
		return true, true
	case "false", "False", "FALSE", "n", "N", "no", "No", "NO", "off", "Off", "OFF":
		return false, true
	}
	return false, false
}

// yaml11Number parses the numeric forms of YAML 1.1 that go-yaml v2 accepts.
func yaml11Number(s string) (float64, bool) {
	switch s {
	case ".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF":
		return math.Inf(1), true
	case "-.inf", "-.Inf", "-.INF":
		return math.Inf(-1), true
	case ".nan", ".NaN", ".NAN":
		return math.NaN(), true
	}
	if yamlInt.MatchString(s) {
		clean := strings.ReplaceAll(s, "_", "")
		if n, err := strconv.ParseInt(clean, 0, 64); err == nil {
			return float64(n), true
		}
		if n, err := strconv.ParseUint(clean, 0, 64); err == nil {
			return float64(n), true
		}
	}
	if yamlNumber.MatchString(s) || strings.Contains(s, "_") && yamlUScore.MatchString(s) {
		if n, err := strconv.ParseFloat(strings.ReplaceAll(s, "_", ""), 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func plainScalar(s string) any {
	switch s {
	case "", "~", "null", "Null", "NULL":
		return nil
	}
	if b, ok := yaml11Bool(s); ok {
		return b
	}
	if n, ok := yaml11Number(s); ok {
		return n
	}
	return s
}

// keyText is the string a mapping key is stored under: the source text of a
// scalar (so an unquoted on, 0x10 or 1.0 stays as written), the compact JSON
// of a collection.
func keyText(v any, raw string, hasRaw bool) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		if hasRaw {
			return raw
		}
		return ""
	case float64, bool:
		if hasRaw {
			return raw
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// applyTag honours the core YAML tags that change a scalar's type. raw is the
// source text of a scalar when hasRaw is set.
func applyTag(tag string, v any, raw string, hasRaw bool) any {
	text := func() string {
		if hasRaw {
			return strings.TrimSpace(raw)
		}
		s, _ := v.(string)
		return strings.TrimSpace(s)
	}
	switch tag {
	case "!!str", "!":
		switch x := v.(type) {
		case string:
			return x
		case nil:
			return ""
		case float64, bool:
			if hasRaw {
				return raw
			}
			return fmt.Sprint(x)
		}
	case "!!int", "!!float":
		if n, ok := yaml11Number(text()); ok {
			return n
		}
		if n, err := strconv.ParseFloat(text(), 64); err == nil {
			return n
		}
	case "!!bool":
		if b, ok := yaml11Bool(text()); ok {
			return b
		}
	case "!!null":
		return nil
	}
	return v
}

// quoteEnd returns the index of the quote that closes the quoted scalar
// starting at s[0], or -1.
func quoteEnd(s string) int {
	q := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q:
			if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

var yamlEscapes = map[byte]string{
	'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n", 'v': "\v", 'f': "\f", 'r': "\r",
	'e': "\x1b", ' ': " ", '"': "\"", '/': "/", '\\': "\\", 'N': "\u0085", '_': " ", 'L': " ", 'P': " ",
}

// unquote decodes the text between the quotes of a quoted scalar, resolving
// escapes and folding line breaks as YAML does.
func unquote(body string, double bool) string {
	var b []byte
	keep := 0 // bytes of b that must not be trimmed (escaped content)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case double && c == '\\' && i+1 < len(body):
			i++
			e := body[i]
			switch {
			case e == '\n':
				for i+1 < len(body) && (body[i+1] == ' ' || body[i+1] == '\t') {
					i++
				}
				continue
			case e == 'x' || e == 'u' || e == 'U':
				n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
				if i+n < len(body) {
					if r, err := strconv.ParseUint(body[i+1:i+1+n], 16, 32); err == nil {
						b = utf8.AppendRune(b, rune(r))
						i += n
						keep = len(b)
						continue
					}
				}
				b = append(b, '\\', e)
			default:
				if r, ok := yamlEscapes[e]; ok {
					b = append(b, r...)
				} else {
					b = append(b, '\\', e)
				}
			}
			keep = len(b)
		case !double && c == '\'' && i+1 < len(body) && body[i+1] == '\'':
			b = append(b, '\'')
			i++
			keep = len(b)
		case c == '\n':
			for len(b) > keep && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
				b = b[:len(b)-1]
			}
			n, j := 0, i
			for j < len(body) && body[j] == '\n' {
				n++
				j++
				for j < len(body) && (body[j] == ' ' || body[j] == '\t') {
					j++
				}
			}
			i = j - 1
			if n == 1 {
				b = append(b, ' ')
			} else {
				b = append(b, strings.Repeat("\n", n-1)...)
			}
			keep = len(b)
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

type flowReader struct {
	s       string
	i       int
	anchors map[string]any
}

func (f *flowReader) ws() {
	for f.i < len(f.s) && strings.IndexByte(" \t\r\n", f.s[f.i]) >= 0 {
		f.i++
	}
}

// value reads one flow node, with its anchor and tag properties.
func (f *flowReader) value() any {
	v, _, _ := f.valueRaw()
	return v
}

// valueRaw is value, also returning a scalar's source text.
func (f *flowReader) valueRaw() (any, string, bool) {
	f.ws()
	var anchor, tag string
	for f.i < len(f.s) && (f.s[f.i] == '&' || f.s[f.i] == '!') {
		start := f.i
		for f.i < len(f.s) && strings.IndexByte(" \t\r\n,]}", f.s[f.i]) < 0 {
			f.i++
		}
		if tok := f.s[start:f.i]; tok[0] == '&' {
			anchor = tok[1:]
		} else {
			tag = tok
		}
		f.ws()
	}
	v, raw, hasRaw := f.node()
	v = applyTag(tag, v, raw, hasRaw)
	if anchor != "" && f.anchors != nil {
		f.anchors[anchor] = v
	}
	return v, raw, hasRaw
}

func (f *flowReader) node() (v any, raw string, hasRaw bool) {
	if f.i >= len(f.s) {
		return nil, "", true
	}
	switch c := f.s[f.i]; c {
	case '[':
		f.i++
		out := []any{}
		for {
			f.ws()
			if f.i >= len(f.s) {
				yfail("yaml: unterminated flow sequence")
			}
			if f.s[f.i] == ']' {
				f.i++
				return out, "", false
			}
			before := f.i
			out = append(out, f.value())
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			} else if f.i == before {
				yfail("yaml: unexpected %q in flow sequence", string(f.s[f.i]))
			}
		}
	case '{':
		f.i++
		out := obj{}
		var merges []any
		for {
			f.ws()
			if f.i >= len(f.s) {
				yfail("yaml: unterminated flow mapping")
			}
			if f.s[f.i] == '}' {
				f.i++
				mergeInto(out, merges)
				return out, "", false
			}
			before := f.i
			kv, kraw, khas := f.valueRaw()
			k := keyText(kv, kraw, khas)
			f.ws()
			var v any
			if f.i < len(f.s) && f.s[f.i] == ':' {
				f.i++
				v = f.value()
			}
			if k == "<<" {
				merges = append(merges, v)
			} else {
				out[k] = v
			}
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			} else if f.i == before {
				yfail("yaml: unexpected %q in flow mapping", string(f.s[f.i]))
			}
		}
	case '"', '\'':
		e := quoteEnd(f.s[f.i:])
		if e < 0 {
			yfail("yaml: unterminated quoted string")
		}
		out := unquote(f.s[f.i+1:f.i+e], c == '"')
		f.i += e + 1
		return out, out, true
	case '*':
		start := f.i
		f.i++
		for f.i < len(f.s) && strings.IndexByte(" \t\r\n,]}", f.s[f.i]) < 0 {
			f.i++
		}
		name := f.s[start+1 : f.i]
		if v, ok := f.anchors[name]; ok {
			return v, "", false
		}
		if strings.HasPrefix(f.s[start:], "*.") {
			s := f.s[start:f.i]
			return s, s, true
		}
		yfail("yaml: unknown anchor %q", name)
	}
	// plain scalar up to a flow delimiter
	start := f.i
	for f.i < len(f.s) && !strings.ContainsRune(",]}", rune(f.s[f.i])) {
		if f.s[f.i] == ':' && (f.i+1 == len(f.s) || strings.IndexByte(" \t\r\n", f.s[f.i+1]) >= 0) {
			break
		}
		f.i++
	}
	s := strings.Join(strings.Fields(f.s[start:f.i]), " ")
	return plainScalar(s), s, true
}
