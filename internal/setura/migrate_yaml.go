package setura

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// A deliberately small YAML reader for Kubernetes manifests (the module has no
// third-party dependencies). It supports block mappings and sequences, plain
// and quoted scalars, single-line flow collections, literal and folded block
// scalars, comments and multi-document streams. It does not support anchors,
// tags, multi-line flow collections or multi-line plain scalars. Numbers
// decode to float64 and null to nil, like encoding/json.

type yline struct {
	indent int
	text   string // content after the indent, comments not yet stripped
	raw    string
}

type yparser struct {
	lines []yline
	pos   int
}

// decodeManifests decodes a YAML or JSON stream into its non-empty documents.
func decodeManifests(data []byte) ([]any, error) {
	text := strings.TrimPrefix(string(data), "\ufeff")
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var v any
		if err := json.Unmarshal([]byte(t), &v); err != nil {
			return nil, err
		}
		return []any{v}, nil
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
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "---" || strings.HasPrefix(l, "--- ") {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		if l == "..." {
			continue
		}
		cur = append(cur, l)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return docs, nil
}

func parseYAMLDoc(lines []string) (v any, err error) {
	p := &yparser{}
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

func (p *yparser) block(indent int) any {
	l := p.lines[p.pos]
	switch {
	case isSeqItem(l.text):
		return p.seq(indent)
	case keyColon(stripComment(l.text)) >= 0:
		return p.mapping(indent)
	}
	p.pos++
	return parseInline(stripComment(l.text))
}

func (p *yparser) seq(indent int) any {
	out := []any{}
	for p.skip() {
		l := p.lines[p.pos]
		if l.indent != indent || !isSeqItem(l.text) {
			break
		}
		rest := strings.TrimLeft(l.text[1:], " ")
		if strings.TrimSpace(stripComment(rest)) == "" {
			p.pos++
			if p.skip() && p.lines[p.pos].indent > indent {
				out = append(out, p.block(p.lines[p.pos].indent))
			} else {
				out = append(out, nil)
			}
			continue
		}
		// Re-read the item as a line indented to where its content starts.
		off := len(l.text) - len(rest)
		p.lines[p.pos] = yline{indent: indent + off, text: rest, raw: l.raw}
		out = append(out, p.block(indent+off))
	}
	return out
}

func (p *yparser) mapping(indent int) any {
	out := obj{}
	for p.skip() {
		l := p.lines[p.pos]
		if l.indent != indent || isSeqItem(l.text) {
			break
		}
		text := stripComment(l.text)
		i := keyColon(text)
		if i < 0 {
			panic(yamlErr(fmt.Sprintf("yaml: expected key: value, got %q", l.text)))
		}
		key := scalarString(strings.TrimSpace(text[:i]))
		val := strings.TrimSpace(text[i+1:])
		p.pos++
		switch {
		case val == "":
			if p.skip() {
				n := p.lines[p.pos]
				if n.indent > indent {
					out[key] = p.block(n.indent)
					continue
				}
				if n.indent == indent && isSeqItem(n.text) {
					out[key] = p.seq(indent)
					continue
				}
			}
			out[key] = nil
		case val[0] == '|' || val[0] == '>':
			out[key] = p.blockScalar(indent, val)
		default:
			out[key] = parseInline(val)
		}
	}
	return out
}

// blockScalar reads a literal (|) or folded (>) scalar whose lines are
// indented deeper than the owning key.
func (p *yparser) blockScalar(parent int, header string) string {
	var body []string
	min := -1
	for p.pos < len(p.lines) {
		l := p.lines[p.pos]
		if strings.TrimSpace(l.raw) != "" {
			if l.indent <= parent {
				break
			}
			if min < 0 || l.indent < min {
				min = l.indent
			}
		}
		body = append(body, l.raw)
		p.pos++
	}
	for len(body) > 0 && strings.TrimSpace(body[len(body)-1]) == "" {
		body = body[:len(body)-1]
	}
	for i, b := range body {
		if len(b) >= min && min > 0 {
			body[i] = b[min:]
		} else {
			body[i] = strings.TrimSpace(b)
		}
	}
	sep := "\n"
	if header[0] == '>' {
		sep = " "
	}
	s := strings.Join(body, sep)
	if !strings.Contains(header, "-") && s != "" {
		s += "\n"
	}
	return s
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

func scalarString(s string) string {
	if v, ok := parseInline(s).(string); ok {
		return v
	}
	return s
}

// parseInline decodes a one-line scalar or flow collection.
func parseInline(s string) any {
	s = strings.TrimSpace(s)
	f := &flowReader{s: s}
	v := f.value()
	f.ws()
	if f.i != len(f.s) {
		// Not valid flow syntax: treat the whole text as a plain scalar.
		return plainScalar(s)
	}
	return v
}

var yamlNumber = regexp.MustCompile(`^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$`)

func plainScalar(s string) any {
	switch s {
	case "", "~", "null", "Null", "NULL":
		return nil
	case "true", "True", "TRUE":
		return true
	case "false", "False", "FALSE":
		return false
	}
	if yamlNumber.MatchString(s) {
		if n, err := strconv.ParseFloat(s, 64); err == nil {
			return n
		}
	}
	return s
}

type flowReader struct {
	s string
	i int
}

func (f *flowReader) ws() {
	for f.i < len(f.s) && (f.s[f.i] == ' ' || f.s[f.i] == '\t') {
		f.i++
	}
}

func (f *flowReader) value() any {
	f.ws()
	if f.i >= len(f.s) {
		return nil
	}
	switch c := f.s[f.i]; c {
	case '[':
		f.i++
		out := []any{}
		for {
			f.ws()
			if f.i >= len(f.s) {
				panic(yamlErr("yaml: unterminated flow sequence"))
			}
			if f.s[f.i] == ']' {
				f.i++
				return out
			}
			out = append(out, f.value())
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
		}
	case '{':
		f.i++
		out := obj{}
		for {
			f.ws()
			if f.i >= len(f.s) {
				panic(yamlErr("yaml: unterminated flow mapping"))
			}
			if f.s[f.i] == '}' {
				f.i++
				return out
			}
			k := f.value()
			f.ws()
			var v any
			if f.i < len(f.s) && f.s[f.i] == ':' {
				f.i++
				v = f.value()
			}
			out[fmt.Sprint(k)] = v
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
		}
	case '"':
		start := f.i
		f.i++
		for f.i < len(f.s) && f.s[f.i] != '"' {
			if f.s[f.i] == '\\' {
				f.i++
			}
			f.i++
		}
		if f.i >= len(f.s) {
			panic(yamlErr("yaml: unterminated double-quoted string"))
		}
		f.i++
		var out string
		if err := json.Unmarshal([]byte(f.s[start:f.i]), &out); err != nil {
			out = f.s[start+1 : f.i-1]
		}
		return out
	case '\'':
		f.i++
		var b strings.Builder
		for f.i < len(f.s) {
			if f.s[f.i] == '\'' {
				if f.i+1 < len(f.s) && f.s[f.i+1] == '\'' {
					b.WriteByte('\'')
					f.i += 2
					continue
				}
				f.i++
				return b.String()
			}
			b.WriteByte(f.s[f.i])
			f.i++
		}
		panic(yamlErr("yaml: unterminated single-quoted string"))
	}
	// plain scalar up to a flow delimiter
	start := f.i
	for f.i < len(f.s) && !strings.ContainsRune(",]}", rune(f.s[f.i])) {
		if f.s[f.i] == ':' && (f.i+1 == len(f.s) || f.s[f.i+1] == ' ') {
			break
		}
		f.i++
	}
	return plainScalar(strings.TrimSpace(f.s[start:f.i]))
}
