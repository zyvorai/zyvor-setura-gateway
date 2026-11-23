package contract

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parseYAML reads the YAML subset OpenAPI documents are normally written in:
// block mappings and sequences, plain, single and double quoted scalars,
// one-line or multi-line flow collections, and | and > block scalars.
// Anchors, aliases, tags, merge keys, multiple documents and tabs are rejected
// with an error rather than guessed at. Every plain scalar except null, ~,
// true and false is returned as a string.
func parseYAML(src []byte) (any, error) {
	p := &yamlParser{}
	for _, l := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		p.lines = append(p.lines, l)
	}
	for i, l := range p.lines {
		if strings.HasPrefix(strings.TrimLeft(l, " "), "\t") {
			p.i = i
			return nil, p.errf("tabs are not allowed for indentation")
		}
	}
	p.skip()
	if p.i < len(p.lines) && strings.TrimSpace(p.lines[p.i]) == "---" {
		p.i++
	}
	p.skip()
	if p.i >= len(p.lines) {
		return nil, errors.New("empty document")
	}
	v, err := p.block(p.indent(p.i))
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.lines) {
		if t := strings.TrimSpace(p.lines[p.i]); t == "---" || t == "..." {
			return nil, errors.New("multiple YAML documents are not supported")
		}
		return nil, p.errf("unexpected content")
	}
	return v, nil
}

type yamlParser struct {
	lines []string
	i     int
}

func (p *yamlParser) errf(format string, a ...any) error {
	return fmt.Errorf("yaml line %d: %s", p.i+1, fmt.Sprintf(format, a...))
}

// skip moves past blank and comment-only lines.
func (p *yamlParser) skip() {
	for p.i < len(p.lines) {
		t := strings.TrimSpace(p.lines[p.i])
		if t == "" || strings.HasPrefix(t, "#") {
			p.i++
			continue
		}
		return
	}
}

func (p *yamlParser) indent(i int) int {
	l := p.lines[i]
	n := 0
	for n < len(l) && l[n] == ' ' {
		n++
	}
	return n
}

// stripComment removes a trailing " #..." outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				if q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					q = 0
				}
			} else if c == '\\' && q == '"' {
				i++
			}
		case c == '"' || c == '\'':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '[' || s[i-1] == '{' || s[i-1] == ',' || s[i-1] == ':' {
				q = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return strings.TrimRight(s, " ")
}

func (p *yamlParser) block(indent int) (any, error) {
	p.skip()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	if strings.Contains(p.lines[p.i][:p.indent(p.i)], "\t") || strings.HasPrefix(p.lines[p.i], "\t") {
		return nil, p.errf("tabs are not allowed for indentation")
	}
	t := stripComment(strings.TrimSpace(p.lines[p.i]))
	if t == "-" || strings.HasPrefix(t, "- ") {
		return p.seq(indent)
	}
	if _, _, ok := splitKey(t); ok {
		return p.mapping(indent)
	}
	// a lone scalar or flow collection
	p.i++
	return p.value(t, indent)
}

func (p *yamlParser) seq(indent int) (any, error) {
	out := []any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.indent(p.i) != indent {
			break
		}
		t := stripComment(strings.TrimSpace(p.lines[p.i]))
		if t != "-" && !strings.HasPrefix(t, "- ") {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(t, "-"))
		if rest == "" {
			p.i++
			p.skip()
			if p.i < len(p.lines) && p.indent(p.i) > indent {
				v, err := p.block(p.indent(p.i))
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, ok := splitKey(rest); ok && !strings.HasPrefix(rest, "[") && !strings.HasPrefix(rest, "{") {
			// "- key: v": the item is a mapping whose first key sits after the dash
			off := indent + (len(t) - len(rest))
			p.lines[p.i] = strings.Repeat(" ", off) + rest
			v, err := p.mapping(off)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.i++
		v, err := p.value(rest, indent)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// splitKey splits "key: value" and reports ok when the line is a mapping entry.
func splitKey(t string) (key, rest string, ok bool) {
	if t == "" {
		return "", "", false
	}
	if t[0] == '"' || t[0] == '\'' {
		q := t[0]
		for i := 1; i < len(t); i++ {
			if t[i] == '\\' && q == '"' {
				i++
				continue
			}
			if t[i] == q {
				if q == '\'' && i+1 < len(t) && t[i+1] == '\'' {
					i++
					continue
				}
				after := t[i+1:]
				if after == ":" || strings.HasPrefix(after, ": ") {
					k, _ := unquote(t[:i+1])
					return k, strings.TrimSpace(after[1:]), true
				}
				return "", "", false
			}
		}
		return "", "", false
	}
	if t[0] == '[' || t[0] == '{' {
		return "", "", false
	}
	for i := 0; i < len(t); i++ {
		if t[i] == ':' && (i+1 == len(t) || t[i+1] == ' ') {
			return strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

func (p *yamlParser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.lines) {
			break
		}
		ind := p.indent(p.i)
		if ind < indent {
			break
		}
		if ind > indent {
			return nil, p.errf("unexpected indentation")
		}
		t := stripComment(strings.TrimSpace(p.lines[p.i]))
		key, rest, ok := splitKey(t)
		if !ok {
			if t == "-" || strings.HasPrefix(t, "- ") {
				break
			}
			return nil, p.errf("expected a key: value pair")
		}
		if key == "<<" {
			return nil, p.errf("merge keys are not supported")
		}
		if _, dup := out[key]; dup {
			return nil, p.errf("duplicate key %q", key)
		}
		p.i++
		if rest == "" {
			p.skip()
			switch {
			case p.i < len(p.lines) && p.indent(p.i) > indent:
				v, err := p.block(p.indent(p.i))
				if err != nil {
					return nil, err
				}
				out[key] = v
			case p.i < len(p.lines) && p.indent(p.i) == indent && strings.HasPrefix(strings.TrimSpace(p.lines[p.i]), "-"):
				v, err := p.seq(indent) // a sequence may sit at the key's own indent
				if err != nil {
					return nil, err
				}
				out[key] = v
			default:
				out[key] = nil
			}
			continue
		}
		v, err := p.value(rest, indent)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, nil
}

// value parses the text after "key:" or "- " that starts on the current line.
// The line after it has already been stepped to (p.i).
func (p *yamlParser) value(s string, indent int) (any, error) {
	switch {
	case strings.HasPrefix(s, "&"), strings.HasPrefix(s, "*"), strings.HasPrefix(s, "!"):
		return nil, p.errf("anchors, aliases and tags are not supported; convert the document to JSON")
	case s[0] == '|' || s[0] == '>':
		return p.blockScalar(s[0] == '>', indent), nil
	case s[0] == '[' || s[0] == '{':
		for !balanced(s) {
			if p.i >= len(p.lines) {
				return nil, p.errf("unterminated flow collection")
			}
			s += " " + stripComment(strings.TrimSpace(p.lines[p.i]))
			p.i++
		}
		fp := &flow{s: s}
		v, err := fp.value()
		if err != nil {
			return nil, p.errf("%v", err)
		}
		fp.ws()
		if fp.i != len(fp.s) {
			return nil, p.errf("unexpected text after flow collection")
		}
		return v, nil
	}
	return scalar(s)
}

func balanced(s string) bool {
	depth := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else if c == '\\' && q == '"' {
				i++
			}
		case c == '"' || c == '\'':
			q = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		}
	}
	return depth <= 0
}

func (p *yamlParser) blockScalar(fold bool, indent int) string {
	var parts []string
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if strings.TrimSpace(l) != "" && p.indent(p.i) <= indent {
			break
		}
		parts = append(parts, strings.TrimSpace(l))
		p.i++
	}
	sep := "\n"
	if fold {
		sep = " "
	}
	return strings.TrimSpace(strings.Join(parts, sep))
}

func unquote(s string) (string, error) {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u, nil
		}
		return s[1 : len(s)-1], nil
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	return s, fmt.Errorf("bad quoted scalar %s", s)
}

func scalar(s string) (any, error) {
	if s[0] == '"' || s[0] == '\'' {
		return unquote(s)
	}
	switch s {
	case "null", "~", "Null", "NULL":
		return nil, nil
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	}
	return s, nil
}

// flow parses [a, b] and {k: v} collections.
type flow struct {
	s string
	i int
}

func (f *flow) ws() {
	for f.i < len(f.s) && f.s[f.i] == ' ' {
		f.i++
	}
}

func (f *flow) value() (any, error) {
	f.ws()
	if f.i >= len(f.s) {
		return nil, errors.New("unexpected end of flow collection")
	}
	switch f.s[f.i] {
	case '[':
		f.i++
		out := []any{}
		for {
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ']' {
				f.i++
				return out, nil
			}
			v, err := f.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
		}
	case '{':
		f.i++
		out := map[string]any{}
		for {
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == '}' {
				f.i++
				return out, nil
			}
			k, err := f.token(true)
			if err != nil {
				return nil, err
			}
			f.ws()
			if f.i >= len(f.s) || f.s[f.i] != ':' {
				return nil, errors.New("expected ':' in flow mapping")
			}
			f.i++
			v, err := f.value()
			if err != nil {
				return nil, err
			}
			ks, _ := k.(string)
			out[ks] = v
			f.ws()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
		}
	}
	return f.token(false)
}

func (f *flow) token(key bool) (any, error) {
	f.ws()
	if f.i >= len(f.s) {
		return nil, errors.New("unexpected end of flow collection")
	}
	c := f.s[f.i]
	if c == '"' || c == '\'' {
		j := f.i + 1
		for j < len(f.s) && f.s[j] != c {
			if f.s[j] == '\\' && c == '"' {
				j++
			}
			j++
		}
		if j >= len(f.s) {
			return nil, errors.New("unterminated quoted scalar")
		}
		tok := f.s[f.i : j+1]
		f.i = j + 1
		return unquote(tok)
	}
	j := f.i
	for j < len(f.s) {
		ch := f.s[j]
		if ch == ',' || ch == ']' || ch == '}' || (ch == ':' && (key || j+1 == len(f.s) || f.s[j+1] == ' ')) {
			break
		}
		j++
	}
	tok := strings.TrimSpace(f.s[f.i:j])
	f.i = j
	if key {
		return tok, nil
	}
	if tok == "" {
		return nil, nil
	}
	return scalar(tok)
}
