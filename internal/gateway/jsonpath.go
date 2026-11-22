package gateway

import (
	"fmt"
	"strconv"
	"strings"
)

// A tiny JSONPath subset used to drop volatile fields before comparing JSON
// bodies: $.a.b, $.a[0], $['a'].b and $..key (the key at any depth).

type pathStep struct {
	key       string
	index     int
	isIndex   bool
	recursive bool
}

// jsonPath is a compiled path.
type jsonPath struct {
	src   string
	steps []pathStep
}

func parseJSONPath(s string) (*jsonPath, error) {
	orig := s
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "$") {
		return nil, fmt.Errorf("json path %q must start with $", orig)
	}
	s = s[1:]
	p := &jsonPath{src: orig}
	for s != "" {
		switch {
		case strings.HasPrefix(s, ".."):
			s = s[2:]
			name, rest := cutName(s)
			if name == "" {
				return nil, fmt.Errorf("json path %q: want a key after ..", orig)
			}
			p.steps = append(p.steps, pathStep{key: name, recursive: true})
			s = rest
		case s[0] == '.':
			name, rest := cutName(s[1:])
			if name == "" || name == "*" {
				return nil, fmt.Errorf("json path %q: want a key after .", orig)
			}
			p.steps = append(p.steps, pathStep{key: name})
			s = rest
		case s[0] == '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, fmt.Errorf("json path %q: missing ]", orig)
			}
			in := strings.TrimSpace(s[1:end])
			s = s[end+1:]
			if len(in) >= 2 && (in[0] == '\'' || in[0] == '"') && in[len(in)-1] == in[0] {
				p.steps = append(p.steps, pathStep{key: in[1 : len(in)-1]})
				continue
			}
			n, err := strconv.Atoi(in)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("json path %q: unsupported subscript [%s]", orig, in)
			}
			p.steps = append(p.steps, pathStep{index: n, isIndex: true})
		default:
			return nil, fmt.Errorf("json path %q: unexpected %q", orig, s[:1])
		}
	}
	if len(p.steps) == 0 {
		return nil, fmt.Errorf("json path %q selects the whole document", orig)
	}
	return p, nil
}

func cutName(s string) (name, rest string) {
	i := strings.IndexAny(s, ".[")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

// prune removes whatever p selects from v and returns the result. Maps are
// edited in place, so callers pass freshly decoded values.
func (p *jsonPath) prune(v any) any { return pruneSteps(v, p.steps) }

func pruneSteps(v any, steps []pathStep) any {
	if len(steps) == 0 {
		return v
	}
	st, rest := steps[0], steps[1:]
	switch t := v.(type) {
	case map[string]any:
		if st.recursive {
			if cur, ok := t[st.key]; ok {
				if len(rest) == 0 {
					delete(t, st.key)
				} else {
					t[st.key] = pruneSteps(cur, rest)
				}
			}
			for k, c := range t {
				t[k] = pruneSteps(c, steps)
			}
			return t
		}
		if st.isIndex {
			return t
		}
		cur, ok := t[st.key]
		if !ok {
			return t
		}
		if len(rest) == 0 {
			delete(t, st.key)
		} else {
			t[st.key] = pruneSteps(cur, rest)
		}
		return t
	case []any:
		if st.recursive {
			for i, c := range t {
				t[i] = pruneSteps(c, steps)
			}
			return t
		}
		if !st.isIndex || st.index >= len(t) {
			return t
		}
		if len(rest) == 0 {
			return append(t[:st.index:st.index], t[st.index+1:]...)
		}
		t[st.index] = pruneSteps(t[st.index], rest)
		return t
	}
	return v
}
