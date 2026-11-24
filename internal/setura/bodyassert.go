package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Body assertions beyond "contains": a regular expression and JSON path
// checks. They read the same bounded body (maxBody) as body_contains.

// JSONAssert is one JSON path expectation. Path is "$.a.b[0].c" (the leading
// "$" and "." are optional). Want is "*" (the path must exist), a literal
// (scalar equality), or an operator form: "!=x", ">n", ">=n", "<n", "<=n",
// "~regex". A literal that starts with an operator is written "==literal".
type JSONAssert struct {
	Path string
	Want string
}

// parseJSONPath splits a path into keys and array indexes.
func parseJSONPath(p string) ([]any, error) {
	s := strings.TrimSpace(p)
	s = strings.TrimPrefix(s, "$")
	var out []any
	for s != "" {
		switch s[0] {
		case '.':
			s = s[1:]
			i := strings.IndexAny(s, ".[")
			if i < 0 {
				i = len(s)
			}
			if i == 0 {
				return nil, userErrorf("invalid JSON path %q", p)
			}
			out = append(out, s[:i])
			s = s[i:]
		case '[':
			j := strings.IndexByte(s, ']')
			if j < 0 {
				return nil, userErrorf("invalid JSON path %q: unclosed [", p)
			}
			n, err := strconv.Atoi(s[1:j])
			if err != nil || n < 0 {
				return nil, userErrorf("invalid JSON path %q: [%s] is not an array index", p, s[1:j])
			}
			out = append(out, n)
			s = s[j+1:]
		default:
			i := strings.IndexAny(s, ".[")
			if i < 0 {
				i = len(s)
			}
			out = append(out, s[:i])
			s = s[i:]
		}
	}
	if len(out) == 0 {
		return nil, userErrorf("invalid JSON path %q", p)
	}
	return out, nil
}

// validate checks the path and any regular expression up front.
func (a JSONAssert) validate() error {
	if _, err := parseJSONPath(a.Path); err != nil {
		return err
	}
	if strings.HasPrefix(a.Want, "~") {
		if _, err := regexp.Compile(a.Want[1:]); err != nil {
			return userErrorf("JSON assertion %s: invalid regular expression: %v", a.Path, err)
		}
	}
	return nil
}

func jsonScalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	case nil:
		return "null", true
	}
	return "", false
}

// evalJSONAssert checks one expectation against a decoded document.
func evalJSONAssert(doc any, a JSONAssert) error {
	steps, err := parseJSONPath(a.Path)
	if err != nil {
		return err
	}
	cur := doc
	for _, st := range steps {
		switch k := st.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return fmt.Errorf("JSON path %s: no object at %q", a.Path, k)
			}
			if cur, ok = m[k]; !ok {
				return fmt.Errorf("JSON path %s is missing", a.Path)
			}
		case int:
			l, ok := cur.([]any)
			if !ok || k >= len(l) {
				return fmt.Errorf("JSON path %s is missing", a.Path)
			}
			cur = l[k]
		}
	}
	want := a.Want
	if want == "*" {
		return nil
	}
	got, scalar := jsonScalar(cur)
	if !scalar {
		switch c := cur.(type) {
		case []any:
			got = fmt.Sprintf("array of %d", len(c))
		default:
			got = "object"
		}
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("JSON %s: %s", a.Path, fmt.Sprintf(format, args...))
	}
	num2 := func(op string) (float64, float64, error) {
		g, err1 := strconv.ParseFloat(got, 64)
		w, err2 := strconv.ParseFloat(strings.TrimSpace(want[len(op):]), 64)
		if !scalar || err1 != nil || err2 != nil {
			return 0, 0, fail("%s needs numbers, received %s", op, pyRepr(got))
		}
		return g, w, nil
	}
	switch {
	case strings.HasPrefix(want, "=="):
		want = want[2:]
	case strings.HasPrefix(want, "!="):
		if scalar && got == want[2:] {
			return fail("must not be %s", pyRepr(want[2:]))
		}
		return nil
	case strings.HasPrefix(want, ">="), strings.HasPrefix(want, "<="):
		g, w, err := num2(want[:2])
		if err != nil {
			return err
		}
		if (want[0] == '>' && g < w) || (want[0] == '<' && g > w) {
			return fail("expected %s, received %s", want, got)
		}
		return nil
	case strings.HasPrefix(want, ">"), strings.HasPrefix(want, "<"):
		g, w, err := num2(want[:1])
		if err != nil {
			return err
		}
		if (want[0] == '>' && g <= w) || (want[0] == '<' && g >= w) {
			return fail("expected %s, received %s", want, got)
		}
		return nil
	case strings.HasPrefix(want, "~"):
		re, err := regexp.Compile(want[1:])
		if err != nil {
			return userErrorf("JSON assertion %s: invalid regular expression: %v", a.Path, err)
		}
		if !scalar || !re.MatchString(got) {
			return fail("%s does not match %s", pyRepr(got), want)
		}
		return nil
	}
	if !scalar || got != want {
		return fail("expected %s, received %s", pyRepr(want), pyRepr(got))
	}
	return nil
}

// checkBody runs the regex and JSON assertions on a response body.
func (o ProbeOptions) checkBody(body []byte) (int, error) {
	n := 0
	if o.BodyContains != "" {
		if !bytes.Contains(body, []byte(o.BodyContains)) {
			return n, fmt.Errorf("response body does not contain %s", pyRepr(o.BodyContains))
		}
		n++
	}
	if o.BodyMatches != "" {
		re, err := regexp.Compile(o.BodyMatches)
		if err != nil {
			return n, userErrorf("invalid body_matches regular expression: %v", err)
		}
		if !re.Match(body) {
			return n, fmt.Errorf("response body does not match /%s/", o.BodyMatches)
		}
		n++
	}
	if len(o.JSON) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return n, fmt.Errorf("response body is not JSON: %v", err)
		}
		for _, a := range o.JSON {
			if err := evalJSONAssert(doc, a); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func (o ProbeOptions) needsBody() bool {
	return o.BodyContains != "" || o.BodyMatches != "" || len(o.JSON) > 0
}

// validateBody rejects bad expectations before any traffic is sent.
func (o ProbeOptions) validateBody() error {
	for name, want := range o.Headers {
		if strings.HasPrefix(want, "~") {
			if _, err := regexp.Compile(want[1:]); err != nil {
				return userErrorf("header %s: invalid regular expression: %v", name, err)
			}
		}
	}
	if o.BodyMatches != "" {
		if _, err := regexp.Compile(o.BodyMatches); err != nil {
			return userErrorf("invalid body_matches regular expression: %v", err)
		}
	}
	for _, a := range o.JSON {
		if err := a.validate(); err != nil {
			return err
		}
	}
	return nil
}

// parseJSONFlag parses "PATH=VALUE" (value defaults to "*", present).
func parseJSONFlag(s string) (JSONAssert, error) {
	p, v, ok := strings.Cut(s, "=")
	if !ok {
		v = "*"
	}
	a := JSONAssert{Path: strings.TrimSpace(p), Want: v}
	return a, a.validate()
}

// applyCheckBody reads body_matches and json from a check case.
func applyCheckBody(m obj, o *ProbeOptions) error {
	o.BodyMatches = str(m, "body_matches", "")
	if j, ok := m["json"]; ok {
		jm := asMap(j)
		if jm == nil {
			return userError("json must be an object of JSON paths to expected values")
		}
		for _, k := range sortedKeys(jm) {
			var want string
			switch x := jm[k].(type) {
			case string:
				want = x
			case float64:
				want = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				want = strconv.FormatBool(x)
			case nil:
				want = "null"
			default:
				return userErrorf("json %s: the expected value must be a string, number, boolean or null", k)
			}
			o.JSON = append(o.JSON, JSONAssert{Path: k, Want: want})
		}
	}
	return o.validateBody()
}

// checkHeader judges one response header expectation. Want is an exact value,
// "*" (present), "!" (must be absent) or "~regex" (the joined value matches).
func checkHeader(h http.Header, name, want string) error {
	vals := h.Values(name)
	if want == "!" {
		if len(vals) > 0 {
			return fmt.Errorf("header %s must be absent, received %s", name, pyRepr(strings.Join(vals, ", ")))
		}
		return nil
	}
	if len(vals) == 0 {
		return fmt.Errorf("header %s is missing", name)
	}
	got := strings.Join(vals, ", ")
	if strings.HasPrefix(want, "~") {
		re, err := regexp.Compile(want[1:])
		if err != nil {
			return userErrorf("header %s: invalid regular expression: %v", name, err)
		}
		if !re.MatchString(got) {
			return fmt.Errorf("header %s: %s does not match %s", name, pyRepr(got), want)
		}
		return nil
	}
	if want != "*" && got != want {
		return fmt.Errorf("header %s: expected %s, received %s", name, pyRepr(want), pyRepr(got))
	}
	return nil
}
