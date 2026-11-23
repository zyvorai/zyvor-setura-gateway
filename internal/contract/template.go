// Package contract learns an inventory of the API endpoints a gateway
// serves (method, path template, status codes, sizes, latencies, parameter
// names), reads OpenAPI 3.x documents, compares the two and checks requests
// against a document. It holds no request bodies and no header or query
// values. Standard library only.
package contract

import (
	"strings"
	"unicode/utf8"
)

// Limits that keep the learner's memory and the templates bounded.
const (
	MaxDepth   = 12 // path segments kept; deeper paths end in "**"
	MaxSegment = 64 // a longer segment is treated as an opaque identifier
	maxFanout  = 64 // distinct literal children of one parent before new ones collapse
	// VarSegment is what an identifier segment becomes.
	VarSegment = "{id}"
)

// SplitPath splits a request path into its non-empty segments.
func SplitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// IsVariable reports whether a path segment looks like an identifier rather
// than a fixed word. The rules, in order:
//
//   - longer than 64 bytes, not valid UTF-8 or containing { or }
//   - digits only, or digits with dots and commas (12, 12.50)
//   - UUID (8-4-4-4-12 hex)
//   - hex string of 16 or more characters (hashes, Mongo ObjectIds)
//   - ISO date (2026-01-31)
//   - ULID (26 characters of Crockford base32 with a digit)
//   - prefixed id (usr_8f3k2m9x1q7z: 2-8 letters, "_" or "-", 12 or more
//     letters and digits including a digit)
//   - opaque token: 20 or more of [A-Za-z0-9_-] containing both a letter and a digit
//
// Everything else, including short words such as v1, me or health, is kept.
func IsVariable(s string) bool {
	n := len(s)
	if n == 0 {
		return false
	}
	if n > MaxSegment || !utf8.ValidString(s) || strings.ContainsAny(s, "{}") {
		return true
	}
	digits, letters, hexs, numeric, token := 0, 0, 0, true, true
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case isDigit(c):
			digits++
		case isAlpha(c):
			letters++
			numeric = false
		default:
			if c != '.' && c != ',' {
				numeric = false
			}
			if c != '_' && c != '-' {
				token = false
			}
		}
		if isHex(c) {
			hexs++
		}
	}
	if numeric && digits > 0 {
		return true
	}
	if n == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && hexs == 32 {
		return true
	}
	if hexs == n && n >= 16 {
		return true
	}
	if n == 10 && s[4] == '-' && s[7] == '-' && digits == 8 {
		return true
	}
	if n == 26 && digits > 0 && strings.Trim(s, "0123456789ABCDEFGHJKMNPQRSTVWXYZ") == "" {
		return true
	}
	if i := strings.IndexAny(s, "_-"); i >= 2 && i <= 8 && n-i-1 >= 12 && digits > 0 && isAllAlpha(s[:i]) && isAlnum(s[i+1:]) {
		return true
	}
	if n >= 20 && token && letters > 0 && digits > 0 {
		return true
	}
	return false
}

func isAllAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlpha(s[i]) {
			return false
		}
	}
	return true
}

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlpha(s[i]) && !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// Template turns a request path into its template using IsVariable only.
func Template(path string) string {
	return buildTemplate(path, nil)
}

// buildTemplate applies the identifier heuristic and, when guard is not nil,
// the fan-out rule: a parent with more than maxFanout distinct literal
// children turns further new children into {id}.
func buildTemplate(path string, guard func(parent, seg string) bool) string {
	segs := SplitPath(path)
	if len(segs) == 0 {
		return "/"
	}
	var b strings.Builder
	for i, s := range segs {
		if i >= MaxDepth {
			b.WriteString("/**")
			break
		}
		parent := b.String()
		switch {
		case IsVariable(s):
			s = VarSegment
		case guard != nil && !guard(parent, s):
			s = VarSegment
		}
		b.WriteByte('/')
		b.WriteString(s)
	}
	return b.String()
}

// Norm turns a template or a spec path into a comparable form: every
// {name} becomes {}.
func Norm(p string) string {
	segs := SplitPath(p)
	if len(segs) == 0 {
		return "/"
	}
	for i, s := range segs {
		if isParam(s) {
			segs[i] = "{}"
		}
	}
	return "/" + strings.Join(segs, "/")
}

func isParam(s string) bool {
	return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}'
}
