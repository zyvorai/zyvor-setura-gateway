package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type obj = map[string]any

// keyError mirrors a missing required field in decoded Kubernetes JSON.
type keyError struct{ key string }

func (e keyError) Error() string { return "'" + e.key + "'" }

// userError is a validation failure caused by caller input.
type userError string

func (e userError) Error() string { return string(e) }

func userErrorf(format string, a ...any) error { return userError(fmt.Sprintf(format, a...)) }

// req returns m[k] and panics with keyError when it is absent. The CLI
// entry point recovers it and reports exit code 2.
func req(m obj, k string) any {
	v, ok := m[k]
	if !ok {
		panic(keyError{k})
	}
	return v
}

func asMap(v any) obj    { m, _ := v.(map[string]any); return m }
func asList(v any) []any { l, _ := v.([]any); return l }
func asStr(v any) string { s, _ := v.(string); return s }

func str(m obj, k, def string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return def
}

// dig walks nested maps and returns nil when any key is missing.
func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func eq(a, b any) bool { return reflect.DeepEqual(a, b) }

var labelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func label(v string) (string, error) {
	if len(v) > 63 || !labelRE.MatchString(v) {
		return "", userErrorf("expected Kubernetes DNS label, got %s", pyRepr(v))
	}
	return v, nil
}

func pyRepr(s string) string { return "'" + s + "'" }

// pyDumps renders JSON with Python's default separators and sorted keys so
// evidence text stays stable and readable.
func pyDumps(v any) string {
	var b strings.Builder
	var write func(any)
	write = func(v any) {
		switch t := v.(type) {
		case nil:
			b.WriteString("null")
		case bool:
			b.WriteString(strconv.FormatBool(t))
		case string:
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(t)
			b.WriteString(strings.TrimRight(buf.String(), "\n"))
		case float64:
			b.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
		case int:
			b.WriteString(strconv.Itoa(t))
		case []any:
			b.WriteByte('[')
			for i, x := range t {
				if i > 0 {
					b.WriteString(", ")
				}
				write(x)
			}
			b.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteString(", ")
				}
				write(k)
				b.WriteString(": ")
				write(t[k])
			}
			b.WriteByte('}')
		default:
			raw, _ := json.Marshal(t)
			var generic any
			if json.Unmarshal(raw, &generic) == nil {
				write(generic)
			}
		}
	}
	write(v)
	return b.String()
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func environ() []string { return os.Environ() }
