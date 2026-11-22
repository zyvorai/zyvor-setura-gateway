package setura

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// A small, deterministic YAML writer for generated Kubernetes objects. Keys
// follow the order Kubernetes users expect (apiVersion, kind, metadata, name,
// namespace, spec first) and then alphabetical, so golden files are stable.

var yamlKeyOrder = map[string]int{
	"apiVersion": 0, "kind": 1, "metadata": 2, "name": 3, "namespace": 4,
	"labels": 5, "annotations": 6, "spec": 7,
}

// emitYAML renders v as block YAML with a trailing newline.
func emitYAML(v any) string {
	var b strings.Builder
	emitNode(&b, v, 0, false)
	return b.String()
}

func yamlScalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case string:
		return yamlString(x)
	}
	return yamlString(fmt.Sprint(v))
}

func yamlString(s string) string {
	if s == "" {
		return `""`
	}
	needs := strings.ContainsAny(s, "\n\r\t\"\\") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") ||
		strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":") ||
		strings.ContainsRune("-?:,[]{}#&*!|>'%@`", rune(s[0]))
	if !needs {
		if _, ok := plainScalar(s).(string); !ok {
			needs = true
		}
		switch strings.ToLower(s) {
		case "y", "n", "yes", "no", "on", "off", "true", "false", "null":
			needs = true
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func orderedKeys(m obj) []string {
	keys := sortedKeys(m)
	sort.SliceStable(keys, func(i, j int) bool {
		oi, iok := yamlKeyOrder[keys[i]]
		oj, jok := yamlKeyOrder[keys[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok:
			return true
		case jok:
			return false
		}
		return false
	})
	return keys
}

func emitNode(b *strings.Builder, v any, indent int, inSeq bool) {
	pad := strings.Repeat("  ", indent)
	switch x := v.(type) {
	case obj:
		if len(x) == 0 {
			b.WriteString(pad + "{}\n")
			return
		}
		for i, k := range orderedKeys(x) {
			prefix := pad
			if inSeq && i == 0 {
				prefix = ""
			}
			emitEntry(b, prefix, k, x[k], indent)
		}
	case []any:
		if len(x) == 0 {
			b.WriteString(pad + "[]\n")
			return
		}
		for _, it := range x {
			b.WriteString(pad + "- ")
			switch y := it.(type) {
			case obj:
				if len(y) == 0 {
					b.WriteString("{}\n")
				} else {
					emitNode(b, y, indent+1, true)
				}
			default:
				b.WriteString(yamlScalar(it) + "\n")
			}
		}
	default:
		b.WriteString(pad + yamlScalar(v) + "\n")
	}
}

func emitEntry(b *strings.Builder, prefix, k string, v any, indent int) {
	key := yamlString(k)
	switch y := v.(type) {
	case obj:
		if len(y) == 0 {
			b.WriteString(prefix + key + ": {}\n")
			return
		}
		b.WriteString(prefix + key + ":\n")
		emitNode(b, y, indent+1, false)
	case []any:
		if len(y) == 0 {
			b.WriteString(prefix + key + ": []\n")
			return
		}
		b.WriteString(prefix + key + ":\n")
		emitNode(b, y, indent+1, false)
	default:
		b.WriteString(prefix + key + ": " + yamlScalar(v) + "\n")
	}
}
