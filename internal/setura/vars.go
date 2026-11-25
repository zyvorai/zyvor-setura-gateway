package setura

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

// Variables in check and watch files: "{{name}}" in any string value is
// replaced, so one file can run against several environments and credentials
// stay out of it. Values come from --var, then --vars-file, then the
// environment variable SETURA_VAR_name. Substitution happens after the JSON is
// parsed, so a value cannot change the structure of the file.

const (
	varEnvPrefix   = "SETURA_VAR_"
	maxVars        = 256
	maxVarValueLen = 4096
)

var (
	// A leading backslash ("\\{{name}}" in JSON) keeps the braces literally.
	varRef  = regexp.MustCompile(`\\?\{\{([A-Za-z_][A-Za-z0-9_-]*)\}\}`)
	varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
)

// Vars resolves variable references. The zero value and nil read only the
// environment.
type Vars struct{ set map[string]string }

func (v *Vars) lookup(name string) (string, bool) {
	if v != nil {
		if s, ok := v.set[name]; ok {
			return s, true
		}
	}
	return os.LookupEnv(varEnvPrefix + name)
}

// parseVar splits name=value. Errors never echo the value.
func parseVar(item, from string) (string, string, error) {
	name, value, ok := strings.Cut(item, "=")
	name = strings.TrimSpace(name)
	if !ok || !varName.MatchString(name) {
		return "", "", userErrorf("%s expects name=value (letters, digits, _ and -)", from)
	}
	if len(value) > maxVarValueLen {
		return "", "", userErrorf("variable %s is longer than %d bytes", name, maxVarValueLen)
	}
	return name, value, nil
}

// newVars reads the --vars-file (name=value lines, # comments) and then the
// --var items, which win.
func newVars(items []string, file string) (*Vars, error) {
	v := &Vars{set: map[string]string{}}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
		seen := map[string]bool{}
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name, value, err := parseVar(line, "a --vars-file line")
			if err != nil {
				return nil, err
			}
			if seen[name] {
				return nil, userErrorf("variable %s is defined twice in the --vars-file", name)
			}
			seen[name] = true
			v.set[name] = strings.TrimSpace(value)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	for _, it := range items {
		name, value, err := parseVar(it, "--var")
		if err != nil {
			return nil, err
		}
		v.set[name] = value
	}
	if len(v.set) > maxVars {
		return nil, userErrorf("at most %d variables are allowed", maxVars)
	}
	return v, nil
}

func (v *Vars) expandString(s string) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	var missing string
	out := varRef.ReplaceAllStringFunc(s, func(m string) string {
		if m[0] == '\\' {
			return m[1:]
		}
		name := m[2 : len(m)-2]
		val, ok := v.lookup(name)
		if !ok && missing == "" {
			missing = name
		}
		return val
	})
	if missing != "" {
		return "", userErrorf("variable {{%s}} is not defined: use --var %s=VALUE, --vars-file or %s%s (write \\\\{{%s}} in JSON for the literal text)",
			missing, missing, varEnvPrefix, missing, missing)
	}
	return out, nil
}

// expand replaces references in every string value of decoded JSON. Object
// keys (header names, JSON paths) are left as written.
func (v *Vars) expand(x any) (any, error) {
	switch t := x.(type) {
	case string:
		return v.expandString(t)
	case []any:
		for i := range t {
			y, err := v.expand(t[i])
			if err != nil {
				return nil, err
			}
			t[i] = y
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			y, err := v.expand(t[k])
			if err != nil {
				return nil, err
			}
			t[k] = y
		}
	}
	return x, nil
}
