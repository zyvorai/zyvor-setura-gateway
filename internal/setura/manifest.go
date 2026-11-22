package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Location is a file position of a resource in a manifest.
type Location struct {
	File string
	Line int
}

// ManifestIndex maps "Kind/namespace/name" (and "Kind//name" when the
// manifest has no namespace) to a file location.
type ManifestIndex map[string]Location

// Find returns the location of a resource id such as HTTPRoute/ns/name.
func (m ManifestIndex) Find(resource, ns string) Location {
	if m == nil {
		return Location{}
	}
	if l, ok := m[resource]; ok {
		return l
	}
	parts := strings.Split(resource, "/")
	if len(parts) == 3 {
		return m[parts[0]+"//"+parts[2]]
	}
	return Location{}
}

func unquoteScalar(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return s
}

// scanYAML finds kind and metadata.name/namespace per document with a
// line-based scanner; it understands nothing else about YAML.
func scanYAML(path, rel string, text string, idx ManifestIndex) {
	var kind, name, ns string
	var line int
	inMeta, metaIndent := false, 0
	flush := func() {
		if kind != "" && name != "" && line > 0 {
			idx[kind+"/"+ns+"/"+name] = Location{rel, line}
		}
		kind, name, ns, line, inMeta, metaIndent = "", "", "", 0, false, 0
	}
	for i, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "---") {
			flush()
			continue
		}
		if l == "" || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if l[0] != ' ' && l[0] != '\t' {
			inMeta = false
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			switch k {
			case "kind":
				kind = unquoteScalar(v)
			case "metadata":
				inMeta, metaIndent = true, 0
			}
			continue
		}
		if !inMeta {
			continue
		}
		t := strings.TrimLeft(l, " ")
		if metaIndent == 0 {
			metaIndent = len(l) - len(t)
		}
		if len(l)-len(t) != metaIndent {
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		switch k {
		case "name":
			if name == "" {
				name, line = unquoteScalar(v), i+1
			}
		case "namespace":
			ns = unquoteScalar(v)
		}
	}
	flush()
}

func scanJSON(rel, text string, idx ManifestIndex) {
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		return
	}
	var items []any
	if m := asMap(v); m != nil && asList(m["items"]) != nil {
		items = asList(m["items"])
	} else {
		items = []any{v}
	}
	for _, it := range items {
		m := asMap(it)
		meta := asMap(m["metadata"])
		kind, name := asStr(m["kind"]), asStr(meta["name"])
		if kind == "" || name == "" {
			continue
		}
		line := 1
		re := regexp.MustCompile(`"name"\s*:\s*` + regexp.QuoteMeta(`"`+name+`"`))
		if loc := re.FindStringIndex(text); loc != nil {
			line = 1 + strings.Count(text[:loc[0]], "\n")
		}
		idx[kind+"/"+asStr(meta["namespace"])+"/"+name] = Location{rel, line}
	}
}

// ScanManifests indexes Gateway and HTTPRoute resources in YAML/JSON files
// below dir. File paths are slash-separated and relative to dir's parent
// working directory when possible, otherwise to dir.
func ScanManifests(dir string) (ManifestIndex, error) {
	idx := ManifestIndex{}
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml", ".json":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		rel := filepath.ToSlash(p)
		if wd, err := os.Getwd(); err == nil {
			if r, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(r, "..") {
				rel = filepath.ToSlash(r)
			}
		}
		if strings.ToLower(filepath.Ext(p)) == ".json" {
			scanJSON(rel, string(raw), idx)
		} else {
			scanYAML(p, rel, string(raw), idx)
		}
	}
	return idx, nil
}
