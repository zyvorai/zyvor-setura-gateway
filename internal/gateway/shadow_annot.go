package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SeturaAnnotationsKey is the route spec key under which a snapshot carries the
// shadow-diff annotations of the object it was taken from (a real object has
// them in metadata.annotations).
const SeturaAnnotationsKey = "setura.zyvor.dev/annotations"

// ShadowRuleAnnotation is the annotation that targets the RequestMirror filter
// of rule n (1-based): setura.zyvor.dev/shadow-diff.rule-N.
func ShadowRuleAnnotation(n int) string { return ShadowDiffKey + ".rule-" + strconv.Itoa(n) }

// ParseShadowBlock decodes a shadow-diff JSON object strictly (unknown fields
// are errors) and validates it the way the gateway does when it compiles the
// route.
func ParseShadowBlock(raw []byte) (*ShadowDiff, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d ShadowDiff
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s: %w", ShadowDiffKey, err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", ShadowDiffKey)
	}
	if _, err := compileShadow(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// annotationBlock decodes one annotation value. A value that cannot be decoded
// becomes a block that fails compilation, so the route turns invalid instead of
// silently comparing nothing.
func annotationBlock(key, v string) *ShadowDiff {
	d, err := ParseShadowBlock([]byte(v))
	if err != nil {
		return &ShadowDiff{annErr: fmt.Errorf("annotation %s: %w", key, err)}
	}
	return d
}

// mapShadow gives every RequestMirror filter in fs that has no block of its own
// the block d.
func mapShadow(fs []Filter, d *ShadowDiff) {
	for i := range fs {
		if fs[i].Type == "RequestMirror" && fs[i].RequestMirror != nil && fs[i].RequestMirror.ShadowDiff == nil {
			fs[i].RequestMirror.ShadowDiff = d
		}
	}
}

// shadowBlocks resolves the annotations for rule n (1-based): the rule specific
// annotation wins over the route wide one.
func shadowBlocks(ann map[string]string, n int) *ShadowDiff {
	if v, ok := ann[ShadowRuleAnnotation(n)]; ok {
		return annotationBlock(ShadowRuleAnnotation(n), v)
	}
	if v, ok := ann[ShadowDiffKey]; ok {
		return annotationBlock(ShadowDiffKey, v)
	}
	return nil
}

// annotateHTTP maps the shadow-diff annotations onto the RequestMirror filters
// of an HTTPRoute's rules.
func annotateHTTP(rules []Rule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		if d := shadowBlocks(ann, i+1); d != nil {
			mapShadow(rules[i].Filters, d)
		}
	}
}

// annotateGRPC does the same for a GRPCRoute.
func annotateGRPC(rules []GRPCRule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		if d := shadowBlocks(ann, i+1); d != nil {
			mapShadow(rules[i].Filters, d)
		}
	}
}

// OrphanShadowAnnotations lists shadow-diff annotation keys that no rule uses:
// a malformed rule-N suffix or a rule number beyond the route's rules.
func OrphanShadowAnnotations(ann map[string]string, rules int) []string {
	var out []string
	for k := range ann {
		if k == ShadowDiffKey || !strings.HasPrefix(k, ShadowDiffKey) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, ShadowDiffKey+".rule-"))
		if !strings.HasPrefix(k, ShadowDiffKey+".rule-") || err != nil || n < 1 || n > rules {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// shadowAnnotations applies the shadow-diff annotations of a Kubernetes object
// (the apply callback) and warns about annotations no rule uses.
func (k *KubeSource) shadowAnnotations(kind string, m meta, rules int, apply func()) {
	apply()
	for _, key := range OrphanShadowAnnotations(m.Annotations, rules) {
		k.warn("%s %s/%s: annotation %s matches no rule (want %s.rule-N with N from 1 to %d)", kind, m.Namespace, m.Name, key, ShadowDiffKey, rules)
	}
}
