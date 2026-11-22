package gateway

import (
	"fmt"
	"sort"
	"strings"
)

// SelectorRequirement is one matchExpressions entry of a label selector.
type SelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

func (r SelectorRequirement) String() string {
	switch r.Operator {
	case "In":
		return fmt.Sprintf("%s in (%s)", r.Key, strings.Join(r.Values, ","))
	case "NotIn":
		return fmt.Sprintf("%s notin (%s)", r.Key, strings.Join(r.Values, ","))
	case "Exists":
		return r.Key
	case "DoesNotExist":
		return "!" + r.Key
	}
	return r.Key + " " + r.Operator
}

// matches evaluates the requirement against a label set, as Kubernetes does:
// NotIn and DoesNotExist match objects that lack the key.
func (r SelectorRequirement) matches(labels map[string]string) bool {
	v, has := labels[r.Key]
	in := false
	for _, want := range r.Values {
		in = in || want == v
	}
	switch r.Operator {
	case "In":
		return has && in
	case "NotIn":
		return !has || !in
	case "Exists":
		return has
	case "DoesNotExist":
		return !has
	}
	return false // an unknown operator fails closed
}

// selectorWhy returns "" when labels satisfy matchLabels and every
// matchExpressions requirement, and the unmet requirements otherwise.
func selectorWhy(matchLabels map[string]string, exprs []SelectorRequirement, labels map[string]string) string {
	var unmet []string
	keys := make([]string, 0, len(matchLabels))
	for k := range matchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := labels[k]; !ok || v != matchLabels[k] {
			unmet = append(unmet, k+"="+matchLabels[k])
		}
	}
	for _, e := range exprs {
		if !e.matches(labels) {
			unmet = append(unmet, e.String())
		}
	}
	if len(unmet) == 0 {
		return ""
	}
	return strings.Join(unmet, ", ")
}
