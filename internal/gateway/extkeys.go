package gateway

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Every key under the setura.zyvor.dev/ prefix is a Setura extension. A key the
// gateway does not know is never read, so a misspelt one (authh, rate-limt)
// would leave the route running without the protection the author meant. The
// tables below are the single source of truth for which keys exist: the rule
// and listener tables are read from the json tags of the structs the gateway
// decodes into, so a new extension field is known here the moment it exists.

// ExtPrefix is the prefix of every Setura extension key.
const ExtPrefix = "setura.zyvor.dev/"

func prefixedTags(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if strings.HasPrefix(tag, ExtPrefix) {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out
}

// Known extension keys per place they can appear.
var (
	// RuleKeys are the extension fields of an HTTPRoute or GRPCRoute rule in a snapshot.
	RuleKeys = mergeKeys(prefixedTags(reflect.TypeOf(Rule{})), prefixedTags(reflect.TypeOf(GRPCRule{})))
	// RouteAnnotationKeys are the route annotations that mean something: every
	// rule extension (route wide, or KEY.rule-N for one rule), shadow-diff and backends.
	RouteAnnotationKeys = mergeKeys(RuleKeys, []string{ShadowDiffKey, BackendsKey})
	// RouteSpecKeys are the setura.zyvor.dev/ keys of a route spec in a snapshot.
	RouteSpecKeys = []string{SeturaAnnotationsKey}
	// GatewayAnnotationKeys are the Gateway annotations that mean something.
	GatewayAnnotationKeys = []string{ClientAllowKey}
	// ListenerKeys are the extension fields of a listener in a snapshot.
	ListenerKeys = prefixedTags(reflect.TypeOf(Listener{}))
	// ListenerOptionKeys are the keys of listener tls.options.
	ListenerOptionKeys = []string{TLSMinVersionOption, TLSMaxVersionOption, TLSCipherSuitesOption, TLSSessionResumptionOption}
	// BackendRefKeys and MirrorKeys are the extension fields of a backendRef and a RequestMirror filter.
	BackendRefKeys = prefixedTags(reflect.TypeOf(BackendRef{}))
	MirrorKeys     = prefixedTags(reflect.TypeOf(Mirror{}))
)

func mergeKeys(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, k := range l {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ExtKeyIssue is one unknown setura.zyvor.dev/ key.
type ExtKeyIssue struct {
	Key     string
	Suggest string // the known key it is most likely meant to be, or ""
	Typo    bool   // within edit distance 2 of a known key: almost certainly a misspelling
}

// Message says what is wrong with the key.
func (i ExtKeyIssue) Message() string {
	s := fmt.Sprintf("unknown Setura extension key %q", i.Key)
	if i.Suggest != "" {
		s += fmt.Sprintf(" (did you mean %q?)", i.Suggest)
	}
	return s
}

var ruleSuffix = regexp.MustCompile(`^(.*)\.rule-[0-9]+$`)

// checkExtKeys reports the keys under ExtPrefix that are not in known. With
// ruleN a known key may also carry a .rule-N suffix (route annotations).
func checkExtKeys(keys []string, known []string, ruleN bool) []ExtKeyIssue {
	set := map[string]bool{}
	for _, k := range known {
		set[k] = true
	}
	var out []ExtKeyIssue
	for _, k := range keys {
		if !strings.HasPrefix(k, ExtPrefix) || set[k] {
			continue
		}
		base, suffix := k, ""
		if m := ruleSuffix.FindStringSubmatch(k); ruleN && m != nil {
			base, suffix = m[1], k[len(m[1]):]
			if set[base] {
				continue
			}
		}
		out = append(out, nearestKey(k, base, suffix, known))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// nearestKey finds the known key closest to base (the key without its rule
// suffix) and keeps the suffix on the suggestion.
func nearestKey(key, base string, suffix string, known []string) ExtKeyIssue {
	issue := ExtKeyIssue{Key: key}
	best, bestD := "", 1<<30
	for _, k := range known {
		if d := editDistance(strings.TrimPrefix(base, ExtPrefix), strings.TrimPrefix(k, ExtPrefix)); d < bestD {
			best, bestD = k, d
		}
	}
	if best == "" {
		return issue
	}
	maxTypo := 2
	if len(best)-len(ExtPrefix) <= 4 { // auth, ai: two edits is no longer a typo
		maxTypo = 1
	}
	if bestD <= maxTypo {
		issue.Typo = true
	}
	if bestD <= 3 && bestD < len(best)-len(ExtPrefix) {
		issue.Suggest = best + suffix
	}
	return issue
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev = cur
	}
	return prev[len(b)]
}

// UnknownRuleKeys checks the keys of a rule object in a snapshot.
func UnknownRuleKeys(keys []string) []ExtKeyIssue { return checkExtKeys(keys, RuleKeys, false) }

// UnknownAnnotationKeys checks the setura.zyvor.dev/ annotations of a route.
func UnknownAnnotationKeys(keys []string) []ExtKeyIssue {
	return checkExtKeys(keys, RouteAnnotationKeys, true)
}

// UnknownGatewayAnnotationKeys checks the setura.zyvor.dev/ annotations of a Gateway.
func UnknownGatewayAnnotationKeys(keys []string) []ExtKeyIssue {
	return checkExtKeys(keys, GatewayAnnotationKeys, false)
}

// UnknownListenerKeys checks the keys of a listener object in a snapshot.
func UnknownListenerKeys(keys []string) []ExtKeyIssue { return checkExtKeys(keys, ListenerKeys, false) }

// UnknownListenerOptionKeys checks the keys of a listener's tls.options.
func UnknownListenerOptionKeys(keys []string) []ExtKeyIssue {
	return checkExtKeys(keys, ListenerOptionKeys, false)
}

// UnknownRouteSpecKeys checks the keys of a route or Gateway spec object in a snapshot.
func UnknownRouteSpecKeys(keys []string) []ExtKeyIssue {
	return checkExtKeys(keys, RouteSpecKeys, false)
}

// UnknownBackendRefKeys and UnknownMirrorKeys check the nested extension objects.
func UnknownBackendRefKeys(keys []string) []ExtKeyIssue {
	return checkExtKeys(keys, BackendRefKeys, false)
}
func UnknownMirrorKeys(keys []string) []ExtKeyIssue { return checkExtKeys(keys, MirrorKeys, false) }

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unknownInRule reads the keys of a raw rule object.
func unknownInRule(raw []byte) []ExtKeyIssue {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return UnknownRuleKeys(mapKeys(m))
}

func unknownErr(where string, is []ExtKeyIssue) error {
	var parts []string
	for _, i := range is {
		parts = append(parts, i.Message())
	}
	return fmt.Errorf("%s: %s: the route is not served because the key is never read, so it would run without that setting (see docs/lint-rules.md SET023)", where, strings.Join(parts, "; "))
}

// UnmarshalJSON decodes a rule and refuses it when it carries a key under
// setura.zyvor.dev/ that no extension reads (a misspelling would otherwise
// serve the rule without the protection its author meant). The rule becomes
// invalid, like a block that fails validation: the route is not served.
func (r *Rule) UnmarshalJSON(raw []byte) error {
	type plain Rule
	var p plain
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	*r = Rule(p)
	if is := unknownInRule(raw); len(is) > 0 && r.extErr == nil {
		r.extErr = unknownErr("rule", is)
	}
	return nil
}

// UnmarshalJSON is Rule.UnmarshalJSON for a GRPCRoute rule: the only
// extension it takes is auth, so a bad key fails the auth policy closed.
func (r *GRPCRule) UnmarshalJSON(raw []byte) error {
	type plain GRPCRule
	var p plain
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	*r = GRPCRule(p)
	if is := unknownInRule(raw); len(is) > 0 {
		failAuth(&r.Auth, unknownErr("rule", is))
	}
	return nil
}

// failAuth makes an auth slot fail compilation with err.
func failAuth(sp **AuthPolicy, err error) {
	if *sp == nil {
		*sp = &AuthPolicy{}
	}
	if (*sp).annErr == nil {
		(*sp).annErr = err
	}
}

// guardAnnotations looks at the setura.zyvor.dev/ annotations of a route. A key
// within two edits of a known one is a probable misspelling: every rule is
// failed (the route is not served) instead of running unprotected. Any other
// unknown key is returned as a warning for the route's status.
func guardAnnotations(ann map[string]string, fail func(err error)) (warnings []string) {
	if len(ann) == 0 {
		return nil
	}
	for _, i := range UnknownAnnotationKeys(mapKeys(ann)) {
		if i.Typo {
			fail(unknownErr("annotation", []ExtKeyIssue{i}))
		} else {
			warnings = append(warnings, i.Message()+": ignored")
		}
	}
	return warnings
}

func guardHTTPAnnotations(rules []Rule, ann map[string]string) []string {
	return guardAnnotations(ann, func(err error) {
		for i := range rules {
			if rules[i].extErr == nil {
				rules[i].extErr = err
			}
		}
	})
}

func guardGRPCAnnotations(rules []GRPCRule, ann map[string]string) []string {
	return guardAnnotations(ann, func(err error) {
		for i := range rules {
			failAuth(&rules[i].Auth, err)
		}
	})
}
