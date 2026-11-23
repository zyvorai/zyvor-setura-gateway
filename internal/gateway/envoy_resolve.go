package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Envoy Gateway policy resolution: which policy applies to which rule, with
// Envoy Gateway's precedence, and what Setura settings that makes. This file
// does no I/O; the Kubernetes source (envoy_kube.go) feeds it the objects it
// listed and reads the outcomes back for status.

// Levels of a policy target, least to most specific.
const (
	levelGateway  = 0
	levelListener = 1
	levelRoute    = 2
	levelRule     = 3
)

// EnvoyObject is a decoded Envoy Gateway object.
type EnvoyObject struct {
	Kind, NS, Name string
	Generation     int64
	Created        time.Time
	Labels         map[string]string
	Annotations    map[string]string
	Spec           map[string]any
}

// Key is Kind/namespace/name.
func (o *EnvoyObject) Key() string { return o.Kind + "/" + o.NS + "/" + o.Name }

type envoyTarget struct {
	Kind, Name, Section string
}

type envoySelector struct {
	Kind   string
	Labels map[string]string
}

// envoyPolicy is a policy with its targets read.
type envoyPolicy struct {
	obj       *EnvoyObject
	targets   []envoyTarget
	selectors []envoySelector
	mergeType string
}

func newEnvoyPolicy(o *EnvoyObject) *envoyPolicy {
	p := &envoyPolicy{obj: o, mergeType: ecStr(o.Spec["mergeType"])}
	refs := ecList(o.Spec["targetRefs"])
	if r := ecMap(o.Spec["targetRef"]); r != nil {
		refs = append(refs, r)
	}
	for _, r := range refs {
		m := ecMap(r)
		p.targets = append(p.targets, envoyTarget{ecStr(m["kind"]), ecStr(m["name"]), ecStr(m["sectionName"])})
	}
	for _, s := range ecList(o.Spec["targetSelectors"]) {
		m := ecMap(s)
		sel := envoySelector{Kind: ecStr(m["kind"]), Labels: map[string]string{}}
		for k, v := range ecMap(ecDig(m, "matchLabels")) {
			sel.Labels[k] = ecStr(v)
		}
		p.selectors = append(p.selectors, sel)
	}
	return p
}

func (p *envoyPolicy) older(q *envoyPolicy) bool {
	a, b := p.obj, q.obj
	if !a.Created.Equal(b.Created) {
		return a.Created.Before(b.Created)
	}
	return a.NS+"/"+a.Name < b.NS+"/"+b.Name
}

func (p *envoyPolicy) failOpen() bool { return p.obj.Annotations[EnvoyFailOpenAnnotation] == "true" }

// EnvoyOutcome is what happened to one policy, for status.
type EnvoyOutcome struct {
	Object *EnvoyObject
	// Ancestors are the Gateways the policy reaches; Missing the targets that name nothing.
	Ancestors  []ParentRef
	Missing    []string
	Ignored    []string // fields Setura ignores (Unsupported, or partly)
	FailClosed []string // guarding fields Setura cannot enforce
	Wins       int      // rules (or listeners) the policy is the effective one of
	// Conflicts names the older policies that win over this one on the same target; OverriddenBy the
	// more specific policies that replace it.
	Conflicts    []string
	OverriddenBy []string
	Merged       []string // policies this one is merged over, by mergeType
	Invalid      []string // translation problems (a bad block, an unreadable Secret)

	ancestors map[string]ParentRef
	conflict  map[string]bool
	overr     map[string]bool
	merged    map[string]bool
}

// Conditions renders the policy status conditions of the outcome.
func (o *EnvoyOutcome) Conditions(now time.Time, prev []Condition) []Condition {
	gen := o.Object.Generation
	mk := func(typ, status, reason, msg string) Condition {
		return mkCond(prev, typ, fact{OK: status == "True", Reason: reason, Message: msg}, gen, now)
	}
	var out []Condition
	switch {
	case len(o.Missing) > 0 && o.Wins == 0 && len(o.ancestors) == 0:
		out = append(out, mk("Accepted", "False", "TargetNotFound", "no target found: "+strings.Join(o.Missing, ", ")))
	case len(o.Invalid) > 0:
		out = append(out, mk("Accepted", "False", "Invalid", strings.Join(o.Invalid, "; ")))
	case len(o.FailClosed) > 0 && !o.Object.failsOpen():
		out = append(out, mk("Accepted", "False", "Unsupported", "Setura cannot enforce "+strings.Join(o.FailClosed, ", ")+", so it refuses the targeted traffic; "+
			"set the annotation "+EnvoyFailOpenAnnotation+": \"true\" to serve it unprotected instead"))
	case o.Wins == 0 && len(o.Conflicts) > 0:
		out = append(out, mk("Accepted", "False", "Conflicted", "older policy "+strings.Join(o.Conflicts, ", ")+" targets the same object and takes precedence"))
	case len(o.Ignored) > 0:
		out = append(out, mk("Accepted", "True", "Unsupported", "translated; Setura ignores these fields: "+strings.Join(o.Ignored, ", ")+" (see docs/envoy-gateway-compat.md)"))
	default:
		out = append(out, mk("Accepted", "True", "Accepted", "translated to Setura settings"))
	}
	if len(o.Conflicts) > 0 {
		out = append(out, mk("Conflicted", "True", "Conflicted", "older policy "+strings.Join(o.Conflicts, ", ")+" targets the same object and takes precedence"))
	}
	if len(o.OverriddenBy) > 0 {
		out = append(out, mk("Overridden", "True", "Overridden", "overridden by the more specific "+strings.Join(o.OverriddenBy, ", ")))
	}
	return out
}

func (o *EnvoyObject) failsOpen() bool { return o.Annotations[EnvoyFailOpenAnnotation] == "true" }

// EnvoyResult is the outcome of ApplyEnvoyCompat.
type EnvoyResult struct {
	Outcomes []*EnvoyOutcome // sorted by key
	// Digest changes when anything that shaped the configuration changed (the policies and the Secret values read).
	Digest string
	Warn   []string
}

// EnvoyInput is everything ApplyEnvoyCompat reads.
type EnvoyInput struct {
	Policies []*EnvoyObject // BackendTrafficPolicy, SecurityPolicy, ClientTrafficPolicy
	Filters  []*EnvoyObject // HTTPRouteFilter
	Backends []*EnvoyObject // Backend
	// Secret returns the data of a Secret (values decoded), or nil, false when it cannot be read.
	Secret func(ns, name string) (map[string]string, bool)
}

type envoyCand struct {
	level int
	pol   *envoyPolicy
}

type envoyEffective struct {
	spec  map[string]any
	chain []*envoyPolicy // top first
}

type envoyCtx struct {
	cfg      *Config
	in       EnvoyInput
	pols     map[string][]*envoyPolicy
	outcomes map[*envoyPolicy]*EnvoyOutcome
	filters  map[string]*EnvoyObject
	backends map[string]*EnvoyObject
	tr       map[string]*EnvoyTranslation
	digest   []string
	warn     []string
}

// ApplyEnvoyCompat resolves Envoy Gateway policies over cfg and writes the
// settings they translate to into it: route rule fields, backend definitions,
// listener TLS options and client certificate validation. Settings a rule
// already has of its own (Setura annotations and fields) are never replaced.
func ApplyEnvoyCompat(cfg *Config, in EnvoyInput) *EnvoyResult {
	c := &envoyCtx{cfg: cfg, in: in, pols: map[string][]*envoyPolicy{}, outcomes: map[*envoyPolicy]*EnvoyOutcome{},
		filters: map[string]*EnvoyObject{}, backends: map[string]*EnvoyObject{}, tr: map[string]*EnvoyTranslation{}}
	for _, o := range in.Policies {
		p := newEnvoyPolicy(o)
		c.pols[o.Kind] = append(c.pols[o.Kind], p)
		out := &EnvoyOutcome{Object: o, ancestors: map[string]ParentRef{}, conflict: map[string]bool{}, overr: map[string]bool{}, merged: map[string]bool{}}
		c.outcomes[p] = out
		own := TranslateEnvoyPolicy(o.Kind, o.Spec, EnvoyOptionsFor(o.Annotations, o.NS, o.Name, ownTargetKind(p)))
		out.Ignored, out.FailClosed = own.Ignored(), own.FailClosed
		b, _ := json.Marshal(o.Spec)
		c.digest = append(c.digest, o.Key()+"@"+string(b))
	}
	for _, o := range in.Filters {
		c.filters[o.NS+"/"+o.Name] = o
	}
	for _, o := range in.Backends {
		c.backends[o.NS+"/"+o.Name] = o
	}
	for _, k := range sortedKeys(c.pols) {
		sort.SliceStable(c.pols[k], func(i, j int) bool { return c.pols[k][i].older(c.pols[k][j]) })
	}
	c.resolveBackends()
	c.resolveRoutes()
	c.resolveListeners()
	c.findMissing()

	res := &EnvoyResult{Warn: c.warn}
	for _, p := range c.allPolicies() {
		out := c.outcomes[p]
		for _, k := range sortedKeys(out.ancestors) {
			out.Ancestors = append(out.Ancestors, out.ancestors[k])
		}
		out.Conflicts, out.OverriddenBy, out.Merged = keysOf(out.conflict), keysOf(out.overr), keysOf(out.merged)
		res.Outcomes = append(res.Outcomes, out)
	}
	sort.Slice(res.Outcomes, func(i, j int) bool { return res.Outcomes[i].Object.Key() < res.Outcomes[j].Object.Key() })
	sort.Strings(c.digest)
	sum := sha256.Sum256([]byte(strings.Join(c.digest, "\n")))
	res.Digest = hex.EncodeToString(sum[:])
	return res
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *envoyCtx) allPolicies() []*envoyPolicy {
	var out []*envoyPolicy
	for _, k := range sortedKeys(c.pols) {
		out = append(out, c.pols[k]...)
	}
	return out
}

// ownTargetKind is the kind a policy is judged by on its own: GRPCRoute when
// that is all it targets, else HTTPRoute.
func ownTargetKind(p *envoyPolicy) string {
	if len(p.targets) > 0 {
		for _, t := range p.targets {
			if t.Kind != "GRPCRoute" {
				return "HTTPRoute"
			}
		}
		return "GRPCRoute"
	}
	return "HTTPRoute"
}

// targetMatch reports the level at which policy p targets the object, and
// whether it does at all.
func (p *envoyPolicy) targetMatch(kind, ns, name string, labels map[string]string, section string, sections []string) (int, bool) {
	if p.obj.NS != ns {
		return 0, false
	}
	best, found := 0, false
	set := func(l int) {
		if !found || l > best {
			best, found = l, true
		}
	}
	for _, t := range p.targets {
		if t.Kind != kind || t.Name != name {
			continue
		}
		switch {
		case t.Section == "":
			if kind == "Gateway" {
				set(levelGateway)
			} else {
				set(levelRoute)
			}
		case kind == "Gateway":
			for _, s := range sections {
				if s == t.Section {
					set(levelListener)
				}
			}
		default:
			if section != "" && section == t.Section {
				set(levelRule)
			}
		}
	}
	for _, s := range p.selectors {
		if s.Kind != kind || len(s.Labels) == 0 {
			continue
		}
		ok := true
		for k, v := range s.Labels {
			if labels[k] != v {
				ok = false
			}
		}
		if ok {
			if kind == "Gateway" {
				set(levelGateway)
			} else {
				set(levelRoute)
			}
		}
	}
	return best, found
}

// parentGateways lists the Gateways a route attaches to (through a
// ListenerSet too) with the listener names it can attach to on each.
type gwAttach struct {
	gw       *Gateway
	sections []string
}

func (c *envoyCtx) parentGateways(ns string, parents []ParentRef) []gwAttach {
	var out []gwAttach
	for _, p := range parents {
		pns := parentNS(p, ns)
		var gw *Gateway
		section := p.SectionName
		switch p.Kind {
		case "", "Gateway":
			for _, g := range c.cfg.Gateways {
				if g.NS == pns && g.Name == p.Name {
					gw = g
				}
			}
		case "ListenerSet":
			for _, ls := range c.cfg.ListenerSets {
				if ls.NS == pns && ls.Name == p.Name {
					for _, g := range c.cfg.Gateways {
						if g.NS == parentNS(ls.Parent, ls.NS) && g.Name == ls.Parent.Name {
							gw = g
						}
					}
				}
			}
			section = ""
		}
		if gw == nil {
			continue
		}
		var secs []string
		if section != "" {
			secs = []string{section}
		} else {
			for _, l := range gw.Listeners {
				secs = append(secs, l.Name)
			}
		}
		out = append(out, gwAttach{gw, secs})
	}
	return out
}

func (c *envoyCtx) candidates(kind, routeKind, ns, name string, labels map[string]string, rule string, gws []gwAttach) []envoyCand {
	var cands []envoyCand
	seen := map[string]bool{}
	add := func(l int, p *envoyPolicy, anc *Gateway) {
		out := c.outcomes[p]
		if anc != nil {
			out.ancestors[anc.Key()] = ParentRef{Group: APIGroup, Kind: "Gateway", Name: anc.Name, Namespace: anc.NS}
		}
		key := fmt.Sprint(p.obj.Key(), "@", l)
		if !seen[key] {
			seen[key] = true
			cands = append(cands, envoyCand{l, p})
		}
	}
	for _, p := range c.pols[kind] {
		if l, ok := p.targetMatch(routeKind, ns, name, labels, rule, nil); ok {
			for _, g := range gws {
				add(l, p, g.gw)
			}
			if len(gws) == 0 {
				add(l, p, nil)
			}
		}
		for _, g := range gws {
			if l, ok := p.targetMatch("Gateway", g.gw.NS, g.gw.Name, g.gw.Labels, "", g.sections); ok {
				add(l, p, g.gw)
			}
		}
	}
	return cands
}

// resolve picks the effective spec of a set of candidates: the most specific
// level wins, the oldest policy within a level, and mergeType merges the winner
// over the next level down.
func (c *envoyCtx) resolve(cands []envoyCand, scope string) *envoyEffective {
	if len(cands) == 0 {
		return nil
	}
	byLevel := map[int][]*envoyPolicy{}
	for _, cd := range cands {
		byLevel[cd.level] = append(byLevel[cd.level], cd.pol)
	}
	var levels []int
	for l := range byLevel {
		levels = append(levels, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(levels)))
	winners := make([]*envoyPolicy, 0, len(levels))
	for _, l := range levels {
		ps := byLevel[l]
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].older(ps[j]) })
		winners = append(winners, ps[0])
		for _, loser := range ps[1:] {
			c.outcomes[loser].conflict[ps[0].obj.Key()] = true
		}
	}
	chain := []*envoyPolicy{winners[0]}
	for i := 0; i < len(winners)-1 && chain[len(chain)-1].mergeType != ""; i++ {
		chain = append(chain, winners[i+1])
	}
	for _, p := range winners[len(chain):] {
		c.outcomes[p].overr[winners[0].obj.Key()] = true
	}
	for _, p := range chain[1:] {
		c.outcomes[chain[0]].merged[p.obj.Key()] = true
	}
	// Spec: merge from the bottom of the chain up.
	spec := chain[len(chain)-1].obj.Spec
	for i := len(chain) - 2; i >= 0; i-- {
		spec = envoyMerge(spec, chain[i].obj.Spec, chain[i].mergeType)
	}
	c.outcomes[chain[0]].Wins++
	return &envoyEffective{spec: spec, chain: chain}
}

// envoyMerge merges over onto base. JSONMerge is RFC 7386 (objects merge,
// everything else is replaced, null removes). StrategicMerge also merges
// lists of objects that all carry a name, by name.
func envoyMerge(base, over map[string]any, mode string) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if k == "mergeType" {
			continue
		}
		if v == nil {
			delete(out, k)
			continue
		}
		bm, om := ecMap(out[k]), ecMap(v)
		if bm != nil && om != nil {
			out[k] = envoyMerge(bm, om, mode)
			continue
		}
		if mode == "StrategicMerge" {
			if bl, ol := ecList(out[k]), ecList(v); bl != nil && ol != nil && namedList(bl) && namedList(ol) {
				out[k] = mergeNamed(bl, ol, mode)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func namedList(l []any) bool {
	for _, e := range l {
		if m := ecMap(e); m == nil || ecStr(m["name"]) == "" {
			return false
		}
	}
	return len(l) > 0
}

func mergeNamed(base, over []any, mode string) []any {
	out := append([]any{}, base...)
	for _, o := range over {
		om := ecMap(o)
		hit := false
		for i, b := range out {
			if bm := ecMap(b); ecStr(bm["name"]) == ecStr(om["name"]) {
				out[i] = envoyMerge(bm, om, mode)
				hit = true
			}
		}
		if !hit {
			out = append(out, o)
		}
	}
	return out
}

func chainKey(e *envoyEffective, targetKind string) string {
	var parts []string
	for _, p := range e.chain {
		parts = append(parts, p.obj.Key())
	}
	return strings.Join(parts, ">") + "#" + targetKind
}

// translation translates an effective spec once per chain and target kind.
func (c *envoyCtx) translation(kind string, e *envoyEffective, targetKind string) *EnvoyTranslation {
	key := kind + "|" + chainKey(e, targetKind)
	if t, ok := c.tr[key]; ok {
		return t
	}
	top := e.chain[0].obj
	t := TranslateEnvoyPolicy(kind, e.spec, EnvoyOptionsFor(top.Annotations, top.NS, top.Name, targetKind))
	c.tr[key] = t
	return t
}

// ---- routes ----

func (c *envoyCtx) resolveRoutes() {
	for _, rt := range c.cfg.Routes {
		gws := c.parentGateways(rt.NS, rt.Parents)
		for i := range rt.Rules {
			c.applyHTTPRule(rt, &rt.Rules[i], gws)
		}
	}
	for _, rt := range c.cfg.GRPCRoutes {
		gws := c.parentGateways(rt.NS, rt.Parents)
		for i := range rt.Rules {
			c.applyGRPCRule(rt, &rt.Rules[i], gws)
		}
	}
}

func (c *envoyCtx) applyHTTPRule(rt *Route, rule *Rule, gws []gwAttach) {
	injects := c.resolveExtensionRefs(rt, rule)
	c.resolveBackendRefs(rt.NS, rule.BackendRefs)
	if cands := c.candidates(kBT, "HTTPRoute", rt.NS, rt.Name, rt.Labels, rule.Name, gws); len(cands) > 0 {
		if e := c.resolve(cands, rt.Key()); e != nil {
			tr := c.translation(kBT, e, "HTTPRoute")
			c.overlayRule(rule, tr)
			c.overlayBackends(rt.NS, rule.BackendRefs, tr)
		}
	}
	if cands := c.candidates(kSP, "HTTPRoute", rt.NS, rt.Name, rt.Labels, rule.Name, gws); len(cands) > 0 {
		if e := c.resolve(cands, rt.Key()); e != nil {
			tr := c.translation(kSP, e, "HTTPRoute")
			c.overlayRule(rule, tr)
			c.overlayAuth(&rule.Auth, e, tr, injects)
			injects = nil
		}
	}
	if len(injects) > 0 {
		c.injectOnly(rt, rule, injects)
	}
}

// injectOnly gives a rule the credential injection of its HTTPRouteFilter when no
// SecurityPolicy builds the rule's auth policy.
func (c *envoyCtx) injectOnly(rt *Route, rule *Rule, injects []any) {
	if rule.Auth != nil {
		c.warn = append(c.warn, fmt.Sprintf("HTTPRoute %s/%s: credentialInjection is not applied to a rule that has an auth policy of its own", rt.NS, rt.Name))
		return
	}
	raw, _ := json.Marshal(map[string]any{"inject": injects})
	p, err := ParseAuthBlock(raw)
	if err != nil {
		c.warn = append(c.warn, fmt.Sprintf("HTTPRoute %s/%s: credentialInjection: %v", rt.NS, rt.Name, err))
		return
	}
	rule.Auth = p
}

func (c *envoyCtx) applyGRPCRule(rt *GRPCRoute, rule *GRPCRule, gws []gwAttach) {
	c.resolveBackendRefs(rt.NS, rule.BackendRefs)
	if cands := c.candidates(kBT, "GRPCRoute", rt.NS, rt.Name, rt.Labels, rule.Name, gws); len(cands) > 0 {
		if e := c.resolve(cands, "GRPCRoute/"+rt.NS+"/"+rt.Name); e != nil {
			c.overlayBackends(rt.NS, rule.BackendRefs, c.translation(kBT, e, "GRPCRoute"))
		}
	}
	if cands := c.candidates(kSP, "GRPCRoute", rt.NS, rt.Name, rt.Labels, rule.Name, gws); len(cands) > 0 {
		if e := c.resolve(cands, "GRPCRoute/"+rt.NS+"/"+rt.Name); e != nil {
			c.overlayAuth(&rule.Auth, e, c.translation(kSP, e, "GRPCRoute"), nil)
		}
	}
}

// overlayRule sets the rule fields a translation produced where the rule has none.
func (c *envoyCtx) overlayRule(rule *Rule, tr *EnvoyTranslation) {
	if len(tr.Rule) > 0 {
		raw, _ := json.Marshal(tr.Rule)
		var tmp Rule
		if err := json.Unmarshal(raw, &tmp); err != nil {
			c.warn = append(c.warn, "envoy compat: "+err.Error())
		} else {
			if rule.Retry == nil {
				rule.Retry = tmp.Retry
			}
			if rule.Timeouts == nil {
				rule.Timeouts = tmp.Timeouts
			}
			if rule.RateLimit == nil {
				rule.RateLimit = tmp.RateLimit
			}
			if rule.Fault == nil {
				rule.Fault = tmp.Fault
			}
			if rule.Compress == nil {
				rule.Compress = tmp.Compress
			}
			if rule.Limits == nil {
				rule.Limits = tmp.Limits
			}
		}
	}
	for _, f := range tr.Filters {
		raw, _ := json.Marshal(f)
		var fl Filter
		if json.Unmarshal(raw, &fl) != nil {
			continue
		}
		have := false
		for _, x := range rule.Filters {
			have = have || x.Type == fl.Type
		}
		if !have {
			rule.Filters = append(rule.Filters, fl)
		}
	}
}

// denyAll is the auth block of traffic that must be refused.
var denyAll = map[string]any{"ipDeny": []any{"0.0.0.0/0", "::/0"}}

// overlayAuth builds the rule's auth policy of an effective SecurityPolicy.
func (c *envoyCtx) overlayAuth(slot **AuthPolicy, e *envoyEffective, tr *EnvoyTranslation, inject []any) {
	if *slot != nil {
		return // a Setura auth policy of the rule wins
	}
	top := e.chain[0]
	out := c.outcomes[top]
	block := map[string]any{}
	for k, v := range tr.Auth {
		block[k] = v
	}
	if tr.APIKey != nil {
		ak := map[string]any{}
		for k, v := range tr.APIKey {
			ak[k] = v
		}
		var keys []any
		for _, ref := range tr.SecretRefs {
			ns := firstStr(ref.Namespace, top.obj.NS)
			data, ok := c.secret(ns, ref.Name)
			if !ok {
				out.addInvalid("Secret " + ns + "/" + ref.Name + " cannot be read")
				continue
			}
			for _, name := range sortedKeys(data) {
				keys = append(keys, map[string]any{"name": ref.Name + "/" + name, "hash": stableKeyHash(ns+"/"+ref.Name+"/"+name, data[name])})
			}
		}
		if len(keys) > 0 {
			ak["keys"] = keys
			block["apiKey"] = ak
		} else {
			tr = &EnvoyTranslation{FailClosed: append(append([]string{}, tr.FailClosed...), "apiKeyAuth")}
		}
	}
	if len(inject) > 0 {
		block["inject"] = inject
	}
	if len(tr.FailClosed) > 0 && !top.obj.failsOpen() {
		block = map[string]any{}
		for k, v := range denyAll {
			block[k] = v
		}
	}
	if len(block) == 0 {
		return
	}
	raw, _ := json.Marshal(block)
	p, err := ParseAuthBlock(raw)
	if err != nil {
		out.addInvalid(err.Error())
		raw, _ = json.Marshal(denyAll)
		p, _ = ParseAuthBlock(raw)
	}
	*slot = p
}

func (o *EnvoyOutcome) addInvalid(msg string) {
	for _, m := range o.Invalid {
		if m == msg {
			return
		}
	}
	o.Invalid = append(o.Invalid, msg)
}

func (c *envoyCtx) secret(ns, name string) (map[string]string, bool) {
	if c.in.Secret == nil {
		return nil, false
	}
	data, ok := c.in.Secret(ns, name)
	if ok {
		keys := sortedKeys(data)
		h := sha256.New()
		for _, k := range keys {
			fmt.Fprintf(h, "%s=%s;", k, data[k])
		}
		c.digest = append(c.digest, "secret/"+ns+"/"+name+"@"+hex.EncodeToString(h.Sum(nil)))
	}
	return data, ok
}

// stableKeyHash is HashAPIKey with a salt derived from where the key came
// from, so the same Secret hashes the same on every reload.
func stableKeyHash(id, key string) string {
	salt := sha256.Sum256([]byte("setura-envoy-compat/" + id))
	return "sha256$" + b64(salt[:16]) + "$" + hex.EncodeToString(saltedSHA256(salt[:16], key))
}

// overlayBackends applies backend settings (circuit breaking, health checks, upstream PROXY protocol).
func (c *envoyCtx) overlayBackends(ns string, refs []BackendRef, tr *EnvoyTranslation) {
	if len(tr.Backend) == 0 {
		return
	}
	raw, _ := json.Marshal(tr.Backend)
	var set struct {
		CircuitBreaker *CircuitConfig  `json:"circuitBreaker"`
		HealthCheck    *HealthCheck    `json:"healthCheck"`
		ProxyProtocol  string          `json:"proxyProtocol"`
		LoadBalancer   json.RawMessage `json:"loadBalancer"`
	}
	if json.Unmarshal(raw, &set) != nil {
		return
	}
	var lb *LBConfig
	if len(set.LoadBalancer) > 0 {
		var err error
		if lb, err = ParseLBBlock(set.LoadBalancer); err != nil {
			c.warn = append(c.warn, "envoy compat: loadBalancer: "+err.Error())
		}
	}
	for _, ref := range refs {
		bns := firstStr(ref.Namespace, ns)
		def := c.cfg.Backends[backendKey(bns, ref.Name, ref.Port)]
		if def == nil {
			def = c.cfg.Backends[bns+"/"+ref.Name]
		}
		if def == nil {
			continue
		}
		if def.CircuitBreaker == nil {
			def.CircuitBreaker = set.CircuitBreaker
		}
		if def.HealthCheck == nil {
			def.HealthCheck = set.HealthCheck
		}
		if def.ProxyProtocol == "" {
			def.ProxyProtocol = set.ProxyProtocol
		}
		if def.LoadBalancer == nil {
			def.LoadBalancer = lb
		}
	}
}

// ---- Backends and HTTPRouteFilters ----

func (c *envoyCtx) resolveBackends() {
	if c.cfg.Backends == nil {
		c.cfg.Backends = map[string]*BackendDef{}
	}
}

// envoyBackendName is the Service style name a Backend object is served under.
func envoyBackendName(name string) string { return "envoy-backend-" + name }

// resolveBackendRefs turns backendRefs of kind Backend into backends made of
// the Backend's endpoints.
func (c *envoyCtx) resolveBackendRefs(routeNS string, refs []BackendRef) {
	for i := range refs {
		ref := &refs[i]
		if ref.Kind != "Backend" || ref.Group != EnvoyGroup {
			continue
		}
		ns := firstStr(ref.Namespace, routeNS)
		o := c.backends[ns+"/"+ref.Name]
		if o == nil {
			continue
		}
		tr := TranslateEnvoyBackend(o.Spec)
		if len(tr.Endpoints) == 0 {
			continue
		}
		name := envoyBackendName(ref.Name)
		def := &BackendDef{Endpoints: tr.Endpoints, Protocol: tr.Protocol}
		c.cfg.Backends[backendKey(ns, name, ref.Port)] = def
		c.digest = append(c.digest, o.Key()+"@"+strings.Join(tr.Endpoints, ","))
		ref.Group, ref.Kind, ref.Name, ref.Namespace = "", "", name, ns
	}
}

// resolveExtensionRefs replaces ExtensionRef filters that name an Envoy
// Gateway HTTPRouteFilter with what the filter translates to. A filter that
// holds anything Setura cannot do stays, so the route is refused rather than
// served without it.
func (c *envoyCtx) resolveExtensionRefs(rt *Route, rule *Rule) (injects []any) {
	var keep []Filter
	for _, f := range rule.Filters {
		if f.Type != "ExtensionRef" || f.ExtensionRef == nil || f.ExtensionRef.Group != EnvoyGroup || f.ExtensionRef.Kind != "HTTPRouteFilter" {
			keep = append(keep, f)
			continue
		}
		o := c.filters[rt.NS+"/"+f.ExtensionRef.Name]
		if o == nil {
			keep = append(keep, f)
			continue
		}
		tr := TranslateHTTPRouteFilter(o.Spec, o.NS)
		clean := tr.Block != nil || tr.Inject != nil
		for _, n := range tr.Notes {
			clean = clean && n.Applied() // a partly applied field (credentialInjection.overwrite) still serves
		}
		if !clean {
			keep = append(keep, f)
			continue
		}
		if tr.Block != nil {
			raw, _ := json.Marshal(tr.Block)
			d, err := ParseDirectResponseBlock(raw)
			if err != nil {
				c.warn = append(c.warn, fmt.Sprintf("HTTPRouteFilter %s/%s: %v", o.NS, o.Name, err))
				keep = append(keep, f)
				continue
			}
			if rule.DirectResponse == nil {
				rule.DirectResponse = d
				rule.BackendRefs = nil
			}
			c.digest = append(c.digest, o.Key()+"@"+string(raw))
		}
		if tr.Inject != nil {
			raw, _ := json.Marshal(tr.Inject)
			injects = append(injects, tr.Inject)
			c.digest = append(c.digest, o.Key()+"@"+string(raw))
		}
	}
	rule.Filters = keep
	return injects
}

// ---- Gateways and listeners ----

func (c *envoyCtx) resolveListeners() {
	for _, gw := range c.cfg.Gateways {
		var sections []string
		for _, l := range gw.Listeners {
			sections = append(sections, l.Name)
		}
		var gwCands []envoyCand
		for _, p := range c.pols[kCT] {
			if l, ok := p.targetMatch("Gateway", gw.NS, gw.Name, gw.Labels, "", sections); ok {
				c.outcomes[p].ancestors[gw.Key()] = ParentRef{Group: APIGroup, Kind: "Gateway", Name: gw.Name, Namespace: gw.NS}
				gwCands = append(gwCands, envoyCand{l, p})
			}
		}
		for i := range gw.Listeners {
			l := &gw.Listeners[i]
			var cands []envoyCand
			for _, cd := range gwCands {
				if cd.level == levelGateway || cd.pol.listenerTargeted(gw, l.Name) {
					cands = append(cands, cd)
				}
			}
			e := c.resolve(cands, gw.Key()+"/"+l.Name)
			if e == nil {
				continue
			}
			tr := c.translation(kCT, e, "Gateway")
			c.overlayListener(gw, l, tr)
		}
	}
}

func (p *envoyPolicy) listenerTargeted(gw *Gateway, name string) bool {
	for _, t := range p.targets {
		if t.Kind == "Gateway" && t.Name == gw.Name && t.Section == name && p.obj.NS == gw.NS {
			return true
		}
	}
	return false
}

func (c *envoyCtx) overlayListener(gw *Gateway, l *Listener, tr *EnvoyTranslation) {
	if lim, ok := tr.Listener["limits"].(map[string]any); ok && l.Limits == nil {
		if n, ok := lim["maxConnections"].(int); ok {
			l.Limits = &ListenerLimits{MaxConnections: n}
		}
	}
	if len(tr.Listener) > 0 && l.TLS != nil {
		opts := map[string]string{}
		for k, v := range l.TLS.Options {
			opts[k] = v
		}
		if v, ok := tr.Listener["tlsMinVersion"].(string); ok && opts[TLSMinVersionOption] == "" {
			opts[TLSMinVersionOption] = v
		}
		if v, ok := tr.Listener["tlsMaxVersion"].(string); ok && opts[TLSMaxVersionOption] == "" {
			opts[TLSMaxVersionOption] = v
		}
		if v, ok := tr.Listener["tlsCipherSuites"].(string); ok && opts[TLSCipherSuitesOption] == "" {
			opts[TLSCipherSuitesOption] = v
		}
		if v, ok := tr.Listener["tlsSessionResumption"].(string); ok && opts[TLSSessionResumptionOption] == "" {
			opts[TLSSessionResumptionOption] = v
		}
		l.TLS.Options = opts
	}
	if len(tr.Frontend) > 0 && (l.Protocol == "HTTPS" || l.Protocol == "TLS") {
		raw, _ := json.Marshal(tr.Frontend)
		var val FrontendValidation
		if json.Unmarshal(raw, &val) != nil || len(val.CACertificateRefs) == 0 {
			return
		}
		if gw.TLS == nil {
			gw.TLS = &GatewayTLS{}
		}
		if gw.TLS.Frontend == nil {
			gw.TLS.Frontend = &FrontendTLS{}
		}
		for _, pp := range gw.TLS.Frontend.PerPort {
			if pp.Port == l.Port {
				return
			}
		}
		gw.TLS.Frontend.PerPort = append(gw.TLS.Frontend.PerPort, struct {
			Port int               `json:"port"`
			TLS  FrontendTLSConfig `json:"tls"`
		}{l.Port, FrontendTLSConfig{Validation: &val}})
	}
}

// ---- targets that match nothing ----

func (c *envoyCtx) findMissing() {
	for _, p := range c.allPolicies() {
		out := c.outcomes[p]
		for _, t := range p.targets {
			if c.targetExists(p.obj.NS, t) {
				c.addAncestors(out, p.obj.NS, t)
				continue
			}
			label := t.Kind + " " + t.Name
			if t.Section != "" {
				label += " (" + t.Section + ")"
			}
			out.Missing = append(out.Missing, label)
		}
	}
}

// addAncestors records the Gateways an existing target leads to.
func (c *envoyCtx) addAncestors(out *EnvoyOutcome, ns string, t envoyTarget) {
	add := func(g *Gateway) {
		out.ancestors[g.Key()] = ParentRef{Group: APIGroup, Kind: "Gateway", Name: g.Name, Namespace: g.NS}
	}
	switch t.Kind {
	case "Gateway":
		for _, g := range c.cfg.Gateways {
			if g.NS == ns && g.Name == t.Name {
				add(g)
			}
		}
	case "HTTPRoute":
		for _, r := range c.cfg.Routes {
			if r.NS == ns && r.Name == t.Name {
				for _, g := range c.parentGateways(r.NS, r.Parents) {
					add(g.gw)
				}
			}
		}
	case "GRPCRoute":
		for _, r := range c.cfg.GRPCRoutes {
			if r.NS == ns && r.Name == t.Name {
				for _, g := range c.parentGateways(r.NS, r.Parents) {
					add(g.gw)
				}
			}
		}
	}
}

func (c *envoyCtx) targetExists(ns string, t envoyTarget) bool {
	switch t.Kind {
	case "Gateway":
		for _, g := range c.cfg.Gateways {
			if g.NS == ns && g.Name == t.Name {
				if t.Section == "" {
					return true
				}
				for _, l := range g.Listeners {
					if l.Name == t.Section {
						return true
					}
				}
			}
		}
	case "HTTPRoute":
		for _, r := range c.cfg.Routes {
			if r.NS == ns && r.Name == t.Name {
				if t.Section == "" {
					return true
				}
				for _, ru := range r.Rules {
					if ru.Name == t.Section {
						return true
					}
				}
			}
		}
	case "GRPCRoute":
		for _, r := range c.cfg.GRPCRoutes {
			if r.NS == ns && r.Name == t.Name {
				if t.Section == "" {
					return true
				}
				for _, ru := range r.Rules {
					if ru.Name == t.Section {
						return true
					}
				}
			}
		}
	}
	return false
}
