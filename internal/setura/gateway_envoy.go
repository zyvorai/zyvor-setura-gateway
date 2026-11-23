package setura

import (
	"fmt"
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Envoy Gateway policies in "setura gateway status" and "setura doctor
// gateway --kube": which policies the Setura controller translates, whether it
// accepted them, and which of their fields Setura ignores. The ignored fields
// are computed here with the controller's own translation, so they are
// reported even before the controller has written a status.

type stPolicy struct {
	Kind        string   `json:"kind"`
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	Targets     []string `json:"targets,omitempty"`
	Accepted    string   `json:"accepted"` // True, False, or "" when the controller has not reported it
	Reason      string   `json:"reason,omitempty"`
	Message     string   `json:"message,omitempty"`
	Conflicted  bool     `json:"conflicted,omitempty"`
	Overridden  bool     `json:"overridden,omitempty"`
	Unsupported []string `json:"unsupported,omitempty"`
	FailClosed  []string `json:"failClosed,omitempty"`
	OK          bool     `json:"ok"`
	Problems    []string `json:"problems,omitempty"`
}

// envoyPolicyItems builds the report rows from the kubectl lists of the policy
// kinds. Policies are shown when they target a Gateway or route the report
// shows (ours), or when the Setura controller has written a status on them.
func envoyPolicyItems(lists map[string][]any, rep *statusReport, all bool) []stPolicy {
	ours := map[string]bool{}
	for _, g := range rep.Gateways {
		ours["Gateway/"+g.Namespace+"/"+g.Name] = true
	}
	for _, r := range rep.Routes {
		ours[r.Kind+"/"+r.Namespace+"/"+r.Name] = true
	}
	var out []stPolicy
	for _, ek := range builtin.EnvoyKinds {
		if ek.Kind != "BackendTrafficPolicy" && ek.Kind != "ClientTrafficPolicy" && ek.Kind != "SecurityPolicy" {
			continue
		}
		for _, o := range lists[ek.Kind] {
			ns, name := asStr(dig(o, "metadata", "namespace")), asStr(dig(o, "metadata", "name"))
			spec := asMap(o.(obj)["spec"])
			it := stPolicy{Kind: ek.Kind, Namespace: ns, Name: name}
			mine := false
			for _, t := range envoyPolicyTargets(spec) {
				it.Targets = append(it.Targets, t[0]+" "+t[1])
				mine = mine || ours[t[0]+"/"+ns+"/"+t[1]]
			}
			var conds map[string]stCond
			for _, a := range asList(dig(o, "status", "ancestors")) {
				if asStr(dig(a, "controllerName")) == builtin.ControllerName {
					mine = true
					conds = condsOf(dig(a, "conditions"))
				}
			}
			if !mine && !all {
				continue
			}
			tk := "HTTPRoute"
			tr := builtin.TranslateEnvoyPolicy(ek.Kind, spec, builtin.EnvoyOptions{TargetKind: tk})
			it.Unsupported, it.FailClosed = tr.Ignored(), tr.FailClosed
			if c, ok := conds["Accepted"]; ok {
				it.Accepted, it.Reason, it.Message = c.Status, c.Reason, c.Message
			}
			it.Conflicted = conds["Conflicted"].Status == "True"
			it.Overridden = conds["Overridden"].Status == "True"
			it.OK = it.Accepted != "False"
			if !it.OK {
				it.Problems = append(it.Problems, "Accepted=False ("+it.Reason+"): "+it.Message)
			}
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	return out
}

func envoyPolicyTargets(spec obj) [][2]string {
	var out [][2]string
	refs := asList(spec["targetRefs"])
	if r := asMap(spec["targetRef"]); r != nil {
		refs = append(refs, r)
	}
	for _, r := range refs {
		m := asMap(r)
		name := asStr(m["name"])
		if s := asStr(m["sectionName"]); s != "" {
			name += "/" + s
		}
		out = append(out, [2]string{asStr(m["kind"]), name})
	}
	for _, s := range asList(spec["targetSelectors"]) {
		out = append(out, [2]string{asStr(asMap(s)["kind"]), "(selector)"})
	}
	return out
}

// readEnvoyPolicies lists the optional Envoy Gateway CRDs; a cluster without
// them, or a denied list, simply has none.
func readEnvoyPolicies(c *Cluster, namespace string) map[string][]any {
	lists := map[string][]any{}
	for _, ek := range builtin.EnvoyKinds {
		if l, err := c.listAll(namespace, ek.Plural+"."+builtin.EnvoyGroup, true); err == nil && len(l) > 0 {
			lists[ek.Kind] = l
		}
	}
	return lists
}

// addEnvoyPolicies adds the policy section to a status report.
func addEnvoyPolicies(rep *statusReport, lists map[string][]any, all bool) {
	rep.Policies = envoyPolicyItems(lists, rep, all)
	bad := 0
	for _, p := range rep.Policies {
		if !p.OK {
			bad++
		}
	}
	if bad > 0 && rep.OK {
		rep.OK = false
		rep.Verdict = plural(bad, "Envoy Gateway policy needs", "Envoy Gateway policies need") + " attention"
		rep.Next = "setura doctor gateway --kube lists the fields Setura ignores; docs/envoy-gateway-compat.md says what each becomes"
	}
}

func (u *ui) policiesPretty(b *strings.Builder, ps []stPolicy) {
	if len(ps) == 0 {
		return
	}
	fmt.Fprintf(b, "\n  %s\n", u.bold("Envoy Gateway policies"))
	for _, p := range ps {
		sym := u.okSym()
		switch {
		case !p.OK:
			sym = u.failSym()
		case len(p.Unsupported) > 0 || p.Conflicted || p.Overridden:
			sym = u.warnSym()
		}
		fmt.Fprintf(b, "  %s %s %s\n", sym, pad(p.Namespace+"/"+p.Name+" ("+p.Kind+")", 52), u.gray("-> "+strings.Join(p.Targets, ", ")))
		switch {
		case p.Accepted == "":
			fmt.Fprintf(b, "      %s not reported yet (is the controller running with --envoy-compat?)\n", u.arrow())
		case !p.OK:
			fmt.Fprintf(b, "      %s Accepted=False (%s): %s\n", u.arrow(), p.Reason, p.Message)
		}
		if p.Conflicted {
			fmt.Fprintf(b, "      %s Conflicted: an older policy on the same target wins\n", u.arrow())
		}
		if p.Overridden {
			fmt.Fprintf(b, "      %s Overridden by a more specific policy\n", u.arrow())
		}
		if len(p.Unsupported) > 0 {
			fmt.Fprintf(b, "      %s Setura ignores: %s\n", u.arrow(), strings.Join(p.Unsupported, ", "))
		}
	}
}

// envoyPoliciesCheck is the "envoy-policies" check of doctor gateway --kube.
func envoyPoliciesCheck(o dgOptions, env dgEnv) dgCheck {
	c := dgCheck{ID: "envoy-policies", Title: "Envoy Gateway policies"}
	if env.cluster == nil {
		c.State, c.Message = "skip", "no cluster access"
		return c
	}
	lists := readEnvoyPolicies(env.cluster, o.KubeNS)
	if len(lists) == 0 {
		c.State, c.Message = "ok", "no Envoy Gateway policy CRDs or objects found (nothing to translate)"
		return c
	}
	rep, err := clusterStatus(env.cluster, o.KubeNS, false)
	if err != nil {
		c.State, c.Message = "skip", "Gateway status unavailable: "+err.Error()
		return c
	}
	ps := rep.Policies
	if len(ps) == 0 {
		c.State, c.Message = "ok", "Envoy Gateway policies exist, but none targets a Gateway or route of the Setura controller"
		return c
	}
	c.State = "ok"
	ignored := 0
	for _, p := range ps {
		line := p.Kind + " " + p.Namespace + "/" + p.Name
		switch {
		case !p.OK:
			c.State = "fail"
			c.Details = append(c.Details, line+": not accepted ("+p.Reason+"): "+p.Message)
		case p.Accepted == "":
			if c.State == "ok" {
				c.State = "warn"
			}
			c.Details = append(c.Details, line+": the controller has not reported it (run it with --envoy-compat)")
		}
		if len(p.Unsupported) > 0 {
			ignored++
			if c.State == "ok" {
				c.State = "warn"
			}
			c.Details = append(c.Details, line+": Setura ignores "+strings.Join(p.Unsupported, ", "))
		}
	}
	c.Message = fmt.Sprintf("%s translated, %s with fields Setura ignores", plural(len(ps), "policy", "policies"), plural(ignored, "policy", "policies"))
	if c.State != "ok" {
		c.Fix = "Each ignored field is in docs/envoy-gateway-compat.md with its Setura equivalent; setura migrate convert --from envoy-gateway --compat-report lists them all"
	}
	return c
}
