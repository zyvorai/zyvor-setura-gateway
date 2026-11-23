package setura

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

const gatewayStatusSchema = "setura.gateway.status/v1"

type stCond struct {
	Status  string `json:"status"` // True, False or Unknown ("" when the controller has not reported it)
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type stListener struct {
	Name       string            `json:"name"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Attached   int               `json:"attachedRoutes"`
	Conditions map[string]stCond `json:"conditions"`
	OK         bool              `json:"ok"`
}

type stParent struct {
	Parent     string            `json:"parent"`
	Conditions map[string]stCond `json:"conditions"`
	OK         bool              `json:"ok"`
}

type stItem struct {
	Kind       string            `json:"kind"`
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Class      string            `json:"class,omitempty"`
	Hostnames  []string          `json:"hostnames,omitempty"`
	Conditions map[string]stCond `json:"conditions,omitempty"`
	Listeners  []stListener      `json:"listeners,omitempty"`
	Parents    []stParent        `json:"parents,omitempty"`
	OK         bool              `json:"ok"`
	Problems   []string          `json:"problems,omitempty"`
}

type statusReport struct {
	Schema   string   `json:"schema"`
	OK       bool     `json:"ok"`
	Verdict  string   `json:"verdict"`
	Gateways []stItem `json:"gateways"`
	Routes   []stItem `json:"routes"`
	// Policies are the Envoy Gateway policies of the Setura controller (--envoy-compat).
	Policies []stPolicy `json:"envoyPolicies,omitempty"`
	Next     string     `json:"next,omitempty"`
}

func condsOf(v any) map[string]stCond {
	out := map[string]stCond{}
	for _, c := range asList(v) {
		m := asMap(c)
		out[asStr(m["type"])] = stCond{Status: asStr(m["status"]), Reason: asStr(m["reason"]), Message: asStr(m["message"])}
	}
	return out
}

func isTrue(c map[string]stCond, typ string) bool { return c[typ].Status == "True" }

// condProblem renders a condition that is not True.
func condProblem(what string, c map[string]stCond, typ string) string {
	cc, ok := c[typ]
	if !ok {
		return what + ": " + typ + " not reported yet"
	}
	s := what + ": " + typ + "=" + cc.Status
	if cc.Reason != "" {
		s += " (" + cc.Reason + ")"
	}
	if cc.Message != "" {
		s += ": " + cc.Message
	}
	return s
}

// buildStatus turns the kubectl lists into the report. gateways, classes and
// the route lists are the "items" of kubectl get. all keeps objects of other
// controllers too.
func buildStatus(classes, gateways []any, routes map[string][]any, all bool) *statusReport {
	ours := map[string]bool{}
	for _, c := range classes {
		if all || asStr(dig(c, "spec", "controllerName")) == builtin.ControllerName {
			ours[asStr(dig(c, "metadata", "name"))] = true
		}
	}
	rep := &statusReport{Schema: gatewayStatusSchema, Gateways: []stItem{}, Routes: []stItem{}}
	kept := map[string]bool{} // namespace/name of the Gateways shown
	for _, g := range gateways {
		class := asStr(dig(g, "spec", "gatewayClassName"))
		if !ours[class] {
			continue
		}
		it := stItem{Kind: "Gateway", Namespace: asStr(dig(g, "metadata", "namespace")), Name: asStr(dig(g, "metadata", "name")), Class: class,
			Conditions: condsOf(dig(g, "status", "conditions"))}
		kept[it.Namespace+"/"+it.Name] = true
		it.OK = isTrue(it.Conditions, "Accepted") && isTrue(it.Conditions, "Programmed")
		if !isTrue(it.Conditions, "Accepted") {
			it.Problems = append(it.Problems, condProblem("Gateway", it.Conditions, "Accepted"))
		}
		if !isTrue(it.Conditions, "Programmed") {
			it.Problems = append(it.Problems, condProblem("Gateway", it.Conditions, "Programmed"))
		}
		specPorts := map[string][2]any{}
		for _, l := range asList(dig(g, "spec", "listeners")) {
			p, _ := num(dig(l, "port"))
			specPorts[asStr(dig(l, "name"))] = [2]any{int(p), asStr(dig(l, "protocol"))}
		}
		for _, l := range asList(dig(g, "status", "listeners")) {
			name := asStr(dig(l, "name"))
			sl := stListener{Name: name, Conditions: condsOf(dig(l, "conditions"))}
			sp := specPorts[name]
			sl.Port, _ = sp[0].(int)
			sl.Protocol, _ = sp[1].(string)
			n, _ := num(dig(l, "attachedRoutes"))
			sl.Attached = int(n)
			sl.OK = isTrue(sl.Conditions, "Accepted") && isTrue(sl.Conditions, "Programmed") && sl.Conditions["Conflicted"].Status != "True"
			what := fmt.Sprintf("listener %s (%d/%s)", name, sl.Port, sl.Protocol)
			switch {
			case sl.Conditions["Conflicted"].Status == "True":
				it.Problems = append(it.Problems, strings.Replace(condProblem(what, sl.Conditions, "Conflicted"), "=True", "", 1))
			case !isTrue(sl.Conditions, "Accepted"):
				it.Problems = append(it.Problems, condProblem(what, sl.Conditions, "Accepted"))
			case !isTrue(sl.Conditions, "Programmed"):
				it.Problems = append(it.Problems, condProblem(what, sl.Conditions, "Programmed"))
			}
			it.Listeners = append(it.Listeners, sl)
		}
		if len(it.Listeners) == 0 && len(it.Conditions) == 0 {
			it.OK = false
			it.Problems = []string{"no status yet: the controller has not reported on this Gateway (is it running? setura doctor gateway --kube)"}
		}
		rep.Gateways = append(rep.Gateways, it)
	}
	for _, kind := range []string{"HTTPRoute", "GRPCRoute", "TLSRoute"} {
		for _, r := range routes[kind] {
			ns := asStr(dig(r, "metadata", "namespace"))
			it := stItem{Kind: kind, Namespace: ns, Name: asStr(dig(r, "metadata", "name"))}
			for _, h := range asList(dig(r, "spec", "hostnames")) {
				it.Hostnames = append(it.Hostnames, asStr(h))
			}
			statuses := asList(dig(r, "status", "parents"))
			attached := false
			for _, pr := range asList(dig(r, "spec", "parentRefs")) {
				pns := asStr(dig(pr, "namespace"))
				if pns == "" {
					pns = ns
				}
				pname, section := asStr(dig(pr, "name")), asStr(dig(pr, "sectionName"))
				if k := asStr(dig(pr, "kind")); (k != "" && k != "Gateway") || (!all && !kept[pns+"/"+pname]) {
					continue
				}
				attached = true
				label := pns + "/" + pname
				if section != "" {
					label += "/" + section
				}
				sp := stParent{Parent: label, Conditions: map[string]stCond{}}
				for _, st := range statuses {
					if asStr(dig(st, "parentRef", "name")) != pname || (asStr(dig(st, "parentRef", "namespace")) != "" && asStr(dig(st, "parentRef", "namespace")) != pns) {
						continue
					}
					if s := asStr(dig(st, "parentRef", "sectionName")); s != section {
						continue
					}
					if !all && asStr(dig(st, "controllerName")) != builtin.ControllerName {
						continue
					}
					sp.Conditions = condsOf(dig(st, "conditions"))
				}
				sp.OK = isTrue(sp.Conditions, "Accepted") && sp.Conditions["ResolvedRefs"].Status != "False"
				switch {
				case !isTrue(sp.Conditions, "Accepted"):
					it.Problems = append(it.Problems, condProblem("parent "+label, sp.Conditions, "Accepted"))
				case sp.Conditions["ResolvedRefs"].Status == "False":
					it.Problems = append(it.Problems, condProblem("parent "+label, sp.Conditions, "ResolvedRefs"))
				}
				it.Parents = append(it.Parents, sp)
			}
			if !attached {
				continue // attaches to Gateways of another controller
			}
			it.OK = len(it.Problems) == 0
			rep.Routes = append(rep.Routes, it)
		}
	}
	less := func(a, b stItem) bool {
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	}
	sort.Slice(rep.Gateways, func(i, j int) bool { return less(rep.Gateways[i], rep.Gateways[j]) })
	sort.Slice(rep.Routes, func(i, j int) bool { return less(rep.Routes[i], rep.Routes[j]) })
	bad := 0
	for _, l := range [][]stItem{rep.Gateways, rep.Routes} {
		for _, it := range l {
			if !it.OK {
				bad++
			}
		}
	}
	rep.OK = bad == 0
	switch {
	case bad > 0:
		rep.Verdict = plural(bad, "object needs", "objects need") + " attention"
		rep.Next = "Fix the listed reasons, then rerun setura gateway status; setura doctor gateway --kube also checks the CRDs"
	case len(rep.Gateways) == 0:
		rep.Verdict = "no Gateways of the Setura controller found"
		rep.Next = "setura gateway install --check, then setura gateway install"
	default:
		rep.Verdict = fmt.Sprintf("%s and %s are accepted and programmed", plural(len(rep.Gateways), "Gateway", "Gateways"), plural(len(rep.Routes), "route", "routes"))
	}
	return rep
}

// listAll runs "kubectl get RESOURCE -o json" for one namespace, or all of them
// when namespace is empty. A resource type the cluster does not know returns
// (nil, nil) when optional.
func (c *Cluster) listAll(namespace, resource string, optional bool) ([]any, error) {
	var m obj
	var err error
	if namespace == "" {
		args := append(c.cmd(), "get", resource, "-A", "-o", "json", "--request-timeout=10s")
		var out, errs string
		var code int
		out, errs, code, err = c.Exec(args)
		if err == nil && code != 0 {
			err = &kubectlError{strings.TrimSpace(errs)}
		}
		if err == nil {
			err = unmarshalObj(out, &m)
		}
	} else {
		m, err = c.getMap(namespace, resource)
	}
	if err != nil {
		if optional && (strings.Contains(err.Error(), "doesn't have a resource type") || strings.Contains(err.Error(), "the server could not find the requested resource")) {
			return nil, nil
		}
		return nil, err
	}
	return asList(m["items"]), nil
}

// clusterStatus reads Gateways and routes through kubectl.
func clusterStatus(c *Cluster, namespace string, all bool) (*statusReport, error) {
	classes, err := c.listAll("", "gatewayclasses."+builtin.CRDGroup, false)
	if err != nil {
		return nil, fmt.Errorf("cannot read GatewayClasses: %w", err)
	}
	gws, err := c.listAll(namespace, "gateways."+builtin.CRDGroup, false)
	if err != nil {
		return nil, fmt.Errorf("cannot read Gateways: %w", err)
	}
	routes := map[string][]any{}
	for _, kr := range [][2]string{{"HTTPRoute", "httproutes"}, {"GRPCRoute", "grpcroutes"}, {"TLSRoute", "tlsroutes"}} {
		kind, res := kr[0], kr[1]
		l, err := c.listAll(namespace, res+"."+builtin.CRDGroup, kind != "HTTPRoute")
		if err != nil {
			return nil, fmt.Errorf("cannot read %ss: %w", kind, err)
		}
		routes[kind] = l
	}
	rep := buildStatus(classes, gws, routes, all)
	if lists := readEnvoyPolicies(c, namespace); len(lists) > 0 {
		addEnvoyPolicies(rep, lists, all)
	}
	return rep, nil
}

func (u *ui) StatusPretty(r *statusReport) string {
	var b strings.Builder
	section := func(title string, items []stItem) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n  %s\n", u.bold(title))
		for _, it := range items {
			sym := u.okSym()
			if !it.OK {
				sym = u.failSym()
			}
			extra := ""
			switch {
			case it.Kind == "Gateway":
				extra = "class " + it.Class
			case len(it.Parents) > 0:
				var ps []string
				for _, p := range it.Parents {
					ps = append(ps, p.Parent)
				}
				extra = "-> " + strings.Join(ps, ", ")
			}
			name := it.Namespace + "/" + it.Name
			if it.Kind != "Gateway" {
				name += " (" + it.Kind + ")"
			}
			fmt.Fprintf(&b, "  %s %s %s\n", sym, pad(name, 38), u.gray(extra))
			for _, p := range it.Problems {
				fmt.Fprintf(&b, "      %s %s\n", u.arrow(), p)
			}
		}
	}
	section("Gateways", r.Gateways)
	section("Routes", r.Routes)
	u.policiesPretty(&b, r.Policies)
	b.WriteString("\n")
	sym := u.okSym()
	if !r.OK {
		sym = u.failSym()
	} else if len(r.Gateways) == 0 {
		sym = u.warnSym()
	}
	fmt.Fprintf(&b, "  %s %s\n", sym, u.bold(r.Verdict))
	if r.Next != "" {
		fmt.Fprintf(&b, "  %s %s\n", u.blue("Next:"), r.Next)
	}
	b.WriteString("\n")
	return b.String()
}

// runGatewayStatus implements "setura gateway status".
func runGatewayStatus(c *Cluster, args []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) int {
	fs := newFlagSet("gateway status", stderr)
	var ns string
	fs.StringVar(&ns, "n", "", "namespace (default: all namespaces)")
	fs.StringVar(&ns, "namespace", "", "namespace (default: all namespaces)")
	allNS := fs.Bool("A", false, "all namespaces (the default)")
	fs.Bool("all-namespaces", false, "all namespaces (the default)")
	allCtl := fs.Bool("all-controllers", false, "also show Gateways and routes of other controllers")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 0 || (*allNS && ns != "") {
		fmt.Fprintln(stderr, "setura gateway status: use either -n NAMESPACE or -A, and no arguments")
		return 2
	}
	pretty, err := wantPretty(*format, stdoutTTY)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway status: %v\n", err)
		return 2
	}
	if ns != "" {
		if _, err := label(ns); err != nil {
			fmt.Fprintf(stderr, "setura gateway status: %v\n", err)
			return 2
		}
	}
	rep, err := clusterStatus(c, ns, *allCtl)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway status: %v\n", err)
		return 1
	}
	if pretty {
		fmt.Fprint(stdout, u.StatusPretty(rep))
	} else if err := writeJSON(stdout, rep); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return boolExit(!rep.OK)
}

func unmarshalObj(raw string, into *obj) error {
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("kubectl returned invalid JSON: %w", err)
	}
	return nil
}
