package setura

import (
	"fmt"
	"io"
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

const crdReportSchema = "setura.gateway.crds/v1"

// crdFinding is one Setura feature judged against the installed CRDs.
type crdFinding struct {
	Feature string `json:"feature"`
	CRD     string `json:"crd"`
	State   string `json:"state"` // ok, warn, fail or info (not installed, not needed)
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

type crdReport struct {
	Schema   string       `json:"schema"`
	OK       bool         `json:"ok"`
	Version  string       `json:"bundleVersion,omitempty"` // from the CRDs' bundle-version annotation
	Channel  string       `json:"channel,omitempty"`
	Target   string       `json:"targetVersion"`
	Verdict  string       `json:"verdict"`
	Findings []crdFinding `json:"findings"`
	Next     string       `json:"next,omitempty"`
}

const (
	annBundle  = "gateway.networking.k8s.io/bundle-version"
	annChannel = "gateway.networking.k8s.io/channel"
)

// crdSchemaHas reports whether the served schema of a CRD contains the field
// path. known is false when the CRD carries no schema at all.
func crdSchemaHas(crd obj, path []string) (has, known bool) {
	var schema any
	versions := asList(dig(crd, "spec", "versions"))
	pick := func(name string) any {
		for _, v := range versions {
			if asStr(dig(v, "name")) == name && dig(v, "served") != false {
				return dig(v, "schema", "openAPIV3Schema")
			}
		}
		return nil
	}
	if schema = pick("v1"); schema == nil {
		for _, v := range versions {
			if dig(v, "served") != false {
				if s := dig(v, "schema", "openAPIV3Schema"); s != nil {
					schema = s
					break
				}
			}
		}
	}
	if schema == nil {
		return false, false
	}
	node := schema
	for _, key := range path {
		for { // step through array levels
			items := dig(node, "items")
			if items == nil || dig(node, "properties") != nil {
				break
			}
			node = items
		}
		props := asMap(dig(node, "properties"))
		next, ok := props[key]
		if !ok {
			return false, true
		}
		node = next
	}
	return true, true
}

// checkCRDs judges the CRDs of a cluster (items of "kubectl get crd") against
// builtin.CRDFeatures. target is the Gateway API release to recommend.
func checkCRDs(items []any, target string) *crdReport {
	if target == "" {
		target = builtin.GatewayAPIVersion
	}
	rep := &crdReport{Schema: crdReportSchema, Target: target}
	byPlural := map[string]obj{}
	suffix := "." + builtin.CRDGroup
	for _, it := range items {
		name := asStr(dig(it, "metadata", "name"))
		if strings.HasSuffix(name, suffix) {
			byPlural[strings.TrimSuffix(name, suffix)] = asMap(it)
		}
	}
	versions := map[string]bool{}
	for _, plural := range sortedKeys(byPlural) {
		ann := asMap(dig(byPlural[plural], "metadata", "annotations"))
		if v := asStr(ann[annBundle]); v != "" {
			versions[v] = true
			if rep.Version == "" || plural == "httproutes" {
				rep.Version = v
			}
		}
		if ch := asStr(ann[annChannel]); ch != "" && (rep.Channel == "" || plural == "httproutes") {
			rep.Channel = ch
		}
	}
	installed := fmt.Sprintf("the installed CRDs (bundle %s, %s channel)", orStr(rep.Version, "unknown version"), orStr(rep.Channel, "unknown"))
	fix := "kubectl apply --server-side -f " + builtin.CRDInstallURL(target, "standard")
	expFix := "kubectl apply --server-side -f " + builtin.CRDInstallURL(target, "experimental")
	add := func(f crdFinding) { rep.Findings = append(rep.Findings, f) }

	if len(byPlural) == 0 {
		add(crdFinding{Feature: "Gateway API CRDs", CRD: builtin.CRDGroup, State: "fail",
			Message: "no Gateway API CRDs are installed, so the controller cannot start watching",
			Fix:     fix})
	}
	if len(versions) > 1 {
		add(crdFinding{Feature: "CRD bundle", State: "warn", CRD: builtin.CRDGroup,
			Message: "CRDs come from different Gateway API releases (" + strings.Join(sortedKeys(versions), ", ") + "); apply one bundle so the schemas agree",
			Fix:     fix})
	}
	for _, f := range builtin.CRDFeatures {
		crd, present := byPlural[f.CRD]
		res := crdFinding{Feature: f.Name, CRD: f.CRD + suffix}
		switch {
		case len(byPlural) == 0 && f.Required:
			continue // covered by the single finding above
		case !present && f.Required:
			res.State, res.Message, res.Fix = "fail", f.CRD+" is not installed; the controller needs it", fix
		case !present && f.Experimental:
			res.State, res.Message, res.Fix = "info", "not installed ("+f.Note+"); only needed for "+f.Name+" listeners and routes", expFix
		case !present:
			res.State, res.Message, res.Fix = "info", "not installed; "+f.Name+" needs "+f.NeedsText(), fix
		case len(f.Path) == 0:
			res.State, res.Message = "ok", "installed"
			if v := rep.Version; v != "" && !f.Experimental {
				if c, err := builtin.CompareGatewayAPIVersion(v, f.MinStandard); err == nil && c < 0 {
					res.State, res.Message, res.Fix = "warn", f.Name+" needs "+f.NeedsText()+" but "+installed+" are older", fix
					if f.Required {
						res.State = "fail"
					}
				}
			}
		default:
			has, known := crdSchemaHas(crd, f.Path)
			switch {
			case known && has:
				res.State, res.Message = "ok", "the CRD has spec."+strings.Join(f.Path[1:], ".")
			case known:
				res.State = "warn"
				res.Message = fmt.Sprintf("%s has no spec.%s field, so the API server rejects such routes with \"unknown field\"; it needs %s", installed, strings.Join(f.Path[1:], "."), f.NeedsText())
				res.Fix = fix
			default:
				res.State, res.Message = "ok", "installed (the CRD schema was not readable, so the field was not checked)"
				if v := rep.Version; v != "" {
					if c, err := builtin.CompareGatewayAPIVersion(v, f.MinStandard); err == nil && c < 0 {
						res.State, res.Message, res.Fix = "warn", f.Name+" needs "+f.NeedsText()+" but "+installed+" are older", fix
					}
				}
			}
		}
		add(res)
	}
	if rep.Version != "" && len(byPlural) > 0 {
		if c, err := builtin.CompareGatewayAPIVersion(rep.Version, builtin.MinGatewayAPIVersion); err == nil && c < 0 {
			add(crdFinding{Feature: "Gateway API release", CRD: builtin.CRDGroup, State: "fail",
				Message: fmt.Sprintf("%s is older than %s, the oldest release the controller supports", rep.Version, builtin.MinGatewayAPIVersion), Fix: fix})
		}
	}
	fails, warns := 0, 0
	for _, f := range rep.Findings {
		switch f.State {
		case "fail":
			fails++
			if rep.Next == "" {
				rep.Next = f.Fix
			}
		case "warn":
			warns++
		}
	}
	if rep.Next == "" {
		for _, f := range rep.Findings {
			if f.State == "warn" && f.Fix != "" {
				rep.Next = f.Fix
				break
			}
		}
	}
	rep.OK = fails == 0
	switch {
	case fails > 0:
		rep.Verdict = plural(fails, "CRD problem needs", "CRD problems need") + " fixing"
	case warns > 0:
		rep.Verdict = plural(warns, "feature is", "features are") + " unavailable with these CRDs"
	default:
		rep.Verdict = "Gateway API CRDs look complete"
		if rep.Version != "" {
			rep.Verdict += " (" + rep.Version + ")"
		}
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool { return crdRank(rep.Findings[i].State) < crdRank(rep.Findings[j].State) })
	return rep
}

func crdRank(s string) int {
	switch s {
	case "fail":
		return 0
	case "warn":
		return 1
	case "ok":
		return 2
	}
	return 3
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// clusterCRDs reads the CRDs through kubectl.
func clusterCRDs(c *Cluster) ([]any, error) {
	m, err := c.getMap("default", "customresourcedefinitions.apiextensions.k8s.io")
	if err != nil {
		return nil, err
	}
	return asList(m["items"]), nil
}

func (u *ui) CRDReportPretty(r *crdReport) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, f := range r.Findings {
		sym := u.okSym()
		switch f.State {
		case "fail":
			sym = u.failSym()
		case "warn":
			sym = u.warnSym()
		case "info":
			sym = u.skipSym()
		}
		fmt.Fprintf(&b, "  %s %s %s\n", sym, pad(f.Feature, 44), f.Message)
		if (f.State == "fail" || f.State == "warn") && f.Fix != "" {
			fmt.Fprintf(&b, "      %s %s\n", u.arrow(), u.gray(f.Fix))
		}
	}
	b.WriteString("\n")
	sym := u.okSym()
	switch {
	case !r.OK:
		sym = u.failSym()
	case strings.Contains(r.Verdict, "unavailable"):
		sym = u.warnSym()
	}
	fmt.Fprintf(&b, "  %s %s\n", sym, u.bold(r.Verdict))
	if r.Next != "" {
		fmt.Fprintf(&b, "  %s %s\n", u.blue("Next:"), r.Next)
	}
	b.WriteString("\n")
	return b.String()
}

// runInstallCheck implements "setura gateway install --check".
func runInstallCheck(c *Cluster, args []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) int {
	fs := newFlagSet("gateway install --check", stderr)
	fs.Bool("check", true, "check the cluster's Gateway API CRDs instead of printing manifests")
	version := fs.String("gateway-api-version", builtin.GatewayAPIVersion, "Gateway API release to recommend when CRDs are missing or too old")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	if _, err := builtin.ParseGatewayAPIVersion(*version); err != nil {
		fmt.Fprintf(stderr, "setura gateway install --check: --gateway-api-version: %v\n", err)
		return 2
	}
	pretty, err := wantPretty(*format, stdoutTTY)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway install --check: %v\n", err)
		return 2
	}
	items, err := clusterCRDs(c)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway install --check: cannot read the CRDs: %v\n", err)
		return 1
	}
	rep := checkCRDs(items, *version)
	failed := !rep.OK
	for _, f := range rep.Findings {
		failed = failed || f.State == "warn" // an explicit prerequisite check: a missing feature is a failure
	}
	if pretty {
		fmt.Fprint(stdout, u.CRDReportPretty(rep))
	} else if err := writeJSON(stdout, rep); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return boolExit(failed)
}
