package setura

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var convertSources = []string{"ingress-nginx", "envoy-gateway", "traefik", "nginx-conf"}

// convertInput is everything the conversions read.
type convertInput struct {
	objs    []obj // every object from files or the cluster
	raw     []namedText
	cluster bool
}

type namedText struct{ Name, Text string }

func ofKind(objs []obj, kinds ...string) []obj {
	var out []obj
	for _, o := range objs {
		for _, k := range kinds {
			if kindOf(o, k) {
				out = append(out, o)
				break
			}
		}
	}
	return out
}

func loadConfFiles(path string) ([]namedText, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.ToLower(filepath.Ext(p)) == ".conf" {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	var out []namedText
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, namedText{f, string(b)})
	}
	return out, nil
}

func runMigrateConvert(cluster *Cluster, fs *flag.FlagSet, args []string, stdout, stderr io.Writer, u *ui, tty bool) (int, error) {
	var ns string
	fs.StringVar(&ns, "n", "default", "namespace to read from the cluster (and for objects that carry none)")
	fs.StringVar(&ns, "namespace", "default", "namespace to read from the cluster (and for objects that carry none)")
	all := fs.Bool("A", false, "read all namespaces from the cluster")
	from := fs.String("from", "ingress-nginx", "what to convert: ingress-nginx, envoy-gateway, traefik or nginx-conf")
	class := fs.String("ingress-class", "", "only convert Ingresses of this class (default: all)")
	gwClass := fs.String("gateway-class", "", "gatewayClassName of the generated Gateways (default setura; envoy-gateway keeps the input's)")
	out := fs.String("out", "", "write one file per resource into this directory instead of stdout")
	force := fs.Bool("force", false, "overwrite existing files in --out and --report")
	report := fs.String("report", "", "write the machine-readable report (JSON) to this file")
	format := fs.String("format", "pretty", "pretty (YAML on stdout, summary on stderr; summary on stdout with --out), json (report with the manifests) or yaml (manifests only)")
	noCheck := fs.Bool("no-check", false, "skip the equivalence check of the generated routes against the originals")

	if len(args) > 0 && args[0] == "convert" {
		args = args[1:]
	}
	paths, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	fail := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura migrate convert: %s\n", msg)
		exampleHint(stderr, "migrate")
		return 2, usageError{msg}
	}
	src := *from
	if src == "ingress" {
		src = "ingress-nginx"
	}
	known := false
	for _, s := range convertSources {
		known = known || s == src
	}
	if !known {
		return fail(fmt.Sprintf("--from must be one of %s, got %q", strings.Join(convertSources, ", "), *from))
	}
	switch *format {
	case "pretty", "auto", "json", "yaml":
	default:
		return fail(fmt.Sprintf("--format must be pretty, json or yaml, got %q", *format))
	}
	if src == "nginx-conf" && len(paths) == 0 {
		return fail("--from nginx-conf needs a nginx.conf file or directory")
	}

	in := convertInput{}
	if src == "nginx-conf" {
		for _, p := range paths {
			txt, err := loadConfFiles(p)
			if err != nil {
				return fail(err.Error())
			}
			in.raw = append(in.raw, txt...)
		}
	} else {
		for _, p := range paths {
			objs, err := loadManifestObjects(p)
			if err != nil {
				return fail(err.Error())
			}
			in.objs = append(in.objs, objs...)
		}
		if len(paths) == 0 {
			in.cluster = true
			if err := readConvertCluster(cluster, src, ns, *all, &in, stderr); err != nil {
				return 0, err
			}
		}
	}

	gc := *gwClass
	if gc == "" && src != "envoy-gateway" {
		gc = "setura"
	}
	c := newConverter(src, gc, ns)
	var originals []obj
	switch src {
	case "ingress-nginx":
		var ings []obj
		for _, ing := range ofKind(in.objs, "Ingress") {
			if ingressClassWanted(ing, ofKind(in.objs, "IngressClass"), *class) {
				ings = append(ings, ing)
			}
		}
		if len(ings) == 0 {
			if *class != "" {
				return 0, userErrorf("no Ingress objects of class %q found", *class)
			}
			return 0, userError("no Ingress objects found; nothing to convert")
		}
		c.loadSupport(in.objs)
		c.convertIngresses(ings)
		originals = ings
	case "envoy-gateway":
		if err := c.convertEnvoy(in.objs); err != nil {
			return 0, err
		}
	case "traefik":
		if err := c.convertTraefik(in.objs); err != nil {
			return 0, err
		}
	case "nginx-conf":
		if errs := c.convertNginxConf(in.raw); len(errs) > 0 {
			fmt.Fprintf(stderr, "setura migrate convert: the nginx configuration uses constructs outside the supported subset (see docs/migrate-convert.md):\n")
			for _, e := range errs {
				fmt.Fprintf(stderr, "  %s\n", e)
			}
			return 2, usageError{"unsupported nginx configuration"}
		}
	}
	c.finishGateways()
	c.order()

	rep := c.buildReport(src, originals, !*noCheck)
	if *out != "" {
		if err := writeConvertFiles(*out, c, *force); err != nil {
			return 0, err
		}
	} else {
		for _, r := range c.res {
			r.File = ""
		}
	}
	rep.Resources = nil
	for _, r := range c.res {
		todos := len(r.Comments)
		rep.Resources = append(rep.Resources, convResource{Kind: r.Kind, Namespace: r.NS, Name: r.Name, File: filepath.ToSlash(r.File), Todos: todos})
	}
	if *format == "json" && *out == "" {
		for _, r := range c.res {
			rep.Manifests = append(rep.Manifests, r.Obj)
		}
	}
	if *report != "" {
		if _, err := os.Stat(*report); err == nil && !*force {
			return 0, userErrorf("refusing to overwrite %s (use --force)", *report)
		}
		rr := *rep
		rr.Manifests = nil
		if err := os.WriteFile(*report, jsonBytes(&rr), 0o644); err != nil {
			return 0, err
		}
	}

	switch {
	case *format == "json":
		if err := writeJSON(stdout, rep); err != nil {
			return 0, err
		}
	case *format == "yaml":
		if *out == "" {
			fmt.Fprint(stdout, c.allYAML())
		}
	case *out != "":
		fmt.Fprint(stdout, u.ConvertPretty(rep, *out, src, *report))
	default:
		fmt.Fprint(stdout, c.allYAML())
		fmt.Fprint(stderr, u.ConvertPretty(rep, "", src, *report))
	}
	return boolExit(!rep.OK), nil
}

// loadSupport picks up Services and ConfigMaps from the inputs.
func (c *converter) loadSupport(objs []obj) {
	if svcs := ofKind(objs, "Service"); len(svcs) > 0 {
		c.svcs, c.haveSvc = extractServices(svcs), true
	}
	for _, cm := range ofKind(objs, "ConfigMap") {
		name, ns := metaOf(cm)
		data := map[string]string{}
		for k, v := range asMap(cm["data"]) {
			data[k] = fmt.Sprint(v)
		}
		c.cms[ns+"/"+name] = data
	}
}

// readConvertCluster lists what a source needs from the cluster.
func readConvertCluster(cluster *Cluster, src, ns string, all bool, in *convertInput, stderr io.Writer) error {
	scope := []string{}
	if all {
		scope = []string{"-A"}
	}
	list := func(resource string, required bool) error {
		v, err := cluster.getMap(ns, resource, scope...)
		if err != nil {
			if required {
				return err
			}
			fmt.Fprintf(stderr, "setura migrate convert: could not read %s: %s\n", resource, err)
			return nil
		}
		in.objs = append(in.objs, itemsOf(v)...)
		return nil
	}
	switch src {
	case "ingress-nginx":
		for _, r := range []struct {
			res string
			req bool
		}{{"ingresses.networking.k8s.io", true}, {"ingressclasses.networking.k8s.io", false}, {"services", false}, {"configmaps", false}} {
			if err := list(r.res, r.req); err != nil {
				return err
			}
		}
	case "traefik":
		for _, r := range []struct {
			res string
			req bool
		}{{"ingressroutes.traefik.io", true}, {"middlewares.traefik.io", false}, {"services", false}} {
			if err := list(r.res, r.req); err != nil {
				return err
			}
		}
	case "envoy-gateway":
		for _, r := range []struct {
			res string
			req bool
		}{{"httproutes.gateway.networking.k8s.io", true}, {"grpcroutes.gateway.networking.k8s.io", false}, {"gateways.gateway.networking.k8s.io", false},
			{"securitypolicies.gateway.envoyproxy.io", false}, {"backendtrafficpolicies.gateway.envoyproxy.io", false}, {"clienttrafficpolicies.gateway.envoyproxy.io", false}} {
			if err := list(r.res, r.req); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- report and check ----------------------------------------------------

func (c *converter) buildReport(src string, originals []obj, check bool) *convReport {
	rep := &convReport{Source: src, Summary: c.counts(), Items: c.items, Notes: c.notes}
	if rep.Items == nil {
		rep.Items = []convItem{}
	}
	if check {
		rep.Check = c.roundTrip(originals)
	} else {
		rep.Check = &convCheck{Skipped: true, Reason: "--no-check", OK: true}
	}
	rep.OK = rep.Summary[convTodo] == 0 && rep.Check.OK
	rep.Verdict = "equivalent"
	if !rep.OK {
		rep.Verdict = "needs-review"
	}
	return rep
}

// roundTrip runs the migrate check comparison offline on the originals and
// the generated routes (re-read from the YAML that would be written).
func (c *converter) roundTrip(originals []obj) *convCheck {
	var routes, gateways, grants []obj
	for _, r := range c.res {
		docs, err := decodeManifests([]byte(r.yaml()))
		if err != nil {
			return &convCheck{OK: false, Notes: []string{"generated YAML does not parse: " + err.Error()}}
		}
		for _, d := range docs {
			o := asMap(d)
			switch asStr(o["kind"]) {
			case kindHTTPRoute, kindGRPCRoute, kindTLSRoute:
				routes = append(routes, o)
			case "Gateway":
				gateways = append(gateways, o)
			case "ReferenceGrant":
				grants = append(grants, o)
			}
		}
	}
	if c.from == "envoy-gateway" {
		return c.envoyCheck(routes)
	}
	ings := originals
	if c.from != "ingress-nginx" {
		ings = c.synthetic
	}
	if len(ings) == 0 {
		return &convCheck{Skipped: true, Reason: "nothing to compare", OK: true}
	}
	rep := compareMigration(migrateInput{Ingresses: ings, Routes: routes, Gateways: gateways, HaveGW: true,
		Services: c.svcs, HaveServices: c.haveSvc, Grants: grants, GrantsAll: true})
	// Settings that became a policy or a filter are handled even where the
	// classic table would flag them.
	handled := map[string]bool{}
	for _, it := range c.items {
		if it.Status == convDone && strings.HasPrefix(it.Source, "Ingress ") {
			_, name, _ := strings.Cut(strings.TrimPrefix(it.Source, "Ingress "), "/")
			handled[name+"|"+it.Key] = true
		}
	}
	var rules []*ruleResult
	for _, r := range rep.Rules {
		if r.Status == statusExtra && r.extra != nil {
			if c.expectedExtra[r.Route+"|"+r.Host+"|all"] || (c.expectedExtra[r.Route+"|"+r.Host+"|redirect"] && r.extra.Redirect != "") ||
				(c.redirectRoutes[r.Route] && r.extra.Redirect != "") {
				continue
			}
		}
		if r.Status == statusDifferent && r.ingress != nil && (r.ingress.Annotations[nginxPrefix+"permanent-redirect"] != "" || r.ingress.Annotations[nginxPrefix+"temporal-redirect"] != "") {
			if strings.Contains(strings.Join(r.Details, "\n"), "instead of forwarding") {
				r.Status = statusEquivalent
			}
		}
		rules = append(rules, r)
	}
	rep.Rules = rules
	if c.from != "ingress-nginx" {
		rep.Annotations = nil
	}
	for i := range rep.Annotations {
		a := &rep.Annotations[i]
		if handled[a.Ingress+"|"+a.Annotation] {
			a.Handled = true
		}
	}
	rep.finish()
	var notes []string
	for _, n := range rep.Notes {
		if !strings.Contains(n, "endpoints were not inspected") {
			notes = append(notes, n)
		}
	}
	s := rep.Summary
	ok := s[statusDifferent]+s[statusMissing]+s[statusExtra]+s[statusUnresolved]+s["grants_missing"] == 0
	return &convCheck{OK: ok, Summary: s, Rules: rep.Rules, Notes: notes}
}

// ---- pretty --------------------------------------------------------------

func shortKey(k string) string {
	return strings.TrimPrefix(k, nginxPrefix)
}

// ConvertPretty is the quiet terminal summary: what converted, what needs a
// human, one verdict line and the next step.
func (u *ui) ConvertPretty(rep *convReport, out, src, reportFile string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s  %s\n", u.bold("setura migrate convert"), u.gray(src+" "+u.arrow()+" Gateway API"))
	var done, todo []convItem
	ignored := 0
	for _, it := range rep.Items {
		switch it.Status {
		case convDone:
			done = append(done, it)
		case convTodo:
			todo = append(todo, it)
		default:
			ignored++
		}
	}
	srcW, keyW := 6, 3
	for _, it := range rep.Items {
		srcW = max(srcW, len([]rune(it.Source)))
		keyW = max(keyW, len([]rune(shortKey(it.Key))))
	}
	section := func(title, sym string, items []convItem, detail func(convItem) string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n  %s\n", u.blue(title))
		for _, it := range items {
			fmt.Fprintf(&b, "    %s  %s  %s  %s\n", sym, u.gray(pad(it.Source, srcW)), pad(shortKey(it.Key), keyW), detail(it))
		}
	}
	section("Converted", u.okSym(), done, func(it convItem) string { return it.Target })
	section("Needs a human", u.warnSym(), todo, func(it convItem) string { return u.gray(truncate(it.Reason, 78)) })
	if ignored > 0 {
		fmt.Fprintf(&b, "\n  %s\n", u.gray(fmt.Sprintf("%d setting%s ignored on purpose (see the report)", ignored, cvPlural(ignored))))
	}
	if len(rep.Resources) > 0 {
		fmt.Fprintf(&b, "\n  %s\n", u.blue("Generated"))
		kw, nw := 4, 4
		for _, r := range rep.Resources {
			kw = max(kw, len(r.Kind))
			nw = max(nw, len(r.Namespace+"/"+r.Name))
		}
		for _, r := range rep.Resources {
			tail := ""
			if r.File != "" {
				tail = u.gray(r.File)
			}
			if r.Todos > 0 {
				tail += u.amber(fmt.Sprintf("  %d TODO", r.Todos))
			}
			fmt.Fprintf(&b, "    %s  %s  %s\n", pad(r.Kind, kw), pad(r.Namespace+"/"+r.Name, nw), tail)
		}
	}
	if ck := rep.Check; ck != nil {
		fmt.Fprintf(&b, "\n  %s  ", u.blue("Check"))
		switch {
		case ck.Skipped:
			fmt.Fprintf(&b, "%s\n", u.gray("skipped ("+ck.Reason+")"))
		case ck.OK:
			eq := 0
			if ck.Summary != nil {
				eq = ck.Summary[statusEquivalent]
			}
			fmt.Fprintf(&b, "%s %d rule%s equivalent to the original\n", u.okSym(), eq, cvPlural(eq))
		default:
			fmt.Fprintf(&b, "%s differences from the original\n", u.failSym())
			for _, r := range ck.Rules {
				if r.Status == statusEquivalent {
					continue
				}
				fmt.Fprintf(&b, "    %s  %s %s %s\n", u.failSym(), r.Status, hostLabel(r.Host), r.Path)
				for _, d := range r.Details {
					fmt.Fprintf(&b, "         %s\n", u.gray(d))
				}
			}
			for _, n := range ck.Notes {
				fmt.Fprintf(&b, "    %s  %s\n", u.warnSym(), n)
			}
		}
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(&b, "\n  %s %s\n", u.warnSym(), n)
	}
	s := rep.Summary
	verdict := u.green("equivalent")
	if !rep.OK {
		verdict = u.amber("needs review")
	}
	fmt.Fprintf(&b, "\n  %s  %d converted, %d need a human, %d resource%s\n", verdict, s[convDone], s[convTodo], s["resources"], cvPlural(s["resources"]))
	next := "setura gateway run --config <snapshot> (after kubectl apply --dry-run=server -f " + orDot(out) + ")"
	switch {
	case s[convTodo] > 0 && out != "":
		next = "resolve the TODO(setura) comments (grep -rn 'TODO(setura)' " + out + "), then setura migrate check --routes " + out
	case s[convTodo] > 0:
		next = "resolve the TODO(setura) comments, then run again with --out DIR"
	case rep.Check != nil && !rep.Check.OK:
		next = "review the differences above, then run again"
	case out == "":
		next = "run again with --out DIR to write one file per resource"
	default:
		next = "kubectl apply --dry-run=server -f " + out + ", then setura migrate check --routes " + out
	}
	fmt.Fprintf(&b, "  %s %s\n\n", u.gray("Next:"), next)
	return b.String()
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}

func cvPlural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
