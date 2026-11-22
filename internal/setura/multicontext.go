package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// multiCommands are the commands that can fan out over several kube contexts.
var multiCommands = map[string]bool{"check": true, "snapshot": true, "gate": true, "lint": true}

// splitContexts splits a comma separated --context value into unique names.
func splitContexts(v string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, userError("--context contains an empty context name")
		}
		if !seen[p] {
			seen[p] = true
			names = append(names, p)
		}
	}
	return names, nil
}

// extractContextFlags removes --context and --all-contexts from args wherever
// they appear (the subcommands have no flag of that name).
func extractContextFlags(args []string) (rest []string, ctx string, all bool, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--all-contexts" || a == "-all-contexts":
			all = true
		case a == "--context" || a == "-context":
			if i+1 >= len(args) {
				return nil, "", false, userError("--context needs a value")
			}
			ctx = args[i+1]
			i++
		case strings.HasPrefix(a, "--context="):
			ctx = strings.TrimPrefix(a, "--context=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, ctx, all, nil
}

// clusterFor returns the cluster for one context, reusing an injected fake's
// Exec so tests never reach kubectl.
func clusterFor(injected *Cluster, ctx string) *Cluster {
	if injected != nil {
		c := *injected
		c.Context = ctx
		return &c
	}
	return NewCluster(ctx)
}

// listContexts asks kubectl for every configured context name.
func listContexts(injected *Cluster) ([]string, error) {
	c := clusterFor(injected, "")
	out, errs, code, err := c.Exec(append(c.cmd(), "config", "get-contexts", "-o", "name"))
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := strings.TrimSpace(errs)
		if msg == "" {
			msg = "kubectl config get-contexts failed"
		}
		return nil, &kubectlError{msg}
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	if len(names) == 0 {
		return nil, userError("--all-contexts found no kube contexts")
	}
	return names, nil
}

// multiContext resolves --context/--all-contexts for cmd. When several
// contexts are selected it runs the command once per context and returns
// done=true with the merged exit code. Otherwise it leaves a single context in
// *ctx and the remaining args in *rest.
func multiContext(injected *Cluster, cmd string, rest *[]string, ctx *string, all bool, stdout, stderr io.Writer, tty bool) (done bool, code int, err error) {
	if !multiCommands[cmd] {
		if all || strings.Contains(*ctx, ",") {
			fmt.Fprintf(stderr, "setura: multiple contexts are supported only for check, snapshot, gate and lint\n")
			return true, 2, usageError{"contexts"}
		}
		return false, 0, nil
	}
	r, local, localAll, err := extractContextFlags(*rest)
	if err != nil {
		return true, 2, err
	}
	*rest = r
	if local != "" {
		*ctx = local
	}
	all = all || localAll
	var names []string
	switch {
	case all && *ctx != "":
		return true, 2, userError("--all-contexts and --context cannot be combined")
	case all:
		if names, err = listContexts(injected); err != nil {
			return true, 2, err
		}
	case *ctx != "":
		if names, err = splitContexts(*ctx); err != nil {
			return true, 2, err
		}
	}
	if len(names) <= 1 {
		if len(names) == 1 {
			*ctx = names[0]
		}
		return false, 0, nil
	}
	code, err = runMulti(injected, names, cmd, *rest, stdout, stderr, tty)
	return true, code, err
}

// stripFormat removes --format and returns its value ("" when absent).
func stripFormat(args []string) (rest []string, format string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "--format" || a == "-format") && i+1 < len(args):
			format = args[i+1]
			i++
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-format="):
			format = strings.TrimPrefix(a, "-format=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, format
}

func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == "--"+n || a == "-"+n || strings.HasPrefix(a, "--"+n+"=") || strings.HasPrefix(a, "-"+n+"=") {
				return true
			}
		}
	}
	return false
}

// ctxResult is the outcome of one per-context run.
type ctxResult struct {
	context string
	code    int
	data    any
	err     string
}

func runMulti(injected *Cluster, names []string, cmd string, rest []string, stdout, stderr io.Writer, tty bool) (int, error) {
	rest, format := stripFormat(rest)
	unsupported := map[string][]string{
		"check": {"junit", "sarif"},
		"lint":  {"snapshot", "write-baseline"},
	}
	for _, f := range unsupported[cmd] {
		if hasFlag(rest, f) {
			fmt.Fprintf(stderr, "setura %s: --%s is not supported with multiple contexts\n", cmd, f)
			return 2, usageError{"flag"}
		}
	}
	mode, err := multiMode(cmd, format, tty)
	if err != nil {
		return 2, err
	}
	sub := append([]string{cmd}, rest...)
	if cmd != "snapshot" {
		sub = append(sub, "--format", "json")
	}
	var tmp string
	if cmd == "check" {
		if tmp, err = os.MkdirTemp("", "setura-multi-"); err != nil {
			return 0, err
		}
		defer os.RemoveAll(tmp)
	}
	results := make([]ctxResult, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		args := sub
		if cmd == "check" {
			args = substituteCheckFile(sub, name, filepath.Join(tmp, fmt.Sprintf("%d.json", i)))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ob, eb bytes.Buffer
			code := runWith(clusterFor(injected, name), args, &ob, &eb)
			res := ctxResult{context: name, code: code}
			var v any
			switch {
			case code == 2:
				res.err = strings.TrimPrefix(strings.TrimSpace(eb.String()), "setura: ")
				if res.err == "" {
					res.err = "failed with exit code 2"
				}
			case json.Unmarshal(ob.Bytes(), &v) != nil:
				res.err = "produced no JSON output"
				res.code = 2
			default:
				res.data = v
			}
			results[i] = res
		}()
	}
	wg.Wait()
	exit := 0
	for _, r := range results {
		exit = max(exit, r.code)
		if r.err != "" {
			fmt.Fprintf(stderr, "setura: context %s: %s\n", r.context, firstLine(r.err))
		}
	}
	if mode == "json" {
		return exit, writeJSON(stdout, mergeResults(cmd, results))
	}
	fmt.Fprint(stdout, renderMulti(cmd, results))
	return exit, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func multiMode(cmd, format string, tty bool) (string, error) {
	if cmd == "snapshot" {
		return "json", nil
	}
	if cmd == "lint" {
		switch format {
		case "", "text":
			return "text", nil
		case "json":
			return "json", nil
		}
		return "", userError("with multiple contexts, setura lint --format must be text or json")
	}
	switch format {
	case "", "auto":
		if tty {
			return "text", nil
		}
		return "json", nil
	case "pretty":
		return "text", nil
	case "json":
		return "json", nil
	}
	return "", userErrorf("with multiple contexts, setura %s --format must be auto, pretty or json", cmd)
}

// substituteCheckFile writes a copy of the check file with {context} replaced
// and returns args pointing at it. On any problem the args are returned as is
// so the sub-run reports the underlying error itself.
func substituteCheckFile(args []string, ctx, dst string) []string {
	idx := -1
	for i := 1; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			idx = i
			break
		}
	}
	if idx < 0 {
		return args
	}
	raw, err := os.ReadFile(args[idx])
	if err != nil {
		return args
	}
	q, _ := json.Marshal(ctx)
	body := strings.ReplaceAll(string(raw), "{context}", string(q[1:len(q)-1]))
	if os.WriteFile(dst, []byte(body), 0o600) != nil {
		return args
	}
	out := append([]string(nil), args...)
	out[idx] = dst
	return out
}

func withContext(ctx string, v any) obj {
	o := obj{}
	if m := asMap(v); m != nil {
		for k, x := range m {
			o[k] = x
		}
	}
	o["context"] = ctx
	return o
}

func errEntry(r ctxResult) obj { return obj{"context": r.context, "ok": false, "error": r.err} }

// mergeResults builds the JSON document for a multi-context run.
func mergeResults(cmd string, results []ctxResult) any {
	switch cmd {
	case "check":
		rows := []any{}
		for _, r := range results {
			if r.err != "" {
				rows = append(rows, errEntry(r))
				continue
			}
			for _, row := range asList(r.data) {
				rows = append(rows, withContext(r.context, row))
			}
		}
		return rows
	case "snapshot":
		list := []any{}
		for _, r := range results {
			if r.err != "" {
				list = append(list, errEntry(r))
			} else {
				list = append(list, obj{"context": r.context, "snapshot": r.data})
			}
		}
		return obj{"contexts": list}
	case "lint":
		findings, list := []any{}, []any{}
		ok, errs, warns := true, 0, 0
		for _, r := range results {
			if r.err != "" {
				ok = false
				list = append(list, errEntry(r))
				continue
			}
			m := asMap(r.data)
			e, _ := num(m["errors"])
			w, _ := num(m["warnings"])
			errs, warns = errs+int(e), warns+int(w)
			ok = ok && m["ok"] == true
			for _, f := range asList(m["findings"]) {
				findings = append(findings, withContext(r.context, f))
			}
			list = append(list, obj{"context": r.context, "ok": m["ok"] == true, "errors": int(e), "warnings": int(w)})
		}
		return obj{"ok": ok, "errors": errs, "warnings": warns, "findings": findings, "contexts": list}
	}
	// gate
	list, ok := []any{}, true
	for _, r := range results {
		if r.err != "" {
			ok = false
			list = append(list, errEntry(r))
			continue
		}
		ok = ok && asMap(r.data)["ok"] == true
		list = append(list, withContext(r.context, r.data))
	}
	return obj{"ok": ok, "contexts": list}
}

// renderMulti prints the human-readable merged view with a context column.
func renderMulti(cmd string, results []ctxResult) string {
	var b strings.Builder
	w := len("CONTEXT")
	for _, r := range results {
		w = max(w, len([]rune(r.context)))
	}
	line := func(ctx string, cols ...string) {
		fmt.Fprintf(&b, "%s  %s\n", pad(ctx, w), strings.TrimRight(strings.Join(cols, "  "), " "))
	}
	switch cmd {
	case "check":
		line("CONTEXT", pad("RESULT", 6), pad("TIME", 9), "URL")
		for _, r := range results {
			if r.err != "" {
				line(r.context, pad("error", 6), pad("-", 9), firstLine(r.err))
				continue
			}
			for _, row := range asList(r.data) {
				m := asMap(row)
				res := "pass"
				detail := asStr(m["url"])
				if m["ok"] != true {
					res = "fail"
					if f := failedStep(m); f != "" {
						detail += "  " + f
					}
				}
				ms, _ := num(m["elapsed_ms"])
				line(r.context, pad(res, 6), pad(fmtMS(ms), 9), detail)
			}
		}
	case "lint":
		for _, r := range results {
			if r.err != "" {
				line(r.context, "error", firstLine(r.err))
				continue
			}
			m := asMap(r.data)
			for _, f := range asList(m["findings"]) {
				fm := asMap(f)
				line(r.context, pad(asStr(fm["id"]), 7), pad(asStr(fm["severity"]), 7), asStr(fm["resource"])+": "+asStr(fm["message"]))
			}
			e, _ := num(m["errors"])
			wn, _ := num(m["warnings"])
			line(r.context, fmt.Sprintf("%d error(s), %d warning(s)", int(e), int(wn)))
		}
	default: // gate
		line("CONTEXT", "RESULT")
		for _, r := range results {
			switch {
			case r.err != "":
				line(r.context, "error  "+firstLine(r.err))
			case asMap(r.data)["ok"] == true:
				line(r.context, "pass")
			default:
				line(r.context, "fail")
			}
		}
	}
	return b.String()
}

// failedStep describes the first failed stage of a decoded check row.
func failedStep(row obj) string {
	steps := asMap(row["steps"])
	for _, name := range stages {
		if s := asMap(steps[name]); s != nil && s["state"] == "failed" {
			d := name
			if r := s["reason"]; r != nil {
				d += ": " + fmt.Sprint(r)
			}
			return d
		}
	}
	return ""
}
