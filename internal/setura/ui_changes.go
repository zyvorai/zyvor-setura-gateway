package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Everything in this file is read-only: it reads the live configuration and
// the backups in .setura-history/ and answers questions about them. Applying
// or rolling back stays a terminal action ("setura gateway rollback").

// uiChange is one plain-language entry of a configuration diff.
type uiChange struct {
	Kind  string   `json:"kind"`  // added, removed, changed
	Group string   `json:"group"` // route, gateway, backend, other
	Name  string   `json:"name"`
	Title string   `json:"title"`
	Lines []string `json:"lines,omitempty"`
}

// ruleDesc is the part of a rule the diff talks about.
type ruleDesc struct {
	key     string // the rule's matches, in words
	order   []string
	share   map[string]float64
	filters []string
	raw     any
}

func resourceParts(key string) (kind, name string) {
	head, rest, _ := strings.Cut(key, "/")
	kind = head
	if i := strings.IndexByte(head, '.'); i >= 0 {
		kind = head[:i]
	}
	return kind, rest
}

func kindWord(kind string) (word, group string) {
	switch kind {
	case "httproutes":
		return "Route", "route"
	case "grpcroutes":
		return "gRPC route", "route"
	case "tlsroutes":
		return "TLS route", "route"
	case "tcproutes":
		return "TCP route", "route"
	case "udproutes":
		return "UDP route", "route"
	case "gateways":
		return "Gateway", "gateway"
	case "backend":
		return "Backend", "backend"
	}
	return strings.Title(kind), "other" //nolint:staticcheck // ASCII kind names
}

func hostsOf(spec obj) []string {
	var out []string
	for _, h := range asList(spec["hostnames"]) {
		out = append(out, asStr(h))
	}
	return out
}

func shareText(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%d%%", int(v))
	}
	return fmt.Sprintf("%.1f%%", v)
}

func rulesOf(spec obj) []ruleDesc {
	var out []ruleDesc
	for _, r := range asList(spec["rules"]) {
		rm := asMap(r)
		d := ruleDesc{share: map[string]float64{}, raw: r}
		var ms []string
		for _, m := range asList(rm["matches"]) {
			ms = append(ms, matchText(asMap(m)))
		}
		d.key = strings.Join(ms, " or ")
		if d.key == "" {
			d.key = "every request"
		}
		total := 0.0
		ws := map[string]float64{}
		for _, b := range asList(rm["backendRefs"]) {
			bm := asMap(b)
			w := 1.0
			if v, ok := num(bm["weight"]); ok {
				w = v
			}
			n := asStr(bm["name"])
			ws[n] += w
			total += w
			d.order = append(d.order, n)
		}
		for n, w := range ws {
			if total > 0 {
				d.share[n] = math.Round(w/total*1000) / 10
			}
		}
		for _, f := range asList(rm["filters"]) {
			d.filters = append(d.filters, asStr(asMap(f)["type"]))
		}
		out = append(out, d)
	}
	return out
}

func describeBackends(d ruleDesc) string {
	seen := map[string]bool{}
	var parts []string
	for _, n := range d.order {
		if seen[n] {
			continue
		}
		seen[n] = true
		if len(d.share) > 1 {
			parts = append(parts, n+" ("+shareText(d.share[n])+")")
		} else {
			parts = append(parts, n)
		}
	}
	return strings.Join(parts, ", ")
}

func setDiff(a, b []string) (added, removed []string) {
	in := func(l []string, v string) bool {
		for _, x := range l {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, v := range b {
		if !in(a, v) {
			added = append(added, v)
		}
	}
	for _, v := range a {
		if !in(b, v) {
			removed = append(removed, v)
		}
	}
	return
}

func changedRouteLines(a, b obj) []string {
	var lines []string
	if add, rem := setDiff(hostsOf(a), hostsOf(b)); len(add)+len(rem) > 0 {
		var bits []string
		if len(add) > 0 {
			bits = append(bits, "now serves "+strings.Join(add, ", "))
		}
		if len(rem) > 0 {
			bits = append(bits, "no longer serves "+strings.Join(rem, ", "))
		}
		lines = append(lines, "Hostnames: "+strings.Join(bits, "; "))
	}
	pa, pb := parentNames(a), parentNames(b)
	if add, rem := setDiff(pa, pb); len(add)+len(rem) > 0 {
		lines = append(lines, "Attached to: "+strings.Join(pb, ", ")+" (was "+strings.Join(pa, ", ")+")")
	}
	ra, rb := rulesOf(a), rulesOf(b)
	byKey := func(rs []ruleDesc) map[string]ruleDesc {
		m := map[string]ruleDesc{}
		for _, r := range rs {
			m[r.key] = r
		}
		return m
	}
	ma, mb := byKey(ra), byKey(rb)
	for _, r := range rb {
		old, ok := ma[r.key]
		if !ok {
			to := describeBackends(r)
			if to == "" {
				to = "no backend"
			}
			lines = append(lines, "New rule for "+r.key+" sends traffic to "+to)
			continue
		}
		if eq(old.raw, r.raw) {
			continue
		}
		var bits []string
		if !eq(old.share, r.share) || strings.Join(old.order, ",") != strings.Join(r.order, ",") {
			names := map[string]bool{}
			var all []string
			for _, n := range append(append([]string{}, old.order...), r.order...) {
				if !names[n] {
					names[n] = true
					all = append(all, n)
				}
			}
			sort.Strings(all)
			for _, n := range all {
				ov, oOK := old.share[n]
				nv, nOK := r.share[n]
				switch {
				case oOK && nOK && ov != nv:
					bits = append(bits, n+" "+shareText(ov)+" → "+shareText(nv))
				case !oOK && nOK:
					bits = append(bits, n+" added at "+shareText(nv))
				case oOK && !nOK:
					bits = append(bits, n+" removed (was "+shareText(ov)+")")
				}
			}
			if len(bits) > 0 {
				lines = append(lines, r.key+": traffic "+strings.Join(bits, ", "))
				bits = nil
			}
		}
		if ad, rm := setDiff(old.filters, r.filters); len(ad)+len(rm) > 0 {
			for _, f := range ad {
				bits = append(bits, "adds "+f)
			}
			for _, f := range rm {
				bits = append(bits, "drops "+f)
			}
			lines = append(lines, r.key+": filters "+strings.Join(bits, ", "))
			bits = nil
		}
		if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], r.key+":") {
			lines = append(lines, r.key+": settings changed")
		}
	}
	for _, r := range ra {
		if _, ok := mb[r.key]; !ok {
			lines = append(lines, "Rule for "+r.key+" was removed")
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "Settings changed")
	}
	return lines
}

func parentNames(spec obj) []string {
	var out []string
	for _, p := range asList(spec["parentRefs"]) {
		m := asMap(p)
		n := asStr(m["name"])
		if s := asStr(m["sectionName"]); s != "" {
			n += "/" + s
		}
		out = append(out, n)
	}
	return out
}

func listenerWords(l obj) string {
	s := fmt.Sprintf("%s on port %v (%s)", asStr(l["name"]), l["port"], asStr(l["protocol"]))
	if h := asStr(l["hostname"]); h != "" {
		s += " for " + h
	}
	return s
}

func describeNew(group string, spec obj) []string {
	switch group {
	case "route":
		var lines []string
		if h := hostsOf(spec); len(h) > 0 {
			lines = append(lines, "Serves "+strings.Join(h, ", "))
		}
		for _, r := range rulesOf(spec) {
			to := describeBackends(r)
			if to == "" {
				to = "no backend"
			}
			lines = append(lines, r.key+" → "+to)
		}
		return lines
	case "gateway":
		var lines []string
		for _, l := range asList(spec["listeners"]) {
			lines = append(lines, "Listener "+listenerWords(asMap(l)))
		}
		return lines
	case "backend":
		var eps []string
		for _, e := range asList(spec["endpoints"]) {
			eps = append(eps, asStr(e))
		}
		if len(eps) > 0 {
			return []string{"Endpoints " + strings.Join(eps, ", ")}
		}
	}
	return nil
}

func changedOtherLines(group string, a, b obj) []string {
	switch group {
	case "route":
		return changedRouteLines(a, b)
	case "gateway":
		var lines []string
		la, lb := map[string]obj{}, map[string]obj{}
		for _, l := range asList(a["listeners"]) {
			la[asStr(asMap(l)["name"])] = asMap(l)
		}
		for _, l := range asList(b["listeners"]) {
			lb[asStr(asMap(l)["name"])] = asMap(l)
		}
		for _, n := range sortedKeys(lb) {
			if old, ok := la[n]; !ok {
				lines = append(lines, "Listener "+listenerWords(lb[n])+" was added")
			} else if !eq(old, lb[n]) {
				lines = append(lines, "Listener "+n+" changed: now "+listenerWords(lb[n]))
			}
		}
		for _, n := range sortedKeys(la) {
			if _, ok := lb[n]; !ok {
				lines = append(lines, "Listener "+n+" was removed")
			}
		}
		if len(lines) == 0 {
			lines = append(lines, "Settings changed")
		}
		return lines
	case "backend":
		var ea, eb []string
		for _, e := range asList(a["endpoints"]) {
			ea = append(ea, asStr(e))
		}
		for _, e := range asList(b["endpoints"]) {
			eb = append(eb, asStr(e))
		}
		var lines []string
		if add, rem := setDiff(ea, eb); len(add)+len(rem) > 0 {
			if len(add) > 0 {
				lines = append(lines, "Added endpoints "+strings.Join(add, ", "))
			}
			if len(rem) > 0 {
				lines = append(lines, "Removed endpoints "+strings.Join(rem, ", "))
			}
		}
		if asStr(a["timeout"]) != asStr(b["timeout"]) {
			lines = append(lines, "Timeout "+orDash(asStr(a["timeout"]))+" → "+orDash(asStr(b["timeout"])))
		}
		if len(lines) == 0 {
			lines = append(lines, "Settings changed")
		}
		return lines
	}
	return []string{"Settings changed"}
}

// plainDiff explains in words what differs between two configurations.
func plainDiff(before, after []byte) ([]uiChange, error) {
	a, errA := snapshotKeys(before)
	if errA != nil {
		return nil, errA
	}
	b, errB := snapshotKeys(after)
	if errB != nil {
		return nil, errB
	}
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	order := make([]string, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	sort.Strings(order)
	out := []uiChange{}
	for _, k := range order {
		av, inA := a[k]
		bv, inB := b[k]
		kind, name := resourceParts(k)
		if strings.HasPrefix(k, "backend/") {
			kind, name = "backend", strings.TrimPrefix(k, "backend/")
		}
		word, group := kindWord(kind)
		switch {
		case inA && inB && eq(av, bv):
			continue
		case !inA:
			out = append(out, uiChange{Kind: "added", Group: group, Name: name, Title: word + " " + name + " was added", Lines: describeNew(group, asMap(bv))})
		case !inB:
			out = append(out, uiChange{Kind: "removed", Group: group, Name: name, Title: word + " " + name + " was removed", Lines: describeNew(group, asMap(av))})
		default:
			out = append(out, uiChange{Kind: "changed", Group: group, Name: name, Title: word + " " + name + " changed", Lines: changedOtherLines(group, asMap(av), asMap(bv))})
		}
	}
	return out, nil
}

func changeCounts(cs []uiChange) obj {
	n := map[string]int{}
	for _, c := range cs {
		n[c.Kind]++
	}
	return obj{"added": n["added"], "removed": n["removed"], "changed": n["changed"]}
}

func changeHeadline(cs []uiChange) string {
	if len(cs) == 0 {
		return "no changes"
	}
	n := map[string]int{}
	for _, c := range cs {
		n[c.Kind]++
	}
	var bits []string
	for _, k := range []string{"changed", "added", "removed"} {
		if n[k] > 0 {
			bits = append(bits, fmt.Sprintf("%d %s", n[k], k))
		}
	}
	return strings.Join(bits, ", ")
}

// changesSource answers the dashboard's /api/changes questions from a live
// configuration file and its .setura-history directory.
type changesSource struct {
	config string
	hist   histStore
}

func newChangesSource(config string) *changesSource {
	return &changesSource{config: config, hist: newHistStore(config)}
}

func friendlyTime(iso string) string {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	return t.Local().Format("Jan 2, 15:04")
}

func entryNames(d diffSummary) string {
	var bits []string
	for _, n := range d.Names {
		if len(n) < 2 {
			continue
		}
		kind, name := resourceParts(n[1:])
		if strings.HasPrefix(n[1:], "backend/") {
			kind, name = "backend", strings.TrimPrefix(n[1:], "backend/")
		}
		word, _ := kindWord(kind)
		verb := map[byte]string{'+': "added", '~': "changed", '-': "removed"}[n[0]]
		bits = append(bits, strings.ToLower(word)+" "+name+" "+verb)
	}
	return strings.Join(bits, "; ")
}

// Doc is the /api/changes document.
func (c *changesSource) Doc() any {
	live, err := os.ReadFile(c.config)
	base := filepath.Base(c.config)
	if err != nil {
		return obj{"available": false, "config": base, "headline": "Cannot read the live configuration",
			"detail": err.Error(), "next": "setura lint --snapshot " + c.config}
	}
	metas, _ := c.hist.list()
	doc := obj{"available": true, "config": base, "hash": hashHex(live)[:8]}
	if g, ok := lintOneLine(live); ok {
		doc["lintOk"] = g
	}
	if len(metas) == 0 {
		doc["headline"] = "No rollouts recorded yet"
		doc["detail"] = "Every guarded rollout keeps a backup of the configuration it replaced, and each one shows up here with what it changed."
		doc["next"] = "setura gateway rollout --config " + base + " --new candidate.json --checks checks.json"
		doc["timeline"] = []any{}
		return doc
	}
	newest := metas[0]
	prevRaw, _, _ := c.hist.get(newest.ID)
	changes, _ := plainDiff(prevRaw, live)
	doc["diff"] = obj{"from": obj{"id": newest.ID, "time": newest.Time, "when": friendlyTime(newest.Time), "reason": newest.Reason},
		"changes": changes, "counts": changeCounts(changes), "summary": changeHeadline(changes)}
	if len(changes) == 0 {
		doc["headline"] = "Nothing has changed since the last rollout"
		doc["detail"] = "The live configuration matches the backup taken on " + friendlyTime(newest.Time) + "."
	} else {
		doc["headline"] = fmt.Sprintf("%d %s since the last rollout", len(changes), pluralWord(len(changes), "change", "changes"))
		doc["detail"] = "Compared with the backup taken on " + friendlyTime(newest.Time) + "."
	}
	tl := []any{}
	for i, m := range metas {
		if i >= 30 {
			break
		}
		e := obj{"id": m.ID, "time": m.Time, "when": friendlyTime(m.Time), "reason": m.Reason, "generation": m.Generation,
			"lintOk": m.LintOK, "summary": m.Diff.String()}
		if s := entryNames(m.Diff); s != "" {
			e["sentence"] = s
		}
		// What this rollout changed: the backup (the config it replaced) against
		// the configuration that took its place.
		var repl []byte
		if i == 0 {
			repl = live
		} else {
			repl, _, _ = c.hist.get(metas[i-1].ID)
		}
		if raw, _, err := c.hist.get(m.ID); err == nil && repl != nil {
			if ch, err := plainDiff(raw, repl); err == nil {
				e["changes"] = ch
			}
		}
		tl = append(tl, e)
	}
	doc["timeline"] = tl
	doc["next"] = "setura gateway history --config " + base
	return doc
}

func lintOneLine(raw []byte) (ok, known bool) {
	var snap obj
	if json.Unmarshal(raw, &snap) != nil {
		return false, false
	}
	rep, err := Lint(snap)
	if err != nil {
		return false, false
	}
	return rep["ok"] == true, true
}

// probeLines builds a synthetic access log: one GET per declared match of
// every route in either configuration, so replay can show what a swap does
// even when no real traffic log is at hand.
func probeLines(docs ...[]byte) ([]byte, int) {
	seen := map[string]bool{}
	var buf bytes.Buffer
	n := 0
	for _, raw := range docs {
		res, err := snapshotKeys(raw)
		if err != nil {
			continue
		}
		for _, k := range sortedKeys(res) {
			if strings.HasPrefix(k, "backend/") {
				continue
			}
			kind, _ := resourceParts(k)
			if kind != "httproutes" {
				continue
			}
			spec := asMap(res[k])
			hosts := hostsOf(spec)
			if len(hosts) == 0 {
				hosts = []string{"example.test"}
			}
			for _, r := range asList(spec["rules"]) {
				for _, m := range asList(asMap(r)["matches"]) {
					p := asMap(asMap(m)["path"])
					v := str(p, "value", "/")
					switch str(p, "type", "PathPrefix") {
					case "RegularExpression":
						continue
					case "Exact":
					default:
						if n < 400 {
							for _, h := range hosts {
								addProbe(&buf, seen, &n, h, strings.TrimRight(v, "/")+"/x")
							}
						}
					}
					for _, h := range hosts {
						if n < 400 {
							addProbe(&buf, seen, &n, h, v)
						}
					}
				}
			}
		}
	}
	return buf.Bytes(), n
}

func addProbe(buf *bytes.Buffer, seen map[string]bool, n *int, host, path string) {
	host = strings.TrimPrefix(host, "*.")
	if host == "" {
		return
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	k := host + " " + path
	if seen[k] {
		return
	}
	seen[k] = true
	b, _ := json.Marshal(obj{"host": host, "method": "GET", "path": path})
	buf.Write(b)
	buf.WriteByte('\n')
	*n++
}

// Detail is the read-only "what would this do" view of one timeline entry:
// the configuration it holds against the live one.
func (c *changesSource) Detail(id string) (any, bool) {
	backup, meta, err := c.hist.get(id)
	if err != nil {
		return nil, false
	}
	live, err := os.ReadFile(c.config)
	if err != nil {
		return nil, false
	}
	doc := obj{"id": meta.ID, "time": meta.Time, "when": friendlyTime(meta.Time), "reason": meta.Reason, "generation": meta.Generation,
		"title":   "Going back to the configuration of " + friendlyTime(meta.Time),
		"command": "setura gateway rollback --config " + filepath.Base(c.config) + " --to " + meta.ID,
		"note":    "This page only shows what would happen. Rolling back is done from the terminal."}
	changes, _ := plainDiff(live, backup)
	doc["changes"] = changes
	doc["counts"] = changeCounts(changes)
	if g, ok := lintOneLine(backup); ok {
		doc["lintOk"] = g
	}
	if len(changes) == 0 {
		doc["summary"] = "Nothing would change: the live configuration already matches this version."
		return doc, true
	}
	doc["summary"] = "Rolling back would make 1 change."
	if len(changes) > 1 {
		doc["summary"] = fmt.Sprintf("Rolling back would make %d changes: %s.", len(changes), changeHeadline(changes))
	}
	dir := filepath.Dir(c.config)
	before, err1 := builtin.ParseReplayConfig(live, dir)
	after, err2 := builtin.ParseReplayConfig(backup, dir)
	if err1 != nil || err2 != nil {
		doc["replayNote"] = "The routing preview is unavailable because one of the configurations could not be parsed offline."
		return doc, true
	}
	lines, probes := probeLines(live, backup)
	rep, err := replayStream(bytes.NewReader(lines), ReplayOptions{Log: "route probes", Before: "live", After: meta.ID}, before, after)
	if err != nil {
		doc["replayNote"] = err.Error()
		return doc, true
	}
	classes := []obj{}
	for _, cl := range rep.Classes {
		if cl.Requests == 0 {
			continue
		}
		e := obj{"class": cl.Class, "requests": cl.Requests}
		if cl.Example != nil {
			e["example"] = cl.Example
		}
		classes = append(classes, e)
	}
	doc["replay"] = obj{"probes": probes, "requests": rep.Input.Requests, "changed": rep.Changed, "unchanged": rep.Unchanged,
		"classes": classes, "shifts": rep.WeightShifts,
		"note": "Preview built from one request per declared route match, resolved offline against both configurations. It is not your real traffic."}
	if rep.Changed > 0 {
		doc["replay"].(obj)["headline"] = fmt.Sprintf("%d of %d probed requests would be routed differently", rep.Changed, rep.Input.Requests)
		if w := whyFirstChange(before, after, lines); w != "" {
			doc["why"] = w
		}
	} else {
		doc["replay"].(obj)["headline"] = "Every probed request would be routed the same way"
	}
	return doc, true
}

// whyFirstChange explains, with the same engine as "setura why", how the
// first probe whose routing differs would be handled after the swap.
func whyFirstChange(before, after *builtin.Table, lines []byte) string {
	port := 0
	for _, l := range after.Listeners {
		if l.Serving {
			port = l.L.Port
			break
		}
	}
	for _, ln := range bytes.Split(lines, []byte("\n")) {
		var p struct{ Host, Path string }
		if json.Unmarshal(ln, &p) != nil || p.Host == "" {
			continue
		}
		spec := builtin.ReqSpec{Host: p.Host, Method: "GET", Path: p.Path}
		if len(classifyReplay(before.Resolve(spec), after.Resolve(spec), false)) == 0 {
			continue
		}
		q, err := builtin.ParseExplainRequest("GET", fmt.Sprintf("http://%s:%d%s", p.Host, max(port, 80), p.Path), nil, "", "")
		if err != nil {
			return ""
		}
		q.Port = max(port, 80)
		u := &ui{ascii: true}
		txt := u.WhyPretty(builtin.Explain(after, q), false, 78)
		return strings.TrimSpace(txt)
	}
	return ""
}

// attach returns the handlers webui.Options takes.
func (c *changesSource) attach() (func() any, func(string) (any, bool)) {
	return c.Doc, c.Detail
}
