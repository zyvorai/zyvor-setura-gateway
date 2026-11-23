package contract

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DiffSchema identifies the diff report format.
const DiffSchema = "setura.contract-diff/v1"

// Finding kinds.
const (
	KindShadow = "shadow" // observed, not documented
	KindZombie = "zombie" // documented, never observed in the window
	KindDrift  = "drift"  // documented endpoint behaving differently
	KindAuth   = "auth"   // served without an auth filter
)

var kindOrder = []string{KindShadow, KindZombie, KindDrift, KindAuth}

// Finding is one difference between the document and the observed traffic.
type Finding struct {
	Kind   string   `json:"kind"`
	Sub    string   `json:"sub,omitempty"` // drift: status, method, content-type; auth: siblings, spec
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Count  int64    `json:"requests,omitempty"`
	Detail string   `json:"detail"`
	Items  []string `json:"items,omitempty"`
	Routes []string `json:"routes,omitempty"`
}

// Window is the observation period the zombie verdict rests on.
type Window struct {
	First    time.Time `json:"first_seen"`
	Last     time.Time `json:"last_seen"`
	Requests int64     `json:"requests"`
}

// Report is the result of Diff.
type Report struct {
	Schema     string         `json:"schema"`
	Spec       string         `json:"spec"`
	Learned    string         `json:"learned"`
	Window     Window         `json:"window"`
	Documented int            `json:"documented_operations"`
	Observed   int            `json:"observed_endpoints"`
	Matched    int            `json:"matched_endpoints"`
	Counts     map[string]int `json:"counts"`
	Findings   []Finding      `json:"findings"`
	Notes      []string       `json:"notes,omitempty"`
	FailOn     []string       `json:"fail_on,omitempty"`
	Failed     bool           `json:"failed"`
}

// DiffOptions tune Diff.
type DiffOptions struct {
	MinRequests  int64           // ignore observed endpoints with fewer requests
	IgnoreStatus map[string]bool // status codes never reported as drift (404, 502 ...)
}

func routesOf(e *Endpoint) []string {
	var r []string
	for k := range e.Routes {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func plural(n int64, one string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// Diff compares a document with observed traffic.
func Diff(spec *Spec, doc *Doc, o DiffOptions) *Report {
	r := &Report{Schema: DiffSchema, Spec: spec.Source, Learned: doc.Source, Documented: len(spec.Ops), Counts: map[string]int{},
		Window: Window{First: doc.First, Last: doc.Last, Requests: doc.Requests}}
	seen := map[string]bool{}
	var eps []*Endpoint
	for _, e := range doc.Endpoints {
		if e.Count >= o.MinRequests {
			eps = append(eps, e)
		}
	}
	r.Observed = len(eps)
	add := func(f Finding) { r.Findings = append(r.Findings, f) }
	matchedOps := map[*Operation]*Endpoint{}
	for _, e := range eps {
		op, known, allow := spec.Lookup(e.Method, e.Path, false)
		if op == nil {
			// a learned {id} may stand for a literal the spec documents
			if lo, _, _ := spec.Lookup(e.Method, e.Path, true); lo != nil {
				seen[lo.Key()] = true
			}
		}
		switch {
		case op == nil && known:
			add(Finding{Kind: KindDrift, Sub: "method", Method: e.Method, Path: e.Path, Count: e.Count, Routes: routesOf(e),
				Detail: fmt.Sprintf("%s is not documented on this path (documented: %s)", e.Method, strings.Join(allow, ", ")), Items: []string{e.Method}})
			continue
		case op == nil:
			add(Finding{Kind: KindShadow, Method: e.Method, Path: e.Path, Count: e.Count, Routes: routesOf(e),
				Detail: fmt.Sprintf("served %s, not in the document", plural(e.Count, "request"))})
			continue
		}
		r.Matched++
		seen[op.Key()] = true
		matchedOps[op] = e
		driftOf(&r.Findings, op, e, o)
	}
	for _, op := range spec.Ops {
		if !seen[op.Key()] {
			d := "documented, no matching request in the window"
			if op.Deprecated {
				d = "deprecated and no longer called in the window; candidate for removal"
			}
			add(Finding{Kind: KindZombie, Method: op.Method, Path: op.Path, Detail: d})
		}
	}
	authGaps(&r.Findings, spec, eps)
	if !doc.First.IsZero() && !doc.Last.IsZero() {
		if w := doc.Last.Sub(doc.First); w < 24*time.Hour {
			r.Notes = append(r.Notes, fmt.Sprintf("The observation window is only %s; zombie results need days or weeks of traffic to be meaningful.", w.Round(time.Second)))
		}
	}
	if doc.DroppedRequests > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%s hit endpoints beyond the learner's cap and were not recorded; shadow results may be incomplete.", plural(doc.DroppedRequests, "request")))
	}
	rank := map[string]int{}
	for i, k := range kindOrder {
		rank[k] = i
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		switch {
		case rank[a.Kind] != rank[b.Kind]:
			return rank[a.Kind] < rank[b.Kind]
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.Method != b.Method:
			return a.Method < b.Method
		}
		return a.Sub < b.Sub
	})
	for _, f := range r.Findings {
		r.Counts[f.Kind]++
	}
	return r
}

func driftOf(out *[]Finding, op *Operation, e *Endpoint, o DiffOptions) {
	var bad []string
	var n int64
	for _, code := range sortedKeys(e.Status) {
		if _, ok := op.StatusDocumented(code); !ok && !o.IgnoreStatus[code] && code != otherKey {
			bad = append(bad, fmt.Sprintf("%s (%s)", code, plural(e.Status[code], "request")))
			n += e.Status[code]
		}
	}
	if len(bad) > 0 {
		*out = append(*out, Finding{Kind: KindDrift, Sub: "status", Method: e.Method, Path: e.Path, Count: n, Routes: routesOf(e),
			Detail: "status codes not documented: " + strings.Join(bad, ", "), Items: bad})
	}
	var docTypes []string
	for _, t := range op.Responses {
		docTypes = append(docTypes, t...)
	}
	var badT []string
	if len(docTypes) > 0 {
		for _, t := range sortedKeys(e.ResponseTypes) {
			if t != otherKey && !TypeAllowed(docTypes, t) {
				badT = append(badT, "response "+t)
			}
		}
	}
	switch {
	case op.HasBody && len(op.RequestTypes) > 0:
		for _, t := range sortedKeys(e.RequestTypes) {
			if t != otherKey && !TypeAllowed(op.RequestTypes, t) {
				badT = append(badT, "request "+t)
			}
		}
	case !op.HasBody && (e.Method == "POST" || e.Method == "PUT" || e.Method == "PATCH"):
		for _, t := range sortedKeys(e.RequestTypes) {
			badT = append(badT, "request "+t+" (no requestBody documented)")
		}
	}
	if len(badT) > 0 {
		*out = append(*out, Finding{Kind: KindDrift, Sub: "content-type", Method: e.Method, Path: e.Path, Count: e.Count, Routes: routesOf(e),
			Detail: "content types not documented: " + strings.Join(badT, ", "), Items: badT})
	}
}

func firstSegment(p string) string {
	s := SplitPath(p)
	if len(s) == 0 || s[0] == VarSegment {
		return ""
	}
	return s[0]
}

// authGaps reports endpoints with no auth filter on the rule that served them
// while a sibling (same route, or same first path segment) has one, and
// documented-secured operations served without one.
func authGaps(out *[]Finding, spec *Spec, eps []*Endpoint) {
	byRoute := map[string][]*Endpoint{}
	bySeg := map[string][]*Endpoint{}
	for _, e := range eps {
		if e.Auth.Protected == 0 {
			continue
		}
		for r := range e.Routes {
			byRoute[r] = append(byRoute[r], e)
		}
		if s := firstSegment(e.Path); s != "" {
			bySeg[s] = append(bySeg[s], e)
		}
	}
	for _, e := range eps {
		if e.Auth.Protected > 0 || e.Auth.Open == 0 || e.Method == "OPTIONS" || e.Method == "HEAD" {
			continue
		}
		sib := map[string]bool{}
		for r := range e.Routes {
			for _, s := range byRoute[r] {
				sib[s.Key()] = true
			}
		}
		for _, s := range bySeg[firstSegment(e.Path)] {
			sib[s.Key()] = true
		}
		if len(sib) > 0 {
			keys := sortedKeys(sib)
			shown := keys
			if len(shown) > 3 {
				shown = shown[:3]
			}
			d := fmt.Sprintf("no auth filter on the serving rule; %s with one: %s", plural(int64(len(keys)), "sibling endpoint"), strings.Join(shown, ", "))
			if len(keys) > 3 {
				d += fmt.Sprintf(" and %d more", len(keys)-3)
			}
			*out = append(*out, Finding{Kind: KindAuth, Sub: "siblings", Method: e.Method, Path: e.Path, Count: e.Auth.Open, Routes: routesOf(e), Detail: d, Items: keys})
			continue
		}
		if op, _, _ := spec.Lookup(e.Method, e.Path, false); op != nil && op.Secured {
			*out = append(*out, Finding{Kind: KindAuth, Sub: "spec", Method: e.Method, Path: e.Path, Count: e.Auth.Open, Routes: routesOf(e),
				Detail: "the document requires security but no auth filter ran at the gateway (the backend may enforce it)"})
		}
	}
}

// ParseFailOn validates a --fail-on list: shadow, zombie, drift, auth or any.
func ParseFailOn(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "":
		case KindShadow, KindZombie, KindDrift, KindAuth:
			out = append(out, p)
		case "any":
			out = append(out, kindOrder...)
		default:
			return nil, fmt.Errorf("--fail-on must be shadow, zombie, drift, auth or any, got %q", p)
		}
	}
	return out, nil
}

// ApplyFailOn marks the report failed when a listed kind has findings.
func (r *Report) ApplyFailOn(kinds []string) {
	r.FailOn = kinds
	for _, k := range kinds {
		if r.Counts[k] > 0 {
			r.Failed = true
		}
	}
}

var kindTitle = map[string]string{
	KindShadow: "Shadow APIs: served but not documented",
	KindZombie: "Zombie APIs: documented but never seen",
	KindDrift:  "Drift: documented endpoints behaving differently",
	KindAuth:   "Auth gaps: served without an auth filter",
}

// KindTitle is the heading of a finding kind.
func KindTitle(k string) string { return kindTitle[k] }

func mdEsc(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "`", "'").Replace(s)
}

// Markdown renders the report for a pull request comment.
func (r *Report) Markdown() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("## API contract check\n\n")
	status := "No differences found."
	if n := len(r.Findings); n > 0 {
		status = fmt.Sprintf("%s found.", plural(int64(n), "difference"))
	}
	p("%s The document describes %d operations; the gateway served %d endpoints (%s", status, r.Documented, r.Observed, plural(r.Window.Requests, "request"))
	if !r.Window.First.IsZero() {
		p(", %s to %s", r.Window.First.UTC().Format("2006-01-02"), r.Window.Last.UTC().Format("2006-01-02"))
	}
	p(").\n\n")
	if len(r.Findings) > 0 {
		p("| Kind | Count |\n| --- | ---: |\n")
		for _, k := range kindOrder {
			if r.Counts[k] > 0 {
				p("| %s | %d |\n", mdEsc(strings.SplitN(kindTitle[k], ":", 2)[0]), r.Counts[k])
			}
		}
		p("\n")
	}
	for _, k := range kindOrder {
		if r.Counts[k] == 0 {
			continue
		}
		p("### %s\n\n| Endpoint | Detail |\n| --- | --- |\n", kindTitle[k])
		for _, f := range r.Findings {
			if f.Kind == k {
				p("| `%s %s` | %s |\n", f.Method, mdEsc(f.Path), mdEsc(f.Detail))
			}
		}
		p("\n")
	}
	for _, n := range r.Notes {
		p("> %s\n", n)
	}
	if len(r.Notes) > 0 {
		p("\n")
	}
	p("<sub>Path templates are inferred from traffic and request or response bodies are never compared. See docs/contract.md.</sub>\n")
	return b.String()
}

// FmtInt renders n with a thousands separator for human output.
func FmtInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
