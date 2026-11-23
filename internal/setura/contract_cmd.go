package setura

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"

	"github.com/zyvorai/zyvor-setura-gateway/internal/contract"
)

// contractFlags are offered after "setura contract".
var contractFlags = []string{"learn", "show", "export", "diff", "--learned", "--admin", "--spec", "--log", "--out", "--format", "--fail-on",
	"--min-requests", "--ignore-status", "--limit", "--title", "--api-version", "--server", "--enable", "--disable"}

type contractArgs struct {
	learned, admin, spec, logPath, out, format, failOn string
	ignore, title, version, server                     string
	minReq                                             int
	limit                                              int
	enable, disable                                    bool
}

func addContractFlags(fs *flag.FlagSet, a *contractArgs) {
	fs.StringVar(&a.learned, "learned", "", "learned inventory file (written by the gateway's --learn or by contract learn)")
	fs.StringVar(&a.admin, "admin", "", "gateway admin address to read the inventory from (default 127.0.0.1:19000 when --learned is not given)")
	fs.StringVar(&a.spec, "spec", "", "OpenAPI 3.x document, JSON or simple YAML (diff)")
	fs.StringVar(&a.logPath, "log", "", "gateway access log to learn from: FILE, FILE.gz or - for stdin (learn)")
	fs.StringVar(&a.out, "out", "", "write the result to FILE (learn: the inventory, export: the OpenAPI document)")
	fs.StringVar(&a.format, "format", "table", "table, json or markdown (markdown: diff only, for pull request comments)")
	fs.StringVar(&a.failOn, "fail-on", "", "diff: exit 1 when findings of this kind exist: shadow, zombie, drift, auth or any (comma separated)")
	fs.IntVar(&a.minReq, "min-requests", 1, "ignore observed endpoints with fewer requests than this (diff, export)")
	fs.StringVar(&a.ignore, "ignore-status", "", "diff: status codes never reported as drift, for example 404,502,503,504")
	fs.IntVar(&a.limit, "limit", 0, "show at most this many rows per table (0 = all)")
	fs.StringVar(&a.title, "title", "", "export: info.title (default \"Observed API\")")
	fs.StringVar(&a.version, "api-version", "", "export: info.version (default 0.0.0-observed)")
	fs.StringVar(&a.server, "server", "", "export: servers[0].url")
	fs.BoolVar(&a.enable, "enable", false, "learn with --admin: turn the gateway's learner on")
	fs.BoolVar(&a.disable, "disable", false, "learn with --admin: turn the gateway's learner off")
}

func adminBase(admin string) string {
	if admin == "" {
		admin = builtin.DefaultAdmin
	}
	if !strings.Contains(admin, "://") {
		admin = "http://" + admin
	}
	return strings.TrimRight(admin, "/")
}

func adminCall(ctx context.Context, admin, method, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, adminBase(admin)+path, nil)
	if err != nil {
		return err
	}
	adminToken(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the gateway admin endpoint at %s: %w", adminBase(admin), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s%s answered %s (is this a setura gateway of this version?)", adminBase(admin), path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(v)
}

// loadInventory reads --learned FILE, else the gateway's /contract.
func loadInventory(a contractArgs) (*contract.Doc, error) {
	if a.learned != "" {
		d, err := contract.ReadDoc(a.learned)
		if err != nil {
			return nil, err
		}
		d.Source = a.learned
		return d, nil
	}
	var raw json.RawMessage
	if err := adminCall(context.Background(), a.admin, http.MethodGet, "/contract", &raw); err != nil {
		return nil, err
	}
	d, err := contract.ParseDoc(raw)
	if err != nil {
		return nil, err
	}
	d.Source = "gateway " + adminBase(a.admin)
	return d, nil
}

func runContract(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui) (int, error) {
	var a contractArgs
	addContractFlags(fs, &a)
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura contract: %s\n", msg)
		exampleHint(stderr, "contract")
		return 2, usageError{msg}
	}
	if len(pos) != 1 {
		return bad("give one of learn, show, export or diff")
	}
	switch a.format {
	case "table", "json":
	case "markdown":
		if pos[0] != "diff" {
			return bad("--format markdown is only for diff")
		}
	default:
		return bad(fmt.Sprintf("--format %q: want table, json or markdown", a.format))
	}
	if a.minReq < 0 || a.limit < 0 {
		return bad("--min-requests and --limit must not be negative")
	}
	if a.learned != "" && a.admin != "" {
		return bad("give --learned or --admin, not both")
	}
	switch pos[0] {
	case "learn":
		return contractLearn(a, stdout, stderr, u, bad)
	case "show":
		d, err := loadInventory(a)
		if err != nil {
			return 2, err
		}
		if a.format == "json" {
			return 0, writeJSON(stdout, d)
		}
		fmt.Fprint(stdout, u.inventoryTable(d, a))
		return 0, nil
	case "export":
		d, err := loadInventory(a)
		if err != nil {
			return 2, err
		}
		doc := contract.ExportOpenAPI(d, contract.ExportOptions{Title: a.title, Version: a.version, Server: a.server, MinRequests: int64(a.minReq)})
		if a.out != "" {
			f, err := os.OpenFile(a.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				return 2, err
			}
			defer f.Close()
			if err := writeJSON(f, doc); err != nil {
				return 2, err
			}
			fmt.Fprintf(stderr, "wrote %d paths to %s\n", len(contract.PathKeys(doc)), a.out)
			return 0, nil
		}
		return 0, writeJSON(stdout, doc)
	case "diff":
		return contractDiff(a, stdout, u, bad)
	}
	return bad(fmt.Sprintf("unknown subcommand %q: want learn, show, export or diff", pos[0]))
}

func contractLearn(a contractArgs, stdout, stderr io.Writer, u *ui, bad func(string) (int, error)) (int, error) {
	if a.logPath != "" && (a.enable || a.disable) {
		return bad("--enable and --disable talk to a gateway; they do not combine with --log")
	}
	if a.enable && a.disable {
		return bad("give --enable or --disable, not both")
	}
	if a.enable || a.disable {
		if a.learned != "" {
			return bad("--enable and --disable need --admin")
		}
		var st struct {
			Enabled   bool  `json:"enabled"`
			Endpoints int   `json:"endpoints"`
			Requests  int64 `json:"requests"`
		}
		q := url.Values{"enabled": {fmt.Sprint(a.enable)}}
		if err := adminCall(context.Background(), a.admin, http.MethodPost, "/contract/learn?"+q.Encode(), &st); err != nil {
			return 2, err
		}
		state := "off"
		if st.Enabled {
			state = "on"
		}
		fmt.Fprintf(stdout, "  %s Endpoint learning is %s (%d endpoints, %s requests so far)\n", u.okSym(), u.bold(state), st.Endpoints, contract.FmtInt(st.Requests))
		return 0, nil
	}
	if a.out == "" {
		return bad("learn needs --out FILE for the inventory")
	}
	if a.logPath != "" {
		l := contract.NewLearner(contract.DefaultMaxEndpoints * 4)
		l.Enable(true)
		if _, err := l.LoadFile(a.out); err != nil {
			return 2, err
		}
		l.SetSource("access log " + a.logPath)
		rd, closeFn, err := openReplayLog(a.logPath, os.Stdin)
		if err != nil {
			return 2, err
		}
		defer closeFn()
		lines, used := learnFromLog(l, rd)
		if err := l.SaveFile(a.out); err != nil {
			return 2, err
		}
		eps, _, dropped := l.Stats()
		fmt.Fprintf(stdout, "  %s Learned %d endpoints from %s of %s log lines, written to %s\n", u.okSym(), eps, contract.FmtInt(used), contract.FmtInt(lines), a.out)
		if dropped > 0 {
			fmt.Fprintf(stdout, "  %s %s requests did not fit the inventory cap and were not recorded\n", u.warnSym(), contract.FmtInt(dropped))
		}
		fmt.Fprintf(stdout, "  %s\n", u.gray("Access logs carry no content types, header names or query names; learn from the gateway (--learn) for those."))
		return 0, nil
	}
	d, err := loadInventory(a)
	if err != nil {
		return 2, err
	}
	if err := contract.WriteDoc(a.out, d); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "  %s Saved %d endpoints (%s requests) from %s to %s\n", u.okSym(), len(d.Endpoints), contract.FmtInt(d.Requests), d.Source, a.out)
	return 0, nil
}

// logLine is the part of an access-log line the learner reads.
type learnLogLine struct {
	Time          string  `json:"time"`
	Method        string  `json:"method"`
	Path          string  `json:"path"`
	Status        int     `json:"status"`
	Millis        float64 `json:"duration_ms"`
	Route         string  `json:"route"`
	Backend       string  `json:"backend"`
	RequestBytes  int64   `json:"request_bytes"`
	ResponseBytes int64   `json:"response_bytes"`
	Bytes         int64   `json:"bytes"`
	AuthProtected bool    `json:"auth_protected"`
	Contract      string  `json:"contract_mode"`
	Protocol      string  `json:"protocol"`
	Error         string  `json:"error"`
}

// learnFromLog feeds an access log to l. JSON lines carry sizes, latency,
// route and backend; text and Common Log Format lines carry method, path and
// status only. Requests the gateway rejected before routing (no route) and
// gRPC calls are skipped.
func learnFromLog(l *contract.Learner, r io.Reader) (lines, used int64) {
	var in interner
	var rec logRec
	replayLines(r, func(line []byte, tooLong bool) {
		if tooLong || len(line) == 0 {
			return
		}
		lines++
		o := contract.Obs{Latency: -1, ReqBytes: -1, RespBytes: -1}
		if line[0] == '{' {
			var j learnLogLine
			if json.Unmarshal(line, &j) != nil || j.Method == "" || j.Path == "" || j.Protocol == "grpc" {
				return
			}
			if j.Route == "" {
				return // no route matched: scanner noise, not an endpoint
			}
			o.Method, o.Status, o.Route, o.Backend, o.Protected = j.Method, j.Status, j.Route, j.Backend, j.AuthProtected
			o.Path, o.QueryNames = splitLogPath(j.Path)
			o.Latency = time.Duration(j.Millis * float64(time.Millisecond))
			if j.RequestBytes > 0 {
				o.ReqBytes = j.RequestBytes
			}
			o.RespBytes = j.ResponseBytes
			if o.RespBytes == 0 {
				o.RespBytes = j.Bytes
			}
			if t, err := time.Parse(time.RFC3339Nano, j.Time); err == nil {
				o.At = t
			}
			if strings.HasPrefix(j.Error, "contract:") {
				return // answered by contract enforcement, not served
			}
		} else {
			if !in.parseLogLine(line, &rec, "") || len(rec.path) == 0 || rec.method == "" {
				return
			}
			if rec.format == "text" && rec.route == "" {
				return
			}
			o.Method, o.Status, o.Route, o.Backend = rec.method, rec.status, rec.route, rec.backend
			o.Path, o.QueryNames = splitLogPath(string(rec.path))
		}
		used++
		l.Record(o)
	})
	return lines, used
}

func splitLogPath(p string) (string, []string) {
	path, q, _ := strings.Cut(p, "?")
	var names []string
	for q != "" {
		var kv string
		kv, q, _ = strings.Cut(q, "&")
		k, _, _ := strings.Cut(kv, "=")
		if n, err := url.QueryUnescape(k); err == nil {
			k = n
		}
		if k != "" {
			names = append(names, k)
		}
	}
	return path, names
}

func contractDiff(a contractArgs, stdout io.Writer, u *ui, bad func(string) (int, error)) (int, error) {
	if a.spec == "" {
		return bad("diff needs --spec openapi.json")
	}
	fail, err := contract.ParseFailOn(a.failOn)
	if err != nil {
		return bad(err.Error())
	}
	ign := map[string]bool{}
	for _, c := range strings.Split(a.ignore, ",") {
		if c = strings.TrimSpace(c); c != "" {
			ign[c] = true
		}
	}
	spec, err := contract.LoadSpecFile(a.spec)
	if err != nil {
		return 2, err
	}
	d, err := loadInventory(a)
	if err != nil {
		return 2, err
	}
	rep := contract.Diff(spec, d, contract.DiffOptions{MinRequests: int64(a.minReq), IgnoreStatus: ign})
	rep.ApplyFailOn(fail)
	switch a.format {
	case "json":
		if err := writeJSON(stdout, rep); err != nil {
			return 2, err
		}
	case "markdown":
		fmt.Fprint(stdout, rep.Markdown())
	default:
		fmt.Fprint(stdout, u.contractDiffTable(rep, a))
	}
	return boolExit(rep.Failed), nil
}

func statusSummary(m map[string]int64) string {
	var c [6]int64
	for k, v := range m {
		if len(k) == 3 && k[0] >= '1' && k[0] <= '5' {
			c[k[0]-'0'] += v
		}
	}
	var parts []string
	for i := 2; i <= 5; i++ {
		if c[i] > 0 {
			parts = append(parts, fmt.Sprintf("%dxx %s", i, contract.FmtInt(c[i])))
		}
	}
	return strings.Join(parts, "  ")
}

func clipEp(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (u *ui) inventoryTable(d *contract.Doc, a contractArgs) string {
	var b strings.Builder
	p := func(f string, args ...any) { fmt.Fprintf(&b, f, args...) }
	p("\n  %s  %s\n", u.bold("setura contract"), d.Source)
	win := ""
	if !d.First.IsZero() {
		win = fmt.Sprintf(", %s %s %s", d.First.UTC().Format("2006-01-02 15:04"), u.arrow(), d.Last.UTC().Format("2006-01-02 15:04"))
	}
	p("  %s\n\n", u.gray(fmt.Sprintf("%d endpoints, %s requests%s", len(d.Endpoints), contract.FmtInt(d.Requests), win)))
	if len(d.Endpoints) == 0 {
		p("  %s %s\n\n", u.idleSym(), "Nothing learned yet. Start the gateway with --learn FILE, or run setura contract learn --log access.jsonl --out FILE.")
		return b.String()
	}
	p("  %s %s %s %s %s %s\n", u.dim(pad("ENDPOINT", 44)), u.dim(pad("REQUESTS", 9)), u.dim(pad("P50", 9)), u.dim(pad("P99", 9)), u.dim(pad("AUTH", 5)), u.dim("STATUS"))
	n := 0
	for _, e := range d.Endpoints {
		if int64(a.minReq) > e.Count {
			continue
		}
		if a.limit > 0 && n >= a.limit {
			p("  %s\n", u.gray(fmt.Sprintf("... %d more (use --limit 0 or --format json)", len(d.Endpoints)-n)))
			break
		}
		n++
		auth := u.warnSym() + "    "
		if e.Auth.Protected > 0 {
			auth = u.okSym() + "    "
		}
		p("  %s %s %s %s %s %s\n", pad(clipEp(e.Method+" "+e.Path, 44), 44), pad(contract.FmtInt(e.Count), 9), pad(fmtMS(e.Latency.P50), 9), pad(fmtMS(e.Latency.P99), 9), auth, statusSummary(e.Status))
	}
	if d.DroppedRequests > 0 {
		p("\n  %s %s requests hit endpoints beyond the cap and were not recorded.\n", u.warnSym(), contract.FmtInt(d.DroppedRequests))
	}
	p("\n")
	return b.String()
}

func (u *ui) contractDiffTable(r *contract.Report, a contractArgs) string {
	var b strings.Builder
	p := func(f string, args ...any) { fmt.Fprintf(&b, f, args...) }
	p("\n  %s  %s %s %s\n", u.bold("setura contract diff"), r.Spec, u.arrow(), r.Learned)
	win := ""
	if !r.Window.First.IsZero() {
		win = fmt.Sprintf(", %s to %s", r.Window.First.UTC().Format("2006-01-02"), r.Window.Last.UTC().Format("2006-01-02"))
	}
	p("  %s\n\n", u.gray(fmt.Sprintf("%d documented operations, %d observed endpoints, %s requests%s", r.Documented, r.Observed, contract.FmtInt(r.Window.Requests), win)))
	if len(r.Findings) == 0 {
		p("  %s %s\n\n", u.okSym(), u.bold("no differences: the document and the traffic agree"))
	} else {
		var parts []string
		for _, k := range []string{contract.KindShadow, contract.KindZombie, contract.KindDrift, contract.KindAuth} {
			if r.Counts[k] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", r.Counts[k], k))
			}
		}
		p("  %s %s\n", u.warnSym(), u.bold(fmt.Sprintf("%d differences: %s", len(r.Findings), strings.Join(parts, ", "))))
	}
	for _, k := range []string{contract.KindShadow, contract.KindZombie, contract.KindDrift, contract.KindAuth} {
		if r.Counts[k] == 0 {
			continue
		}
		p("\n  %s\n", u.blue(contract.KindTitle(k)))
		n := 0
		for _, f := range r.Findings {
			if f.Kind != k {
				continue
			}
			if a.limit > 0 && n >= a.limit {
				p("    %s\n", u.gray(fmt.Sprintf("... %d more (use --limit 0 or --format json)", r.Counts[k]-n)))
				break
			}
			n++
			sym := u.warnSym()
			if k == contract.KindZombie {
				sym = u.idleSym()
			}
			p("    %s %s  %s\n", sym, pad(f.Method+" "+f.Path, 38), u.gray(f.Detail))
		}
	}
	for _, n := range r.Notes {
		p("\n  %s %s\n", u.idleSym(), u.gray(n))
	}
	if len(r.FailOn) > 0 {
		if r.Failed {
			p("\n  %s %s\n", u.failSym(), u.bold("failing on "+strings.Join(r.FailOn, ", ")))
		} else {
			p("\n  %s %s\n", u.okSym(), "nothing found for "+strings.Join(r.FailOn, ", "))
		}
	}
	p("\n")
	return b.String()
}
