package setura

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultConnAdmin = "127.0.0.1:19000"

// connDoc is the gateway's /connections document, kept loose so new fields
// show up in --format json without a CLI change.
type connDoc struct {
	Enabled  bool             `json:"enabled"`
	Capacity int              `json:"capacity"`
	Latest   int64            `json:"latest"`
	History  []map[string]any `json:"history"`
	Open     []map[string]any `json:"open"`
}

type connFilter struct{ key, val string }

// parseConnFilters validates --filter k=v pairs.
func parseConnFilters(in []string) ([]connFilter, error) {
	var out []connFilter
	for _, f := range in {
		k, v, ok := strings.Cut(f, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, userErrorf("--filter %q: want key=value, for example status=5xx or route=orders", f)
		}
		out = append(out, connFilter{k, strings.ToLower(v)})
	}
	return out, nil
}

func fieldStr(r map[string]any, k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

// matchConn reports whether a record passes every filter. The status filter
// takes a code (502) or a class (5xx); the others are case-insensitive
// substrings of the named field. Any other key is compared with the JSON field
// of that name.
func matchConn(r map[string]any, fs []connFilter) bool {
	for _, f := range fs {
		var ok bool
		switch f.key {
		case "status":
			s := fieldStr(r, "status")
			ok = s == f.val || (len(f.val) == 3 && strings.HasSuffix(f.val, "xx") && s != "" && s[:1] == f.val[:1])
		case "client", "ip":
			ok = strings.Contains(strings.ToLower(fieldStr(r, "client_ip")+":"+fieldStr(r, "client_port")), f.val)
		case "upstream":
			ok = strings.Contains(strings.ToLower(fieldStr(r, "upstream_addr")), f.val)
		case "proto", "protocol":
			ok = strings.Contains(strings.ToLower(fieldStr(r, "protocol")), f.val)
		case "sni":
			ok = strings.Contains(strings.ToLower(fieldStr(r, "tls_sni")), f.val)
		case "route", "backend", "listener", "host", "method", "path":
			ok = strings.Contains(strings.ToLower(fieldStr(r, f.key)), f.val)
		default:
			ok = strings.EqualFold(fieldStr(r, f.key), f.val)
		}
		if !ok {
			return false
		}
	}
	return true
}

func filterRows(rows []map[string]any, fs []connFilter) []map[string]any {
	if len(fs) == 0 {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		if matchConn(r, fs) {
			out = append(out, r)
		}
	}
	return out
}

// connURL builds the /connections URL for an admin address.
func connURL(admin string, limit int, since int64) (string, error) {
	if !strings.Contains(admin, "://") {
		admin = "http://" + admin
	}
	u, err := url.Parse(admin)
	if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return "", userErrorf("--admin %q: want HOST:PORT, for example %s", admin, defaultConnAdmin)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return "", userErrorf("--admin %q: want HOST:PORT, for example %s", admin, defaultConnAdmin)
	}
	u.Path = "/connections"
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func fetchConnections(ctx context.Context, c *http.Client, target string) (*connDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the gateway admin endpoint (is `setura gateway run` up, and is --admin right?): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("gateway answered %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var d connDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("unexpected /connections response: %w", err)
	}
	return &d, nil
}

// reverse flips newest-first rows to oldest-first.
func reverseRows(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[len(rows)-1-i] = r
	}
	return out
}

func runConnections(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) (int, error) {
	admin := fs.String("admin", defaultConnAdmin, "gateway admin address")
	follow := fs.Bool("follow", false, "keep running and print new requests as they finish")
	format := fs.String("format", "auto", "auto (table on a terminal, JSON when piped), table or json")
	limit := fs.Int("limit", 50, "most recent requests to show")
	interval := fs.Duration("interval", time.Second, "poll interval with --follow")
	var filters stringFlags
	fs.Var(&filters, "filter", "keep rows matching key=value (client, listener, protocol, route, backend, upstream, sni, status, host, path); repeatable")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		fmt.Fprintln(stderr, "setura connections: unexpected arguments")
		exampleHint(stderr, "connections")
		return 2, usageError{"arguments"}
	}
	var table bool
	switch *format {
	case "auto":
		table = stdoutTTY
	case "table":
		table = true
	case "json":
	default:
		return 2, userErrorf("--format must be auto, table or json, got %q", *format)
	}
	if *limit < 1 || *interval <= 0 {
		return 2, userErrorf("--limit must be at least 1 and --interval positive")
	}
	fl, err := parseConnFilters(filters)
	if err != nil {
		return 2, err
	}
	if _, err := connURL(*admin, *limit, 0); err != nil {
		return 2, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return connectionsRun(ctx, &http.Client{Timeout: 10 * time.Second}, *admin, *limit, *follow, table, fl, *interval, stdout, u)
}

type stringFlags []string

func (s *stringFlags) String() string     { return strings.Join(*s, ",") }
func (s *stringFlags) Set(v string) error { *s = append(*s, v); return nil }

// connectionsRun prints the connections once, or follows until ctx ends.
func connectionsRun(ctx context.Context, c *http.Client, admin string, limit int, follow, table bool, fl []connFilter, interval time.Duration, out io.Writer, u *ui) (int, error) {
	target, err := connURL(admin, limit, 0)
	if err != nil {
		return 2, err
	}
	doc, err := fetchConnections(ctx, c, target)
	if err != nil {
		return 1, err
	}
	if !doc.Enabled {
		return 1, userErrorf("the gateway keeps no connection history (it was started with --conn-history 0)")
	}
	doc.History, doc.Open = filterRows(doc.History, fl), filterRows(doc.Open, fl)
	if !follow {
		if table {
			fmt.Fprint(out, renderConnTable(u, doc.Open, reverseRows(doc.History), true))
			return 0, nil
		}
		return 0, writeJSON(out, doc)
	}
	w := &connWriter{out: out, u: u, table: table}
	w.rows(doc.Open, reverseRows(doc.History), true)
	latest := doc.Latest
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, nil
		case <-tk.C:
		}
		t, _ := connURL(admin, limit, latest)
		d, err := fetchConnections(ctx, c, t)
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil
			}
			return 1, err
		}
		latest = d.Latest
		w.rows(nil, reverseRows(filterRows(d.History, fl)), false)
	}
}

// connWriter prints rows incrementally, with the header once.
type connWriter struct {
	out    io.Writer
	u      *ui
	table  bool
	header bool
}

func (w *connWriter) rows(open, hist []map[string]any, first bool) {
	if !w.table {
		enc := json.NewEncoder(w.out)
		for _, r := range open {
			enc.Encode(map[string]any{"open": r})
		}
		for _, r := range hist {
			enc.Encode(r)
		}
		return
	}
	if len(hist) == 0 && len(open) == 0 && w.header {
		return
	}
	s := renderConnTable(w.u, open, hist, first && !w.header)
	w.header = true
	fmt.Fprint(w.out, s)
}

func connClient(r map[string]any) string {
	ip := fieldStr(r, "client_ip")
	if ip == "" {
		return fieldStr(r, "remote")
	}
	if p := fieldStr(r, "client_port"); p != "" {
		if strings.Contains(ip, ":") {
			return "[" + ip + "]:" + p
		}
		return ip + ":" + p
	}
	return ip
}

func connListener(r map[string]any) string {
	if p := fieldStr(r, "listener_port"); p != "" {
		return ":" + p
	}
	return fieldStr(r, "listener")
}

func connRoute(r map[string]any) string {
	route := fieldStr(r, "route")
	if i := strings.IndexByte(route, '/'); i >= 0 {
		route = route[i+1:] // drop the kind prefix, keep namespace/name
	}
	if route == "" {
		return "-"
	}
	return route
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtAge(msec float64) string {
	d := time.Duration(msec * float64(time.Millisecond))
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func fmtBytes(f float64) string {
	n := int64(f)
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1fK", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
}

func (u *ui) statusColor(code string) string {
	switch {
	case code == "":
		return code
	case code[0] == '2' || code[0] == '1':
		return u.green(code)
	case code[0] == '3':
		return u.gray(code)
	case code[0] == '4':
		return u.amber(code)
	}
	return u.red(code)
}

// renderConnTable lays out open connections and finished requests as a
// compact table. Columns are sized on plain text so colour never skews them.
func renderConnTable(u *ui, open, hist []map[string]any, header bool) string {
	var b strings.Builder
	cols := []string{"CLIENT", "LISTENER", "PROTO", "ROUTE", "UPSTREAM", "STATUS", "MS"}
	var rows [][]string
	for _, r := range hist {
		ms := ""
		if v, ok := r["duration_ms"].(float64); ok {
			ms = fmtMS(v)
		}
		rows = append(rows, []string{connClient(r), connListener(r), orDash(fieldStr(r, "protocol")), connRoute(r), orDash(fieldStr(r, "upstream_addr")), fieldStr(r, "status"), ms})
	}
	var orows [][]string
	for _, r := range open {
		age, _ := r["age_ms"].(float64)
		in, _ := r["bytes_in"].(float64)
		out, _ := r["bytes_out"].(float64)
		orows = append(orows, []string{connClient(r), connListener(r), orDash(fieldStr(r, "protocol")), connRoute(r), orDash(fieldStr(r, "upstream_addr")),
			"open " + fmtAge(age), fmtBytes(in) + "/" + fmtBytes(out)})
	}
	all := append(append([][]string{cols}, orows...), rows...)
	widths := make([]int, len(cols))
	for _, r := range all {
		for i, c := range r {
			if n := len([]rune(c)); n > widths[i] {
				widths[i] = n
			}
		}
	}
	line := func(r []string, style func(i int, s string) string) {
		b.WriteString("  ")
		for i, c := range r {
			cell := pad(c, widths[i])
			if i >= 5 {
				if n := widths[i] - len([]rune(c)); n > 0 { // right-align status and ms
					cell = strings.Repeat(" ", n) + c
				}
			}
			if style != nil {
				cell = strings.Replace(cell, c, style(i, c), 1)
			}
			b.WriteString(cell)
			if i < len(r)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
	}
	if header {
		line(cols, func(_ int, s string) string { return u.gray(s) })
	}
	for _, r := range orows {
		line(r, func(i int, s string) string {
			if i == 5 {
				return u.blue(s)
			}
			return s
		})
	}
	if header && len(orows) > 0 && len(rows) > 0 {
		b.WriteString("  " + u.gray(strings.Repeat(u.sym("─", "-"), 3)+" recent") + "\n")
	}
	for _, r := range rows {
		line(r, func(i int, s string) string {
			if i == 5 {
				return u.statusColor(s)
			}
			return s
		})
	}
	if len(orows) == 0 && len(rows) == 0 && header {
		b.WriteString("  " + u.gray("no connections yet") + "\n")
	}
	return b.String()
}
