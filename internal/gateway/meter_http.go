package gateway

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// meterCtx is what an admitted request carries to its completion.
type meterCtx struct {
	id, route, plan string
	over            bool
}

// planRuntime is the server side of plans: the current set and reload status.
type planRuntime struct {
	set      atomic.Pointer[PlanSet]
	mu       sync.Mutex
	err      string
	errHash  string
	reloads  int64
	errs     int64
	loadedAt time.Time
	stop     chan struct{}
	done     sync.WaitGroup
	once     sync.Once
}

// quotaHeaders are the response headers the gateway owns on metered requests.
var quotaHeaders = []string{"X-Quota-Limit", "X-Quota-Remaining", "X-Quota-Reset", "X-Quota-Window", "X-Quota-Plan", "X-Quota-Warning"}

func stripQuotaHeaders(h http.Header, st *reqState) {
	if st.meter == nil {
		return
	}
	for _, k := range quotaHeaders {
		h.Del(k)
	}
}

// initMeter creates the meter and loads the plan file and the state file. A
// failure is kept and reported by the first Apply, like ACME's.
func (s *Server) initMeter() error {
	o := s.opts.Meter
	if o.PlansFile == "" {
		return nil
	}
	s.meter = newMeter(o)
	s.pl = &planRuntime{stop: make(chan struct{})}
	if _, err := s.ReloadPlans(); err != nil {
		return err
	}
	if err := s.meter.load(); err != nil {
		return err
	}
	if o.StateFile != "" && o.StateInterval >= 0 {
		s.pl.done.Add(1)
		go s.pl.persistLoop(s.meter)
	}
	if o.PlansInterval >= 0 {
		iv := o.PlansInterval
		if iv == 0 {
			iv = time.Second
		}
		s.pl.done.Add(1)
		go func() {
			defer s.pl.done.Done()
			tk := time.NewTicker(iv)
			defer tk.Stop()
			for {
				select {
				case <-s.pl.stop:
					return
				case <-tk.C:
					s.ReloadPlans()
				}
			}
		}()
	}
	return nil
}

func (p *planRuntime) persistLoop(m *meter) {
	defer p.done.Done()
	tk := time.NewTicker(m.opt.StateInterval)
	defer tk.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-tk.C:
			m.save(false)
		}
	}
}

// closeMeter stops the loops and writes the final state.
func (s *Server) closeMeter() {
	if s.pl == nil {
		return
	}
	s.pl.once.Do(func() { close(s.pl.stop) })
	s.pl.done.Wait()
	s.meter.save(true)
}

// FlushUsage writes the usage state file now.
func (s *Server) FlushUsage() error {
	if s.meter == nil {
		return nil
	}
	return s.meter.save(true)
}

// Plans returns the plan set in force, or nil.
func (s *Server) Plans() *PlanSet {
	if s.pl == nil {
		return nil
	}
	return s.pl.set.Load()
}

// ReloadPlans re-reads the plan file. An invalid file keeps the previous plans
// and is counted and reported once; it returns whether new plans took effect.
func (s *Server) ReloadPlans() (bool, error) {
	if s.pl == nil {
		return false, nil
	}
	pl := s.pl
	fail := func(err error, hash string) (bool, error) {
		pl.mu.Lock()
		first := pl.errHash != hash
		pl.err, pl.errHash = err.Error(), hash
		if first {
			pl.errs++
		}
		pl.mu.Unlock()
		if first {
			s.diag("plans: keeping the previous plans: %v", err)
		}
		return false, err
	}
	raw, err := os.ReadFile(s.opts.Meter.PlansFile)
	if err != nil {
		return fail(fmt.Errorf("plans: %w", err), "read:"+err.Error())
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:8])
	if cur := pl.set.Load(); cur != nil && cur.Hash == hash {
		return false, nil
	}
	ps, err := ParsePlans(raw)
	if err != nil {
		return fail(err, hash)
	}
	pl.set.Store(ps)
	pl.mu.Lock()
	pl.err, pl.errHash, pl.reloads, pl.loadedAt = "", "", pl.reloads+1, s.meter.now()
	pl.mu.Unlock()
	s.diag("plans loaded (%d plans, hash %s)", len(ps.File.Plans), ps.Hash)
	if t := s.table.Load(); t != nil {
		var routes []string
		for _, r := range t.Cfg.Routes {
			routes = append(routes, r.Key())
		}
		for _, bad := range ps.UnknownRoutes(routes) {
			s.diag("plans: route %s matches no route in the configuration", bad)
		}
	}
	return true, nil
}

// quotaJSON writes a JSON error body.
func quotaJSON(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

func secondsUntil(t, now time.Time) int {
	n := int(math.Ceil(t.Sub(now).Seconds()))
	if n < 1 {
		n = 1
	}
	return n
}

// setQuotaHeaders writes X-Quota-* for the headline quota.
func setQuotaHeaders(h http.Header, plan string, a Admission, now time.Time) {
	if a.Head == nil {
		return
	}
	hd := a.Head
	h.Set("X-Quota-Limit", strconv.FormatInt(hd.Limit, 10))
	rem := hd.Remaining
	if !a.Allowed || (hd.Exceeded && hd.Soft) {
		rem = 0
	}
	h.Set("X-Quota-Remaining", strconv.FormatInt(rem, 10))
	h.Set("X-Quota-Reset", strconv.Itoa(secondsUntil(hd.Reset, now)))
	h.Set("X-Quota-Window", hd.Window)
	h.Set("X-Quota-Plan", plan)
	if len(a.Soft) > 0 {
		names := make([]string, len(a.Soft))
		for i, s := range a.Soft {
			names[i] = s.Name
		}
		h.Set("X-Quota-Warning", "soft quota exceeded: "+strings.Join(names, ", "))
	}
}

// planDenied applies the plan to an authenticated request: unknown identities,
// routes and methods the plan forbids, and quotas. It answers refused requests.
func (s *Server) planDenied(w http.ResponseWriter, r *http.Request, st *reqState) bool {
	m, ps := s.meter, s.Plans()
	if m == nil || ps == nil || ps.unmetered(st.route) {
		return false
	}
	now := m.now()
	in := ps.requestIdentity(r, st.auth, s.trusted.clientIP(r))
	rs := ps.resolve(in)
	if rs.Rejected {
		m.recordBlocked(rs.Identity, st.route, noPlan, now, true)
		st.errMsg = "plan: unknown identity"
		quotaJSON(w, http.StatusForbidden, map[string]any{"error": "unknown_identity",
			"message": "this identity has no plan; ask for access or send a credential that maps to one"})
		return true
	}
	plan := ps.File.Plans[rs.Plan]
	if ok, why := plan.allows(st.route, r.Method); !ok {
		m.recordBlocked(rs.Identity, st.route, rs.Plan, now, false)
		st.errMsg = "plan " + rs.Plan + " does not allow this request"
		quotaJSON(w, http.StatusForbidden, map[string]any{"error": "plan_forbids", "plan": rs.Plan,
			"message": "plan " + rs.Plan + " does not include " + r.Method + " " + st.route + ": " + why})
		return true
	}
	a := m.admit(rs.Identity, ps, rs.Plan, plan, now)
	setQuotaHeaders(w.Header(), rs.Plan, a, now)
	if !a.Allowed {
		d := a.Denied
		secs := secondsUntil(d.Reset, now)
		m.recordBlocked(rs.Identity, st.route, rs.Plan, now, false)
		st.errMsg = "quota exceeded: " + d.Name
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		quotaJSON(w, http.StatusTooManyRequests, map[string]any{"error": "quota_exceeded", "quota": d.Name, "plan": rs.Plan,
			"limit": d.Limit, "used": d.Used, "window": d.Window, "reset": d.Reset.UTC().Format(time.RFC3339), "retry_after_seconds": secs,
			"message": fmt.Sprintf("plan %s allows %d (%s) per %s window and %d are used", rs.Plan, d.Limit, d.Name, d.Window, d.Used)})
		return true
	}
	st.meter = &meterCtx{id: rs.Identity, route: st.route, plan: rs.Plan, over: len(a.Soft) > 0}
	return false
}

// meterDone records the finished request of an admitted identity.
func (s *Server) meterDone(rec *recorder, st *reqState, status int, d time.Duration) {
	if st.meter == nil || s.meter == nil {
		return
	}
	var in int64
	if st.in != nil {
		in = st.in.n.Load()
	}
	s.meter.record(completion{id: st.meter.id, route: st.meter.route, plan: st.meter.plan, in: in, out: rec.bytesOut(),
		status: status, latency: d, overQuota: st.meter.over}, s.meter.now())
}

// ---- admin ----

// ParseSince turns a --since value into a UTC day: a duration (24h, 7d), a
// day (2026-11-01) or an RFC 3339 time. Usage is kept per UTC day, so a
// duration includes the whole day it lands on.
func ParseSince(v string, now time.Time) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if n, ok := strings.CutSuffix(v, "d"); ok {
		if d, err := strconv.Atoi(n); err == nil && d >= 0 {
			return now.UTC().AddDate(0, 0, -d).Format("2006-01-02"), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return now.UTC().Add(-d).Format("2006-01-02"), nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.Format("2006-01-02"), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format("2006-01-02"), nil
	}
	return "", fmt.Errorf("%q: want a duration (24h, 7d), a day (2026-11-01) or an RFC 3339 time", v)
}

// PeriodDays turns "2026-11" into its first and last UTC day.
func PeriodDays(p string) (since, until string, err error) {
	t, e := time.Parse("2006-01", p)
	if e != nil {
		return "", "", fmt.Errorf("period %q: want YYYY-MM, for example 2026-11", p)
	}
	return t.Format("2006-01-02"), t.AddDate(0, 1, -1).Format("2006-01-02"), nil
}

// queryFromValues reads the /usage filters.
func (s *Server) queryFromValues(v map[string][]string) (UsageQuery, error) {
	get := func(k string) string {
		if x := v[k]; len(x) > 0 {
			return x[0]
		}
		return ""
	}
	var q UsageQuery
	now := s.meter.now()
	var err error
	if q.Since, err = ParseSince(get("since"), now); err != nil {
		return q, fmt.Errorf("since: %w", err)
	}
	if u := get("until"); u != "" {
		if q.Until, err = ParseSince(u, now); err != nil {
			return q, fmt.Errorf("until: %w", err)
		}
	}
	if p := get("period"); p != "" {
		if q.Since, q.Until, err = PeriodDays(p); err != nil {
			return q, err
		}
	}
	q.Identity, q.Route, q.Plan = get("identity"), get("route"), get("plan")
	q.By = v["by"]
	if _, err := NormalizeBy(q.By); err != nil {
		return q, err
	}
	return q, nil
}

func (s *Server) usageHandler(csvOut bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			plain(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		if s.meter == nil {
			plain(w, http.StatusNotFound, "metering is not enabled (start the gateway with --plans FILE)")
			return
		}
		q, err := s.queryFromValues(r.URL.Query())
		if err != nil {
			plain(w, http.StatusBadRequest, err.Error())
			return
		}
		rep := s.meter.Query(q)
		if csvOut {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			UsageCSV(w, rep)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeIndented(w, rep)
	}
}

// UsageCSV writes a report as CSV: the grouping columns, then every counter.
func UsageCSV(w io.Writer, rep UsageReport) error {
	cw := csv.NewWriter(w)
	var head []string
	has := map[string]bool{}
	for _, b := range rep.By {
		has[b] = true
	}
	for _, c := range []string{"day", "identity", "route", "plan"} {
		if has[c] {
			head = append(head, c)
		}
	}
	head = append(head, "requests", "billable", "blocked", "over_quota", "bytes_in", "bytes_out", "status_2xx", "status_3xx", "status_4xx", "status_5xx", "latency_ms_sum", "latency_ms_avg")
	cw.Write(head)
	for _, r := range rep.Rows {
		var rec []string
		if has["day"] {
			rec = append(rec, csvSafe(r.Day))
		}
		if has["identity"] {
			rec = append(rec, csvSafe(r.Identity))
		}
		if has["route"] {
			rec = append(rec, csvSafe(r.Route))
		}
		if has["plan"] {
			rec = append(rec, csvSafe(r.Plan))
		}
		i := strconv.FormatInt
		rec = append(rec, i(r.Requests, 10), i(r.Billable, 10), i(r.Blocked, 10), i(r.OverQuota, 10), i(r.BytesIn, 10), i(r.BytesOut, 10),
			i(r.Status2xx, 10), i(r.Status3xx, 10), i(r.Status4xx, 10), i(r.Status5xx, 10),
			strconv.FormatFloat(r.LatencyMsSum, 'f', 3, 64), strconv.FormatFloat(r.LatencyMsAvg, 'f', 3, 64))
		cw.Write(rec)
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe defuses spreadsheet formula injection in values that come from
// client credentials (an API key name or JWT subject).
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// PlansDoc is the /plans document.
type PlansDoc struct {
	Schema      string           `json:"schema"`
	Hash        string           `json:"hash"`
	LoadedAt    string           `json:"loaded_at,omitempty"`
	Reloads     int64            `json:"reloads"`
	ReloadError string           `json:"reload_error,omitempty"`
	DefaultPlan string           `json:"default_plan,omitempty"`
	Unmetered   []string         `json:"unmetered_routes,omitempty"`
	Plans       map[string]*Plan `json:"plans"`
	Identities  int              `json:"identities"`
}

func (s *Server) plansDoc() any {
	ps := s.Plans()
	if ps == nil {
		return nil
	}
	pl := s.pl
	pl.mu.Lock()
	defer pl.mu.Unlock()
	d := &PlansDoc{Schema: "setura.plans/v1", Hash: ps.Hash, Reloads: pl.reloads, ReloadError: pl.err, DefaultPlan: ps.File.DefaultPlan,
		Unmetered: ps.File.UnmeteredRoutes, Plans: ps.File.Plans, Identities: len(ps.File.Identities)}
	if !pl.loadedAt.IsZero() {
		d.LoadedAt = pl.loadedAt.UTC().Format(time.RFC3339)
	}
	return d
}

// writeUsageMetrics adds the metering families: every label is a plan, a
// configured route, a status class or a fixed word, never an identity.
func (s *Server) writeUsageMetrics(w io.Writer) {
	m := s.meter
	if m == nil {
		return
	}
	head := func(name, typ, help string) { fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ) }
	m.mu.Lock()
	req := make(map[[3]string]int64, len(m.reqMx))
	for k, v := range m.reqMx {
		req[k] = v
	}
	by := make(map[[2]string]int64, len(m.byteMx))
	for k, v := range m.byteMx {
		by[k] = v
	}
	ex := make(map[[3]string]int64, len(m.exceededMx))
	for k, v := range m.exceededMx {
		ex[k] = v
	}
	rejected, nseries, overflow, perr := m.rejectedMx, len(m.series), m.overflow, m.persistErr
	m.mu.Unlock()
	s.pl.mu.Lock()
	rerr, nplans := s.pl.errs, 0
	s.pl.mu.Unlock()
	if ps := s.Plans(); ps != nil {
		nplans = len(ps.File.Plans)
	}
	head("setura_gateway_usage_requests_total", "counter", "Metered requests per plan, route and status class.")
	k3 := func(m map[[3]string]int64) [][3]string {
		keys := make([][3]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			for n := 0; n < 3; n++ {
				if keys[i][n] != keys[j][n] {
					return keys[i][n] < keys[j][n]
				}
			}
			return false
		})
		return keys
	}
	for _, k := range k3(req) {
		fmt.Fprintf(w, "setura_gateway_usage_requests_total{plan=\"%s\",route=\"%s\",code=\"%s\"} %d\n", promLabel(k[0]), promLabel(k[1]), k[2], req[k])
	}
	head("setura_gateway_usage_bytes_total", "counter", "Metered body bytes per plan and direction (in = request, out = response).")
	bk := make([][2]string, 0, len(by))
	for k := range by {
		bk = append(bk, k)
	}
	sort.Slice(bk, func(i, j int) bool { return bk[i][0]+bk[i][1] < bk[j][0]+bk[j][1] })
	for _, k := range bk {
		fmt.Fprintf(w, "setura_gateway_usage_bytes_total{plan=\"%s\",direction=\"%s\"} %d\n", promLabel(k[0]), k[1], by[k])
	}
	head("setura_gateway_quota_exceeded_total", "counter", "Requests over a plan quota per plan, quota and mode (hard refused with 429, soft only warned).")
	for _, k := range k3(ex) {
		fmt.Fprintf(w, "setura_gateway_quota_exceeded_total{plan=\"%s\",quota=\"%s\",mode=\"%s\"} %d\n", promLabel(k[0]), k[1], k[2], ex[k])
	}
	head("setura_gateway_plan_rejected_total", "counter", "Requests refused because the identity has no plan and there is no default plan.")
	fmt.Fprintf(w, "setura_gateway_plan_rejected_total %d\n", rejected)
	head("setura_gateway_usage_series", "gauge", "Usage counters held in memory (capped by --usage-max-series).")
	fmt.Fprintf(w, "setura_gateway_usage_series %d\n", nseries)
	head("setura_gateway_usage_overflow_total", "counter", "Observations folded into the overflow series because the cardinality cap was reached.")
	fmt.Fprintf(w, "setura_gateway_usage_overflow_total %d\n", overflow)
	head("setura_gateway_usage_persist_errors_total", "counter", "Failed writes of the usage state file.")
	fmt.Fprintf(w, "setura_gateway_usage_persist_errors_total %d\n", perr)
	head("setura_gateway_plans_reload_errors_total", "counter", "Plan file reloads rejected (the previous plans stay in force).")
	fmt.Fprintf(w, "setura_gateway_plans_reload_errors_total %d\n", rerr)
	head("setura_gateway_plans", "gauge", "Plans defined in the plan file in force.")
	fmt.Fprintf(w, "setura_gateway_plans %d\n", nplans)
}

// ---- invoice ----

// InvoiceLine is the billable usage of one identity on one plan.
type InvoiceLine struct {
	Identity   string  `json:"identity"`
	Plan       string  `json:"plan"`
	Requests   int64   `json:"requests"`
	Billable   int64   `json:"billable_requests"`
	Included   int64   `json:"included_requests"`
	Chargeable int64   `json:"chargeable_requests"`
	Blocked    int64   `json:"blocked"`
	OverQuota  int64   `json:"over_quota"`
	BytesTotal int64   `json:"bytes"`
	Price1k    float64 `json:"price_per_1k"`
	Currency   string  `json:"currency,omitempty"`
	Amount     float64 `json:"amount"`
}

// Invoice summarises one period.
type Invoice struct {
	Schema    string             `json:"schema"`
	Period    string             `json:"period"`
	Generated string             `json:"generated"`
	Lines     []InvoiceLine      `json:"lines"`
	Totals    map[string]float64 `json:"totals"` // per currency
	Notes     []string           `json:"notes,omitempty"`
}

// BuildInvoice prices rows (grouped by identity and plan) with the plan
// prices. Billable units are admitted requests that did not end in a 5xx; the
// plan's included allowance is taken off per identity and plan; each line is
// rounded to two decimals half away from zero.
func BuildInvoice(period string, rep UsageReport, plans map[string]*Plan, now time.Time) Invoice {
	inv := Invoice{Schema: "setura.invoice/v1", Period: period, Generated: now.UTC().Format(time.RFC3339), Lines: []InvoiceLine{}, Totals: map[string]float64{}}
	for _, r := range rep.Rows {
		l := InvoiceLine{Identity: r.Identity, Plan: r.Plan, Requests: r.Requests, Billable: r.Billable, Blocked: r.Blocked, OverQuota: r.OverQuota, BytesTotal: r.BytesIn + r.BytesOut}
		if p := plans[r.Plan]; p != nil {
			l.Included, l.Price1k, l.Currency = p.IncludedRequests, p.PricePer1kRequests, p.Currency
		}
		l.Chargeable = max(0, l.Billable-l.Included)
		l.Amount = math.Round(float64(l.Chargeable)/1000*l.Price1k*100) / 100
		inv.Lines = append(inv.Lines, l)
		if l.Currency != "" {
			inv.Totals[l.Currency] = math.Round((inv.Totals[l.Currency]+l.Amount)*100) / 100
		}
	}
	if len(inv.Lines) == 0 {
		inv.Notes = append(inv.Notes, "no usage recorded in this period")
	}
	inv.Notes = append(inv.Notes, "usage is counted per UTC day; billable units are admitted requests that did not end in a 5xx; requests refused by a plan or quota are not billed")
	return inv
}
