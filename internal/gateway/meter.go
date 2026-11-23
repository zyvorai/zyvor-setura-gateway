package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Usage metering and quota accounting. One mutex guards everything; a request
// takes it twice (admission, completion) for a few map operations.

// UsageStateSchema stamps the persisted state file.
const UsageStateSchema = "setura.usage-state/v1"

const (
	defaultMaxSeries     = 10000
	defaultRetentionDays = 100
	defaultStateInterval = 30 * time.Second
	quotaKeepDays        = 62 // days of per-identity totals kept for windows
	overflowID           = "_overflow"
	noPlan               = "_none"
)

// MeterOptions configures plans, metering and persistence.
type MeterOptions struct {
	PlansFile     string        // plan file, hot-reloaded; empty disables metering
	PlansInterval time.Duration // reload poll (default 1s)
	StateFile     string        // persisted usage counters; empty keeps them in memory only
	StateInterval time.Duration // snapshot period (default 30s; negative disables the timer)
	MaxSeries     int           // distinct day+identity+route+plan counters (default 10000)
	RetentionDays int           // days of counters kept (default 100)
	Now           func() time.Time
}

type seriesKey struct{ Day, Identity, Route, Plan string }

// seriesVal are the counters of one series. Latency is in microseconds.
type seriesVal struct {
	Requests  int64 `json:"requests"`
	BytesIn   int64 `json:"bytes_in"`
	BytesOut  int64 `json:"bytes_out"`
	S2xx      int64 `json:"status_2xx"`
	S3xx      int64 `json:"status_3xx"`
	S4xx      int64 `json:"status_4xx"`
	S5xx      int64 `json:"status_5xx"`
	Blocked   int64 `json:"blocked"`    // refused by plan or quota (429, 403)
	OverQuota int64 `json:"over_quota"` // admitted beyond a soft quota
	Billable  int64 `json:"billable"`   // admitted requests that did not end in 5xx
	LatencyUS int64 `json:"latency_us"`
}

func (v *seriesVal) add(o seriesVal) {
	v.Requests += o.Requests
	v.BytesIn += o.BytesIn
	v.BytesOut += o.BytesOut
	v.S2xx += o.S2xx
	v.S3xx += o.S3xx
	v.S4xx += o.S4xx
	v.S5xx += o.S5xx
	v.Blocked += o.Blocked
	v.OverQuota += o.OverQuota
	v.Billable += o.Billable
	v.LatencyUS += o.LatencyUS
}

type dayTot struct{ req, bytes int64 }

// quotaState is the live window accounting of one identity.
type quotaState struct {
	secStart, secN int64 // unix second and requests in it
	minStart, minN int64 // unix minute and requests in it
	days           map[int64]*dayTot
}

type meter struct {
	opt MeterOptions
	now func() time.Time

	mu       sync.Mutex
	series   map[seriesKey]*seriesVal
	idents   map[string]*quotaState
	overflow int64 // observations folded into the overflow series
	dirty    bool

	// process-lifetime counters for Prometheus (bounded labels)
	reqMx      map[[3]string]int64 // plan, route, status class
	byteMx     map[[2]string]int64 // plan, direction
	exceededMx map[[3]string]int64 // plan, quota, mode
	rejectedMx int64
	persistErr int64
	lastSaved  time.Time
}

func newMeter(o MeterOptions) *meter {
	if o.MaxSeries <= 0 {
		o.MaxSeries = defaultMaxSeries
	}
	if o.RetentionDays <= 0 {
		o.RetentionDays = defaultRetentionDays
	}
	if o.StateInterval == 0 {
		o.StateInterval = defaultStateInterval
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &meter{opt: o, now: now, series: map[seriesKey]*seriesVal{}, idents: map[string]*quotaState{},
		reqMx: map[[3]string]int64{}, byteMx: map[[2]string]int64{}, exceededMx: map[[3]string]int64{}}
}

func dayIndex(t time.Time) int64 { return t.UTC().Unix() / 86400 }
func dayString(idx int64) string { return time.Unix(idx*86400, 0).UTC().Format("2006-01-02") }

func (m *meter) quota(id string) *quotaState {
	if q := m.idents[id]; q != nil {
		return q
	}
	if len(m.idents) >= m.opt.MaxSeries {
		id = overflowID
		if q := m.idents[id]; q != nil {
			return q
		}
	}
	q := &quotaState{days: map[int64]*dayTot{}}
	m.idents[id] = q
	return q
}

// monthWindow returns the first and last day index counted by the plan's
// month quotas on day today.
func monthWindow(p *Plan, now time.Time) (first, last int64) {
	today := dayIndex(now)
	if p.Window == "rolling" {
		return today - 29, today
	}
	u := now.UTC()
	first = dayIndex(time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC))
	last = dayIndex(time.Date(u.Year(), u.Month()+1, 1, 0, 0, 0, 0, time.UTC)) - 1
	return first, last
}

// QuotaHit is one quota evaluated for a request.
type QuotaHit struct {
	Name      string
	Limit     int64
	Used      int64 // before this request
	Remaining int64 // after this request is counted (bytes: before)
	Reset     time.Time
	Soft      bool
	Exceeded  bool
	Window    string
}

// usageOf reads a quota's current use and the time it resets.
func (q *quotaState) usageOf(name string, p *Plan, now time.Time) (used int64, reset time.Time, window string) {
	switch name {
	case QuotaBurst:
		if q.secStart == now.Unix() {
			used = q.secN
		}
		return used, time.Unix(now.Unix()+1, 0).UTC(), "second"
	case QuotaMinute:
		if q.minStart == now.Unix()/60 {
			used = q.minN
		}
		return used, time.Unix((now.Unix()/60+1)*60, 0).UTC(), "minute"
	case QuotaDay:
		if d := q.days[dayIndex(now)]; d != nil {
			used = d.req
		}
		return used, time.Unix((dayIndex(now)+1)*86400, 0).UTC(), "day"
	}
	first, last := monthWindow(p, now)
	oldest := int64(-1)
	for d, t := range q.days {
		if d < first || d > last {
			continue
		}
		if name == QuotaMonth {
			used += t.req
		} else {
			used += t.bytes
		}
		if (t.req > 0 || t.bytes > 0) && (oldest < 0 || d < oldest) {
			oldest = d
		}
	}
	window = "month"
	if p.Window == "rolling" {
		window = "30d"
		if oldest >= 0 {
			return used, time.Unix((oldest+30)*86400, 0).UTC(), window
		}
		return used, time.Unix((dayIndex(now)+1)*86400, 0).UTC(), window
	}
	return used, time.Unix((last+1)*86400, 0).UTC(), window
}

// Admission is the verdict on one request.
type Admission struct {
	Allowed bool
	Denied  *QuotaHit  // the hard quota that refused the request
	Soft    []QuotaHit // soft quotas the request went over
	Head    *QuotaHit  // the quota the X-Quota-* headers describe
	All     []QuotaHit
}

// evaluate computes all quota views without changing state.
func (m *meter) evaluate(q *quotaState, ps *PlanSet, planName string, p *Plan, now time.Time) Admission {
	var a Admission
	for _, l := range p.limits() {
		used, reset, win := q.usageOf(l.Name, p, now)
		h := QuotaHit{Name: l.Name, Limit: l.Limit, Used: used, Reset: reset, Window: win, Soft: ps.Soft(planName, l.Name)}
		if l.Name == QuotaBytesMon {
			h.Exceeded = used >= l.Limit
			h.Remaining = max(0, l.Limit-used)
		} else {
			h.Exceeded = used >= l.Limit
			h.Remaining = max(0, l.Limit-used-1)
		}
		a.All = append(a.All, h)
	}
	a.Allowed = true
	for i := range a.All {
		h := &a.All[i]
		switch {
		case h.Exceeded && !h.Soft && a.Denied == nil:
			c := *h
			a.Denied = &c
			a.Allowed = false
		case h.Exceeded && h.Soft:
			a.Soft = append(a.Soft, *h)
		}
	}
	// Headline: the quota with the smallest remaining share (burst only counts
	// when it is the whole plan, since it resets every second).
	var best *QuotaHit
	for i := range a.All {
		h := &a.All[i]
		if h.Name == QuotaBurst && len(a.All) > 1 {
			continue
		}
		if a.Denied != nil && h.Name != a.Denied.Name {
			continue
		}
		if best == nil || float64(h.Remaining)/float64(h.Limit) < float64(best.Remaining)/float64(best.Limit) {
			best = h
		}
	}
	a.Head = best
	return a
}

// admit decides a request and, when it is allowed, counts it.
func (m *meter) admit(id string, ps *PlanSet, planName string, p *Plan, now time.Time) Admission {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.quota(id)
	a := m.evaluate(q, ps, planName, p, now)
	for _, h := range a.All {
		if h.Exceeded {
			mode := "hard"
			if h.Soft {
				mode = "soft"
			}
			if a.Denied == nil || h.Name == a.Denied.Name || h.Soft {
				m.exceededMx[[3]string{planName, h.Name, mode}]++
			}
		}
	}
	if !a.Allowed {
		return a
	}
	if s := now.Unix(); q.secStart != s {
		q.secStart, q.secN = s, 0
	}
	q.secN++
	if mi := now.Unix() / 60; q.minStart != mi {
		q.minStart, q.minN = mi, 0
	}
	q.minN++
	di := dayIndex(now)
	d := q.days[di]
	if d == nil {
		d = &dayTot{}
		q.days[di] = d
		q.pruneDays(di)
	}
	d.req++
	return a
}

func (q *quotaState) pruneDays(today int64) {
	if len(q.days) <= quotaKeepDays {
		return
	}
	for d := range q.days {
		if d < today-quotaKeepDays {
			delete(q.days, d)
		}
	}
}

// peek evaluates a request without counting it (setura why, /why).
func (m *meter) peek(id string, ps *PlanSet, planName string, p *Plan, now time.Time) Admission {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.idents[id]
	if q == nil {
		q = &quotaState{days: map[int64]*dayTot{}}
	}
	return m.evaluate(q, ps, planName, p, now)
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	case status >= 200:
		return "2xx"
	}
	return "1xx"
}

func (m *meter) seriesFor(day, id, route, plan string) *seriesVal {
	k := seriesKey{day, id, route, plan}
	if v := m.series[k]; v != nil {
		return v
	}
	if len(m.series) >= m.opt.MaxSeries {
		k = seriesKey{day, overflowID, overflowID, plan}
		m.overflow++
		if v := m.series[k]; v != nil {
			return v
		}
	}
	v := &seriesVal{}
	m.series[k] = v
	return v
}

// Completion describes a finished request for accounting.
type completion struct {
	id, route, plan string
	in, out         int64
	status          int
	latency         time.Duration
	overQuota       bool
}

// record counts an admitted request once it has finished.
func (m *meter) record(c completion, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.seriesFor(dayString(dayIndex(now)), c.id, c.route, c.plan)
	v.Requests++
	v.BytesIn += c.in
	v.BytesOut += c.out
	switch statusClass(c.status) {
	case "2xx", "1xx":
		v.S2xx++
	case "3xx":
		v.S3xx++
	case "4xx":
		v.S4xx++
	default:
		v.S5xx++
	}
	if c.status < 500 {
		v.Billable++
	}
	if c.overQuota {
		v.OverQuota++
	}
	v.LatencyUS += c.latency.Microseconds()
	q := m.quota(c.id)
	di := dayIndex(now)
	d := q.days[di]
	if d == nil {
		d = &dayTot{}
		q.days[di] = d
	}
	d.bytes += c.in + c.out
	m.reqMx[[3]string{c.plan, boundedRoute(m.reqMx, c.plan, c.route), statusClass(c.status)}]++
	m.byteMx[[2]string{c.plan, "in"}] += c.in
	m.byteMx[[2]string{c.plan, "out"}] += c.out
	m.dirty = true
}

// boundedRoute keeps the Prometheus label set finite when routes churn.
func boundedRoute(mx map[[3]string]int64, plan, route string) string {
	if len(mx) < 5000 {
		return route
	}
	for k := range mx {
		if k[0] == plan && k[1] == route {
			return route
		}
	}
	return "_other"
}

// recordBlocked counts a request refused before it reached a backend.
func (m *meter) recordBlocked(id, route, plan string, now time.Time, rejected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seriesFor(dayString(dayIndex(now)), id, route, plan).Blocked++
	if rejected {
		m.rejectedMx++
	}
	m.dirty = true
}

// ---- queries ----

// UsageRow is one line of /usage, after grouping.
type UsageRow struct {
	Identity     string  `json:"identity,omitempty"`
	Route        string  `json:"route,omitempty"`
	Plan         string  `json:"plan,omitempty"`
	Day          string  `json:"day,omitempty"`
	Requests     int64   `json:"requests"`
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
	Status2xx    int64   `json:"status_2xx"`
	Status3xx    int64   `json:"status_3xx"`
	Status4xx    int64   `json:"status_4xx"`
	Status5xx    int64   `json:"status_5xx"`
	Blocked      int64   `json:"blocked"`
	OverQuota    int64   `json:"over_quota"`
	Billable     int64   `json:"billable"`
	LatencyMsSum float64 `json:"latency_ms_sum"`
	LatencyMsAvg float64 `json:"latency_ms_avg"`
}

// UsageQuery filters and groups usage. Days are UTC "2006-01-02", inclusive.
type UsageQuery struct {
	Since, Until string
	Identity     string // exact, or a prefix with a trailing *
	Route        string
	Plan         string
	By           []string // identity (key), route, plan, day; empty groups by identity
}

// UsageReport is the /usage document.
type UsageReport struct {
	Schema    string     `json:"schema"`
	Generated string     `json:"generated"`
	Since     string     `json:"since,omitempty"`
	Until     string     `json:"until,omitempty"`
	By        []string   `json:"by"`
	Rows      []UsageRow `json:"rows"`
	Totals    UsageRow   `json:"totals"`
	// Series and MaxSeries show how close the cardinality cap is; Overflow
	// counts observations folded into the "_overflow" identity.
	Series    int   `json:"series"`
	MaxSeries int   `json:"max_series"`
	Overflow  int64 `json:"overflow_observations"`
}

func matchFilter(pat, v string) bool {
	if pat == "" {
		return true
	}
	if p, ok := strings.CutSuffix(pat, "*"); ok {
		return strings.HasPrefix(v, p)
	}
	return pat == v
}

// NormalizeBy validates a grouping list and expands aliases.
func NormalizeBy(by []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, b := range by {
		for _, f := range strings.Split(b, ",") {
			f = strings.TrimSpace(strings.ToLower(f))
			switch f {
			case "":
				continue
			case "key", "identity":
				f = "identity"
			case "route", "plan", "day":
			default:
				return nil, fmt.Errorf("--by %q: want key, route, plan or day", f)
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"identity"}
	}
	return out, nil
}

// Query aggregates the stored series.
func (m *meter) Query(q UsageQuery) UsageReport {
	by, _ := NormalizeBy(q.By)
	has := map[string]bool{}
	for _, b := range by {
		has[b] = true
	}
	m.mu.Lock()
	groups := map[seriesKey]*seriesVal{}
	for k, v := range m.series {
		if (q.Since != "" && k.Day < q.Since) || (q.Until != "" && k.Day > q.Until) {
			continue
		}
		if !matchFilter(q.Identity, k.Identity) || !matchFilter(q.Route, k.Route) || !matchFilter(q.Plan, k.Plan) {
			continue
		}
		g := seriesKey{}
		if has["identity"] {
			g.Identity = k.Identity
		}
		if has["route"] {
			g.Route = k.Route
		}
		if has["plan"] {
			g.Plan = k.Plan
		}
		if has["day"] {
			g.Day = k.Day
		}
		if groups[g] == nil {
			groups[g] = &seriesVal{}
		}
		groups[g].add(*v)
	}
	rep := UsageReport{Schema: "setura.usage/v1", Generated: m.now().UTC().Format(time.RFC3339), Since: q.Since, Until: q.Until, By: by,
		Series: len(m.series), MaxSeries: m.opt.MaxSeries, Overflow: m.overflow, Rows: []UsageRow{}}
	m.mu.Unlock()
	keys := make([]seriesKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Day != b.Day {
			return a.Day < b.Day
		}
		if a.Identity != b.Identity {
			return a.Identity < b.Identity
		}
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		return a.Plan < b.Plan
	})
	var tot seriesVal
	for _, k := range keys {
		v := groups[k]
		tot.add(*v)
		rep.Rows = append(rep.Rows, rowOf(k, v))
	}
	rep.Totals = rowOf(seriesKey{}, &tot)
	return rep
}

func rowOf(k seriesKey, v *seriesVal) UsageRow {
	r := UsageRow{Identity: k.Identity, Route: k.Route, Plan: k.Plan, Day: k.Day, Requests: v.Requests, BytesIn: v.BytesIn, BytesOut: v.BytesOut,
		Status2xx: v.S2xx, Status3xx: v.S3xx, Status4xx: v.S4xx, Status5xx: v.S5xx, Blocked: v.Blocked, OverQuota: v.OverQuota, Billable: v.Billable,
		LatencyMsSum: float64(v.LatencyUS) / 1000}
	if v.Requests > 0 {
		r.LatencyMsAvg = r.LatencyMsSum / float64(v.Requests)
	}
	return r
}

// ---- persistence ----

type stateFile struct {
	Schema   string        `json:"schema"`
	Saved    string        `json:"saved"`
	Overflow int64         `json:"overflow_observations"`
	Series   []stateSeries `json:"series"`
}

type stateSeries struct {
	Day      string `json:"day"`
	Identity string `json:"identity"`
	Route    string `json:"route"`
	Plan     string `json:"plan"`
	seriesVal
}

// load reads the state file (absent is fine) and rebuilds the quota windows.
func (m *meter) load() error {
	path := m.opt.StateFile
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("usage state %s: %w", path, err)
	}
	var sf stateFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return fmt.Errorf("usage state %s is not valid (move it aside to start empty): %w", path, err)
	}
	if sf.Schema != UsageStateSchema {
		return fmt.Errorf("usage state %s: schema %q, want %s", path, sf.Schema, UsageStateSchema)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := dayString(dayIndex(m.now()) - int64(m.opt.RetentionDays))
	m.overflow = sf.Overflow
	for _, s := range sf.Series {
		if s.Day < cutoff {
			continue
		}
		k := seriesKey{s.Day, s.Identity, s.Route, s.Plan}
		v := m.series[k]
		if v == nil {
			v = &seriesVal{}
			m.series[k] = v
		}
		v.add(s.seriesVal)
		t, err := time.Parse("2006-01-02", s.Day)
		if err != nil {
			return fmt.Errorf("usage state %s: bad day %q", path, s.Day)
		}
		q := m.quota(s.Identity)
		di := dayIndex(t)
		d := q.days[di]
		if d == nil {
			d = &dayTot{}
			q.days[di] = d
		}
		d.req += s.Requests
		d.bytes += s.BytesIn + s.BytesOut
	}
	today := dayIndex(m.now())
	for _, q := range m.idents {
		for d := range q.days {
			if d < today-quotaKeepDays {
				delete(q.days, d)
			}
		}
	}
	return nil
}

// prune drops counters older than the retention.
func (m *meter) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	today := dayIndex(m.now())
	cutoff := dayString(today - int64(m.opt.RetentionDays))
	for k := range m.series {
		if k.Day < cutoff {
			delete(m.series, k)
			m.dirty = true
		}
	}
	for id, q := range m.idents {
		for d := range q.days {
			if d < today-quotaKeepDays {
				delete(q.days, d)
			}
		}
		if len(q.days) == 0 {
			delete(m.idents, id)
		}
	}
}

// save writes the counters atomically (temp file, fsync, rename).
func (m *meter) save(force bool) error {
	path := m.opt.StateFile
	if path == "" {
		return nil
	}
	m.prune()
	m.mu.Lock()
	if !m.dirty && !force {
		m.mu.Unlock()
		return nil
	}
	sf := stateFile{Schema: UsageStateSchema, Saved: m.now().UTC().Format(time.RFC3339), Overflow: m.overflow, Series: make([]stateSeries, 0, len(m.series))}
	for k, v := range m.series {
		sf.Series = append(sf.Series, stateSeries{k.Day, k.Identity, k.Route, k.Plan, *v})
	}
	m.dirty = false
	m.mu.Unlock()
	sort.Slice(sf.Series, func(i, j int) bool {
		a, b := sf.Series[i], sf.Series[j]
		return a.Day+"\x00"+a.Identity+"\x00"+a.Route+"\x00"+a.Plan < b.Day+"\x00"+b.Identity+"\x00"+b.Route+"\x00"+b.Plan
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", " ")
	enc.Encode(sf)
	err := writeFileAtomic(path, buf.Bytes())
	m.mu.Lock()
	if err != nil {
		m.persistErr++
		m.dirty = true
	} else {
		m.lastSaved = m.now()
	}
	m.mu.Unlock()
	return err
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".usage-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
