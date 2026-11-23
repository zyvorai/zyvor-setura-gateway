package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fault injection ("game days"). A fault is attached to a route rule, either
// in the snapshot (the rule field or route annotation setura.zyvor.dev/fault)
// or at run time through the admin API (POST /chaos). Faults are built so they
// cannot be left on by accident:
//
//   - a fault without a ttl or an expires time does not compile; the route is
//     refused, exactly like a rule with an invalid auth block;
//   - ttl is capped at MaxFaultTTL, and a fault that has expired is never
//     applied, checked on every request (no timer has to fire);
//   - DELETE /chaos (setura chaos stop) removes every run-time fault at once
//     and disables the faults of the running table until the next reload;
//   - every active fault is listed in /status, /chaos, why and the dashboard.

// FaultKey is the rule field and the route annotation (setura.zyvor.dev/fault,
// setura.zyvor.dev/fault.rule-N) that attach a fault to a rule.
const FaultKey = "setura.zyvor.dev/fault"

// FaultHeader is set on every response the fault engine touched.
const FaultHeader = "X-Setura-Fault"

// MaxFaultTTL is the longest a fault may live without being renewed.
const MaxFaultTTL = 24 * time.Hour

// Fault is the declared form of one fault. Every effect rolls its own percent
// among the requests the fault selects.
type Fault struct {
	Name string `json:"name,omitempty"`
	// Percent is the share of matching requests the fault selects (1-100).
	// Required unless Header is set (then it defaults to 100).
	Percent *int `json:"percent,omitempty"`
	// Header limits the fault to requests carrying it: "X-Chaos: 1" (name and
	// value) or "X-Chaos" (any value).
	Header   string         `json:"header,omitempty"`
	Latency  *FaultLatency  `json:"latency,omitempty"`
	Abort    *FaultAbort    `json:"abort,omitempty"`
	Reset    *FaultReset    `json:"reset,omitempty"`
	Truncate *FaultTruncate `json:"truncate,omitempty"`
	Throttle *FaultThrottle `json:"throttle,omitempty"`
	// TTL (relative, starts when the gateway applies the fault) and Expires
	// (absolute RFC 3339) bound the fault's life. At least one is required.
	TTL     string `json:"ttl,omitempty"`
	Expires string `json:"expires,omitempty"`

	annErr error
}

// FaultLatency adds a delay before the request proceeds: Delay plus a random
// extra of up to Jitter.
type FaultLatency struct {
	Delay   string `json:"delay"`
	Jitter  string `json:"jitter,omitempty"`
	Percent *int   `json:"percent,omitempty"`
}

// FaultAbort answers with Status instead of calling the backend.
type FaultAbort struct {
	Status  int  `json:"status"`
	Percent *int `json:"percent,omitempty"`
}

// FaultReset drops the client connection without an answer (TCP RST when the
// transport allows it).
type FaultReset struct {
	Percent *int `json:"percent,omitempty"`
}

// FaultTruncate cuts the response body after Bytes bytes and aborts the stream.
type FaultTruncate struct {
	Bytes   int  `json:"bytes"`
	Percent *int `json:"percent,omitempty"`
}

// FaultThrottle limits the response to BytesPerSecond.
type FaultThrottle struct {
	BytesPerSecond int  `json:"bytesPerSecond"`
	Percent        *int `json:"percent,omitempty"`
}

// CFault is a compiled fault.
type CFault struct {
	Spec   Fault
	Name   string
	Source string // "config" or "runtime"
	ID     string // runtime faults only
	Route  string // runtime faults: the route key
	Rule   int    // runtime faults: 1-based rule, 0 for every rule

	pct             int
	hdrName, hdrVal string
	delay, jitter   time.Duration
	latPct          int
	abortStatus     int
	abortPct        int
	resetPct        int
	truncBytes      int
	truncPct        int
	bps, thrPct     int
	ttl             time.Duration
	absExpires      time.Time
	expires         atomic.Int64 // unix nanoseconds, 0 until armed
	injected        atomic.Int64
}

func pctOf(p *int, def int, what string) (int, error) {
	if p == nil {
		return def, nil
	}
	if *p < 1 || *p > 100 {
		return 0, fmt.Errorf("%s percent %d must be from 1 to 100", what, *p)
	}
	return *p, nil
}

// ParseFaultBlock decodes a fault strictly (unknown fields are errors) and
// validates it as the gateway does when it compiles the route.
func ParseFaultBlock(raw []byte) (*Fault, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f Fault
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", FaultKey, err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", FaultKey)
	}
	if _, err := CompileFault(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// CompileFault validates a fault. It does not arm it: expiry is set when the
// fault is applied (armFault).
func CompileFault(f *Fault) (*CFault, error) {
	if f.annErr != nil {
		return nil, f.annErr
	}
	c := &CFault{Spec: *f, Name: f.Name, Source: "config", pct: 100}
	if f.Latency == nil && f.Abort == nil && f.Reset == nil && f.Truncate == nil && f.Throttle == nil {
		return nil, fmt.Errorf("fault has no effect: set latency, abort, reset, truncate or throttle")
	}
	var err error
	if f.Header != "" {
		n, v, hasVal := strings.Cut(f.Header, ":")
		c.hdrName, c.hdrVal = strings.TrimSpace(n), strings.TrimSpace(v)
		if c.hdrName == "" || (hasVal && c.hdrVal == "") {
			return nil, fmt.Errorf("fault header %q: want \"Name: value\" or \"Name\"", f.Header)
		}
		if !hasVal {
			c.hdrVal = ""
		}
	}
	if f.Percent == nil && f.Header == "" {
		return nil, fmt.Errorf("fault needs a percent or a header selector, so it can never hit all traffic by omission")
	}
	if c.pct, err = pctOf(f.Percent, 100, "fault"); err != nil {
		return nil, err
	}
	if l := f.Latency; l != nil {
		if c.delay, err = parseDur(l.Delay); err != nil || c.delay <= 0 {
			return nil, fmt.Errorf("latency delay %q must be a positive duration", l.Delay)
		}
		if c.jitter, err = parseDur(l.Jitter); err != nil || c.jitter < 0 {
			return nil, fmt.Errorf("latency jitter %q must be a duration", l.Jitter)
		}
		if c.delay+c.jitter > 5*time.Minute {
			return nil, fmt.Errorf("latency of up to %s is more than the 5m limit", c.delay+c.jitter)
		}
		if c.latPct, err = pctOf(l.Percent, 100, "latency"); err != nil {
			return nil, err
		}
	}
	if a := f.Abort; a != nil {
		if a.Status < 400 || a.Status > 599 {
			return nil, fmt.Errorf("abort status %d must be 400-599", a.Status)
		}
		c.abortStatus = a.Status
		if c.abortPct, err = pctOf(a.Percent, 100, "abort"); err != nil {
			return nil, err
		}
	}
	if r := f.Reset; r != nil {
		if c.resetPct, err = pctOf(r.Percent, 100, "reset"); err != nil {
			return nil, err
		}
	}
	if t := f.Truncate; t != nil {
		if t.Bytes < 0 {
			return nil, fmt.Errorf("truncate bytes %d must not be negative", t.Bytes)
		}
		c.truncBytes = t.Bytes
		if c.truncPct, err = pctOf(t.Percent, 100, "truncate"); err != nil {
			return nil, err
		}
	}
	if t := f.Throttle; t != nil {
		if t.BytesPerSecond < 1 {
			return nil, fmt.Errorf("throttle bytesPerSecond %d must be at least 1", t.BytesPerSecond)
		}
		c.bps = t.BytesPerSecond
		if c.thrPct, err = pctOf(t.Percent, 100, "throttle"); err != nil {
			return nil, err
		}
	}
	if f.TTL == "" && f.Expires == "" {
		return nil, fmt.Errorf("fault has no ttl or expires: a fault must always end (ttl up to %s)", MaxFaultTTL)
	}
	if f.TTL != "" {
		if c.ttl, err = time.ParseDuration(f.TTL); err != nil || c.ttl <= 0 {
			return nil, fmt.Errorf("fault ttl %q must be a positive duration", f.TTL)
		}
		if c.ttl > MaxFaultTTL {
			return nil, fmt.Errorf("fault ttl %s is longer than the %s limit", c.ttl, MaxFaultTTL)
		}
	}
	if f.Expires != "" {
		if c.absExpires, err = time.Parse(time.RFC3339, f.Expires); err != nil {
			return nil, fmt.Errorf("fault expires %q: want an RFC 3339 time", f.Expires)
		}
	}
	return c, nil
}

// arm sets the expiry: now+ttl, or the absolute time, whichever is earlier.
func (c *CFault) arm(now time.Time) {
	var exp time.Time
	if c.ttl > 0 {
		exp = now.Add(c.ttl)
	}
	if !c.absExpires.IsZero() && (exp.IsZero() || c.absExpires.Before(exp)) {
		exp = c.absExpires
	}
	if exp.After(now.Add(MaxFaultTTL)) { // an absolute time cannot outlive the cap either
		exp = now.Add(MaxFaultTTL)
	}
	c.expires.Store(exp.UnixNano())
}

// expiry is the armed expiry, zero when not armed.
func (c *CFault) expiry() time.Time {
	if n := c.expires.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// live reports whether the fault is armed and not yet expired.
func (c *CFault) live(now time.Time) bool {
	n := c.expires.Load()
	return n != 0 && now.UnixNano() < n
}

func (c *CFault) selects(r *http.Request, intn func(int) int) bool {
	if c.hdrName != "" {
		vs := r.Header.Values(c.hdrName)
		if len(vs) == 0 {
			return false
		}
		if c.hdrVal != "" {
			ok := false
			for _, v := range vs {
				ok = ok || strings.TrimSpace(v) == c.hdrVal
			}
			if !ok {
				return false
			}
		}
	}
	return roll(c.pct, intn)
}

func roll(pct int, intn func(int) int) bool {
	return pct >= 100 || (pct > 0 && intn(100) < pct)
}

// kinds lists the effects.
func (c *CFault) kinds() []string {
	var k []string
	if c.delay > 0 {
		k = append(k, "latency")
	}
	if c.abortStatus != 0 {
		k = append(k, "abort")
	}
	if c.resetPct != 0 {
		k = append(k, "reset")
	}
	if c.Spec.Truncate != nil {
		k = append(k, "truncate")
	}
	if c.bps != 0 {
		k = append(k, "throttle")
	}
	return k
}

// summary is a one line description.
func (c *CFault) Summary() string {
	var p []string
	if c.delay > 0 {
		s := "latency +" + c.delay.String()
		if c.jitter > 0 {
			s += " (jitter up to " + c.jitter.String() + ")"
		}
		if c.latPct < 100 {
			s += fmt.Sprintf(" on %d%%", c.latPct)
		}
		p = append(p, s)
	}
	if c.abortStatus != 0 {
		s := fmt.Sprintf("abort %d", c.abortStatus)
		if c.abortPct < 100 {
			s += fmt.Sprintf(" on %d%%", c.abortPct)
		}
		p = append(p, s)
	}
	if c.resetPct != 0 {
		s := "connection reset"
		if c.resetPct < 100 {
			s += fmt.Sprintf(" on %d%%", c.resetPct)
		}
		p = append(p, s)
	}
	if c.Spec.Truncate != nil {
		s := fmt.Sprintf("truncate body after %d bytes", c.truncBytes)
		if c.truncPct < 100 {
			s += fmt.Sprintf(" on %d%%", c.truncPct)
		}
		p = append(p, s)
	}
	if c.bps != 0 {
		s := fmt.Sprintf("throttle to %d B/s", c.bps)
		if c.thrPct < 100 {
			s += fmt.Sprintf(" on %d%%", c.thrPct)
		}
		p = append(p, s)
	}
	return strings.Join(p, ", ")
}

func (c *CFault) Selector() string {
	sel := fmt.Sprintf("%d%% of requests", c.pct)
	if c.hdrName != "" {
		h := c.hdrName
		if c.hdrVal != "" {
			h += ": " + c.hdrVal
		}
		sel = "requests with header " + h
		if c.pct < 100 {
			sel += fmt.Sprintf(" (%d%% of them)", c.pct)
		}
	}
	return sel
}

// FaultView is the public face of a fault: /status, /chaos, why, the dashboard.
type FaultView struct {
	ID        string   `json:"id,omitempty"`
	Name      string   `json:"name,omitempty"`
	Source    string   `json:"source"` // config or runtime
	Route     string   `json:"route"`
	Rule      int      `json:"rule"` // 1-based, 0 = every rule of the route
	Kinds     []string `json:"kinds"`
	Effect    string   `json:"effect"`
	Selector  string   `json:"selector"`
	Percent   int      `json:"percent"`
	Header    string   `json:"header,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
	// RemainingSeconds is how long the fault stays on; 0 when it is not armed yet.
	RemainingSeconds int    `json:"remainingSeconds"`
	TTL              string `json:"ttl,omitempty"`
	Armed            bool   `json:"armed"`
	Injected         int64  `json:"injected"`
}

func (c *CFault) view(route string, rule int, now time.Time) FaultView {
	v := FaultView{ID: c.ID, Name: c.Name, Source: c.Source, Route: route, Rule: rule, Kinds: c.kinds(), Effect: c.Summary(),
		Selector: c.Selector(), Percent: c.pct, Header: c.Spec.Header, TTL: c.Spec.TTL, Injected: c.injected.Load()}
	if e := c.expiry(); !e.IsZero() {
		v.Armed = true
		v.ExpiresAt = e.UTC().Format(time.RFC3339)
		if d := e.Sub(now); d > 0 {
			v.RemainingSeconds = int((d + time.Second - 1) / time.Second)
		}
	}
	return v
}

// annotateFault gives every rule without a fault of its own the fault of its
// annotation (rule-N wins over the route wide key). A value that cannot be
// decoded becomes a fault that fails compilation, so the route turns invalid
// instead of running a half-understood experiment.
func annotateFault(rules []Rule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		if rules[i].Fault != nil {
			continue
		}
		key := FaultRuleAnnotation(i + 1)
		v, ok := ann[key]
		if !ok {
			key = FaultKey
			v, ok = ann[key]
		}
		if !ok {
			continue
		}
		f, err := ParseFaultBlock([]byte(v))
		if err != nil {
			f = &Fault{annErr: fmt.Errorf("annotation %s: %w", key, err)}
		}
		rules[i].Fault = f
	}
}

// FaultRuleAnnotation targets rule n (1-based): setura.zyvor.dev/fault.rule-N.
func FaultRuleAnnotation(n int) string { return FaultKey + ".rule-" + strconv.Itoa(n) }

// OrphanFaultAnnotations lists fault annotation keys that no rule uses.
func OrphanFaultAnnotations(ann map[string]string, rules int) []string {
	var out []string
	for k := range ann {
		if k == FaultKey || !strings.HasPrefix(k, FaultKey) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, FaultKey+".rule-"))
		if !strings.HasPrefix(k, FaultKey+".rule-") || err != nil || n < 1 || n > rules {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- run-time state ----

// chaosState is the server's fault set that is not part of the config.
type chaosState struct {
	mu       sync.Mutex
	runtime  []*CFault
	seq      int
	killedAt time.Time
	killed   atomic.Pointer[Table] // the table whose config faults the kill switch disabled
}

// rulesOf lists the distinct compiled rules of a table.
func (t *Table) allRules() []*CRule {
	seen := map[*CRule]bool{}
	var out []*CRule
	for _, l := range t.Listeners {
		for _, e := range l.Entries {
			if !seen[e.Rule] {
				seen[e.Rule] = true
				out = append(out, e.Rule)
			}
		}
	}
	return out
}

func (t *Table) hasRoute(key string) (rules int, ok bool) {
	for _, r := range t.allRules() {
		if r.RouteKey == key {
			ok = true
			if r.Index+1 > rules {
				rules = r.Index + 1
			}
		}
	}
	return
}

func sameFault(a, b *Fault) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// armFaults starts the clock of every config fault of a new table. A fault
// that is unchanged since the old table keeps its expiry, so a reload for
// another reason never extends an experiment.
func armFaults(old, next *Table, now time.Time) {
	prev := map[string]*CFault{}
	if old != nil {
		for _, r := range old.allRules() {
			if r.Fault != nil {
				prev[fmt.Sprintf("%s#%d", r.RouteKey, r.Index)] = r.Fault
			}
		}
	}
	for _, r := range next.allRules() {
		if r.Fault == nil {
			continue
		}
		if p := prev[fmt.Sprintf("%s#%d", r.RouteKey, r.Index)]; p != nil && sameFault(&p.Spec, &r.Fault.Spec) && !p.expiry().IsZero() {
			r.Fault.expires.Store(p.expires.Load())
			r.Fault.injected.Store(p.injected.Load())
			continue
		}
		r.Fault.arm(now)
	}
}

// RuntimeFault is one fault of a POST /chaos request.
type RuntimeFault struct {
	Route string `json:"route"`
	Rule  int    `json:"rule,omitempty"` // 1-based; 0 = every rule of the route
	Fault Fault  `json:"fault"`
}

// ChaosRequest is the body of POST /chaos: the complete run-time fault set.
type ChaosRequest struct {
	Faults []RuntimeFault `json:"faults"`
}

// ChaosStatus is the /chaos document and the "chaos" block of /status.
type ChaosStatus struct {
	Active   bool        `json:"active"`
	Faults   []FaultView `json:"faults"`
	KilledAt string      `json:"killedAt,omitempty"`
	MaxTTL   string      `json:"maxTTL"`
	Note     string      `json:"note,omitempty"`
}

// SetFaults replaces the run-time fault set. Every fault needs a ttl or an
// expiry and a route that exists; an invalid request changes nothing.
func (s *Server) SetFaults(req ChaosRequest) (ChaosStatus, error) {
	t := s.table.Load()
	if t == nil {
		return ChaosStatus{}, errors.New("not ready")
	}
	now := s.res.now()
	var out []*CFault
	for i, rf := range req.Faults {
		n, ok := t.hasRoute(rf.Route)
		if !ok {
			return ChaosStatus{}, fmt.Errorf("fault %d: no route %q is attached on this gateway", i+1, rf.Route)
		}
		if rf.Rule < 0 || rf.Rule > n {
			return ChaosStatus{}, fmt.Errorf("fault %d: route %s has %d rule(s), not %d", i+1, rf.Route, n, rf.Rule)
		}
		f := rf.Fault
		c, err := CompileFault(&f)
		if err != nil {
			return ChaosStatus{}, fmt.Errorf("fault %d: %w", i+1, err)
		}
		c.Source, c.Route, c.Rule = "runtime", rf.Route, rf.Rule
		c.arm(now)
		if !c.live(now) {
			return ChaosStatus{}, fmt.Errorf("fault %d: expires in the past", i+1)
		}
		out = append(out, c)
	}
	s.chaos.mu.Lock()
	for _, c := range out {
		s.chaos.seq++
		c.ID = fmt.Sprintf("f%d", s.chaos.seq)
	}
	s.chaos.runtime = out
	if len(out) > 0 {
		s.chaos.killedAt = time.Time{}
	}
	s.chaos.mu.Unlock()
	return s.ChaosStatus(), nil
}

// StopFaults is the kill switch: every run-time fault is removed and the
// config faults of the running table are switched off until the next reload.
func (s *Server) StopFaults() ChaosStatus {
	s.chaos.mu.Lock()
	s.chaos.runtime = nil
	s.chaos.killedAt = s.res.now()
	s.chaos.mu.Unlock()
	s.chaos.killed.Store(s.table.Load())
	return s.ChaosStatus()
}

// activeFaults lists the faults that apply to a rule right now.
func (s *Server) activeFaults(t *Table, rule *CRule, now time.Time) []*CFault {
	var out []*CFault
	s.chaos.mu.Lock()
	for _, c := range s.chaos.runtime {
		if c.Route == rule.RouteKey && (c.Rule == 0 || c.Rule == rule.Index+1) && c.live(now) {
			out = append(out, c)
		}
	}
	s.chaos.mu.Unlock()
	if rule.Fault != nil && s.chaos.killed.Load() != t && rule.Fault.live(now) {
		out = append(out, rule.Fault)
	}
	return out
}

// ChaosStatus lists the active faults.
func (s *Server) ChaosStatus() ChaosStatus {
	now := s.res.now()
	st := ChaosStatus{Faults: []FaultView{}, MaxTTL: MaxFaultTTL.String()}
	s.chaos.mu.Lock()
	live := s.chaos.runtime[:0:0]
	for _, c := range s.chaos.runtime {
		if c.live(now) {
			live = append(live, c)
			st.Faults = append(st.Faults, c.view(c.Route, c.Rule, now))
		}
	}
	s.chaos.runtime = live
	if !s.chaos.killedAt.IsZero() {
		st.KilledAt = s.chaos.killedAt.UTC().Format(time.RFC3339)
	}
	s.chaos.mu.Unlock()
	if t := s.table.Load(); t != nil && s.chaos.killed.Load() != t {
		for _, r := range t.allRules() {
			if r.Fault != nil && r.Fault.live(now) {
				st.Faults = append(st.Faults, r.Fault.view(r.RouteKey, r.Index+1, now))
			}
		}
	}
	sort.SliceStable(st.Faults, func(i, j int) bool {
		a, b := st.Faults[i], st.Faults[j]
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		return a.Rule < b.Rule
	})
	st.Active = len(st.Faults) > 0
	return st
}

// chaosForStatus is the block of /status and the dashboard: nil when nothing
// is on and no kill switch was used since the last reload.
func (s *Server) chaosForStatus() *ChaosStatus {
	st := s.ChaosStatus()
	if !st.Active && st.KilledAt == "" {
		return nil
	}
	return &st
}

func (s *Server) chaosHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		writeIndented(w, s.ChaosStatus())
	case http.MethodDelete:
		writeIndented(w, s.StopFaults())
	case http.MethodPost:
		var req ChaosRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			plain(w, http.StatusBadRequest, "chaos request: "+err.Error())
			return
		}
		st, err := s.SetFaults(req)
		if err != nil {
			plain(w, http.StatusBadRequest, err.Error())
			return
		}
		writeIndented(w, st)
	default:
		plain(w, http.StatusMethodNotAllowed, "GET, POST or DELETE")
	}
}

// ---- data path ----

type faultPlan struct {
	delay    time.Duration
	abort    int
	reset    bool
	truncate int // -1 none
	bps      int
	names    []string
	faults   []*CFault
}

// planFaults rolls the dice for one request. nil means no fault hit.
func (s *Server) planFaults(t *Table, rule *CRule, r *http.Request) *faultPlan {
	now := s.res.now()
	fs := s.activeFaults(t, rule, now)
	if len(fs) == 0 {
		return nil
	}
	p := &faultPlan{truncate: -1}
	hit := false
	for _, c := range fs {
		if !c.selects(r, s.intn) {
			continue
		}
		used := false
		if c.delay > 0 && roll(c.latPct, s.intn) {
			d := c.delay
			if c.jitter > 0 {
				d += time.Duration(s.intn(int(c.jitter/time.Microsecond)+1)) * time.Microsecond
			}
			p.delay += d
			used = true
		}
		if c.abortStatus != 0 && p.abort == 0 && roll(c.abortPct, s.intn) {
			p.abort = c.abortStatus
			used = true
		}
		if c.resetPct != 0 && roll(c.resetPct, s.intn) {
			p.reset = true
			used = true
		}
		if c.Spec.Truncate != nil && roll(c.truncPct, s.intn) && (p.truncate < 0 || c.truncBytes < p.truncate) {
			p.truncate = c.truncBytes
			used = true
		}
		if c.bps != 0 && roll(c.thrPct, s.intn) && (p.bps == 0 || c.bps < p.bps) {
			p.bps = c.bps
			used = true
		}
		if used {
			hit = true
			c.injected.Add(1)
			p.faults = append(p.faults, c)
			p.names = append(p.names, c.kinds()...)
		}
	}
	if !hit {
		return nil
	}
	return p
}

var errFaultTruncated = errors.New("setura: response truncated by fault injection")

// faultWriter applies truncate and throttle to the response body.
type faultWriter struct {
	http.ResponseWriter
	s     *Server
	ctx   context.Context
	limit int // -1 unlimited
	bps   int
	sent  int
	cut   bool
}

func (f *faultWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if f.limit >= 0 {
			room := f.limit - f.sent
			if room <= 0 {
				f.cut = true
				f.flush()
				return total, errFaultTruncated
			}
			if len(chunk) > room {
				chunk = chunk[:room]
			}
		}
		if f.bps > 0 {
			if step := max(1, f.bps/10); len(chunk) > step {
				chunk = chunk[:step]
			}
		}
		n, err := f.ResponseWriter.Write(chunk)
		total += n
		f.sent += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if f.bps > 0 {
			f.flush()
			if err := f.s.res.sleep(f.ctx, time.Duration(float64(n)/float64(f.bps)*float64(time.Second))); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (f *faultWriter) flush() {
	if fl, ok := f.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (f *faultWriter) Flush()                      { f.flush() }
func (f *faultWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// resetConn closes the client connection abruptly: with a TCP RST when the
// connection can be hijacked, otherwise by aborting the handler.
func resetConn(rec *recorder) {
	if conn, _, err := http.NewResponseController(rec).Hijack(); err == nil {
		c := conn
		for {
			if u, ok := c.(interface{ NetConn() net.Conn }); ok {
				c = u.NetConn()
				continue
			}
			break
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
		return
	}
	panic(http.ErrAbortHandler)
}

// applyFaults runs the planned fault. It returns true when the request was
// answered (or the connection dropped) and the handler must stop. Truncate and
// throttle wrap the writer, and the returned func must be deferred: it aborts
// the stream when the body was cut.
func (s *Server) applyFaults(rec *recorder, r *http.Request, st *reqState, p *faultPlan) (done bool, after func()) {
	rec.Header().Set(FaultHeader, strings.Join(uniq(p.names), "+"))
	if p.delay > 0 {
		if err := s.res.sleep(r.Context(), p.delay); err != nil {
			st.errMsg = "chaos: client left during injected latency"
			rec.status = 499
			return true, nil
		}
	}
	if p.reset {
		st.errMsg = "chaos: connection reset injected"
		rec.status = http.StatusBadGateway
		resetConn(rec)
		return true, nil
	}
	if p.abort != 0 {
		st.errMsg = fmt.Sprintf("chaos: abort %d injected", p.abort)
		plain(rec, p.abort, "fault injected by setura chaos")
		return true, nil
	}
	if p.truncate >= 0 || p.bps > 0 {
		fw := &faultWriter{ResponseWriter: rec.ResponseWriter, s: s, ctx: r.Context(), limit: p.truncate, bps: p.bps}
		rec.ResponseWriter = fw
		return false, func() {
			if fw.cut {
				st.errMsg = "chaos: response truncated"
				panic(http.ErrAbortHandler)
			}
		}
	}
	return false, nil
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- explain ----

// TraceFault is a fault that applies to the winning rule, for why and explain.
type TraceFault struct {
	FaultView
	Note string `json:"note,omitempty"`
}

// describeFaults lists the config fault of the rule and, when the explainer
// belongs to a running gateway, its run-time faults.
func (e ExplainServer) describeFaults(t *Table, rule *CRule, now time.Time) []TraceFault {
	var out []TraceFault
	if e.chaos != nil {
		e.chaos.mu.Lock()
		for _, c := range e.chaos.runtime {
			if c.Route == rule.RouteKey && (c.Rule == 0 || c.Rule == rule.Index+1) && c.live(now) {
				out = append(out, TraceFault{FaultView: c.view(c.Route, rule.Index+1, now), Note: "injected through the admin API (setura chaos); setura chaos stop removes it"})
			}
		}
		e.chaos.mu.Unlock()
	}
	if f := rule.Fault; f != nil {
		tf := TraceFault{FaultView: f.view(rule.RouteKey, rule.Index+1, now)}
		switch {
		case e.chaos != nil && e.chaos.killed.Load() == t:
			tf.Note = "switched off by the kill switch until the next reload"
		case !tf.Armed:
			tf.Note = fmt.Sprintf("declared in the config; arms for %s when a gateway applies it", f.expiryText())
		case !f.live(now):
			tf.Note = "expired: no longer applied"
		}
		out = append(out, tf)
	}
	return out
}

func (c *CFault) expiryText() string {
	switch {
	case c.ttl > 0 && !c.absExpires.IsZero():
		return c.ttl.String() + " (or until " + c.absExpires.UTC().Format(time.RFC3339) + ")"
	case c.ttl > 0:
		return c.ttl.String()
	}
	return "until " + c.absExpires.UTC().Format(time.RFC3339)
}
