package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// mclock is the injectable clock of metering.
type mclock struct {
	mu sync.Mutex
	t  time.Time
}

func newMClock(t time.Time) *mclock { return &mclock{t: t} }
func (c *mclock) now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *mclock) set(t time.Time)   { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *mclock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var nov10 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

type mrig struct {
	*Server
	up    *upstream
	clk   *mclock
	plans string // plan file path
	state string
}

func writePlans(t *testing.T, path string, doc m) {
	t.Helper()
	if err := os.WriteFile(path, mustJSON(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func apiKeys(names ...string) m {
	var ks l
	for _, n := range names {
		ks = append(ks, m{"name": n, "key": "k-" + n})
	}
	return m{"apiKey": m{"keys": ks}}
}

// meterRig serves a.test/ behind an API key policy with plans in force.
func meterRig(t *testing.T, plans m, policy m, mod func(*Options)) *mrig {
	t.Helper()
	dir := t.TempDir()
	clk := newMClock(nov10)
	rg := &mrig{clk: clk, plans: filepath.Join(dir, "plans.json"), state: filepath.Join(dir, "usage.json")}
	writePlans(t, rg.plans, plans)
	be, ups := upstreams(t, "a")
	rg.up = ups["a"]
	r := rule("/", ref("a", 1))
	if policy != nil {
		r[authKeyT] = policy
	}
	rg.Server = startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), func(o *Options) {
		o.AuthClock = func() time.Time { return t0 }
		o.Meter = MeterOptions{PlansFile: rg.plans, PlansInterval: -1, StateFile: rg.state, StateInterval: -1, Now: clk.now}
		if mod != nil {
			mod(o)
		}
	})
	return rg
}

func (rg *mrig) hit(t *testing.T, key string, extra ...string) reply {
	t.Helper()
	h := append([]string{"X-API-Key", "k-" + key}, extra...)
	return get(t, rg.Server, "a.test", "/", h...)
}

func (rg *mrig) usage(t *testing.T, query string) UsageReport {
	t.Helper()
	rg.FlushAccessLog()
	rec := httptest.NewRecorder()
	rg.usageHandler(false)(rec, httptest.NewRequest("GET", "/usage?"+query, nil))
	if rec.Code != 200 {
		t.Fatalf("/usage?%s: %d %s", query, rec.Code, rec.Body)
	}
	var rep UsageReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func plansOne(name string, p m) m {
	return m{"plans": m{name: p}, "identities": m{"apikey:acme": name}}
}

func TestMonthlyQuotaHardAndCalendarRollover(t *testing.T) {
	rg := meterRig(t, plansOne("free", m{"requestsPerMonth": 3}), apiKeys("acme"), nil)
	for i := 0; i < 3; i++ {
		r := rg.hit(t, "acme")
		if r.Status != 200 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Body)
		}
		h := r.Header
		if h.Get("X-Quota-Limit") != "3" || h.Get("X-Quota-Remaining") != strconv.Itoa(2-i) || h.Get("X-Quota-Window") != "month" || h.Get("X-Quota-Plan") != "free" {
			t.Fatalf("headers on request %d: %v", i, h)
		}
	}
	r := rg.hit(t, "acme")
	if r.Status != 429 {
		t.Fatalf("over quota: %d %s", r.Status, r.Body)
	}
	secs := int(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC).Sub(nov10).Seconds())
	if r.Header.Get("Retry-After") != strconv.Itoa(secs) || r.Header.Get("X-Quota-Reset") != strconv.Itoa(secs) || r.Header.Get("X-Quota-Remaining") != "0" {
		t.Fatalf("429 headers: %v want reset %d", r.Header, secs)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil || body["error"] != "quota_exceeded" || body["quota"] != "requestsPerMonth" || body["plan"] != "free" ||
		body["limit"] != float64(3) || body["used"] != float64(3) || body["reset"] != "2026-12-01T00:00:00Z" {
		t.Fatalf("429 body: %s (%v)", r.Body, err)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", r.Header.Get("Content-Type"))
	}
	if n := len(rg.up.seen()); n != 3 {
		t.Fatalf("backend saw %d requests, want 3 (a blocked request must not reach it)", n)
	}
	// Calendar rollover: the first of the next month starts a fresh window.
	rg.clk.set(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if r := rg.hit(t, "acme"); r.Status != 200 || r.Header.Get("X-Quota-Remaining") != "2" {
		t.Fatalf("after rollover: %d %v", r.Status, r.Header)
	}
	rep := rg.usage(t, "by=key")
	if len(rep.Rows) != 1 || rep.Rows[0].Identity != "apikey:acme" || rep.Rows[0].Requests != 4 || rep.Rows[0].Blocked != 1 {
		t.Fatalf("usage: %+v", rep.Rows)
	}
}

func TestMinuteBurstAndDayWindows(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"requestsPerMinute": 2, "burst": 5, "requestsPerDay": 4}), apiKeys("acme"), nil)
	rg.hit(t, "acme")
	rg.hit(t, "acme")
	r := rg.hit(t, "acme")
	if r.Status != 429 || !strings.Contains(r.Body, `"requestsPerMinute"`) {
		t.Fatalf("minute: %d %s", r.Status, r.Body)
	}
	secs := int(time.Date(2026, 11, 10, 12, 1, 0, 0, time.UTC).Sub(nov10).Seconds())
	if r.Header.Get("Retry-After") != strconv.Itoa(secs) {
		t.Errorf("Retry-After %q want %d", r.Header.Get("Retry-After"), secs)
	}
	rg.clk.add(time.Minute)
	for i := 0; i < 2; i++ {
		if r := rg.hit(t, "acme"); r.Status != 200 {
			t.Fatalf("next minute %d: %d %s", i, r.Status, r.Body)
		}
	}
	rg.clk.add(time.Minute) // a fresh minute, so only the day quota can refuse
	if r := rg.hit(t, "acme"); r.Status != 429 || !strings.Contains(r.Body, `"requestsPerDay"`) {
		t.Fatalf("day quota (4 used): %d %s", r.Status, r.Body)
	}
	rg.clk.set(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	if r := rg.hit(t, "acme"); r.Status != 200 {
		t.Fatalf("next day: %d %s", r.Status, r.Body)
	}
	// Burst is a per-second cap.
	rg2 := meterRig(t, plansOne("p", m{"burst": 2}), apiKeys("acme"), nil)
	rg2.hit(t, "acme")
	rg2.hit(t, "acme")
	if r := rg2.hit(t, "acme"); r.Status != 429 || r.Header.Get("Retry-After") != "1" || !strings.Contains(r.Body, `"burst"`) {
		t.Fatalf("burst: %d %v %s", r.Status, r.Header, r.Body)
	}
	rg2.clk.add(time.Second)
	if r := rg2.hit(t, "acme"); r.Status != 200 {
		t.Fatalf("burst window moved on: %d", r.Status)
	}
}

func TestRollingMonthWindow(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"requestsPerMonth": 2, "window": "rolling"}), apiKeys("acme"), nil)
	start := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	rg.clk.set(start)
	rg.hit(t, "acme")
	rg.hit(t, "acme")
	rg.clk.set(start.AddDate(0, 0, 29)) // day 29: the first day is still inside the window
	r := rg.hit(t, "acme")
	if r.Status != 429 {
		t.Fatalf("day 29: %d", r.Status)
	}
	reset := time.Date(2026, 12, 3, 0, 0, 0, 0, time.UTC) // the first day leaves the window after midnight of day 30
	if want := int(reset.Sub(start.AddDate(0, 0, 29)).Seconds()); r.Header.Get("Retry-After") != strconv.Itoa(want) {
		t.Errorf("Retry-After %s want %d", r.Header.Get("Retry-After"), want)
	}
	rg.clk.set(reset)
	if r := rg.hit(t, "acme"); r.Status != 200 {
		t.Fatalf("day 30: %d %s", r.Status, r.Body)
	}
}

func TestSoftLimitsWarnAndMixedPlans(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"requestsPerMonth": 2, "enforcement": "soft"}), apiKeys("acme"), nil)
	for i := 0; i < 4; i++ {
		r := rg.hit(t, "acme")
		if r.Status != 200 {
			t.Fatalf("soft plan must not block: %d", r.Status)
		}
		warned := r.Header.Get("X-Quota-Warning") != ""
		if warned != (i >= 2) {
			t.Fatalf("request %d warning=%v header %v", i, warned, r.Header)
		}
		if i >= 2 && (r.Header.Get("X-Quota-Remaining") != "0" || !strings.Contains(r.Header.Get("X-Quota-Warning"), "requestsPerMonth")) {
			t.Fatalf("soft headers: %v", r.Header)
		}
	}
	rep := rg.usage(t, "by=key")
	if rep.Rows[0].Requests != 4 || rep.Rows[0].OverQuota != 2 || rep.Rows[0].Blocked != 0 {
		t.Fatalf("soft usage: %+v", rep.Rows[0])
	}
	// A hard plan may keep one quota soft: the day quota warns, the month quota blocks.
	rg = meterRig(t, plansOne("p", m{"requestsPerDay": 1, "requestsPerMonth": 3, "softQuotas": l{"requestsPerDay"}}), apiKeys("acme"), nil)
	for i := 0; i < 3; i++ {
		if r := rg.hit(t, "acme"); r.Status != 200 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Body)
		}
	}
	if r := rg.hit(t, "acme"); r.Status != 429 || !strings.Contains(r.Body, `"requestsPerMonth"`) {
		t.Fatalf("hard month quota: %d %s", r.Status, r.Body)
	}
}

func TestBytesQuota(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"bytesPerMonth": 300}), apiKeys("acme"), nil)
	// Each echo response is a few hundred bytes, so the first request fills the quota.
	r := rg.hit(t, "acme")
	if r.Status != 200 || r.Header.Get("X-Quota-Window") != "month" {
		t.Fatalf("first: %d %v", r.Status, r.Header)
	}
	rg.FlushAccessLog()
	r = rg.hit(t, "acme")
	if r.Status != 429 || !strings.Contains(r.Body, `"bytesPerMonth"`) {
		t.Fatalf("bytes quota: %d %s", r.Status, r.Body)
	}
}

func TestPlanRoutesMethodsAndUnmetered(t *testing.T) {
	plans := m{"plans": m{"ro": m{"methods": l{"GET"}, "routes": l{"t/r"}}, "other": m{"routes": l{"t/zzz"}}},
		"identities": m{"apikey:acme": "ro", "apikey:bob": "other"}, "unmeteredRoutes": l{"t/health*"}}
	rg := meterRig(t, plans, apiKeys("acme", "bob"), nil)
	if r := rg.hit(t, "acme"); r.Status != 200 {
		t.Fatalf("GET: %d", r.Status)
	}
	r := req(t, client(rg.Addr(8080), nil), "http", "POST", "a.test", "/", "", "X-API-Key", "k-acme")
	if r.Status != 403 || !strings.Contains(r.Body, "plan_forbids") || !strings.Contains(r.Body, "methods are GET") {
		t.Fatalf("POST: %d %s", r.Status, r.Body)
	}
	if r := rg.hit(t, "bob"); r.Status != 403 || !strings.Contains(r.Body, "routes are t/zzz") {
		t.Fatalf("route: %d %s", r.Status, r.Body)
	}
	if n := len(rg.up.seen()); n != 1 {
		t.Fatalf("backend saw %d", n)
	}
	// An unmetered route is served without a plan, quota headers or counters.
	plans["unmeteredRoutes"] = l{"t/r"}
	writePlans(t, rg.plans, plans)
	if ch, err := rg.ReloadPlans(); !ch || err != nil {
		t.Fatal(ch, err)
	}
	r = rg.hit(t, "bob")
	if r.Status != 200 || r.Header.Get("X-Quota-Plan") != "" {
		t.Fatalf("unmetered: %d %v", r.Status, r.Header)
	}
}

func TestUnknownIdentityDefaultOrRejected(t *testing.T) {
	plans := m{"plans": m{"free": m{"requestsPerMonth": 1}, "pro": m{"requestsPerMonth": 100}}, "identities": m{"apikey:acme": "pro"}}
	rg := meterRig(t, plans, apiKeys("acme", "newbie"), nil)
	r := rg.hit(t, "newbie")
	if r.Status != 403 || !strings.Contains(r.Body, "unknown_identity") {
		t.Fatalf("no default plan: %d %s", r.Status, r.Body)
	}
	if rg.hit(t, "acme").Header.Get("X-Quota-Plan") != "pro" {
		t.Fatal("mapped identity should get its plan")
	}
	plans["defaultPlan"] = "free"
	writePlans(t, rg.plans, plans)
	rg.ReloadPlans()
	if r := rg.hit(t, "newbie"); r.Status != 200 || r.Header.Get("X-Quota-Plan") != "free" {
		t.Fatalf("default plan: %d %v", r.Status, r.Header)
	}
	if r := rg.hit(t, "newbie"); r.Status != 429 {
		t.Fatalf("default plan quota: %d", r.Status)
	}
	rep := rg.usage(t, "by=plan")
	got := map[string]int64{}
	for _, row := range rep.Rows {
		got[row.Plan] = row.Blocked
	}
	if got["_none"] != 1 || got["free"] != 1 {
		t.Fatalf("blocked by plan: %v", got)
	}
}

func TestJWTPlanClaimAndTenant(t *testing.T) {
	k := newRSAKey(t, "k1")
	plans := m{"plans": m{"free": m{"requestsPerMonth": 10}, "gold": m{"requestsPerMonth": 1000}},
		"defaultPlan": "free", "identities": m{"tenant:globex": "gold"}}
	rg := meterRig(t, plans, m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}}, nil)
	call := func(extra map[string]any) reply {
		return rg.hit0(t, bearer(k.sign(t, nil, claims(extra))))
	}
	r := call(nil)
	if r.Status != 200 || r.Header.Get("X-Quota-Plan") != "free" || r.Header.Get("X-Quota-Limit") != "10" {
		t.Fatalf("subject alice, default plan: %d %v", r.Status, r.Header)
	}
	if r := call(map[string]any{"plan": "gold"}); r.Header.Get("X-Quota-Plan") != "gold" {
		t.Fatalf("plan claim: %v", r.Header)
	}
	if r := call(map[string]any{"plan": "nonexistent"}); r.Header.Get("X-Quota-Plan") != "free" {
		t.Fatalf("a claim naming no plan falls through to the default: %v", r.Header)
	}
	if r := call(map[string]any{"tenant": "globex"}); r.Header.Get("X-Quota-Plan") != "gold" {
		t.Fatalf("tenant mapping: %v", r.Header)
	}
	rep := rg.usage(t, "by=key")
	ids := map[string]int64{}
	for _, row := range rep.Rows {
		ids[row.Identity] = row.Requests
	}
	if ids["jwt:alice"] != 3 || ids["tenant:globex"] != 1 {
		t.Fatalf("identities: %v", ids)
	}
}

func (rg *mrig) hit0(t *testing.T, hdr []string) reply {
	t.Helper()
	return get(t, rg.Server, "a.test", "/", hdr...)
}

func TestTrustedPlanHeader(t *testing.T) {
	mk := func(from string) *mrig {
		return meterRig(t, m{"plans": m{"free": m{"requestsPerMonth": 5}, "gold": m{"requestsPerMonth": 500}}, "defaultPlan": "free",
			"planHeader": m{"name": "X-Plan", "tenantName": "X-Tenant", "trustedFrom": l{from}}}, apiKeys("acme"), nil)
	}
	rg := mk("127.0.0.1/32")
	r := rg.hit(t, "acme", "X-Plan", "gold", "X-Tenant", "initech")
	if r.Header.Get("X-Quota-Plan") != "gold" {
		t.Fatalf("trusted header: %v", r.Header)
	}
	if rep := rg.usage(t, "by=key"); rep.Rows[0].Identity != "tenant:initech" {
		t.Fatalf("tenant from header: %+v", rep.Rows)
	}
	rg = mk("10.0.0.0/8") // the test client is 127.0.0.1: an untrusted peer cannot pick its plan
	if r := rg.hit(t, "acme", "X-Plan", "gold", "X-Tenant", "initech"); r.Header.Get("X-Quota-Plan") != "free" {
		t.Fatalf("untrusted header was believed: %v", r.Header)
	}
}

func TestPlanFileValidation(t *testing.T) {
	good := `{"plans":{"a":{"requestsPerMonth":1}},"defaultPlan":"a"}`
	if _, err := ParsePlans([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"unknown field":     `{"plans":{"a":{}},"bogus":1}`,
		"no plans":          `{"plans":{}}`,
		"bad default":       `{"plans":{"a":{}},"defaultPlan":"b"}`,
		"negative":          `{"plans":{"a":{"requestsPerDay":-1}}}`,
		"price no currency": `{"plans":{"a":{"pricePer1kRequests":1}}}`,
		"bad window":        `{"plans":{"a":{"window":"weekly"}}}`,
		"bad enforcement":   `{"plans":{"a":{"enforcement":"maybe"}}}`,
		"bad soft quota":    `{"plans":{"a":{"softQuotas":["nope"]}}}`,
		"lowercase method":  `{"plans":{"a":{"methods":["get"]}}}`,
		"bad route":         `{"plans":{"a":{"routes":["noslash"]}}}`,
		"mid wildcard":      `{"plans":{"a":{"routes":["a*/b"]}}}`,
		"bad identity kind": `{"plans":{"a":{}},"identities":{"bob":"a"}}`,
		"identity bad plan": `{"plans":{"a":{}},"identities":{"apikey:x":"zz"}}`,
		"bad ip identity":   `{"plans":{"a":{}},"identities":{"ip:nope":"a"}}`,
		"header no trust":   `{"plans":{"a":{}},"planHeader":{"name":"X-Plan"}}`,
		"trailing data":     `{"plans":{"a":{}}} {}`,
		"bad plan name":     `{"plans":{"a b":{}}}`,
		"future version":    `{"version":2,"plans":{"a":{}}}`,
	} {
		if _, err := ParsePlans([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlanHotReloadKeepsPreviousOnError(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"requestsPerMonth": 1}), apiKeys("acme"), nil)
	if r := rg.hit(t, "acme"); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if r := rg.hit(t, "acme"); r.Status != 429 {
		t.Fatal(r.Status)
	}
	// Raise the quota: the new plan applies to the next request, usage is kept.
	writePlans(t, rg.plans, plansOne("p", m{"requestsPerMonth": 2}))
	if ch, err := rg.ReloadPlans(); !ch || err != nil {
		t.Fatal(ch, err)
	}
	if r := rg.hit(t, "acme"); r.Status != 200 || r.Header.Get("X-Quota-Limit") != "2" {
		t.Fatalf("after raise: %d %v", r.Status, r.Header)
	}
	if ch, err := rg.ReloadPlans(); ch || err != nil {
		t.Fatalf("unchanged file: %v %v", ch, err)
	}
	// A broken file is refused, counted once, and the previous plans keep serving.
	hash := rg.Plans().Hash
	os.WriteFile(rg.plans, []byte(`{"plans":`), 0o600)
	if _, err := rg.ReloadPlans(); err == nil {
		t.Fatal("broken file accepted")
	}
	rg.ReloadPlans()
	if rg.Plans().Hash != hash {
		t.Fatal("previous plans were replaced")
	}
	if r := rg.hit(t, "acme"); r.Status != 429 || r.Header.Get("X-Quota-Limit") != "2" {
		t.Fatalf("old plan still enforced: %d %v", r.Status, r.Header)
	}
	rec := httptest.NewRecorder()
	rg.metrics(rec, nil)
	if out := rec.Body.String(); !strings.Contains(out, "setura_gateway_plans_reload_errors_total 1\n") {
		t.Fatalf("reload errors should be counted once per bad file:\n%s", out)
	}
	if doc, _ := rg.plansDoc().(*PlansDoc); doc == nil || doc.ReloadError == "" || doc.Hash != hash {
		t.Fatalf("/plans: %+v", doc)
	}
}

func TestPlanFileWatcherReloads(t *testing.T) {
	dir := t.TempDir()
	plans := filepath.Join(dir, "plans.json")
	writePlans(t, plans, plansOne("p", m{"requestsPerMonth": 1}))
	s, up := authServer(t, apiKeys("acme"), func(o *Options) {
		o.Meter = MeterOptions{PlansFile: plans, PlansInterval: 5 * time.Millisecond, Now: newMClock(nov10).now}
	})
	_ = up
	first := s.Plans().Hash
	writePlans(t, plans, plansOne("p", m{"requestsPerMonth": 7}))
	deadline := time.Now().Add(5 * time.Second)
	for s.Plans().Hash == first {
		if time.Now().After(deadline) {
			t.Fatal("the watcher never picked up the new plan file")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if r := get(t, s, "a.test", "/", "X-API-Key", "k-acme"); r.Header.Get("X-Quota-Limit") != "7" {
		t.Fatalf("%v", r.Header)
	}
}

func TestUsageEndpointFiltersCSVAndCounters(t *testing.T) {
	plans := m{"plans": m{"free": m{}, "pro": m{}}, "identities": m{"apikey:acme": "pro", "apikey:bob": "free"}}
	rg := meterRig(t, plans, apiKeys("acme", "bob"), nil)
	rg.hit(t, "acme")
	rg.hit(t, "acme")
	rg.hit(t, "bob")
	req(t, client(rg.Addr(8080), nil), "http", "POST", "a.test", "/x", "12345", "X-API-Key", "k-bob")
	rep := rg.usage(t, "by=key")
	if len(rep.Rows) != 2 || rep.Totals.Requests != 4 {
		t.Fatalf("%+v", rep)
	}
	acme := rep.Rows[0]
	if acme.Identity != "apikey:acme" || acme.Requests != 2 || acme.Status2xx != 2 || acme.Billable != 2 || acme.BytesOut <= 0 || acme.LatencyMsSum <= 0 {
		t.Fatalf("acme: %+v", acme)
	}
	if bob := rep.Rows[1]; bob.BytesIn != 5 || bob.Requests != 2 {
		t.Fatalf("bob bytes in: %+v", bob)
	}
	if r := rg.usage(t, "identity=apikey:b*&by=route,plan"); len(r.Rows) != 1 || r.Rows[0].Route != "t/r" || r.Rows[0].Plan != "free" || r.Totals.Requests != 2 {
		t.Fatalf("filter: %+v", r)
	}
	if r := rg.usage(t, "plan=pro&by=plan"); len(r.Rows) != 1 || r.Rows[0].Requests != 2 {
		t.Fatalf("plan filter: %+v", r.Rows)
	}
	// since/until work on UTC days
	rg.clk.set(nov10.AddDate(0, 0, 5))
	rg.hit(t, "acme")
	if r := rg.usage(t, "since=2026-11-12&by=day"); len(r.Rows) != 1 || r.Rows[0].Day != "2026-11-15" {
		t.Fatalf("since: %+v", r.Rows)
	}
	if r := rg.usage(t, "period=2026-11&by=key"); r.Totals.Requests != 5 {
		t.Fatalf("period: %+v", r.Totals)
	}
	if r := rg.usage(t, "period=2026-12&by=key"); len(r.Rows) != 0 {
		t.Fatalf("empty period: %+v", r.Rows)
	}
	if r := rg.usage(t, "since=3d&by=key"); r.Totals.Requests != 1 {
		t.Fatalf("relative since: %+v", r.Totals)
	}
	// CSV
	rec := httptest.NewRecorder()
	rg.usageHandler(true)(rec, httptest.NewRequest("GET", "/usage.csv?by=key,plan", nil))
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" || len(lines) != 3 || !strings.HasPrefix(lines[0], "identity,plan,requests,billable,") ||
		!strings.HasPrefix(lines[1], "apikey:acme,pro,3,3,") {
		t.Fatalf("csv: %q", rec.Body.String())
	}
	// bad input
	rec = httptest.NewRecorder()
	rg.usageHandler(false)(rec, httptest.NewRequest("GET", "/usage?by=nope", nil))
	if rec.Code != 400 {
		t.Fatalf("bad by: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	rg.usageHandler(false)(rec, httptest.NewRequest("GET", "/usage?since=yesterday-ish", nil))
	if rec.Code != 400 {
		t.Fatalf("bad since: %d", rec.Code)
	}
}

func TestCSVDefusesFormulaIdentities(t *testing.T) {
	if csvSafe("=cmd|' /C calc'!A0") != "'=cmd|' /C calc'!A0" || csvSafe("apikey:x") != "apikey:x" {
		t.Fatal("csvSafe")
	}
}

func TestUsagePersistsAcrossRestart(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{"requestsPerMonth": 3}), apiKeys("acme"), nil)
	rg.hit(t, "acme")
	rg.hit(t, "acme")
	rg.FlushAccessLog()
	if err := rg.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(rg.state)
	if err != nil || !strings.Contains(string(raw), UsageStateSchema) || !strings.Contains(string(raw), `"identity": "apikey:acme"`) {
		t.Fatalf("state file: %v %s", err, raw)
	}
	if st, _ := os.Stat(rg.state); st.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v", st.Mode())
	}
	if tmp, _ := filepath.Glob(filepath.Join(filepath.Dir(rg.state), ".usage-*")); len(tmp) != 0 {
		t.Errorf("temp files left behind: %v", tmp)
	}
	rg.Close()
	// A new process with the same files continues the month.
	be, ups := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	r[authKeyT] = apiKeys("acme")
	s2 := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), func(o *Options) {
		o.Meter = MeterOptions{PlansFile: rg.plans, PlansInterval: -1, StateFile: rg.state, StateInterval: -1, Now: rg.clk.now}
	})
	if x := get(t, s2, "a.test", "/", "X-API-Key", "k-acme"); x.Status != 200 || x.Header.Get("X-Quota-Remaining") != "0" {
		t.Fatalf("third request of the month after restart: %d %v", x.Status, x.Header)
	}
	if x := get(t, s2, "a.test", "/", "X-API-Key", "k-acme"); x.Status != 429 {
		t.Fatalf("restart must not reset the month: %d", x.Status)
	}
	if len(ups["a"].seen()) != 1 {
		t.Fatalf("backend saw %d", len(ups["a"].seen()))
	}
	s2.FlushAccessLog()
	if rep := s2.meter.Query(UsageQuery{By: []string{"key"}}); rep.Rows[0].Requests != 3 || rep.Rows[0].Blocked != 1 {
		t.Fatalf("persisted counters: %+v", rep.Rows)
	}
}

func TestCorruptUsageStateIsReported(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "u.json")
	os.WriteFile(state, []byte("{not json"), 0o600)
	plans := filepath.Join(dir, "p.json")
	writePlans(t, plans, plansOne("p", m{}))
	s := New(Options{Admin: "off", Meter: MeterOptions{PlansFile: plans, StateFile: state, PlansInterval: -1, StateInterval: -1}})
	defer s.Close()
	cfg, _ := ParseConfig(snap(httpGateway(""), map[string]m{}, nil), dir)
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("Apply = %v", err)
	}
}

func TestPeriodicStateWrite(t *testing.T) {
	rg := meterRig(t, plansOne("p", m{}), apiKeys("acme"), func(o *Options) { o.Meter.StateInterval = 5 * time.Millisecond })
	rg.hit(t, "acme")
	rg.FlushAccessLog()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if raw, err := os.ReadFile(rg.state); err == nil && strings.Contains(string(raw), "apikey:acme") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the periodic snapshot never wrote the state file")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCardinalityCapFoldsIntoOverflow(t *testing.T) {
	names := []string{"k1", "k2", "k3", "k4", "k5", "k6"}
	rg := meterRig(t, m{"plans": m{"free": m{"requestsPerMonth": 1000}}, "defaultPlan": "free"}, apiKeys(names...), func(o *Options) { o.Meter.MaxSeries = 3 })
	for _, n := range names {
		if r := rg.hit(t, n); r.Status != 200 {
			t.Fatalf("%s: %d", n, r.Status)
		}
	}
	rep := rg.usage(t, "by=key")
	if len(rep.Rows) != 4 || rep.Totals.Requests != 6 {
		t.Fatalf("rows %d totals %+v", len(rep.Rows), rep.Totals)
	}
	var over int64
	for _, r := range rep.Rows {
		if r.Identity == "_overflow" {
			over = r.Requests
		}
	}
	if over != 3 || rep.Overflow < 3 || rep.Series > 4 || rep.MaxSeries != 3 {
		t.Fatalf("overflow %d, report %+v", over, rep)
	}
	// Quota identities are capped too: the overflow identities share one allowance.
	rg.meter.mu.Lock()
	n := len(rg.meter.idents)
	rg.meter.mu.Unlock()
	if n > 4 {
		t.Fatalf("%d quota identities held with a cap of 3", n)
	}
}

func TestMetricsHaveBoundedLabels(t *testing.T) {
	rg := meterRig(t, plansOne("free", m{"requestsPerMonth": 1}), apiKeys("acme"), nil)
	rg.hit(t, "acme")
	rg.hit(t, "acme")
	rg.FlushAccessLog()
	rec := httptest.NewRecorder()
	rg.metrics(rec, nil)
	out := rec.Body.String()
	for _, want := range []string{
		`setura_gateway_usage_requests_total{plan="free",route="t/r",code="2xx"} 1`,
		`setura_gateway_quota_exceeded_total{plan="free",quota="requestsPerMonth",mode="hard"} 1`,
		`setura_gateway_usage_series 1`,
		`setura_gateway_plans 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "acme") {
		t.Error("an identity leaked into a metric label")
	}
}

func TestAdminEndpointsOverHTTP(t *testing.T) {
	dir := t.TempDir()
	plans := filepath.Join(dir, "plans.json")
	writePlans(t, plans, plansOne("p", m{"requestsPerMonth": 5, "pricePer1kRequests": 2.5, "currency": "USD"}))
	be, ups := upstreams(t, "a")
	_ = ups
	r := rule("/", ref("a", 1))
	r[authKeyT] = apiKeys("acme")
	cfg := filepath.Join(dir, "gw.json")
	os.WriteFile(cfg, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), 0o600)
	s, _, _ := startFile(t, cfg, func(o *Options) {
		o.Meter = MeterOptions{PlansFile: plans, PlansInterval: -1, Now: newMClock(nov10).now}
	})
	get(t, s, "a.test", "/", "X-API-Key", "k-acme")
	s.FlushAccessLog()
	for path, want := range map[string]string{"/usage?by=key": `"identity": "apikey:acme"`, "/usage.csv": "identity,requests", "/plans": `"pricePer1kRequests": 2.5`} {
		resp, err := http.Get("http://" + s.AdminAddr() + path)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(b.String(), want) {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b.String())
		}
	}
}

func TestUsageEndpointWithoutPlans(t *testing.T) {
	s := startServer(t, snap(httpGateway(""), map[string]m{}, nil), nil)
	rec := httptest.NewRecorder()
	s.usageHandler(false)(rec, httptest.NewRequest("GET", "/usage", nil))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "--plans") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if s.plansDoc() != nil {
		t.Fatal("plansDoc without plans")
	}
}

func TestInvoice(t *testing.T) {
	rep := UsageReport{Rows: []UsageRow{
		{Identity: "apikey:acme", Plan: "pro", Requests: 12000, Billable: 11500, Blocked: 3},
		{Identity: "apikey:bob", Plan: "free", Requests: 90, Billable: 90},
		{Identity: "apikey:cy", Plan: "pro", Requests: 10, Billable: 10},
	}}
	plans := map[string]*Plan{"pro": {PricePer1kRequests: 1.25, Currency: "USD", IncludedRequests: 1000}, "free": {}}
	inv := BuildInvoice("2026-11", rep, plans, nov10)
	a := inv.Lines[0]
	if a.Chargeable != 10500 || a.Amount != 13.13 { // 10.5 * 1.25 = 13.125 -> 13.13
		t.Fatalf("acme: %+v", a)
	}
	if b := inv.Lines[1]; b.Amount != 0 || b.Currency != "" {
		t.Fatalf("free plan: %+v", b)
	}
	if c := inv.Lines[2]; c.Chargeable != 0 || c.Amount != 0 {
		t.Fatalf("inside the allowance: %+v", c)
	}
	if inv.Totals["USD"] != 13.13 || inv.Period != "2026-11" {
		t.Fatalf("totals: %+v", inv)
	}
}

func TestPeriodAndSinceParsing(t *testing.T) {
	if s, e, err := PeriodDays("2026-02"); err != nil || s != "2026-02-01" || e != "2026-02-28" {
		t.Fatal(s, e, err)
	}
	if _, _, err := PeriodDays("2026-13"); err == nil {
		t.Fatal("month 13")
	}
	for in, want := range map[string]string{"7d": "2026-11-03", "36h": "2026-11-09", "2026-10-01": "2026-10-01", "2026-10-05T23:00:00+02:00": "2026-10-05", "": ""} {
		if got, err := ParseSince(in, nov10); err != nil || got != want {
			t.Errorf("%q: %q %v want %q", in, got, err, want)
		}
	}
}

func TestExplainPlanOfflineAndLive(t *testing.T) {
	plans := m{"plans": m{"pro": m{"requestsPerMonth": 3, "methods": l{"GET"}, "enforcement": "hard", "softQuotas": l{"requestsPerDay"}, "requestsPerDay": 1}},
		"identities": m{"apikey:acme": "pro"}}
	rg := meterRig(t, plans, apiKeys("acme"), nil)
	tb := rg.Table()
	ps := rg.Plans()
	ex := func(live bool, hdr ...string) *TracePlan {
		q, err := ParseExplainRequest("GET", "http://a.test:8080/", hdr, "", "")
		if err != nil {
			t.Fatal(err)
		}
		q.Now = nov10
		if live {
			q.Live, q.Server = true, rg.liveServerPolicy()
		} else {
			q.Server = ExplainServer{Plans: ps}
		}
		tr := Explain(tb, q)
		if tr.Winner == nil || tr.Winner.Plan == nil {
			t.Fatalf("no plan in trace: %+v", tr.Winner)
		}
		return tr.Winner.Plan
	}
	p := ex(false, "X-API-Key: k-acme")
	if !p.Applies || p.Plan != "pro" || p.Identity != "apikey:acme" || p.Decision != "allow" || p.Live || len(p.Limits) != 2 ||
		!strings.Contains(p.Source, "identities[apikey:acme]") {
		t.Fatalf("offline: %+v", p)
	}
	if p := ex(false, "X-API-Key: k-wrong"); p.Applies || !strings.Contains(p.Note, "auth policy") {
		t.Fatalf("denied by auth first: %+v", p)
	}
	if p := ex(false); p.Applies {
		t.Fatalf("no credential: %+v", p)
	}
	rg.hit(t, "acme")
	rg.hit(t, "acme") // over the soft daily quota, month at 2 of 3
	rg.FlushAccessLog()
	p = ex(true, "X-API-Key: k-acme")
	if !p.Live || p.Decision != "warn" || p.Mode != "mixed" {
		t.Fatalf("live: %+v", p)
	}
	byName := map[string]TraceQuota{}
	for _, q := range p.Limits {
		byName[q.Name] = q
	}
	if mq := byName["requestsPerMonth"]; mq.Used == nil || *mq.Used != 2 || mq.Mode != "hard" || *mq.ResetSeconds <= 0 {
		t.Fatalf("month: %+v", mq)
	}
	if dq := byName["requestsPerDay"]; dq.Mode != "soft" || !*dq.Exceeded {
		t.Fatalf("day: %+v", dq)
	}
	rg.hit(t, "acme")
	if p = ex(true, "X-API-Key: k-acme"); p.Decision != "quota" || p.Status != 429 {
		t.Fatalf("exhausted: %+v", p)
	}
	// The explainer does not consume quota.
	rg.FlushAccessLog()
	if rep := rg.usage(t, "by=key"); rep.Rows[0].Requests != 3 {
		t.Fatalf("why consumed quota: %+v", rep.Rows[0])
	}
	// The admin endpoint returns the same plan block.
	rec := httptest.NewRecorder()
	rg.handleWhy(rec, httptest.NewRequest("GET", "/why?method=GET&url=http://a.test:8080/&header=X-API-Key:+k-acme", nil))
	var tr Trace
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil || tr.Winner == nil || tr.Winner.Plan == nil || tr.Winner.Plan.Plan != "pro" || !tr.Winner.Plan.Live {
		t.Fatalf("/why: %v %s", err, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "k-acme") {
		t.Error("/why echoed the API key")
	}
}

func TestMethodNotInPlanExplain(t *testing.T) {
	rg := meterRig(t, plansOne("ro", m{"methods": l{"GET"}}), apiKeys("acme"), nil)
	q, _ := ParseExplainRequest("DELETE", "http://a.test:8080/", []string{"X-API-Key: k-acme"}, "", "")
	q.Server = ExplainServer{Plans: rg.Plans()}
	tr := Explain(rg.Table(), q)
	if p := tr.Winner.Plan; p.Decision != "forbidden" || p.Status != 403 || !strings.Contains(p.Note, "methods are GET") {
		t.Fatalf("%+v", p)
	}
	q.Server = ExplainServer{}
	if p := Explain(rg.Table(), q).Winner.Plan; p.Enabled || !strings.Contains(p.Note, "--plans") {
		t.Fatalf("%+v", p)
	}
}

func TestQuotaHeadersNotDuplicatedByUpstream(t *testing.T) {
	// An upstream that sends its own X-Quota-* headers must not confuse clients.
	be, ups := upstreams(t, "a")
	_ = ups
	dir := t.TempDir()
	plans := filepath.Join(dir, "p.json")
	writePlans(t, plans, plansOne("p", m{"requestsPerMonth": 9}))
	r := rule("/", ref("a", 1))
	r[authKeyT] = apiKeys("acme")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be), func(o *Options) {
		o.Meter = MeterOptions{PlansFile: plans, PlansInterval: -1, Now: newMClock(nov10).now}
	})
	// the shared upstream helper does not set them, so inject through a wrapper handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Quota-Limit", "999999")
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	cfg, _ := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("a.test", func() m { x := rule("/", ref("a", 1)); x[authKeyT] = apiKeys("acme"); return x }())}, map[string]any{"a": strings.TrimPrefix(srv.URL, "http://")}), dir)
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h2"}); err != nil {
		t.Fatal(err)
	}
	x := get(t, s, "a.test", "/", "X-API-Key", "k-acme")
	if vals := x.Header.Values("X-Quota-Limit"); len(vals) != 1 || vals[0] != "9" {
		t.Fatalf("X-Quota-Limit = %v", vals)
	}
}

func TestMeterFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--config", "x.json", "--usage-state", "u.json"},
		{"run", "--config", "x.json", "--plans", "p.json", "--usage-max-series", "-1"},
		{"run", "--config", "x.json", "--plans", "p.json", "--usage-interval", "-1s"},
		{"run", "--config", "x.json", "--plans", "p.json", "--usage-retention-days", "-3"},
	} {
		var out, errb strings.Builder
		if code := Main(args, &out, &errb, nil); code != 2 || errb.Len() == 0 {
			t.Errorf("%v: code %d %q", args, code, errb.String())
		}
	}
	var out, errb strings.Builder
	if Main([]string{"run", "--config", filepath.Join(t.TempDir(), "gone.json"), "--plans", "p.json", "--admin", "off"}, &out, &errb, nil) != 2 {
		t.Error("a missing config should still fail")
	}
}
