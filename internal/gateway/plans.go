package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// API plans: named quota sets, and the mapping from an identity (API key, JWT
// subject, tenant, client address) to a plan. See docs/metering-plans.md.

// PlansSchema is the version stamped in plan files; "version" may be omitted.
const PlansVersion = 1

// Quota names, as written in the plan file, in 429 bodies and in softQuotas.
const (
	QuotaBurst    = "burst"
	QuotaMinute   = "requestsPerMinute"
	QuotaDay      = "requestsPerDay"
	QuotaMonth    = "requestsPerMonth"
	QuotaBytesMon = "bytesPerMonth"
)

var quotaNames = []string{QuotaBurst, QuotaMinute, QuotaDay, QuotaMonth, QuotaBytesMon}

// PlanFile is the JSON document read with --plans.
type PlanFile struct {
	Version int `json:"version,omitempty"`
	// DefaultPlan is given to identities that no mapping names. Empty rejects
	// them with 403.
	DefaultPlan string `json:"defaultPlan,omitempty"`
	// UnmeteredRoutes are never metered or limited (health checks, docs). A
	// route is "namespace/name"; a trailing * matches a prefix.
	UnmeteredRoutes []string `json:"unmeteredRoutes,omitempty"`
	// PlanClaim is the JWT claim that names a plan (default "plan"); TenantClaim
	// names the tenant (default "tenant"). Dotted names reach into objects.
	PlanClaim   string `json:"planClaim,omitempty"`
	TenantClaim string `json:"tenantClaim,omitempty"`
	// PlanHeader takes the plan, and optionally the tenant, from headers set by
	// a trusted upstream. They are believed only from the listed peers.
	PlanHeader *PlanHeader      `json:"planHeader,omitempty"`
	Plans      map[string]*Plan `json:"plans"`
	// Identities maps "apikey:NAME", "jwt:SUBJECT", "basic:USER", "tenant:ID"
	// or "ip:ADDRESS" to a plan name.
	Identities map[string]string `json:"identities,omitempty"`
}

// PlanHeader reads plan and tenant from request headers of a trusted proxy.
type PlanHeader struct {
	Name        string   `json:"name"`
	TenantName  string   `json:"tenantName,omitempty"`
	TrustedFrom []string `json:"trustedFrom"`
}

// Plan is one named plan. Zero quotas are unlimited.
type Plan struct {
	Burst             int64 `json:"burst,omitempty"` // most requests in any one second
	RequestsPerMinute int64 `json:"requestsPerMinute,omitempty"`
	RequestsPerDay    int64 `json:"requestsPerDay,omitempty"`
	RequestsPerMonth  int64 `json:"requestsPerMonth,omitempty"`
	BytesPerMonth     int64 `json:"bytesPerMonth,omitempty"` // request plus response body bytes
	// Window "calendar" (default, UTC) resets month quotas on the 1st; "rolling"
	// counts the last 30 days.
	Window string `json:"window,omitempty"`
	// Enforcement "hard" (default) answers 429 over a quota; "soft" only warns
	// (headers, metrics, the over-quota counter used for overage billing).
	Enforcement string   `json:"enforcement,omitempty"`
	SoftQuotas  []string `json:"softQuotas,omitempty"` // quotas that stay soft in a hard plan
	// Routes and Methods restrict what the plan may call. Empty allows all.
	Routes  []string `json:"routes,omitempty"`
	Methods []string `json:"methods,omitempty"`
	// PricePer1kRequests is the price of 1000 billable requests; IncludedRequests
	// is the free allowance per identity and invoice period.
	PricePer1kRequests float64 `json:"pricePer1kRequests,omitempty"`
	Currency           string  `json:"currency,omitempty"`
	IncludedRequests   int64   `json:"includedRequests,omitempty"`
	Description        string  `json:"description,omitempty"`
}

var (
	planNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	identKinds = map[string]bool{"apikey": true, "jwt": true, "basic": true, "tenant": true, "ip": true}
)

// PlanSet is a parsed, validated plan file.
type PlanSet struct {
	File    *PlanFile
	Hash    string
	planCl  string
	tenCl   string
	trusted trustedNets
	soft    map[string]map[string]bool // plan -> soft quota names
}

// ParsePlans decodes a plan file strictly and validates it.
func ParsePlans(raw []byte) (*PlanSet, error) {
	if len(raw) > 4<<20 {
		return nil, errors.New("plan file is larger than 4 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f PlanFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("plans: %w", err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("plans: trailing data after the JSON object")
	}
	ps := &PlanSet{File: &f, soft: map[string]map[string]bool{}}
	sum := sha256.Sum256(raw)
	ps.Hash = hex.EncodeToString(sum[:8])
	if err := ps.validate(); err != nil {
		return nil, err
	}
	return ps, nil
}

func (ps *PlanSet) validate() error {
	f := ps.File
	if f.Version != 0 && f.Version != PlansVersion {
		return fmt.Errorf("plans: version %d is not supported (want %d)", f.Version, PlansVersion)
	}
	if len(f.Plans) == 0 {
		return errors.New("plans: define at least one plan under \"plans\"")
	}
	for _, name := range sortedKeys(f.Plans) {
		p := f.Plans[name]
		if !planNameRe.MatchString(name) {
			return fmt.Errorf("plans.%s: the name must be 1-64 letters, digits, '.', '_' or '-'", name)
		}
		if p == nil {
			return fmt.Errorf("plans.%s: empty plan", name)
		}
		for q, v := range map[string]int64{QuotaBurst: p.Burst, QuotaMinute: p.RequestsPerMinute, QuotaDay: p.RequestsPerDay, QuotaMonth: p.RequestsPerMonth, QuotaBytesMon: p.BytesPerMonth, "includedRequests": p.IncludedRequests} {
			if v < 0 {
				return fmt.Errorf("plans.%s.%s must not be negative", name, q)
			}
		}
		if p.PricePer1kRequests < 0 || math.IsNaN(p.PricePer1kRequests) || math.IsInf(p.PricePer1kRequests, 0) {
			return fmt.Errorf("plans.%s.pricePer1kRequests must be a non-negative number", name)
		}
		if p.PricePer1kRequests > 0 && p.Currency == "" {
			return fmt.Errorf("plans.%s: pricePer1kRequests needs a currency (for example USD)", name)
		}
		switch p.Window {
		case "", "calendar", "rolling":
		default:
			return fmt.Errorf("plans.%s.window %q: want calendar or rolling", name, p.Window)
		}
		switch p.Enforcement {
		case "", "hard", "soft":
		default:
			return fmt.Errorf("plans.%s.enforcement %q: want hard or soft", name, p.Enforcement)
		}
		soft := map[string]bool{}
		for _, q := range p.SoftQuotas {
			ok := false
			for _, n := range quotaNames {
				ok = ok || n == q
			}
			if !ok {
				return fmt.Errorf("plans.%s.softQuotas: %q is not a quota (want one of %s)", name, q, strings.Join(quotaNames, ", "))
			}
			soft[q] = true
		}
		ps.soft[name] = soft
		for _, m := range p.Methods {
			if m != strings.ToUpper(m) || !validMethod(m) {
				return fmt.Errorf("plans.%s.methods: %q must be an upper-case HTTP method", name, m)
			}
		}
		for _, r := range p.Routes {
			if err := checkRoutePattern(r); err != nil {
				return fmt.Errorf("plans.%s.routes: %w", name, err)
			}
		}
	}
	for _, r := range f.UnmeteredRoutes {
		if err := checkRoutePattern(r); err != nil {
			return fmt.Errorf("unmeteredRoutes: %w", err)
		}
	}
	if f.DefaultPlan != "" && f.Plans[f.DefaultPlan] == nil {
		return fmt.Errorf("defaultPlan %q is not defined under plans", f.DefaultPlan)
	}
	for _, id := range sortedKeys(f.Identities) {
		kind, val, ok := strings.Cut(id, ":")
		if !ok || !identKinds[kind] || val == "" {
			return fmt.Errorf("identities: key %q: want apikey:NAME, jwt:SUBJECT, basic:USER, tenant:ID or ip:ADDRESS", id)
		}
		if kind == "ip" {
			if _, err := netip.ParseAddr(val); err != nil {
				return fmt.Errorf("identities: key %q: %q is not an IP address", id, val)
			}
		}
		if f.Plans[f.Identities[id]] == nil {
			return fmt.Errorf("identities: %q maps to plan %q, which is not defined under plans", id, f.Identities[id])
		}
	}
	ps.planCl, ps.tenCl = f.PlanClaim, f.TenantClaim
	if ps.planCl == "" {
		ps.planCl = "plan"
	}
	if ps.tenCl == "" {
		ps.tenCl = "tenant"
	}
	if h := f.PlanHeader; h != nil {
		if h.Name == "" {
			return errors.New("planHeader.name is required")
		}
		if len(h.TrustedFrom) == 0 {
			return errors.New("planHeader.trustedFrom is required: a plan header from an unknown peer would let any client pick its plan")
		}
		pf, err := ParseTrustedProxies(strings.Join(h.TrustedFrom, ","))
		if err != nil {
			return fmt.Errorf("planHeader.trustedFrom: %w", err)
		}
		ps.trusted = trustedNets(pf)
	}
	return nil
}

func validMethod(m string) bool {
	if m == "" {
		return false
	}
	for _, c := range m {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

func checkRoutePattern(p string) error {
	if p == "" {
		return errors.New("empty route")
	}
	if p == "*" {
		return nil
	}
	body := strings.TrimSuffix(p, "*")
	if strings.Contains(body, "*") {
		return fmt.Errorf("route %q: only a trailing * is a wildcard", p)
	}
	if !strings.Contains(body, "/") {
		return fmt.Errorf("route %q: want namespace/name", p)
	}
	return nil
}

func routeMatches(pattern, route string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(route, p)
	}
	return pattern == route
}

func routeAny(patterns []string, route string) bool {
	for _, p := range patterns {
		if routeMatches(p, route) {
			return true
		}
	}
	return false
}

// PlanRoutes lists every route pattern the file mentions with where it is used.
func (ps *PlanSet) PlanRoutes() map[string][]string {
	out := map[string][]string{}
	for _, r := range ps.File.UnmeteredRoutes {
		out[r] = append(out[r], "unmeteredRoutes")
	}
	for _, n := range sortedKeys(ps.File.Plans) {
		for _, r := range ps.File.Plans[n].Routes {
			out[r] = append(out[r], "plans."+n+".routes")
		}
	}
	return out
}

// UnknownRoutes returns the route patterns that match none of routes.
func (ps *PlanSet) UnknownRoutes(routes []string) []string {
	var bad []string
	for p, where := range ps.PlanRoutes() {
		hit := false
		for _, r := range routes {
			hit = hit || routeMatches(p, r)
		}
		if !hit {
			bad = append(bad, p+" ("+strings.Join(where, ", ")+")")
		}
	}
	sort.Strings(bad)
	return bad
}

func (ps *PlanSet) unmetered(route string) bool { return routeAny(ps.File.UnmeteredRoutes, route) }

// Soft reports whether quota q of plan is a warning instead of a block.
func (ps *PlanSet) Soft(plan, q string) bool {
	p := ps.File.Plans[plan]
	return p != nil && (p.Enforcement == "soft" || ps.soft[plan][q])
}

// ---- identity and plan resolution ----

// identInput is what plan resolution knows about a request.
type identInput struct {
	method   string // credential that passed: jwt, apikey, basic, "" or none
	subject  string
	claims   jwtClaims
	clientIP string
	planHdr  string // plan from a trusted header, if any
	tenant   string
}

// Resolved is the outcome of mapping a request to a plan.
type Resolved struct {
	Identity string `json:"identity"` // the metering key
	Tenant   string `json:"tenant,omitempty"`
	Plan     string `json:"plan,omitempty"`
	Source   string `json:"source"` // how the plan was chosen
	Rejected bool   `json:"rejected,omitempty"`
}

// requestIdentity extracts identity inputs from a request and its auth result.
func (ps *PlanSet) requestIdentity(r *http.Request, res *authResult, clientIP string) identInput {
	in := identInput{clientIP: clientIP}
	if res != nil && res.Method != "" && res.Method != "none" {
		in.method, in.subject, in.claims = res.Method, res.Subject, res.claims
	}
	trusted := ps.File.PlanHeader != nil && ps.trusted.peerTrusted(r)
	if trusted {
		in.planHdr = strings.TrimSpace(r.Header.Get(ps.File.PlanHeader.Name))
		if tn := ps.File.PlanHeader.TenantName; tn != "" {
			in.tenant = strings.TrimSpace(r.Header.Get(tn))
		}
	}
	if in.tenant == "" && in.claims != nil {
		if v, ok := claimAt(in.claims, ps.tenCl); ok {
			if s, ok := v.(string); ok {
				in.tenant = s
			}
		}
	}
	return in
}

// resolve maps identity inputs to a plan: trusted header, JWT claim, the
// credential's own entry, the tenant's entry, the client address entry, then the
// default plan. No match and no default is a rejection.
func (ps *PlanSet) resolve(in identInput) Resolved {
	f := ps.File
	cred := ""
	if in.method != "" && in.subject != "" {
		cred = in.method + ":" + in.subject
	}
	rs := Resolved{Tenant: in.tenant}
	switch {
	case in.tenant != "":
		rs.Identity = "tenant:" + in.tenant
	case cred != "":
		rs.Identity = cred
	default:
		rs.Identity = "ip:" + in.clientIP
	}
	set := func(plan, why string) Resolved { rs.Plan, rs.Source = plan, why; return rs }
	if in.planHdr != "" && f.Plans[in.planHdr] != nil {
		return set(in.planHdr, "header "+f.PlanHeader.Name+" from a trusted upstream")
	}
	if in.claims != nil {
		if v, ok := claimAt(in.claims, ps.planCl); ok {
			if s, ok := v.(string); ok && f.Plans[s] != nil {
				return set(s, "JWT claim "+ps.planCl)
			}
		}
	}
	for _, key := range []string{cred, tenantKey(in.tenant), ipKey(in.clientIP)} {
		if key == "" {
			continue
		}
		if p, ok := f.Identities[key]; ok {
			return set(p, "identities["+key+"]")
		}
	}
	if f.DefaultPlan != "" {
		return set(f.DefaultPlan, "defaultPlan")
	}
	rs.Rejected, rs.Source = true, "no mapping names this identity and the file has no defaultPlan"
	return rs
}

func tenantKey(t string) string {
	if t == "" {
		return ""
	}
	return "tenant:" + t
}

func ipKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "ip:" + ip
}

// allows reports whether plan p may call route with method; why names the
// restriction that refuses.
func (p *Plan) allows(route, method string) (bool, string) {
	if len(p.Routes) > 0 && !routeAny(p.Routes, route) {
		return false, "the plan's routes are " + strings.Join(p.Routes, ", ")
	}
	if len(p.Methods) > 0 {
		for _, m := range p.Methods {
			if m == method {
				return true, ""
			}
		}
		return false, "the plan's methods are " + strings.Join(p.Methods, ", ")
	}
	return true, ""
}

// limits lists the plan's quotas in enforcement order.
func (p *Plan) limits() []struct {
	Name  string
	Limit int64
} {
	var out []struct {
		Name  string
		Limit int64
	}
	for _, q := range []struct {
		n string
		v int64
	}{{QuotaBurst, p.Burst}, {QuotaMinute, p.RequestsPerMinute}, {QuotaDay, p.RequestsPerDay}, {QuotaMonth, p.RequestsPerMonth}, {QuotaBytesMon, p.BytesPerMonth}} {
		if q.v > 0 {
			out = append(out, struct {
				Name  string
				Limit int64
			}{q.n, q.v})
		}
	}
	return out
}
