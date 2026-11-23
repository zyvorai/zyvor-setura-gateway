package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TracePlan is the API plan decision for the request: which identity it
// resolves to, which plan applies and why, and where each quota stands.
type TracePlan struct {
	Enabled  bool         `json:"enabled"`
	Applies  bool         `json:"applies"`
	Identity string       `json:"identity,omitempty"`
	Tenant   string       `json:"tenant,omitempty"`
	Plan     string       `json:"plan,omitempty"`
	Source   string       `json:"source,omitempty"`   // how the plan was chosen
	Decision string       `json:"decision,omitempty"` // allow, warn, quota, forbidden, rejected, unmetered, unknown
	Status   int          `json:"status,omitempty"`
	Mode     string       `json:"mode,omitempty"` // hard, soft or mixed
	Limits   []TraceQuota `json:"limits,omitempty"`
	Live     bool         `json:"live"` // usage figures come from a running gateway
	Note     string       `json:"note,omitempty"`
}

// TraceQuota is one quota of the plan.
type TraceQuota struct {
	Name         string `json:"name"`
	Limit        int64  `json:"limit"`
	Mode         string `json:"mode"`
	Window       string `json:"window,omitempty"`
	Used         *int64 `json:"used,omitempty"`
	ResetSeconds *int   `json:"reset_seconds,omitempty"`
	Exceeded     *bool  `json:"exceeded,omitempty"`
}

// explainPlan resolves the plan the data path would apply, with the same
// functions (requestIdentity, resolve, allows, evaluate).
func (tr *Trace) explainPlan(e *Entry, q ExplainRequest, r *http.Request, route string) *TracePlan {
	ps := q.Server.Plans
	tp := &TracePlan{}
	if ps == nil {
		tp.Note = "no plans are configured on the gateway (--plans); pass --plans FILE to evaluate one"
		return tp
	}
	tp.Enabled = true
	if ps.unmetered(route) {
		tp.Decision, tp.Note = "unmetered", "the route is listed in unmeteredRoutes, so no plan or quota applies"
		return tp
	}
	if a := tr.authRes; a != nil && !a.allowed() {
		tp.Note = "the auth policy does not admit this request, so it is answered before any plan applies"
		if a.Decision == "unknown" {
			tp.Decision, tp.Note = "unknown", "the identity cannot be determined offline: "+a.Reason
		}
		return tp
	}
	remote := q.Remote
	if remote == "" {
		remote = "<client-ip>"
	}
	tp.Applies = true
	in := ps.requestIdentity(r, tr.authRes, remote)
	rs := ps.resolve(in)
	tp.Identity, tp.Tenant, tp.Source = rs.Identity, rs.Tenant, rs.Source
	if rs.Rejected {
		tp.Decision, tp.Status = "rejected", http.StatusForbidden
		tp.Note = "the gateway answers 403 unknown_identity; add the identity to \"identities\" or set a defaultPlan"
		return tp
	}
	tp.Plan = rs.Plan
	plan := ps.File.Plans[rs.Plan]
	if ok, why := plan.allows(route, q.Method); !ok {
		tp.Decision, tp.Status = "forbidden", http.StatusForbidden
		tp.Note = "the gateway answers 403 plan_forbids: " + why
		return tp
	}
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	var adm Admission
	live := q.Live && q.Server.meter != nil
	if live {
		now = q.Server.meter.now()
		adm = q.Server.meter.peek(rs.Identity, ps, rs.Plan, plan, now)
	} else {
		adm = (&meter{}).evaluate(&quotaState{days: map[int64]*dayTot{}}, ps, rs.Plan, plan, now)
	}
	tp.Live = live
	hard, soft := 0, 0
	for _, h := range adm.All {
		mode := "hard"
		if h.Soft {
			mode = "soft"
			soft++
		} else {
			hard++
		}
		tq := TraceQuota{Name: h.Name, Limit: h.Limit, Mode: mode, Window: h.Window}
		if live {
			used, exc, secs := h.Used, h.Exceeded, secondsUntil(h.Reset, now)
			tq.Used, tq.Exceeded, tq.ResetSeconds = &used, &exc, &secs
		}
		tp.Limits = append(tp.Limits, tq)
	}
	switch {
	case hard > 0 && soft > 0:
		tp.Mode = "mixed"
	case soft > 0:
		tp.Mode = "soft"
	case hard > 0:
		tp.Mode = "hard"
	}
	switch {
	case adm.Denied != nil:
		tp.Decision, tp.Status = "quota", http.StatusTooManyRequests
		tp.Note = fmt.Sprintf("the gateway answers 429 quota_exceeded: %s is %d of %d and resets in %ds", adm.Denied.Name, adm.Denied.Used, adm.Denied.Limit, secondsUntil(adm.Denied.Reset, now))
	case len(adm.Soft) > 0:
		names := make([]string, len(adm.Soft))
		for i, s := range adm.Soft {
			names[i] = s.Name
		}
		tp.Decision = "warn"
		tp.Note = "admitted with X-Quota-Warning: soft quota exceeded: " + strings.Join(names, ", ")
	default:
		tp.Decision = "allow"
		if !live && len(tp.Limits) > 0 {
			tp.Note = "quotas shown are the plan's limits; current usage needs --admin against a running gateway"
		}
	}
	return tp
}
