package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"time"
)

// TraceLB says how a request to a backend would choose its endpoint
// (setura why, /why).
type TraceLB struct {
	Algorithm string `json:"algorithm"`
	Source    string `json:"source"`         // rule, backend, gateway default or built in
	Hash      string `json:"hash,omitempty"` // what consistentHash hashes on, never the value
	Ring      string `json:"ring,omitempty"` // ring or Maglev
	// Endpoint is the endpoint a deterministic algorithm (consistentHash) would
	// pick right now; the other algorithms choose per request.
	Endpoint string `json:"endpoint,omitempty"`
	Why      string `json:"why"`
	Mode     string `json:"mode,omitempty"` // normal, panic or all-down
	Details  string `json:"details,omitempty"`
}

// lbSource names where the block that applies comes from.
func lbSource(b *Backend, rule *CLB, def *CLB) string {
	switch {
	case rule != nil:
		return "rule"
	case b.LB != nil && b.LB != def:
		return "backend"
	case b.LB != nil:
		return "gateway default (--load-balancer)"
	}
	return "built in"
}

func (c *CLB) describe() string {
	s := c.Algo
	switch c.Algo {
	case AlgoLeastRequest:
		s += fmt.Sprintf(" (power of %d choices)", c.Choices)
	case AlgoConsistentHash:
		kind := "ring"
		if c.Hash.Maglev {
			kind = "Maglev"
		}
		on := c.Hash.On
		if c.Hash.Name != "" {
			on += " " + c.Hash.Name
		}
		s += fmt.Sprintf(" (%s on %s)", kind, on)
	}
	if c.SlowWindow > 0 {
		s += ", slow start " + c.SlowWindow.String()
	}
	if c.PreferLocal {
		s += ", prefer local zone"
	}
	if c.Panic > 0 {
		s += fmt.Sprintf(", panic under %d%% healthy", c.Panic)
	}
	return s
}

// traceLB explains the endpoint choice of backend b for the request r.
func (tr *Trace) traceLB(b *Backend, rule *CRule, r *http.Request) *TraceLB {
	if b == nil || len(b.Eps) == 0 {
		return nil
	}
	rq := &lbReq{rule: rule.LB, r: r, rnd: func(int) int { return 0 }, ip: remoteIP(r)}
	var def *CLB
	if srv := tr.Request.Server.srv; srv != nil {
		rq.zone, rq.ip, def = srv.opts.Zone, srv.trusted.clientIP(r), srv.lbDefault
	}
	rq.def = def
	now := tr.Request.Now
	if now.IsZero() {
		now = time.Now()
	}
	c := b.cfg(rq)
	ep, why := b.pickLB(now, nil, rq, true)
	out := &TraceLB{Algorithm: c.describe(), Source: lbSource(b, rule.LB, def), Why: why.String(), Mode: "normal"}
	switch {
	case why.Panic:
		out.Mode = "panic"
	case why.AllDown:
		out.Mode = "all-down"
	}
	if c.Algo == AlgoConsistentHash {
		out.Hash, out.Ring = why.Hash, why.Ring
		if ep != nil && !why.NoKey {
			out.Endpoint = ep.URL.String()
		}
	}
	if rq.cookie != nil {
		out.Details = "the request has no " + c.Hash.Name + " cookie: the gateway would set one, and later requests with it stick to the endpoint it hashes to"
	}
	return out
}

// ---- /status ----

// LBStatus is the live endpoint selection state of the gateway.
type LBStatus struct {
	Default  string                `json:"default,omitempty"` // the --load-balancer block
	Zone     string                `json:"zone,omitempty"`    // --zone
	Backends map[string]*LBBackend `json:"backends"`
	Rules    []LBRule              `json:"rules,omitempty"` // rules with a load-balancer block
	DNS      []DNSStatus           `json:"dns,omitempty"`
}

// LBRule is a rule that has its own load-balancer block.
type LBRule struct {
	Route     string `json:"route"`
	Rule      int    `json:"rule"` // 1-based
	Algorithm string `json:"algorithm"`
}

// LBBackend is one backend's pool.
type LBBackend struct {
	Algorithm string       `json:"algorithm"`
	Source    string       `json:"source"`
	Kind      string       `json:"kind,omitempty"` // Backend for a Service-less backend
	Mode      string       `json:"mode"`           // normal, panic or all-down
	Healthy   int          `json:"healthy"`
	Total     int          `json:"total"`
	Tiers     []LBTier     `json:"tiers,omitempty"`
	Endpoints []LBEndpoint `json:"endpoints"`
	Last      *LBLast      `json:"last,omitempty"`
}

// LBTier is the health of one priority tier.
type LBTier struct {
	Priority int `json:"priority"`
	Healthy  int `json:"healthy"`
	Total    int `json:"total"`
	Percent  int `json:"percent"`
}

// LBEndpoint is one endpoint with its balancing state.
type LBEndpoint struct {
	URL         string  `json:"url"`
	State       string  `json:"state"` // up, unhealthy or ejected
	Weight      int     `json:"weight"`
	Effective   float64 `json:"effectiveWeight"` // weight after slow start
	Zone        string  `json:"zone,omitempty"`
	Priority    int     `json:"priority"`
	InFlight    int64   `json:"inFlight"`
	Authority   string  `json:"authority,omitempty"` // the name a DNS endpoint was resolved from
	UnixSocket  string  `json:"unixSocket,omitempty"`
	SlowStarted bool    `json:"slowStart,omitempty"`
}

// LBLast is the last endpoint chosen for a backend and why.
type LBLast struct {
	Endpoint string `json:"endpoint"`
	Why      string `json:"why"`
	At       string `json:"at"`
}

func (s *Server) lbStatus() *LBStatus {
	t := s.Table()
	if t == nil {
		return nil
	}
	now := s.res.now()
	out := &LBStatus{Zone: s.opts.Zone, Backends: map[string]*LBBackend{}}
	if s.lbDefault != nil {
		out.Default = s.lbDefault.describe()
	}
	for _, key := range sortedKeys(t.Backends) {
		out.Backends[key] = t.Backends[key].lbStatus(now, s.lbDefault, s.opts.Zone)
	}
	seen := map[*CRule]bool{}
	for _, l := range t.Listeners {
		for _, en := range l.Entries {
			if cr := en.Rule; cr.LB != nil && !seen[cr] {
				seen[cr] = true
				out.Rules = append(out.Rules, LBRule{Route: en.Route.StatusKey(), Rule: cr.Index + 1, Algorithm: cr.LB.describe()})
			}
		}
	}
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Route != out.Rules[j].Route {
			return out.Rules[i].Route < out.Rules[j].Route
		}
		return out.Rules[i].Rule < out.Rules[j].Rule
	})
	if s.dns != nil {
		out.DNS = s.dns.status()
	}
	return out
}

func (b *Backend) lbStatus(now time.Time, def *CLB, zone string) *LBBackend {
	c := b.cfg(&lbReq{def: def})
	out := &LBBackend{Algorithm: c.describe(), Source: lbSource(b, nil, def), Kind: b.Kind, Mode: "normal", Total: len(b.Eps)}
	b.hmu.Lock()
	defer b.hmu.Unlock()
	tier := map[int]*LBTier{}
	for _, e := range b.Eps {
		st := "up"
		switch {
		case !e.healthy.Load():
			st = "unhealthy"
		case now.Before(e.st.until):
			st = "ejected"
		}
		ew := LBEndpoint{URL: e.URL.String(), State: st, Weight: e.W(), Effective: weightOf(e, c, now), Zone: e.Zone, Priority: e.Priority,
			InFlight: e.inflight.Load(), Authority: e.Authority, UnixSocket: e.Unix}
		ew.SlowStarted = c.SlowWindow > 0 && ew.Effective < float64(ew.Weight)
		if st == "up" {
			out.Healthy++
		}
		out.Endpoints = append(out.Endpoints, ew)
		tt := tier[e.Priority]
		if tt == nil {
			tt = &LBTier{Priority: e.Priority}
			tier[e.Priority] = tt
		}
		tt.Total++
		if st == "up" {
			tt.Healthy++
		}
	}
	if len(tier) > 1 {
		for _, tt := range tier {
			tt.Percent = tt.Healthy * 100 / tt.Total
			out.Tiers = append(out.Tiers, *tt)
		}
		sort.Slice(out.Tiers, func(i, j int) bool { return out.Tiers[i].Priority < out.Tiers[j].Priority })
	}
	switch {
	case out.Healthy == 0:
		out.Mode = "all-down"
	case c.Panic > 0 && out.Healthy*100 < c.Panic*out.Total:
		out.Mode = "panic"
	}
	if l := b.last.Load(); l != nil {
		out.Last = &LBLast{Endpoint: l.ep.URL.String(), Why: l.why.String(), At: l.at.UTC().Format(time.RFC3339)}
	}
	return out
}
