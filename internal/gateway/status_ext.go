package gateway

import "time"

// ListenerSetStatus is the status of one ListenerSet.
type ListenerSetStatus struct {
	ObservedGeneration int64            `json:"observedGeneration"`
	Conditions         []Condition      `json:"conditions"`
	Listeners          []ListenerStatus `json:"listeners"`
}

// setCond replaces the condition of the given type, or appends it.
func setCond(cs []Condition, c Condition) []Condition {
	for i := range cs {
		if cs[i].Type == c.Type {
			cs[i] = c
			return cs
		}
	}
	return append(cs, c)
}

// extraStatus adds the Gateway API 1.5 parts of the status: static Gateway
// addresses, the backend client certificate condition, ListenerSets and
// BackendTLSPolicy ancestors.
func (t *Table) extraStatus(doc *StatusDoc, now time.Time, prev *StatusDoc) {
	for _, gw := range t.Cfg.Gateways {
		gs := doc.Gateways[gw.Key()]
		if gs == nil {
			continue
		}
		var old []Condition
		if prev != nil && prev.Gateways[gw.Key()] != nil {
			old = prev.Gateways[gw.Key()].Conditions
		}
		if len(gw.Addresses) > 0 {
			var bad fact
			for _, a := range gw.Addresses {
				if err := validAddress(a); err != nil && bad.Reason == "" {
					bad = fact{false, "UnsupportedAddress", err.Error()}
				}
			}
			if bad.Reason != "" {
				gs.Conditions = setCond(gs.Conditions, mkCond(old, "Accepted", bad, gw.Generation, now))
				gs.Conditions = setCond(gs.Conditions, mkCond(old, "Programmed", fact{false, "AddressNotUsable", bad.Message}, gw.Generation, now))
			} else {
				for _, a := range gw.Addresses {
					if a.Type == "" {
						a.Type = "IPAddress"
					}
					if a.Value != "" { // an empty value asks for "any": nothing to report yet
						gs.Addresses = append(gs.Addresses, a)
					}
				}
			}
		}
		if gc := t.gwCerts[gw.Key()]; gc != nil {
			gs.Conditions = setCond(gs.Conditions, mkCond(old, "ResolvedRefs", gc.fact, gw.Generation, now))
		}
		attached := 0
		for _, r := range t.sets {
			if r.GW == gw {
				attached++
			}
		}
		if attached > 0 || len(t.sets) > 0 {
			gs.AttachedListenerSets = &attached
		}
	}
	if len(t.sets) > 0 {
		doc.ListenerSets = map[string]*ListenerSetStatus{}
	}
	for _, r := range t.sets {
		var oldC []Condition
		var oldL map[string][]Condition
		if prev != nil && prev.ListenerSets[r.LS.Key()] != nil {
			p := prev.ListenerSets[r.LS.Key()]
			oldC, oldL = p.Conditions, map[string][]Condition{}
			for _, l := range p.Listeners {
				oldL[l.Name] = l.Conditions
			}
		}
		ss := &ListenerSetStatus{ObservedGeneration: r.LS.Generation}
		allOK := true
		for _, l := range t.Listeners {
			if l.LS != r.LS {
				continue
			}
			prog := fact{true, "Programmed", ""}
			switch {
			case !l.Accepted.OK:
				prog = fact{false, "Invalid", l.Accepted.Message}
			case l.Conflicted.OK:
				prog = fact{false, "Invalid", l.Conflicted.Message}
			case !l.Resolved.OK:
				prog = fact{false, "Invalid", l.Resolved.Message}
			}
			allOK = allOK && prog.OK
			ls := ListenerStatus{Name: l.L.Name, AttachedRoutes: l.Attached, SupportedKinds: []KindRef{}}
			if l.Accepted.OK {
				ls.SupportedKinds = l.supportedKinds()
			}
			ls.Conditions = []Condition{
				mkCond(oldL[l.L.Name], "Accepted", l.Accepted, r.LS.Generation, now),
				mkCond(oldL[l.L.Name], "Programmed", prog, r.LS.Generation, now),
				mkCond(oldL[l.L.Name], "ResolvedRefs", l.Resolved, r.LS.Generation, now),
				mkCond(oldL[l.L.Name], "Conflicted", fact{l.Conflicted.OK, l.Conflicted.Reason, l.Conflicted.Message}, r.LS.Generation, now),
			}
			ss.Listeners = append(ss.Listeners, ls)
		}
		prog := fact{r.Accepted.OK && allOK, "Programmed", ""}
		switch {
		case !r.Accepted.OK:
			prog = fact{false, r.Accepted.Reason, r.Accepted.Message}
		case !allOK:
			prog = fact{false, "ListenersNotValid", "one or more listeners are not programmed"}
		}
		ss.Conditions = []Condition{mkCond(oldC, "Accepted", r.Accepted, r.LS.Generation, now), mkCond(oldC, "Programmed", prog, r.LS.Generation, now)}
		doc.ListenerSets[r.LS.Key()] = ss
	}
	if len(t.policies) > 0 {
		var prevP map[string]*PolicyStatus
		if prev != nil {
			prevP = prev.Policies
		}
		doc.Policies = t.policyStatuses(now, prevP)
	}
}
