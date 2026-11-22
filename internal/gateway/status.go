package gateway

import "time"

// StatusSchema identifies the /status document.
const StatusSchema = "setura.gateway-status/v1"

// Condition is a Gateway API style condition.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionTime string `json:"lastTransitionTime"`
}

// KindRef names a supported route kind.
type KindRef struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
}

// ListenerStatus is the status of one listener.
type ListenerStatus struct {
	Name           string      `json:"name"`
	SupportedKinds []KindRef   `json:"supportedKinds"`
	AttachedRoutes int         `json:"attachedRoutes"`
	Conditions     []Condition `json:"conditions"`
}

// GatewayStatus is the status of one Gateway.
type GatewayStatus struct {
	ObservedGeneration int64            `json:"observedGeneration"`
	Conditions         []Condition      `json:"conditions"`
	Listeners          []ListenerStatus `json:"listeners"`
}

// ParentStatus is a route's status for one parentRef.
type ParentStatus struct {
	ParentRef      ParentRef   `json:"parentRef"`
	ControllerName string      `json:"controllerName"`
	Conditions     []Condition `json:"conditions"`
}

// RouteStatus is the status of one HTTPRoute.
type RouteStatus struct {
	ObservedGeneration int64          `json:"observedGeneration"`
	Parents            []ParentStatus `json:"parents"`
}

// ReloadInfo records the outcome of the latest configuration load.
type ReloadInfo struct {
	OK    bool   `json:"ok"`
	Time  string `json:"time"`
	Error string `json:"error,omitempty"`
}

// StatusDoc is what /status serves and what controller mode writes back.
type StatusDoc struct {
	Schema     string                    `json:"schema"`
	Generation int64                     `json:"generation"`
	ConfigHash string                    `json:"configHash"`
	Applied    string                    `json:"applied"`
	LastReload ReloadInfo                `json:"lastReload"`
	Gateways   map[string]*GatewayStatus `json:"gateways"`
	Routes     map[string]*RouteStatus   `json:"routes"`
}

func mkCond(prev []Condition, typ string, f fact, gen int64, now time.Time) Condition {
	status := "False"
	if f.OK {
		status = "True"
	}
	c := Condition{Type: typ, Status: status, Reason: f.Reason, Message: f.Message, ObservedGeneration: gen,
		LastTransitionTime: now.UTC().Format(time.RFC3339)}
	for _, p := range prev {
		if p.Type == typ && p.Status == status {
			c.LastTransitionTime = p.LastTransitionTime
		}
	}
	return c
}

// BuildStatus derives Accepted/Programmed/ResolvedRefs conditions from a
// table. bindErr maps listener keys to bind failures. prev keeps
// lastTransitionTime stable across identical results.
func BuildStatus(t *Table, bindErr map[string]string, now time.Time, prev *StatusDoc) *StatusDoc {
	doc := &StatusDoc{Schema: StatusSchema, Applied: now.UTC().Format(time.RFC3339),
		Gateways: map[string]*GatewayStatus{}, Routes: map[string]*RouteStatus{}}
	oldG := func(key string) *GatewayStatus {
		if prev != nil {
			return prev.Gateways[key]
		}
		return nil
	}
	for _, gw := range t.Cfg.Gateways {
		old := oldG(gw.Key())
		gs := &GatewayStatus{ObservedGeneration: gw.Generation}
		doc.Gateways[gw.Key()] = gs
		allOK, accepted := true, true
		for _, l := range t.Listeners {
			if l.GW != gw {
				continue
			}
			var oldL []Condition
			if old != nil {
				for _, ol := range old.Listeners {
					if ol.Name == l.L.Name {
						oldL = ol.Conditions
					}
				}
			}
			prog := fact{true, "Programmed", ""}
			switch {
			case !l.Accepted.OK:
				prog = fact{false, "Invalid", l.Accepted.Message}
			case l.Conflicted.OK:
				prog = fact{false, "Invalid", l.Conflicted.Message}
			case !l.Resolved.OK:
				prog = fact{false, "Invalid", l.Resolved.Message}
			case bindErr[l.Key] != "":
				prog = fact{false, "PortUnavailable", bindErr[l.Key]}
			}
			accepted = accepted && l.Accepted.OK
			allOK = allOK && prog.OK
			conflict := l.Conflicted // OK means "is conflicted"
			cf := fact{conflict.OK, conflict.Reason, conflict.Message}
			ls := ListenerStatus{Name: l.L.Name, AttachedRoutes: l.Attached, SupportedKinds: []KindRef{}}
			if l.Accepted.OK {
				ls.SupportedKinds = l.supportedKinds()
			}
			ls.Conditions = []Condition{
				mkCond(oldL, "Accepted", l.Accepted, gw.Generation, now),
				mkCond(oldL, "Programmed", prog, gw.Generation, now),
				mkCond(oldL, "ResolvedRefs", l.Resolved, gw.Generation, now),
				mkCond(oldL, "Conflicted", cf, gw.Generation, now),
			}
			gs.Listeners = append(gs.Listeners, ls)
		}
		var oldC []Condition
		if old != nil {
			oldC = old.Conditions
		}
		acc := fact{true, "Accepted", "Gateway is served by the Setura built-in gateway"}
		if !accepted {
			acc.Reason = "ListenersNotValid"
		}
		prog := fact{true, "Programmed", "all listeners are serving"}
		if !allOK {
			prog = fact{false, "ListenersNotValid", "one or more listeners are not programmed"}
		}
		gs.Conditions = []Condition{mkCond(oldC, "Accepted", acc, gw.Generation, now), mkCond(oldC, "Programmed", prog, gw.Generation, now)}
	}
	for _, rr := range t.routes {
		rs := &RouteStatus{ObservedGeneration: rr.Route.Generation}
		var old *RouteStatus
		if prev != nil {
			old = prev.Routes[rr.Route.StatusKey()]
		}
		for i, p := range rr.Parents {
			var oldC []Condition
			if old != nil && i < len(old.Parents) {
				oldC = old.Parents[i].Conditions
			}
			ref := p.Ref
			if ref.Group == "" {
				ref.Group = APIGroup
			}
			if ref.Kind == "" {
				ref.Kind = "Gateway"
			}
			rs.Parents = append(rs.Parents, ParentStatus{ParentRef: ref, ControllerName: ControllerName, Conditions: []Condition{
				mkCond(oldC, "Accepted", p.Accepted, rr.Route.Generation, now),
				mkCond(oldC, "ResolvedRefs", rr.Refs, rr.Route.Generation, now),
			}})
		}
		doc.Routes[rr.Route.StatusKey()] = rs
	}
	return doc
}
