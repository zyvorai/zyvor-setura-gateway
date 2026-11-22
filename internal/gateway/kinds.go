package gateway

import "sort"

// Route kinds beyond HTTPRoute and which listener protocols accept them.
const (
	grpcRouteKey = "grpcroutes." + APIGroup
	tlsRouteKey  = "tlsroutes." + APIGroup
	grantKey     = "referencegrants." + APIGroup
)

// protocolKinds lists the route kinds a listener protocol can carry.
func protocolKinds(proto string) []string {
	switch proto {
	case "HTTP", "HTTPS":
		return []string{"HTTPRoute", "GRPCRoute"}
	case "TLS":
		return []string{"TLSRoute"}
	}
	return nil
}

// supportedKinds is the intersection of what the protocol carries and what the
// listener's allowedRoutes.kinds names (all of it when kinds is empty).
func (l *RTListener) supportedKinds() []KindRef {
	out := []KindRef{}
	for _, k := range protocolKinds(l.L.Protocol) {
		if l.explicitKind(k) {
			out = append(out, KindRef{Group: APIGroup, Kind: k})
		}
	}
	return out
}

func (l *RTListener) explicitKind(kind string) bool {
	ar := l.L.AllowedRoutes
	if ar == nil || len(ar.Kinds) == 0 {
		return true
	}
	for _, k := range ar.Kinds {
		if k.Kind == kind && (k.Group == "" || k.Group == APIGroup) {
			return true
		}
	}
	return false
}

// allowsKind reports whether routes of kind may attach to the listener.
func (l *RTListener) allowsKind(kind string) bool {
	for _, k := range protocolKinds(l.L.Protocol) {
		if k == kind {
			return l.explicitKind(kind)
		}
	}
	return false
}

// attachExtra attaches GRPCRoutes and TLSRoutes, oldest first.
func (t *Table) attachExtra() {
	older := func(a, b *Route) bool {
		if !a.Created.Equal(b.Created) {
			return a.Created.Before(b.Created)
		}
		return a.Key() < b.Key()
	}
	gs := append([]*GRPCRoute(nil), t.Cfg.GRPCRoutes...)
	sort.SliceStable(gs, func(i, j int) bool { return older(gs[i].stub(), gs[j].stub()) })
	for _, r := range gs {
		t.attachGRPC(r)
	}
	ts := append([]*TLSRoute(nil), t.Cfg.TLSRoutes...)
	sort.SliceStable(ts, func(i, j int) bool { return older(ts[i].stub(), ts[j].stub()) })
	for _, r := range ts {
		t.attachTLS(r)
	}
}

func (c *Config) dumpExtra(out map[string]any) {
	if len(c.GRPCRoutes) > 0 {
		var rs []any
		for _, r := range c.GRPCRoutes {
			rs = append(rs, map[string]any{"namespace": r.NS, "name": r.Name, "generation": r.Generation,
				"parentRefs": r.Parents, "hostnames": r.Hostnames, "rules": r.Rules})
		}
		out["grpcroutes"] = rs
	}
	if len(c.TLSRoutes) > 0 {
		var rs []any
		for _, r := range c.TLSRoutes {
			rs = append(rs, map[string]any{"namespace": r.NS, "name": r.Name, "generation": r.Generation,
				"parentRefs": r.Parents, "hostnames": r.Hostnames, "rules": r.Rules})
		}
		out["tlsroutes"] = rs
	}
}
