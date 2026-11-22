package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// ListenerSet (gateway.networking.k8s.io/v1) lets other teams add listeners to
// a Gateway without editing it. A Gateway admits ListenerSets through
// spec.allowedListeners.namespaces (default: none). A route attaches to a
// ListenerSet's listeners with a parentRef of kind ListenerSet; a parentRef to
// the Gateway itself (no sectionName) attaches to the Gateway's listeners and
// those of every attached ListenerSet.

const listenerSetKey = "listenersets." + APIGroup

// ListenerSet is the subset of the resource the data plane honours.
type ListenerSet struct {
	NS, Name   string
	Generation int64
	Created    time.Time
	Parent     ParentRef
	Listeners  []Listener
}

// Key is namespace/name.
func (s *ListenerSet) Key() string { return s.NS + "/" + s.Name }

type listenerSetSpec struct {
	creationMeta
	ParentRef ParentRef  `json:"parentRef"`
	Listeners []Listener `json:"listeners"`
}

// setResult is a ListenerSet's attachment outcome.
type setResult struct {
	LS       *ListenerSet
	GW       *Gateway // nil when the parent does not exist
	Accepted fact
}

// lsEntry is a listener together with the ListenerSet it came from (nil for
// the Gateway's own listeners).
type lsEntry struct {
	L  Listener
	LS *ListenerSet
}

// key is the listener key used in status and logs.
func (e lsEntry) key(gw *Gateway) string {
	if e.LS == nil {
		return gw.Key() + "/" + e.L.Name
	}
	return "ListenerSet/" + e.LS.Key() + "/" + e.L.Name
}

func (p ParentRef) kindName() string {
	if p.Kind == "" {
		return "Gateway"
	}
	return p.Kind
}

func parentNS(p ParentRef, routeNS string) string {
	if p.Namespace != "" {
		return p.Namespace
	}
	return routeNS
}

func (l *RTListener) ownerNS() string {
	if l.LS != nil {
		return l.LS.NS
	}
	return l.GW.NS
}

func (l *RTListener) ownerKind() string {
	if l.LS != nil {
		return "ListenerSet"
	}
	return "Gateway"
}

// parseGatewayAPI15 reads the resource kinds added after GRPCRoute and TLSRoute.
func (c *Config) parseGatewayAPI15(kind, ns, name string, raw json.RawMessage) error {
	switch kind {
	case listenerSetKey:
		var spec listenerSetSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return err
		}
		created, err := spec.created()
		if err != nil {
			return err
		}
		c.ListenerSets = append(c.ListenerSets, &ListenerSet{NS: ns, Name: name, Created: created, Parent: spec.ParentRef, Listeners: spec.Listeners})
	case tcpRouteKey, udpRouteKey:
		return c.parseL4Route(kind, ns, name, raw)
	case backendTLSPolicyKey:
		return c.parseBackendTLSPolicy(ns, name, raw)
	}
	return nil
}

// resolveListenerSets decides which ListenerSets each Gateway admits.
func (t *Table) resolveListenerSets() {
	gateways := map[string]*Gateway{}
	for _, g := range t.Cfg.Gateways {
		gateways[g.Key()] = g
	}
	sets := append([]*ListenerSet(nil), t.Cfg.ListenerSets...)
	sort.SliceStable(sets, func(i, j int) bool {
		if !sets[i].Created.Equal(sets[j].Created) {
			return sets[i].Created.Before(sets[j].Created)
		}
		return sets[i].Key() < sets[j].Key()
	})
	for _, ls := range sets {
		res := &setResult{LS: ls, Accepted: fact{true, "Accepted", "ListenerSet attached to the Gateway"}}
		t.sets = append(t.sets, res)
		if (ls.Parent.Kind != "" && ls.Parent.Kind != "Gateway") || (ls.Parent.Group != "" && ls.Parent.Group != APIGroup) {
			res.Accepted = fact{false, "ParentNotAccepted", "parentRef is not a Gateway"}
			continue
		}
		gw := gateways[parentNS(ls.Parent, ls.NS)+"/"+ls.Parent.Name]
		if gw == nil {
			res.Accepted = fact{false, "ParentNotAccepted", fmt.Sprintf("Gateway %s/%s not found", parentNS(ls.Parent, ls.NS), ls.Parent.Name)}
			continue
		}
		if why := t.Cfg.listenersAllowed(gw, ls.NS); why != "" {
			res.Accepted = fact{false, "NotAllowed", why}
			continue
		}
		res.GW = gw
	}
}

// listenersAllowed is "" when gw admits ListenerSets from namespace ns.
func (c *Config) listenersAllowed(gw *Gateway, ns string) string {
	al := gw.AllowedListeners
	from := "None"
	if al != nil && al.From != "" {
		from = al.From
	}
	switch from {
	case "All":
		return ""
	case "Same":
		if ns == gw.NS {
			return ""
		}
		return fmt.Sprintf("Gateway %s admits ListenerSets from its own namespace only (allowedListeners.namespaces.from is Same)", gw.Key())
	case "Selector":
		if al.Selector == nil {
			return "allowedListeners.namespaces.from is Selector without a selector"
		}
		if why := selectorWhy(al.Selector.MatchLabels, al.Selector.MatchExpressions, c.Namespaces[ns]); why != "" {
			return fmt.Sprintf("namespace %s does not match the Gateway's allowedListeners selector (%s)", ns, why)
		}
		return ""
	}
	return fmt.Sprintf("Gateway %s admits no ListenerSets (allowedListeners is %s, the default)", gw.Key(), from)
}

// setGateway returns the Gateway an attached ListenerSet belongs to.
func (t *Table) setGateway(key string) *Gateway {
	for _, r := range t.sets {
		if r.LS.Key() == key {
			return r.GW
		}
	}
	return nil
}

// listenersOf lists gw's own listeners followed by those of the ListenerSets
// it admits, oldest set first (the Gateway's own listeners win conflicts).
func (t *Table) listenersOf(gw *Gateway) []lsEntry {
	var out []lsEntry
	for _, l := range gw.Listeners {
		out = append(out, lsEntry{L: l})
	}
	for _, r := range t.sets {
		if r.GW != gw {
			continue
		}
		for _, l := range r.LS.Listeners {
			out = append(out, lsEntry{L: l, LS: r.LS})
		}
	}
	return out
}

func l4Proto(proto string) string {
	if proto == "TCP" || proto == "UDP" {
		return proto
	}
	return ""
}

// validAddress reports whether a Gateway spec.addresses entry is something
// the gateway can report: an IP address or a hostname (value may be empty,
// meaning "any address of this type").
func validAddress(a GatewayAddress) error {
	switch a.Type {
	case "", "IPAddress":
		if a.Value != "" && net.ParseIP(a.Value) == nil {
			return fmt.Errorf("%q is not an IP address", a.Value)
		}
	case "Hostname":
		if strings.ContainsAny(a.Value, " /:") {
			return fmt.Errorf("%q is not a hostname", a.Value)
		}
	default:
		return fmt.Errorf("address type %q is not supported (IPAddress and Hostname are)", a.Type)
	}
	return nil
}
