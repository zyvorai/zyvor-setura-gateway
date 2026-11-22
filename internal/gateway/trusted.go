package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
)

// trustedNets is the set of peers whose X-Forwarded-For is believed.
type trustedNets []netip.Prefix

// ParseTrustedProxies parses "10.0.0.0/8,192.168.1.5,fd00::/8": CIDRs or bare
// addresses, separated by commas.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: want a CIDR or an IP address", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (t trustedNets) contains(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range t {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// peerTrusted reports whether the TCP peer of r is a trusted proxy.
func (t trustedNets) peerTrusted(r *http.Request) bool {
	if len(t) == 0 {
		return false
	}
	a, ok := peerAddr(r)
	return ok && t.contains(a)
}

// clientIP is the address of the original client. Without trusted proxies, or
// when the peer is not one, it is the TCP peer. From a trusted peer the
// X-Forwarded-For chain is walked right to left past other trusted hops, and
// the first address that is not trusted is the client; an unparsable entry
// stops the walk at the last hop that could be verified.
func (t trustedNets) clientIP(r *http.Request) string {
	peer, ok := peerAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if !t.contains(peer) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	cand := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			return cand.String()
		}
		cand = a
		if !t.contains(a) {
			return a.String()
		}
	}
	return cand.String()
}

// setForwarded fills the X-Forwarded-* headers of an outbound request. The
// incoming X-Forwarded-For is dropped (it is client-controlled) unless the
// TCP peer is a trusted proxy, in which case the peer is appended to it.
func (s *Server) setForwarded(pr *httputil.ProxyRequest) {
	pr.SetXForwarded()
	if !s.trusted.peerTrusted(pr.In) {
		return
	}
	var prior []string
	for _, v := range pr.In.Header.Values("X-Forwarded-For") {
		prior = append(prior, strings.TrimSpace(v))
	}
	if len(prior) == 0 {
		return
	}
	peer, _ := peerAddr(pr.In)
	pr.Out.Header.Set("X-Forwarded-For", strings.Join(prior, ", ")+", "+peer.String())
}

// applyRefFilters applies a rule's and a backendRef's request filters.
func applyRefFilters(out *http.Request, rule *CRule, ref *CRef, m *CMatch) {
	filters := append(append([]Filter(nil), rule.Rule.Filters...), ref.Filters...)
	for _, f := range filters {
		switch {
		case f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil:
			applyHeaderMod(out.Header, f.RequestHeaderModifier)
		case f.Type == "URLRewrite" && f.URLRewrite != nil:
			if f.URLRewrite.Hostname != "" {
				out.Host = f.URLRewrite.Hostname
			}
			if p := f.URLRewrite.Path; p != nil {
				np := rewritePath(out.URL.Path, p, m)
				out.URL.Path, out.URL.RawPath = np, ""
			}
		}
	}
}
