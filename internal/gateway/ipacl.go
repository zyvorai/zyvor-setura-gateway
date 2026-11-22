package gateway

import (
	"fmt"
	"net/netip"
)

// ipACL is a route's client address allow and deny lists. The client address
// is the one the rest of the gateway uses (rate limits, access logs): the TCP
// peer, or the X-Forwarded-For client when the peer is in --trusted-proxies.
type ipACL struct {
	allow, deny []netip.Prefix
}

func compileIPACL(allow, deny []string) (*ipACL, error) {
	a := &ipACL{}
	var err error
	if len(allow) > 0 {
		if a.allow, err = ParseTrustedProxies(joinList(allow)); err != nil {
			return nil, fmt.Errorf("ipAllow: %w", err)
		}
	}
	if len(deny) > 0 {
		if a.deny, err = ParseTrustedProxies(joinList(deny)); err != nil {
			return nil, fmt.Errorf("ipDeny: %w", err)
		}
	}
	if len(a.allow) == 0 && len(a.deny) == 0 {
		return nil, nil
	}
	return a, nil
}

func joinList(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// check returns "" when the address passes, otherwise why it does not. The
// deny list wins over the allow list; a non-empty allow list admits only its
// members.
func (a *ipACL) check(ip netip.Addr) string {
	if a == nil {
		return ""
	}
	in := func(list []netip.Prefix) bool {
		ip = ip.Unmap().WithZone("")
		for _, p := range list {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	switch {
	case in(a.deny):
		return fmt.Sprintf("client address %s is on the deny list", ip)
	case len(a.allow) > 0 && !in(a.allow):
		return fmt.Sprintf("client address %s is not on the allow list", ip)
	}
	return ""
}
