package gateway

import (
	"net"
	"sort"
	"strconv"
)

// ListenPort is one listener the gateway has bound: the port the Gateway
// config names (Spec) and the address it really listens on (Addr), which
// differs under --port-map and --port-offset.
type ListenPort struct {
	Spec  int    `json:"spec"`
	Addr  string `json:"addr"`
	Proto string `json:"proto"` // tcp or udp
}

// Port is the numeric port of Addr.
func (p ListenPort) Port() int {
	_, ps, err := net.SplitHostPort(p.Addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(ps)
	return n
}

// listenPorts lists the bound listeners, ordered by spec port. The admin
// /status serves it so tools can tell which process owns a port.
func (s *Server) listenPorts() []ListenPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ListenPort
	for spec, bp := range s.ports {
		switch {
		case bp.udp != nil:
			out = append(out, ListenPort{Spec: spec, Addr: bp.udp.pc.LocalAddr().String(), Proto: "udp"})
		case bp.ln != nil:
			out = append(out, ListenPort{Spec: spec, Addr: bp.ln.Addr().String(), Proto: "tcp"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec < out[j].Spec })
	return out
}

// specPortFor maps a port a client really connects to onto the spec port the
// routing table is keyed by. A port that is the bound port of a listener (the
// real port under --port-map or --port-offset) wins; any other port is taken
// as a spec port already.
func (s *Server) specPortFor(port int) int {
	for _, p := range s.listenPorts() {
		if p.Proto == "tcp" && p.Port() == port {
			return p.Spec
		}
	}
	return port
}
