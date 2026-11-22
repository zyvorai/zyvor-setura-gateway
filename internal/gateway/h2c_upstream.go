package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
)

// HTTP/2 with prior knowledge (h2c) to plaintext upstreams, and the per-backend
// transports that PROXY protocol and h2c need.
//
// A backend with protocol: h2c (or a Service port with appProtocol
// kubernetes.io/h2c) is spoken to in HTTP/2 over cleartext TCP, the way gRPC
// backends already are, for ordinary HTTPRoutes too. https upstreams need no
// option: the shared transport offers h2 and http/1.1 by ALPN and uses what the
// server picks, falling back to HTTP/1.1 when it does not speak h2.

const (
	backendH2C  = "h2c"
	k8sH2C      = "kubernetes.io/h2c"
	annotPROXY  = "setura.zyvor.dev/proxy-protocol"
	annotProto  = "setura.zyvor.dev/protocol"
	protoHTTP11 = "http/1.1"
)

// applyProtocol validates and records the protocol options of a backend.
func (b *Backend) applyProtocol(def *BackendDef) error {
	switch def.Protocol {
	case "", "http", protoHTTP11, "h1":
	case backendH2C:
		for _, e := range b.Eps {
			if e.URL.Scheme != "http" {
				return fmt.Errorf("protocol h2c needs plain http:// endpoints, %s is %s", e.URL.Host, e.URL.Scheme)
			}
		}
		b.H2C = true
	default:
		return fmt.Errorf("protocol %q: want h2c or http/1.1", def.Protocol)
	}
	if err := validProxyVersion(def.ProxyProtocol); err != nil {
		return err
	}
	b.ProxyProto = def.ProxyProtocol
	return nil
}

// kubeBackendProtocol maps a Service port's appProtocol and annotations.
func kubeBackendProtocol(def *BackendDef, appProtocol *string, annotations map[string]string) {
	if appProtocol != nil && *appProtocol == k8sH2C {
		def.Protocol = backendH2C
	}
	if v := annotations[annotProto]; v != "" {
		def.Protocol = v
	}
	if v := annotations[annotPROXY]; v != "" {
		def.ProxyProtocol = v
	}
}

// derivedTransport returns the transport b needs when it differs from the
// shared ones: h2c for plain HTTP/2, a dialer that writes the PROXY header (with
// keep-alives off, because the header names one client). grpc selects the
// gRPC base transports, which are HTTP/2 already.
func (s *Server) derivedTransport(b *Backend, base http.RoundTripper, grpc bool) http.RoundTripper {
	if b.ProxyProto == "" && (!b.H2C || grpc) {
		return base
	}
	bt, ok := base.(*http.Transport)
	if !ok {
		return base
	}
	key := fmt.Sprintf("%s|%s|%t|%t|%p", b.Key, b.ProxyProto, b.H2C && !grpc, grpc, bt)
	if v, ok := s.dx.Load(key); ok {
		return v.(*http.Transport)
	}
	t := bt.Clone()
	if b.H2C && !grpc {
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		t.Protocols = &p
		t.ForceAttemptHTTP2 = false
	}
	if b.ProxyProto != "" {
		t.DialContext = proxyDialer(b.ProxyProto)
		t.DisableKeepAlives = true
	}
	v, _ := s.dx.LoadOrStore(key, t)
	return v.(*http.Transport)
}

func (s *Server) closeDerivedTransports() {
	s.dx.Range(func(_, v any) bool {
		v.(*http.Transport).CloseIdleConnections()
		return true
	})
}

// proxySync notes whether any backend wants PROXY headers, so requests only
// carry the client address on their context when somebody will read it.
func (s *Server) proxySync(t *Table) {
	on := false
	for _, b := range t.Backends {
		if b.ProxyProto != "" {
			on = true
		}
	}
	s.proxyOut.Store(on)
}

// withProxyClient puts the inbound connection's addresses on the request
// context for proxyDialer.
func (s *Server) withProxyClient(r *http.Request) *http.Request {
	if !s.proxyOut.Load() {
		return r
	}
	var src, dst net.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		src = net.TCPAddrFromAddrPort(ap)
	}
	dst, _ = r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return r.WithContext(withProxyClient(r.Context(), src, dst))
}
