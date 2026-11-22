package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const grpcKeyT = "grpcroutes.gateway.networking.k8s.io/"

func grpcFrame(msg string) []byte {
	b := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	copy(b[5:], msg)
	return b
}

func readGRPCFrame(r io.Reader) (string, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	msg := make([]byte, binary.BigEndian.Uint32(hdr[1:]))
	_, err := io.ReadFull(r, msg)
	return string(msg), err
}

// grpcBackend is a hand-rolled gRPC server: length-prefixed frames over h2c,
// echoing every message as "<name>:<msg>" and ending with grpc-status 0 in the
// trailers. A path ending in /Fail answers Trailers-Only with status 5.
type grpcBackend struct {
	*httptest.Server
	name string
	mu   sync.Mutex
	seen []grpcSeen
}

type grpcSeen struct {
	Path, ContentType, TE, Host, Custom, Proto string
}

func newGRPCBackend(t *testing.T, name string) *grpcBackend {
	t.Helper()
	b := &grpcBackend{name: name}
	b.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.seen = append(b.seen, grpcSeen{Path: r.URL.Path, ContentType: r.Header.Get("Content-Type"), TE: r.Header.Get("Te"),
			Host: r.Host, Custom: r.Header.Get("X-Added"), Proto: r.Proto})
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Upstream", name)
		if strings.HasSuffix(r.URL.Path, "/Fail") {
			w.Header().Set("Grpc-Status", "5")
			w.Header().Set("Grpc-Message", "nope")
			return
		}
		fl := w.(http.Flusher)
		for {
			msg, err := readGRPCFrame(r.Body)
			if err != nil {
				break
			}
			w.Write(grpcFrame(name + ":" + msg))
			fl.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "done-"+name)
	}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	b.Server.Config.Protocols = &p
	b.Start()
	t.Cleanup(b.Close)
	return b
}

func (b *grpcBackend) addr() string { return strings.TrimPrefix(b.URL, "http://") }

func (b *grpcBackend) paths() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, s := range b.seen {
		out = append(out, s.Path)
	}
	return out
}

func h2cClient(addr string) *http.Client {
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Protocols: &p,
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}}}
}

type grpcReply struct {
	HTTP    int
	Proto   string
	Msgs    []string
	Header  http.Header
	Trailer http.Header
	Status  string
	Message string
}

func grpcRequest(c *http.Client, scheme, authority, path string, body io.Reader, hdr ...string) (*http.Response, error) {
	rq, err := http.NewRequest(http.MethodPost, scheme+"://"+authority+path, body)
	if err != nil {
		return nil, err
	}
	rq.Header.Set("Content-Type", "application/grpc")
	rq.Header.Set("Te", "trailers")
	for i := 0; i+1 < len(hdr); i += 2 {
		rq.Header.Set(hdr[i], hdr[i+1])
	}
	return c.Do(rq)
}

func grpcCall(t *testing.T, c *http.Client, scheme, authority, path string, msgs []string, hdr ...string) grpcReply {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range msgs {
		buf.Write(grpcFrame(m))
	}
	resp, err := grpcRequest(c, scheme, authority, path, &buf, hdr...)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := grpcReply{HTTP: resp.StatusCode, Proto: resp.Proto, Header: resp.Header}
	for {
		m, err := readGRPCFrame(resp.Body)
		if err != nil {
			break
		}
		r.Msgs = append(r.Msgs, m)
	}
	r.Trailer = resp.Trailer
	r.Status, r.Message = resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if r.Status == "" { // Trailers-Only
		r.Status, r.Message = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	return r
}

func grpcGateway(extraListeners ...m) m {
	ls := l{m{"name": "web", "protocol": "HTTP", "port": 8080}}
	for _, x := range extraListeners {
		ls = append(ls, x)
	}
	return m{"gatewayClassName": "setura", "listeners": ls}
}

func gref(name string, weight int) m { return ref(name, weight) }

func gmethod(typ, svc, method string) m {
	mm := m{}
	if typ != "" {
		mm["type"] = typ
	}
	if svc != "" {
		mm["service"] = svc
	}
	if method != "" {
		mm["method"] = method
	}
	return m{"method": mm}
}

func grule(matches []any, backends ...m) m {
	r := m{"backendRefs": toList(backends)}
	if matches != nil {
		r["matches"] = matches
	}
	return r
}

func grpcRoute(host string, rules ...m) m {
	r := m{"parentRefs": l{m{"name": "gw"}}, "rules": toRuleList(rules)}
	if host != "" {
		r["hostnames"] = l{host}
	}
	return r
}

func toRuleList(in []m) []any { return toList(in) }

func grpcSnap(gw m, res map[string]m, backends map[string]any, secrets m) []byte {
	resources := m{gwKeyT + "gw": gw}
	for k, v := range res {
		resources[k] = v
	}
	be := m{}
	for k, v := range backends {
		be["t/"+k+":80"] = v
	}
	doc := m{"schema": SnapshotSchema, "namespace": "t", "resources": resources, "backends": be}
	if secrets != nil {
		doc["secrets"] = secrets
	}
	return mustJSON(doc)
}

func grpcBackends(t *testing.T, names ...string) (map[string]any, map[string]*grpcBackend) {
	be, bs := map[string]any{}, map[string]*grpcBackend{}
	for _, n := range names {
		b := newGRPCBackend(t, n)
		bs[n], be[n] = b, b.addr()
	}
	return be, bs
}

func TestGRPCRouteMatching(t *testing.T) {
	be, bs := grpcBackends(t, "exact", "svc", "re", "hdr", "any")
	hdrMatch := gmethod("Exact", "pkg.Hdr", "")
	hdrMatch["headers"] = l{m{"name": "X-Tenant", "value": "acme"}}
	rt := grpcRoute("",
		grule([]any{gmethod("Exact", "pkg.Orders", "Get")}, gref("exact", 1)),
		grule([]any{gmethod("Exact", "pkg.Orders", "")}, gref("svc", 1)),
		grule([]any{gmethod("RegularExpression", "pkg\\.Re.*", "List.+")}, gref("re", 1)),
		grule([]any{hdrMatch}, gref("hdr", 1)),
		grule(nil, gref("any", 1)),
	)
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": rt}, be, nil), nil)
	c := h2cClient(s.Addr(8080))

	for _, tc := range []struct {
		path, want string
		hdr        []string
	}{
		{"/pkg.Orders/Get", "exact", nil},
		{"/pkg.Orders/Put", "svc", nil},
		{"/pkg.Orders2/Get", "any", nil}, // prefix matching is element-wise
		{"/pkg.ReThing/ListAll", "re", nil},
		{"/pkg.ReThing/Other", "any", nil},
		{"/pkg.Hdr/X", "hdr", []string{"X-Tenant", "acme"}},
		{"/pkg.Hdr/X", "any", []string{"X-Tenant", "other"}},
		{"/pkg.Hdr/X", "any", nil},
	} {
		r := grpcCall(t, c, "http", "svc.test", tc.path, []string{"ping"}, tc.hdr...)
		if r.HTTP != 200 || r.Status != "0" || len(r.Msgs) != 1 || r.Msgs[0] != tc.want+":ping" {
			t.Errorf("%s %v: got %+v, want backend %s", tc.path, tc.hdr, r, tc.want)
		}
	}
	// What the backend saw: still gRPC, original path, h2c, trailers requested, forwarded host.
	bs["exact"].mu.Lock()
	got := bs["exact"].seen[0]
	bs["exact"].mu.Unlock()
	if got.Path != "/pkg.Orders/Get" || got.ContentType != "application/grpc" || got.TE != "trailers" || got.Host != "svc.test" || !strings.HasPrefix(got.Proto, "HTTP/2") {
		t.Errorf("backend saw %+v", got)
	}
}

func TestGRPCTrailersAndHeaders(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	rule0 := grule([]any{gmethod("Exact", "pkg.S", "")}, gref("a", 1))
	rule0["filters"] = l{
		m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{"set": l{m{"name": "X-Added", "value": "yes"}}}},
		m{"type": "ResponseHeaderModifier", "responseHeaderModifier": m{"set": l{m{"name": "X-Resp", "value": "gw"}}}},
	}
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": grpcRoute("", rule0)}, be, nil), nil)
	c := h2cClient(s.Addr(8080))

	r := grpcCall(t, c, "http", "x.test", "/pkg.S/Echo", []string{"one", "two", "three"})
	if r.Status != "0" || r.Message != "done-a" || strings.Join(r.Msgs, ",") != "a:one,a:two,a:three" {
		t.Fatalf("reply %+v", r)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/grpc" {
		t.Errorf("content-type %q", ct)
	}
	if r.Header.Get(BackendHeader) != "a" || r.Header.Get("X-Resp") != "gw" || r.Header.Get("X-Upstream") != "a" {
		t.Errorf("headers %v", r.Header)
	}
	// Trailers-Only error from the backend passes through untouched.
	f := grpcCall(t, c, "http", "x.test", "/pkg.S/Fail", []string{"x"})
	if f.HTTP != 200 || f.Status != "5" || f.Message != "nope" {
		t.Errorf("Trailers-Only reply %+v", f)
	}
	bs := s.Table().Backends
	if len(bs) != 1 {
		t.Errorf("backends %v", bs)
	}
}

func TestGRPCBidirectionalStreaming(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": grpcRoute("", grule(nil, gref("a", 1)))}, be, nil), nil)
	pr, pw := io.Pipe()
	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := grpcRequest(h2cClient(s.Addr(8080)), "http", "x.test", "/pkg.S/Chat", pr)
		ch <- result{resp, err}
	}()
	var resp *http.Response
	// Each reply must arrive while the request body is still open.
	for _, msg := range []string{"m1", "m2", "m3"} {
		if _, err := pw.Write(grpcFrame(msg)); err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			r := <-ch
			if r.err != nil {
				t.Fatal(r.err)
			}
			resp = r.resp
			defer resp.Body.Close()
		}
		got, err := readGRPCFrame(resp.Body)
		if err != nil || got != "a:"+msg {
			t.Fatalf("stream reply %q err %v", got, err)
		}
	}
	pw.Close()
	if _, err := readGRPCFrame(resp.Body); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	if resp.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("trailers %v", resp.Trailer)
	}
}

func TestGRPCWeightedBackends(t *testing.T) {
	be, bs := grpcBackends(t, "a", "b", "off")
	rt := grpcRoute("", grule(nil, gref("a", 3), gref("b", 1), gref("off", 0)))
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": rt}, be, nil), nil)
	c := h2cClient(s.Addr(8080))
	for i := 0; i < 200; i++ {
		if r := grpcCall(t, c, "http", "x.test", "/p.S/M", []string{"x"}); r.Status != "0" {
			t.Fatalf("call %d: %+v", i, r)
		}
	}
	a, b, off := len(bs["a"].paths()), len(bs["b"].paths()), len(bs["off"].paths())
	if a+b != 200 || off != 0 || a < 110 || a > 190 || b < 10 {
		t.Errorf("a=%d b=%d off=%d", a, b, off)
	}
}

func TestGRPCErrors(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	be["dead"] = deadAddr
	be["zero"] = deadAddr
	rt := grpcRoute("grpc.test",
		grule([]any{gmethod("Exact", "pkg.Ok", "")}, gref("a", 1)),
		grule([]any{gmethod("Exact", "pkg.Dead", "")}, gref("dead", 1)),
		grule([]any{gmethod("Exact", "pkg.Zero", "")}, gref("zero", 0)),
		grule([]any{gmethod("Exact", "pkg.Missing", "")}, gref("ghost", 1)),
		grule([]any{gmethod("Exact", "pkg.NoRefs", "")}),
	)
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": rt}, be, nil), nil)
	c := h2cClient(s.Addr(8080))
	for _, tc := range []struct{ host, path, status string }{
		{"grpc.test", "/pkg.Unknown/M", "12"}, // no route: UNIMPLEMENTED
		{"other.test", "/pkg.Ok/M", "12"},     // no listener host match
		{"grpc.test", "/pkg.Dead/M", "14"},    // backend refused: UNAVAILABLE
		{"grpc.test", "/pkg.Zero/M", "14"},    // zero weight everywhere
		{"grpc.test", "/pkg.Missing/M", "14"}, // unresolved backend
		{"grpc.test", "/pkg.NoRefs/M", "14"},  // no backendRefs
		{"grpc.test", "/pkg.Ok/M", "0"},
	} {
		r := grpcCall(t, c, "http", tc.host, tc.path, []string{"x"})
		if r.HTTP != 200 || r.Status != tc.status {
			t.Errorf("%s%s: HTTP %d grpc-status %q (%q), want %s", tc.host, tc.path, r.HTTP, r.Status, r.Message, tc.status)
		}
		if tc.status != "0" {
			if ct := r.Header.Get("Content-Type"); ct != "application/grpc" || r.Message == "" {
				t.Errorf("%s: content-type %q message %q", tc.path, ct, r.Message)
			}
		}
	}
	// The failures are counted as unmatched or errors in stats, not as 2xx.
	snap := s.Stats().Snapshot()
	if snap["unmatched"].(int64) < 2 {
		t.Errorf("stats %v", snap)
	}
}

func TestGRPCAndHTTPShareListener(t *testing.T) {
	be, _ := grpcBackends(t, "g")
	hbe, _ := upstreams(t, "h")
	be["h"] = hbe["h"]
	httpRt := route("", rule("/", ref("h", 1)))
	grpcRt := grpcRoute("", grule([]any{gmethod("Exact", "pkg.S", "")}, gref("g", 1)))
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{rtKeyT + "h": httpRt, grpcKeyT + "g": grpcRt}, be, nil), nil)
	if r := get(t, s, "x.test", "/anything"); r.Status != 200 || r.Echo.Name != "h" {
		t.Errorf("HTTP: %d %s", r.Status, r.Body)
	}
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "x.test", "/pkg.S/M", []string{"x"}); r.Status != "0" || r.Msgs[0] != "g:x" {
		t.Errorf("gRPC: %+v", r)
	}
	// An HTTPRoute never serves a gRPC call, and no GRPCRoute serves plain HTTP.
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "x.test", "/other/M", []string{"x"}); r.Status != "12" {
		t.Errorf("gRPC on HTTP-only path: %+v", r)
	}
}

func TestGRPCOverTLSALPN(t *testing.T) {
	p := newPKI(t)
	be, _ := grpcBackends(t, "a")
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "tls", "protocol": "HTTPS", "port": 8443, "hostname": "g.test", "tls": m{"mode": "Terminate", "certificateRefs": l{m{"name": "c"}}}}}}
	rt := grpcRoute("g.test", grule([]any{gmethod("Exact", "pkg.S", "")}, gref("a", 1)))
	s := startServer(t, grpcSnap(gw, map[string]m{grpcKeyT + "g": rt}, be, m{"c": p.files("c", "g.test")}), nil)
	c := tlsClient(s.Addr(8443), p, "g.test")
	r := grpcCall(t, c, "https", "g.test", "/pkg.S/M", []string{"hi"})
	if r.Status != "0" || r.Proto != "HTTP/2.0" || len(r.Msgs) != 1 || r.Msgs[0] != "a:hi" {
		t.Fatalf("reply %+v", r)
	}
	// h2 was negotiated through ALPN.
	conn, err := tls.Dial("tcp", s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "g.test", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		t.Errorf("ALPN = %q", proto)
	}
}

func TestGRPCBackendOverTLS(t *testing.T) {
	// An https:// endpoint is dialled with h2 via ALPN; here a TLS h2 echo server.
	p := newPKI(t)
	cert, key := p.issue("127.0.0.1")
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg, _ := readGRPCFrame(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Write(grpcFrame("tls:" + msg))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	be := map[string]any{"a": m{"endpoints": l{srv.URL}, "insecureSkipVerify": true}}
	rt := grpcRoute("", grule(nil, gref("a", 1)))
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": rt}, be, nil), nil)
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "x.test", "/p.S/M", []string{"x"})
	if r.Status != "0" || len(r.Msgs) != 1 || r.Msgs[0] != "tls:x" {
		t.Errorf("reply %+v", r)
	}
}

func TestGRPCRouteStatusAndAllowedKinds(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080},
		m{"name": "httponly", "protocol": "HTTP", "port": 8081, "allowedRoutes": m{"kinds": l{m{"kind": "HTTPRoute"}}}},
		m{"name": "grpconly", "protocol": "HTTP", "port": 8082, "allowedRoutes": m{"kinds": l{m{"kind": "GRPCRoute", "group": APIGroup}}}},
	}}
	mk := func(section string, rules ...m) m {
		r := grpcRoute("", rules...)
		r["parentRefs"] = l{m{"name": "gw", "sectionName": section}}
		return r
	}
	okRule := grule(nil, gref("a", 1))
	redirect := grule(nil, gref("a", 1))
	redirect["filters"] = l{m{"type": "RequestRedirect"}}
	badRe := grule([]any{gmethod("RegularExpression", "(", "")}, gref("a", 1))
	res := map[string]m{
		grpcKeyT + "good":     mk("web", okRule),
		grpcKeyT + "httponly": mk("httponly", okRule),
		grpcKeyT + "grpconly": mk("grpconly", okRule),
		grpcKeyT + "missing":  mk("web", grule(nil, gref("ghost", 1))),
		grpcKeyT + "filter":   mk("web", redirect),
		grpcKeyT + "regex":    mk("web", badRe),
		grpcKeyT + "nosec":    mk("nope", okRule),
	}
	raw := grpcSnap(gw, res, be, nil)
	s := startServerPorts(t, raw, map[int]int{8080: 0, 8081: 0, 8082: 0})
	st := s.Status()
	for name, want := range map[string][2]string{
		"good": {"True/Accepted", "True/ResolvedRefs"}, "httponly": {"False/NotAllowedByListeners", "True/ResolvedRefs"},
		"grpconly": {"True/Accepted", "True/ResolvedRefs"}, "missing": {"True/Accepted", "False/BackendNotFound"},
		"filter": {"False/UnsupportedValue", "True/ResolvedRefs"}, "regex": {"False/UnsupportedValue", "True/ResolvedRefs"},
		"nosec": {"False/NoMatchingParent", "True/ResolvedRefs"},
	} {
		rs := st.Routes["GRPCRoute/t/"+name]
		if rs == nil || len(rs.Parents) != 1 {
			t.Errorf("%s: no status (%v)", name, st.Routes)
			continue
		}
		cs := rs.Parents[0].Conditions
		got := [2]string{cond(cs, "Accepted").Status + "/" + cond(cs, "Accepted").Reason, cond(cs, "ResolvedRefs").Status + "/" + cond(cs, "ResolvedRefs").Reason}
		if got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
		if rs.Parents[0].ControllerName != ControllerName {
			t.Errorf("%s: controller %q", name, rs.Parents[0].ControllerName)
		}
	}
	kinds := func(listener string) string {
		var out []string
		for _, ls := range st.Gateways["t/gw"].Listeners {
			if ls.Name == listener {
				for _, k := range ls.SupportedKinds {
					out = append(out, k.Kind)
				}
			}
		}
		return strings.Join(out, ",")
	}
	if kinds("web") != "HTTPRoute,GRPCRoute" || kinds("httponly") != "HTTPRoute" || kinds("grpconly") != "GRPCRoute" {
		t.Errorf("supported kinds: web=%q httponly=%q grpconly=%q", kinds("web"), kinds("httponly"), kinds("grpconly"))
	}
	if n := attached(st, "grpconly"); n != 1 {
		t.Errorf("grpconly attached = %d", n)
	}
	if r := grpcCall(t, h2cClient(s.Addr(8082)), "http", "x.test", "/p.S/M", []string{"x"}); r.Status != "0" {
		t.Errorf("grpconly listener: %+v", r)
	}
	if r := grpcCall(t, h2cClient(s.Addr(8081)), "http", "x.test", "/p.S/M", []string{"x"}); r.Status != "12" {
		t.Errorf("httponly listener must not serve gRPC: %+v", r)
	}
}

func attached(st *StatusDoc, listener string) int {
	for _, ls := range st.Gateways["t/gw"].Listeners {
		if ls.Name == listener {
			return ls.AttachedRoutes
		}
	}
	return -1
}

func startServerPorts(t *testing.T, raw []byte, ports map[int]int) *Server {
	t.Helper()
	return startServer(t, raw, func(o *Options) { o.PortMap = ports })
}

func TestGRPCKubernetesSource(t *testing.T) {
	be := newGRPCBackend(t, "kube")
	api := newFakeAPI(t)
	api.put("gatewayclasses", "", "setura", m{"spec": m{"controllerName": ControllerName}})
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080, "allowedRoutes": m{"namespaces": m{"from": "All"}}}}}})
	api.put("grpcroutes", "shop", "orders", m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z", "generation": 2},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}},
			"rules": l{m{"matches": l{gmethod("Exact", "shop.Orders", "")}, "backendRefs": l{m{"name": "orders", "port": 50051}}}}}})
	api.put("services", "shop", "orders", m{"spec": m{"ports": l{m{"name": "grpc", "port": 50051}}}})
	api.put("endpointslices", "shop", "orders-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders"}},
		"endpoints": l{m{"addresses": l{hostOf(be.addr())}, "conditions": m{"ready": true}}},
		"ports":     l{m{"name": "grpc", "port": portOf(be.addr())}}})
	s, _, _ := kubeServer(t, api, nil)

	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "x.test", "/shop.Orders/List", []string{"k"})
	if r.Status != "0" || len(r.Msgs) != 1 || r.Msgs[0] != "kube:k" {
		t.Fatalf("reply %+v", r)
	}
	waitFor(t, "grpcroute status", func() bool {
		st, _ := api.get("grpcroutes", "shop", "orders")["status"].(m)
		parents, _ := st["parents"].([]any)
		if len(parents) != 1 {
			return false
		}
		p, _ := parents[0].(m)
		return p["controllerName"] == ControllerName
	})
}
