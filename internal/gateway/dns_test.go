package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNS is an injectable resolver.
type fakeDNS struct {
	mu    sync.Mutex
	ans   map[string][]string
	ttl   time.Duration
	err   error
	calls map[string]int
}

func newFakeDNS(ttl time.Duration, ans map[string][]string) *fakeDNS {
	return &fakeDNS{ans: ans, ttl: ttl, calls: map[string]int{}}
}

func (f *fakeDNS) LookupHost(_ context.Context, host string) ([]string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[host]++
	if f.err != nil {
		return nil, 0, f.err
	}
	a, ok := f.ans[host]
	if !ok {
		return nil, 0, errors.New("no such host")
	}
	return append([]string(nil), a...), f.ttl, nil
}

func (f *fakeDNS) set(host string, ttl time.Duration, addrs ...string) {
	f.mu.Lock()
	f.ans[host], f.ttl = addrs, ttl
	f.mu.Unlock()
}

func (f *fakeDNS) fail(err error)    { f.mu.Lock(); f.err = err; f.mu.Unlock() }
func (f *fakeDNS) n(host string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[host] }

func TestDNSCacheClampsTTLAndKeepsStaleAnswers(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	r := newFakeDNS(0, map[string][]string{"a.test": {"10.0.0.2", "10.0.0.1", "10.0.0.2"}})
	c := newDNSCache(DNSOptions{Resolver: r, TTLMin: 10 * time.Second, TTLMax: time.Minute}, clk.now)
	expires := func() time.Duration {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.ents["a.test"].expires.Sub(clk.now())
	}
	for _, tc := range []struct {
		ttl  time.Duration
		want time.Duration
	}{{0, 10 * time.Second}, {3 * time.Second, 10 * time.Second}, {25 * time.Second, 25 * time.Second}, {time.Hour, time.Minute}, {-1, unknownDNSTTL}} {
		r.set("a.test", tc.ttl, "10.0.0.2", "10.0.0.1", "10.0.0.2")
		c.resolve(context.Background(), "a.test", 0, 0)
		if got := expires(); got != tc.want {
			t.Errorf("ttl %v: trusted for %v, want %v", tc.ttl, got, tc.want)
		}
	}
	got, err := c.lookup("a.test", 0, 0)
	if err != nil || strings.Join(got, ",") != "10.0.0.1,10.0.0.2" {
		t.Fatalf("answers are sorted and deduplicated: %v %v", got, err)
	}
	// A backend's own bounds override the gateway's.
	r.set("a.test", 2*time.Second, "10.0.0.1")
	c.resolve(context.Background(), "a.test", 20*time.Second, 40*time.Second)
	if got := expires(); got != 20*time.Second {
		t.Errorf("backend ttlMin: %v", got)
	}
	// Errors keep the last answer, mark it stale and retry after the minimum.
	r.fail(errors.New("SERVFAIL"))
	if changed := c.resolve(context.Background(), "a.test", 0, 0); changed {
		t.Error("a failed lookup changes nothing")
	}
	st := c.status()[0]
	if !st.Stale || st.Error != "SERVFAIL" || strings.Join(st.Addresses, ",") != "10.0.0.1" || st.Errors != 1 {
		t.Fatalf("status %+v", st)
	}
	if got := expires(); got != 10*time.Second {
		t.Errorf("retry after the minimum, got %v", got)
	}
	if _, err := c.lookup("never.test", 0, 0); err == nil || !strings.Contains(err.Error(), "cannot resolve never.test") {
		t.Fatalf("a name with no answer ever: %v", err)
	}
	if _, ok := c.nextDue([]string{"a.test"}); !ok {
		t.Error("nextDue")
	}
}

func extSnapshot(backends m, routes map[string]m) []byte {
	raw, _ := json.Marshal(m{"schema": SnapshotSchema, "namespace": "t", "resources": withRoutes(m{gwKeyT + "gw": httpGateway("")}, routes), "backends": backends})
	return raw
}

func withRoutes(res m, routes map[string]m) m {
	for k, v := range routes {
		res[rtKeyT+k] = v
	}
	return res
}

func backendRef(name string) m {
	return m{"group": BackendGroup, "kind": BackendKind, "name": name}
}

func dnsServer(t *testing.T, raw []byte, r DNSResolver, clk *fakeClock) *Server {
	return startServer(t, raw, func(o *Options) {
		o.DNS = DNSOptions{Resolver: r, TTLMin: 10 * time.Second, TTLMax: time.Minute}
		o.Resilience.Now = clk.now
	})
}

func TestExternalDNSBackendResolvesAndRefreshes(t *testing.T) {
	up := newUpstream(t, "ext")
	port := portOf(up.addr())
	r := newFakeDNS(30*time.Second, map[string][]string{"api.test": {"127.0.0.1"}})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	be := m{"t/ext": m{"endpoints": []any{fmt.Sprintf("http://api.test:%d", port)}}}
	s := dnsServer(t, extSnapshot(be, map[string]m{"r": route("", rule("/", backendRef("ext")))}), r, clk)

	reply := get(t, s, "x.test", "/")
	if reply.Status != 200 || reply.Echo.Name != "ext" {
		t.Fatalf("reply %d %s", reply.Status, reply.Body)
	}
	if reply.Echo.Host != "x.test" {
		t.Fatalf("the Host header is preserved as the Gateway API says, got %q", reply.Echo.Host)
	}
	key := "t/ext"
	b := s.Table().Backends[key]
	if b == nil || b.Kind != BackendKind || len(b.Eps) != 1 || b.Eps[0].Authority == "" {
		t.Fatalf("backend %+v", b)
	}
	first := b.Eps[0]
	if r.n("api.test") != 1 {
		t.Fatalf("lookups %d", r.n("api.test"))
	}

	refresh := func() bool {
		t.Helper()
		rebuilt, err := s.RefreshDNS(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return rebuilt
	}
	clk.add(20 * time.Second)
	if refresh() || r.n("api.test") != 1 {
		t.Fatal("an answer is trusted until its TTL ends")
	}
	clk.add(11 * time.Second)
	if refresh() || r.n("api.test") != 2 {
		t.Fatalf("an unchanged answer re-resolves without rebuilding (lookups %d)", r.n("api.test"))
	}

	r.set("api.test", time.Second, "127.0.0.1", "::1") // the TTL is raised to the 10s minimum
	clk.add(31 * time.Second)
	if !refresh() {
		t.Fatal("a changed answer rebuilds the table")
	}
	b = s.Table().Backends[key]
	if len(b.Eps) != 2 || b.Eps[1].URL.Host != fmt.Sprintf("127.0.0.1:%d", port) && b.Eps[0].URL.Host != fmt.Sprintf("127.0.0.1:%d", port) {
		t.Fatalf("endpoints %v", hosts(b))
	}
	carried, added := 0, 0
	for _, e := range b.Eps {
		if e == first {
			carried++
		} else if !e.added.IsZero() {
			added++
		}
	}
	if carried != 1 || added != 1 {
		t.Fatalf("the known endpoint keeps its state (%d) and the new one starts slow (%d)", carried, added)
	}

	r.fail(errors.New("SERVFAIL"))
	clk.add(11 * time.Second)
	if refresh() {
		t.Fatal("a failed lookup must not rebuild")
	}
	if st := s.lbStatus().DNS; len(st) != 1 || !st[0].Stale || st[0].Error != "SERVFAIL" || len(st[0].Addresses) != 2 {
		t.Fatalf("dns status %+v", st)
	}
	if get(t, s, "x.test", "/").Status != 200 {
		t.Fatal("stale answers keep serving")
	}
	r.fail(nil)
	clk.add(11 * time.Second)
	refresh()
	if st := s.lbStatus().DNS; st[0].Stale || st[0].Error != "" {
		t.Fatalf("recovered: %+v", st)
	}
}

func hosts(b *Backend) []string {
	var out []string
	for _, e := range b.Eps {
		out = append(out, e.URL.Host)
	}
	return out
}

func TestExternalBackendUnresolvedAtStartRecovers(t *testing.T) {
	up := newUpstream(t, "late")
	r := newFakeDNS(time.Minute, map[string][]string{})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	be := m{"t/ext": m{"endpoints": []any{fmt.Sprintf("api.test:%d", portOf(up.addr()))}}}
	s := dnsServer(t, extSnapshot(be, map[string]m{"r": route("", rule("/", backendRef("ext")))}), r, clk)
	if got := get(t, s, "x.test", "/"); got.Status != 500 {
		t.Fatalf("unresolved name: %d", got.Status)
	}
	r.set("api.test", time.Minute, "127.0.0.1")
	clk.add(11 * time.Second)
	if rebuilt, err := s.RefreshDNS(context.Background()); !rebuilt || err != nil {
		t.Fatalf("rebuilt %v %v", rebuilt, err)
	}
	if got := get(t, s, "x.test", "/"); got.Status != 200 || got.Echo.Name != "late" {
		t.Fatalf("after the name resolves: %d %s", got.Status, got.Body)
	}
}

func TestExternalBackendWithDNSOffDialsTheName(t *testing.T) {
	up := newUpstream(t, "plain")
	r := newFakeDNS(time.Minute, map[string][]string{})
	be := m{"t/ext": m{"endpoints": []any{"http://localhost:" + fmt.Sprint(portOf(up.addr()))}, "dns": false}}
	s := dnsServer(t, extSnapshot(be, map[string]m{"r": route("", rule("/", backendRef("ext")))}), r, &fakeClock{t: time.Unix(1_700_000_000, 0)})
	if got := get(t, s, "x.test", "/"); got.Status != 200 || r.n("localhost") != 0 {
		t.Fatalf("status %d, resolver calls %d", got.Status, r.n("localhost"))
	}
}

func TestPlainDNSNamesOfServicesAreNotResolvedByTheGateway(t *testing.T) {
	up := newUpstream(t, "svc")
	r := newFakeDNS(time.Minute, map[string][]string{})
	be := map[string]any{"svc": "localhost:" + fmt.Sprint(portOf(up.addr()))}
	s := dnsServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, be), r, &fakeClock{t: time.Unix(1_700_000_000, 0)})
	if got := get(t, s, "x.test", "/"); got.Status != 200 || r.n("localhost") != 0 {
		t.Fatalf("a Service endpoint keeps being dialled by name: %d %d", got.Status, r.n("localhost"))
	}
}

func TestBackendsAnnotationDeclaresServicelessBackends(t *testing.T) {
	up := newUpstream(t, "ann")
	ann := m{BackendsKey: fmt.Sprintf(`{"ext":{"endpoints":[{"address":"%s","weight":2,"zone":"z"}]}}`, up.addr())}
	rt := route("", rule("/", backendRef("ext")))
	rt["setura.zyvor.dev/annotations"] = ann
	s := startServer(t, extSnapshot(m{}, map[string]m{"r": rt}), nil)
	if got := get(t, s, "x.test", "/"); got.Status != 200 || got.Echo.Name != "ann" {
		t.Fatalf("%d %s", got.Status, got.Body)
	}
	if e := s.Table().Backends["t/ext"].Eps[0]; e.W() != 2 || e.Zone != "z" {
		t.Fatalf("endpoint %+v", e)
	}
	// An undeclared Backend and a broken annotation are reported, not served.
	missing := route("", rule("/", backendRef("nope")))
	s2 := startServer(t, extSnapshot(m{}, map[string]m{"r": missing}), nil)
	if got := get(t, s2, "x.test", "/"); got.Status != 500 {
		t.Fatalf("undeclared Backend: %d", got.Status)
	}
	var cond string
	for _, rs := range s2.Status().Routes {
		for _, p := range rs.Parents {
			for _, c := range p.Conditions {
				if c.Type == "ResolvedRefs" {
					cond = c.Reason
				}
			}
		}
	}
	if cond != "BackendNotFound" {
		t.Fatalf("ResolvedRefs reason %q", cond)
	}
	bad := route("", rule("/", backendRef("ext")))
	bad["setura.zyvor.dev/annotations"] = m{BackendsKey: `{"ext": 5}`}
	s3 := startServer(t, extSnapshot(m{}, map[string]m{"r": bad}), nil)
	if got := get(t, s3, "x.test", "/"); got.Status != 404 {
		t.Fatalf("a malformed backends annotation turns the route invalid: %d", got.Status)
	}
}

func TestUnixSocketEndpoint(t *testing.T) {
	dir, err := os.MkdirTemp("", "su")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(echo{Name: "unix", Host: r.Host, Path: r.URL.Path})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	be := map[string]any{"svc": []any{"unix://" + sock}}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, be), nil)
	got := get(t, s, "x.test", "/hello")
	if got.Status != 200 || got.Echo.Name != "unix" || got.Echo.Host != "x.test" || got.Echo.Path != "/hello" {
		t.Fatalf("%d %s", got.Status, got.Body)
	}
	if e := s.Table().Backends["t/svc:80"].Eps[0]; e.Unix != sock {
		t.Fatalf("endpoint %+v", e)
	}
	// Bare absolute paths work too, relative ones do not.
	if _, err := unixPath("/run/app.sock"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"unix:run/app.sock", "unix:///", "unix:"} {
		if _, err := unixPath(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestCheckBackendDef(t *testing.T) {
	for in, want := range map[string]string{
		`{"endpoints":["a:80","unix:///run/x.sock"],"dns":{"ttlMin":"5s","ttlMax":"1m"},"loadBalancer":"random"}`: "",
		`{"endpoints":[]}`:                                           "no endpoints",
		`{"endpoints":["unix:rel"]}`:                                 "absolute path",
		`{"endpoints":["nonsense"]}`:                                 "want host:port",
		`{"endpoints":["a:80"],"dns":{"ttlMin":"1m","ttlMax":"5s"}}`: "above ttlMax",
		`{"endpoints":["a:80"],"loadBalancer":{"algorithm":"x"}}`:    "loadBalancer",
		`{"endpoints":[{"address":"a:80","priority":500}]}`:          "priority",
		`{"endpoints":["a:80"],"timeout":"soon"}`:                    "timeout",
	} {
		err := CheckBackendDef([]byte(in))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", in, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
}

func TestKubernetesEndpointSliceZoneAndServiceAnnotation(t *testing.T) {
	up := newUpstream(t, "z")
	api := newFakeAPI(t)
	api.seed(up.addr())
	api.put("services", "shop", "orders", m{"metadata": m{"annotations": m{LoadBalancerKey: `{"algorithm":"random"}`}},
		"spec": m{"ports": l{m{"name": "http", "port": 80, "targetPort": 8080}}}})
	api.put("endpointslices", "shop", "orders-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders"}},
		"endpoints": l{m{"addresses": l{hostOf(up.addr())}, "conditions": m{"ready": true}, "zone": "eu-west-1a"}},
		"ports":     l{m{"name": "http", "port": portOf(up.addr())}}})
	s, _, _ := kubeServer(t, api, nil)
	waitFor(t, "backend", func() bool { return s.Table() != nil && s.Table().Backends["shop/orders:80"] != nil })
	b := s.Table().Backends["shop/orders:80"]
	if len(b.Eps) != 1 || b.Eps[0].Zone != "eu-west-1a" || !b.hasZone {
		t.Fatalf("endpoint zone: %+v", b.Eps)
	}
	if b.LB == nil || b.LB.Algo != AlgoRandom {
		t.Fatalf("Service annotation: %+v", b.LB)
	}
}

func TestHTTPSEndpointResolvedFromANameSendsThatNameAsSNI(t *testing.T) {
	var mu sync.Mutex
	var sni []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	srv.EnableHTTP2 = false
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		sni = append(sni, h.ServerName)
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := newFakeDNS(time.Minute, map[string][]string{"secure.test": {"127.0.0.1"}})
	be := m{"t/ext": m{"endpoints": []any{"https://secure.test:" + fmt.Sprint(portOf(strings.TrimPrefix(srv.URL, "https://")))}, "insecureSkipVerify": true}}
	s := dnsServer(t, extSnapshot(be, map[string]m{"r": route("", rule("/", backendRef("ext")))}), r, &fakeClock{t: time.Unix(1_700_000_000, 0)})
	if got := get(t, s, "x.test", "/"); got.Status != 200 {
		t.Fatalf("status %d %s", got.Status, got.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sni) == 0 || sni[0] != "secure.test" {
		t.Fatalf("SNI %v: the certificate is checked against the name, not the address", sni)
	}
}
