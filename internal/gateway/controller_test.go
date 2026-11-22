package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// watchServer runs the controller against the fake API with watches on and the
// poll/resync interval so long that only events can drive reloads.
func watchServer(t *testing.T, api *fakeAPI, tune func(*KubeSource)) (*Server, *KubeSource) {
	t.Helper()
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Resync = time.Hour
	ks.watchBackoff = 10 * time.Millisecond
	ks.fallbackPoll = 20 * time.Millisecond
	if tune != nil {
		tune(ks)
	}
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, time.Hour) }()
	waitFor(t, "controller ready", s.Ready)
	t.Cleanup(func() { cancel(); <-done })
	return s, ks
}

func orders(t *testing.T, s *Server) string {
	t.Helper()
	r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", "")
	if r.Status != 200 {
		return "status " + string(rune('0'+r.Status/100))
	}
	return r.Echo.Name
}

func endpointsTo(api *fakeAPI, up *upstream) {
	api.put("endpointslices", "shop", "orders-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders"}},
		"endpoints": l{m{"addresses": l{hostOf(up.addr())}, "conditions": m{"ready": true}}},
		"ports":     l{m{"name": "http", "port": portOf(up.addr())}}})
}

func TestWatchDrivesReloads(t *testing.T) {
	up1, up2 := newUpstream(t, "u1"), newUpstream(t, "u2")
	api := newFakeAPI(t)
	api.setWatch(func(w *fakeWatchState) { w.bookmarks = true })
	api.seed(up1.addr())
	s, _ := watchServer(t, api, nil)
	if got := orders(t, s); got != "u1" {
		t.Fatalf("served by %q", got)
	}
	// Every collection is watched from a resourceVersion, with no polling at all.
	waitFor(t, "watches open", func() bool { return api.watchCount("httproutes") >= 1 && api.watchCount("endpointslices") >= 1 })
	for _, l := range api.watchLog() {
		if strings.HasSuffix(l, "@") {
			t.Errorf("watch without resourceVersion: %s", l)
		}
	}
	endpointsTo(api, up2)
	waitFor(t, "endpoint event", func() bool { return orders(t, s) == "u2" })

	// A new route arrives by event, and a deleted one goes away.
	api.put("httproutes", "shop", "extra", m{"metadata": m{"creationTimestamp": "2026-02-01T00:00:00Z"},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}},
			"rules": l{m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/extra"}}}, "backendRefs": l{m{"name": "orders", "port": 80}}}}}})
	waitFor(t, "route added", func() bool {
		return req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/extra", "").Status == 200
	})
	api.del("httproutes", "shop", "extra")
	waitFor(t, "route deleted", func() bool {
		return req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/extra", "").Status == 404
	})
	waitFor(t, "attachedRoutes back to 1", func() bool {
		st, _ := api.get("gateways", "infra", "edge")["status"].(m)
		ls, _ := st["listeners"].([]any)
		return len(ls) == 1 && ls[0].(m)["attachedRoutes"].(float64) == 1
	})
}

func TestWatchReconnectReplaysMissedEvents(t *testing.T) {
	up1, up2 := newUpstream(t, "u1"), newUpstream(t, "u2")
	api := newFakeAPI(t)
	api.seed(up1.addr())
	s, _ := watchServer(t, api, nil)
	waitFor(t, "watch open", func() bool { return api.watchCount("endpointslices") >= 1 })
	before := api.watchCount("endpointslices")
	api.dropWatches()
	endpointsTo(api, up2) // lands while the controller is reconnecting; replayed from its resourceVersion
	waitFor(t, "reconnect", func() bool { return api.watchCount("endpointslices") > before })
	waitFor(t, "replayed event applied", func() bool { return orders(t, s) == "u2" })
}

func TestWatch410GoneRelists(t *testing.T) {
	up1, up2, up3 := newUpstream(t, "u1"), newUpstream(t, "u2"), newUpstream(t, "u3")
	api := newFakeAPI(t)
	api.seed(up1.addr())
	s, _ := watchServer(t, api, nil)
	waitFor(t, "watch open", func() bool { return api.watchCount("endpointslices") >= 1 })

	// Request-level 410: history compacted past the controller's resourceVersion.
	n := api.watchCount("endpointslices")
	api.setWatch(func(w *fakeWatchState) { w.goneOnce = map[string]int{"endpointslices": 1} })
	api.dropWatches()
	endpointsTo(api, up2)
	waitFor(t, "relist after 410 applies the change", func() bool { return orders(t, s) == "u2" })
	waitFor(t, "watch resumes after relist", func() bool { return api.watchCount("endpointslices") > n+1 })

	// In-stream ERROR event with code 410 has the same effect.
	api.sendGone()
	endpointsTo(api, up3)
	waitFor(t, "event after in-stream 410", func() bool { return orders(t, s) == "u3" })
}

func TestWatchUnavailableFallsBackToPolling(t *testing.T) {
	up1, up2 := newUpstream(t, "u1"), newUpstream(t, "u2")
	api := newFakeAPI(t)
	api.setWatch(func(w *fakeWatchState) { w.noWatch = true })
	api.seed(up1.addr())
	s, _ := watchServer(t, api, nil)
	endpointsTo(api, up2)
	waitFor(t, "change seen without a watch", func() bool { return orders(t, s) == "u2" })
}

func TestStatusCleanupWhenRouteDetached(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	s, _, _ := kubeServer(t, api, nil)
	ours := func() int {
		st, _ := api.get("httproutes", "shop", "orders")["status"].(m)
		n := 0
		for _, p := range st["parents"].([]any) {
			if p.(m)["controllerName"] == ControllerName {
				n++
			}
		}
		return n
	}
	attached := func() float64 {
		st, _ := api.get("gateways", "infra", "edge")["status"].(m)
		ls, _ := st["listeners"].([]any)
		if len(ls) == 0 {
			return -1
		}
		return ls[0].(m)["attachedRoutes"].(float64)
	}
	waitFor(t, "status written", func() bool { return ours() == 1 && attached() == 1 })

	// Detach: the route now names only another controller's Gateway.
	r := api.get("httproutes", "shop", "orders")
	r["spec"].(m)["parentRefs"] = l{m{"name": "foreign", "namespace": "infra"}}
	api.put("httproutes", "shop", "orders", r)
	waitFor(t, "our parent entry removed", func() bool { return ours() == 0 })
	waitFor(t, "attachedRoutes back to 0", func() bool { return attached() == 0 })
	st := api.get("httproutes", "shop", "orders")["status"].(m)["parents"].([]any)
	if len(st) != 1 || st[0].(m)["controllerName"] != "example.com/other" {
		t.Fatalf("the other controller's entry must survive: %v", st)
	}
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", ""); r.Status != 404 {
		t.Fatalf("detached route still served: %d", r.Status)
	}

	// Re-attach: status returns; then retarget one of two parentRefs.
	r = api.get("httproutes", "shop", "orders")
	r["spec"].(m)["parentRefs"] = l{m{"name": "edge", "namespace": "infra"}}
	api.put("httproutes", "shop", "orders", r)
	waitFor(t, "status back", func() bool { return ours() == 1 && attached() == 1 })
}

func TestGatewayAddressesFromService(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	api.put("services", "setura-system", "setura-gateway", m{"spec": m{"type": "ClusterIP", "clusterIP": "10.0.0.7",
		"ports": l{m{"name": "http", "port": 80}}}})
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll = true
	ks.SvcName, ks.SvcNS = "setura-gateway", "setura-system"
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "ready", s.Ready)

	addrs := func() string {
		st, _ := api.get("gateways", "infra", "edge")["status"].(m)
		b, _ := json.Marshal(st["addresses"])
		return string(b)
	}
	waitFor(t, "ClusterIP address", func() bool { return addrs() == `[{"type":"IPAddress","value":"10.0.0.7"}]` })

	api.put("services", "setura-system", "setura-gateway", m{"spec": m{"type": "LoadBalancer", "clusterIP": "10.0.0.7",
		"ports": l{m{"name": "http", "port": 80}}},
		"status": m{"loadBalancer": m{"ingress": l{m{"ip": "203.0.113.5"}, m{"hostname": "lb.example.test"}}}}})
	waitFor(t, "LoadBalancer addresses", func() bool {
		return addrs() == `[{"type":"IPAddress","value":"203.0.113.5"},{"type":"Hostname","value":"lb.example.test"}]`
	})
	if api.get("gateways", "infra", "foreign")["status"] != nil {
		t.Error("foreign Gateway status must not be touched")
	}
}

func TestExposeGatewayPorts(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080, "allowedRoutes": m{"namespaces": m{"from": "All"}}},
		m{"name": "plain", "protocol": "HTTP", "port": 81},
		m{"name": "std", "protocol": "HTTP", "port": 80},
		m{"name": "udp", "protocol": "UDP", "port": 5353}}}})
	api.put("services", "setura-system", "setura-gateway", m{"spec": m{"type": "ClusterIP", "ports": l{
		m{"name": "http", "port": 80, "targetPort": "http"}, m{"name": "gw-9999", "port": 9999, "targetPort": 9999}}}})
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.SvcName, ks.SvcNS, ks.ExposePorts, ks.PortOffset = "setura-gateway", "setura-system", true, 8000
	ctx := context.Background()
	ld, err := ks.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = ld
	if err := ks.WriteStatus(ctx, &StatusDoc{}); err != nil {
		t.Fatal(err)
	}
	spec := api.get("services", "setura-system", "setura-gateway")["spec"].(m)["ports"].([]any)
	got := map[string]float64{}
	for _, p := range spec {
		pm := p.(m)
		if tp, ok := pm["targetPort"].(float64); ok {
			got[pm["name"].(string)] = tp
		} else {
			got[pm["name"].(string)] = -1 // named targetPort, untouched
		}
	}
	want := map[string]float64{"http": -1, "gw-8080": 8080, "gw-81": 8081}
	if len(got) != len(want) {
		t.Fatalf("ports %v, want %v (gw-9999 removed, port 80 kept, UDP ignored)", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("port %s targetPort %v, want %v", k, got[k], v)
		}
	}
	// Converged: a second pass patches nothing.
	if _, err := ks.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api.setWatch(func(w *fakeWatchState) { w.svcPatches = nil })
	ks.WriteStatus(ctx, &StatusDoc{})
	api.mu.Lock()
	n := len(api.watch.svcPatches)
	api.mu.Unlock()
	if n != 0 {
		t.Fatalf("service patched again while converged (%d)", n)
	}
}

func leaseKS(api *fakeAPI, id string) *KubeSource {
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll = true
	ks.Lease = &LeaseConfig{Name: "setura-gateway", Namespace: "setura-system", Identity: id,
		Duration: time.Second, RenewDeadline: 600 * time.Millisecond, RetryPeriod: 20 * time.Millisecond}
	return ks
}

func startLease(t *testing.T, ks *KubeSource, wakes *atomic.Int32) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ks.Start(ctx, func() { wakes.Add(1) })
	t.Cleanup(func() { cancel(); ks.Wait() })
	return cancel
}

func TestLeaseAcquireRenewRelease(t *testing.T) {
	api := newFakeAPI(t)
	var wakes atomic.Int32
	a := leaseKS(api, "a")
	cancel := startLease(t, a, &wakes)
	waitFor(t, "a leads", func() bool { return a.isLeader() })
	if h, _, ok := api.leaseSpec("setura-system", "setura-gateway"); !ok || h != "a" {
		t.Fatalf("lease holder %q", h)
	}
	if wakes.Load() == 0 {
		t.Error("gaining leadership must wake the controller to write status")
	}
	// Renewal moves renewTime forward.
	first := api.leaseTime()
	waitFor(t, "renewed", func() bool { return api.leaseTime() != first })

	// A second replica stays a follower while a renews.
	b := leaseKS(api, "b")
	startLease(t, b, &wakes)
	time.Sleep(300 * time.Millisecond)
	if b.isLeader() || !a.isLeader() {
		t.Fatalf("leaders: a=%v b=%v", a.isLeader(), b.isLeader())
	}

	// a shuts down: it releases the lease and b takes over at once, not after expiry.
	cancel()
	a.Wait()
	if a.isLeader() {
		t.Error("a still leads after release")
	}
	waitFor(t, "b leads", func() bool { return b.isLeader() })
	if h, tr, _ := api.leaseSpec("setura-system", "setura-gateway"); h != "b" || tr < 1 {
		t.Fatalf("holder %q transitions %d", h, tr)
	}
}

func (f *fakeAPI) leaseTime() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.watch.leases["setura-system/setura-gateway"]
	if o == nil {
		return ""
	}
	return o["spec"].(m)["renewTime"].(string)
}

func TestLeaseFollowerNeverWritesStatusAndTakesOverOnExpiry(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	api.setLease("setura-system", "setura-gateway", "someone-else", 1) // not renewed again: expires
	ks := leaseKS(api, "me")
	var wakes atomic.Int32
	startLease(t, ks, &wakes)
	ctx := context.Background()
	ld, err := ks.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	doc := BuildStatus(BuildTable(ld.Config), nil, time.Now(), nil)
	time.Sleep(200 * time.Millisecond)
	if ks.isLeader() {
		t.Fatal("took a lease that has not expired")
	}
	if err := ks.WriteStatus(ctx, doc); err != nil || len(api.patchLog()) != 0 {
		t.Fatalf("follower wrote status: err %v patches %v", err, api.patchLog())
	}
	waitFor(t, "takeover after expiry", func() bool { return ks.isLeader() })
	if h, tr, _ := api.leaseSpec("setura-system", "setura-gateway"); h != "me" || tr != 2 {
		t.Fatalf("holder %q transitions %d", h, tr)
	}
	if err := ks.WriteStatus(ctx, doc); err != nil || len(api.patchLog()) == 0 {
		t.Fatalf("leader did not write status: err %v", err)
	}
}

func TestLeaseLostWhenStolenOrAPIFails(t *testing.T) {
	api := newFakeAPI(t)
	var wakes atomic.Int32
	a := leaseKS(api, "a")
	startLease(t, a, &wakes)
	waitFor(t, "a leads", func() bool { return a.isLeader() })

	// Another holder appears (clock skew, manual edit): leadership is dropped at once.
	api.setLease("setura-system", "setura-gateway", "usurper", 60)
	waitFor(t, "a steps down", func() bool { return !a.isLeader() })

	// If the usurper's lease is cleared, a comes back; then API failures longer
	// than the renew deadline make it step down on its own.
	api.setLease("setura-system", "setura-gateway", "", 1)
	waitFor(t, "a leads again", func() bool { return a.isLeader() })
	api.setWatch(func(w *fakeWatchState) { w.leaseFail = true })
	waitFor(t, "a steps down after renew deadline", func() bool { return !a.isLeader() })
	api.setWatch(func(w *fakeWatchState) { w.leaseFail = false })
	waitFor(t, "a recovers", func() bool { return a.isLeader() })
}

func TestTwoReplicasOnlyLeaderWritesStatus(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	mk := func(id string) *KubeSource {
		ks := leaseKS(api, id)
		return ks
	}
	a, b := mk("a"), mk("b")
	run := func(ks *KubeSource) context.CancelFunc {
		s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
		t.Cleanup(func() { cancel(); <-done })
		waitFor(t, "ready", s.Ready)
		// Every replica serves.
		if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", ""); r.Status != 200 {
			t.Errorf("replica %s serves %d", ks.Lease.Identity, r.Status)
		}
		return cancel
	}
	cancelA := run(a)
	waitFor(t, "a leads", a.isLeader)
	run(b)
	waitFor(t, "status written by leader", func() bool { return len(api.patchLog()) > 0 })
	if b.isLeader() {
		t.Fatal("two leaders")
	}
	// Leader leaves: b takes over and repairs wiped status.
	cancelA()
	waitFor(t, "b leads", b.isLeader)
	before := len(api.patchLog())
	api.mu.Lock()
	api.objects["httproutes"]["shop/orders"].(m)["status"] = m{}
	api.mu.Unlock()
	waitFor(t, "b repairs status", func() bool { return len(api.patchLog()) > before })
}

func TestInvalidRouteKindsListener(t *testing.T) {
	cfg := &Config{Backends: map[string]*BackendDef{}, Gateways: []*Gateway{{NS: "t", Name: "gw", Generation: 4, ClassName: "setura", Listeners: []Listener{
		{Name: "bad", Protocol: "HTTP", Port: 80, AllowedRoutes: &AllowedRoutes{Kinds: []struct {
			Group string `json:"group,omitempty"`
			Kind  string `json:"kind"`
		}{{Kind: "UDPRoute"}, {Kind: "HTTPRoute"}}}},
		{Name: "good", Protocol: "HTTP", Port: 81},
	}}}}
	doc := BuildStatus(BuildTable(cfg), nil, time.Now(), nil)
	ls := doc.Gateways["t/gw"].Listeners
	rr := cond(ls[0].Conditions, "ResolvedRefs")
	if rr.Status != "False" || rr.Reason != "InvalidRouteKinds" || rr.ObservedGeneration != 4 {
		t.Errorf("bad listener ResolvedRefs: %+v", rr)
	}
	if len(ls[0].SupportedKinds) != 1 || ls[0].SupportedKinds[0].Kind != "HTTPRoute" {
		t.Errorf("supportedKinds lists the valid subset only: %+v", ls[0].SupportedKinds)
	}
	if c := cond(ls[1].Conditions, "ResolvedRefs"); c.Status != "True" {
		t.Errorf("good listener: %+v", c)
	}
}
