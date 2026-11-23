package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var lbT0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// lbBackend builds a backend of plain addresses (nothing is dialled).
func lbBackend(t *testing.T, eps []any, lb m) *Backend {
	t.Helper()
	def := m{"endpoints": eps}
	if lb != nil {
		def["loadBalancer"] = lb
	}
	var bd BackendDef
	if err := json.Unmarshal(mustJSON(def), &bd); err != nil {
		t.Fatal(err)
	}
	b, err := newBackend(&Config{}, "t/x:80", "x", &bd)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lbAddrs(n int) []any {
	var out []any
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("10.0.0.%d:80", i))
	}
	return out
}

func lbRq(rule *CLB, zone string, rnd func(int) int) *lbReq {
	return &lbReq{rule: rule, zone: zone, rnd: rnd}
}

func lbTally(b *Backend, n int, rq func() *lbReq) map[string]int {
	out := map[string]int{}
	for i := 0; i < n; i++ {
		ep, _ := b.pickLB(lbT0, nil, rq(), false)
		out[ep.URL.Host]++
	}
	return out
}

func TestParseLBBlockValidation(t *testing.T) {
	good := []string{
		`"leastRequest"`, `{"algorithm":"random"}`, `{}`,
		`{"algorithm":"leastRequest","choices":3}`,
		`{"algorithm":"consistentHash","consistentHash":{"on":"header","name":"X-User","minRingSize":2048}}`,
		`{"algorithm":"consistentHash","consistentHash":{"type":"maglev","on":"cookie","name":"lb","ttl":"1h","path":"/app","tableSize":5003}}`,
		`{"algorithm":"consistentHash","consistentHash":{"on":"sourceIP"}}`,
		`{"algorithm":"consistentHash","consistentHash":{"on":"query","name":"user"}}`,
		`{"slowStart":{"window":"30s","aggression":2,"minWeightPercent":20},"locality":{"preferLocalZone":true,"minHealthyPercent":60},"priority":{"healthyPercent":80},"panicThreshold":50}`,
	}
	for _, g := range good {
		if _, err := ParseLBBlock([]byte(g)); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
	bad := map[string]string{
		`{"algorithm":"fastest"}`:                                                                            "want roundRobin",
		`{"algorithm":"consistentHash"}`:                                                                     "needs a consistentHash block",
		`{"algorithm":"random","consistentHash":{"on":"sourceIP"}}`:                                          "algorithm is random",
		`{"algorithm":"random","choices":2}`:                                                                 "only applies to leastRequest",
		`{"algorithm":"leastRequest","choices":99}`:                                                          "outside 1-16",
		`{"algorithm":"consistentHash","consistentHash":{"on":"header"}}`:                                    "not a header name",
		`{"algorithm":"consistentHash","consistentHash":{"on":"mac"}}`:                                       "want header, cookie",
		`{"algorithm":"consistentHash","consistentHash":{"on":"sourceIP","name":"x"}}`:                       "does not apply to sourceIP",
		`{"algorithm":"consistentHash","consistentHash":{"on":"header","name":"x","ttl":"1h"}}`:              "only apply to a cookie",
		`{"algorithm":"consistentHash","consistentHash":{"on":"sourceIP","minRingSize":0,"tableSize":10}}`:   "only applies to maglev",
		`{"algorithm":"consistentHash","consistentHash":{"type":"maglev","on":"sourceIP","tableSize":100}}`:  "must be a prime",
		`{"algorithm":"consistentHash","consistentHash":{"type":"maglev","on":"sourceIP","minRingSize":10}}`: "does not apply to maglev",
		`{"algorithm":"consistentHash","consistentHash":{"on":"sourceIP","minRingSize":99999999}}`:           "outside 1-",
		`{"algorithm":"consistentHash","consistentHash":{"on":"sourceIP"},"slowStart":{"window":"1s"}}`:      "does not apply to consistentHash",
		`{"slowStart":{"window":"0s"}}`:                                                                      "positive duration",
		`{"slowStart":{"window":"1s","aggression":50}}`:                                                      "aggression",
		`{"locality":{"preferLocalZone":true,"minHealthyPercent":101}}`:                                      "outside 1-100",
		`{"panicThreshold":150}`:                                                                             "panicThreshold",
		`{"bogus":1}`:                                                                                        "unknown field",
	}
	for in, want := range bad {
		_, err := ParseLBBlock([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", in, err, want)
		}
	}
	if c, err := ParseLBFlag("leastRequest"); err != nil || c.Algorithm != "leastRequest" {
		t.Errorf("flag shorthand: %v %v", c, err)
	}
	if c, err := ParseLBFlag(`{"algorithm":"random"}`); err != nil || c.Algorithm != "random" {
		t.Errorf("flag json: %v %v", c, err)
	}
	if _, err := ParseLBFlag("nope"); err == nil {
		t.Error("a bad algorithm name must be refused")
	}
}

func TestEndpointObjectsAndWeights(t *testing.T) {
	b := lbBackend(t, []any{m{"address": "10.0.0.1:80", "weight": 3}, "10.0.0.2:80"}, nil)
	got := lbTally(b, 400, func() *lbReq { return nil })
	if got["10.0.0.1:80"] != 300 || got["10.0.0.2:80"] != 100 {
		t.Fatalf("smooth weighted round robin must split 3:1 exactly, got %v", got)
	}
	var bd BackendDef
	for _, bad := range []string{`{"endpoints":[{"address":"a:1","weight":5000}]}`, `{"endpoints":[{"address":"a:1","bogus":1}]}`, `{"endpoints":[{"weight":2}]}`} {
		if err := json.Unmarshal([]byte(bad), &bd); err == nil {
			t.Errorf("%s must not parse", bad)
		}
	}
}

func TestRoundRobinKeepsOrderForEqualWeights(t *testing.T) {
	b := lbBackend(t, lbAddrs(3), nil)
	var order []string
	for i := 0; i < 6; i++ {
		ep := b.choose(lbT0, nil)
		order = append(order, strings.TrimPrefix(strings.TrimSuffix(ep.URL.Host, ":80"), "10.0.0."))
	}
	if strings.Join(order, "") != "123123" {
		t.Fatalf("order %v", order)
	}
}

func TestLeastRequestPrefersIdleEndpoints(t *testing.T) {
	lb := m{"algorithm": "leastRequest", "choices": 3}
	b := lbBackend(t, lbAddrs(3), lb)
	b.Eps[0].inflight.Store(10)
	b.Eps[1].inflight.Store(2)
	b.Eps[2].inflight.Store(7)
	for i := 0; i < 20; i++ {
		if ep := b.choose(lbT0, nil); ep != b.Eps[1] {
			t.Fatalf("pick %d: %s, want the endpoint with 2 in flight", i, ep.URL.Host)
		}
	}
	_, why := b.pickLB(lbT0, nil, nil, false)
	if why.Load != 2 || why.Other != 7 || !strings.Contains(why.String(), "fewest in-flight") {
		t.Fatalf("why %+v %q", why, why.String())
	}
}

func TestLeastRequestPowerOfTwoSamplesTwo(t *testing.T) {
	b := lbBackend(t, lbAddrs(4), m{"algorithm": "leastRequest"})
	for i, n := range []int64{9, 1, 9, 5} {
		b.Eps[i].inflight.Store(n)
	}
	// rnd returns 0 each time: the sample is endpoint 0, then (after the swap) endpoint 1.
	ep, why := b.pickLB(lbT0, nil, lbRq(nil, "", func(int) int { return 0 }), false)
	if ep != b.Eps[1] || why.Sampled != 2 {
		t.Fatalf("picked %s sampled %d", ep.URL.Host, why.Sampled)
	}
	// Sampling endpoints 0 and 2 only (9 vs 9) cannot reach the idle one: that is power of two choices.
	seq := []int{0, 1} // first draw index 0; second draw from the remaining [1 2 3] index 1 -> endpoint 2
	i := 0
	ep, _ = b.pickLB(lbT0, nil, lbRq(nil, "", func(int) int { v := seq[i%2]; i++; return v }), false)
	if ep != b.Eps[0] {
		t.Fatalf("tie must keep the first sample, got %s", ep.URL.Host)
	}
}

func TestRandomIsWeightedAndInjectable(t *testing.T) {
	b := lbBackend(t, []any{m{"address": "10.0.0.1:80", "weight": 1}, m{"address": "10.0.0.2:80", "weight": 3}}, m{"algorithm": "random"})
	r := seededRand(5)
	got := lbTally(b, 4000, func() *lbReq { return lbRq(nil, "", r) })
	if a := got["10.0.0.2:80"]; a < 2800 || a > 3200 {
		t.Fatalf("weight 3 of 4 should take about 3000, got %v", got)
	}
	again := lbTally(b, 4000, func() *lbReq { return lbRq(nil, "", seededRand(5)) })
	if len(again) == 0 {
		t.Fatal("no picks")
	}
}

func lbHashReq(hdr, val string) *lbReq {
	r, _ := http.NewRequest("GET", "http://x.test/p?user="+val, nil)
	if hdr != "" {
		r.Header.Set(hdr, val)
	}
	r.RemoteAddr = val + ":1234"
	return &lbReq{r: r, ip: val, rnd: seededRand(3)}
}

func TestConsistentHashRingAndMaglev(t *testing.T) {
	for _, typ := range []string{"ring", "maglev"} {
		t.Run(typ, func(t *testing.T) {
			b := lbBackend(t, lbAddrs(5), m{"algorithm": "consistentHash", "consistentHash": m{"type": typ, "on": "header", "name": "X-User"}})
			owner := map[string]*Endpoint{}
			spread := map[*Endpoint]int{}
			for i := 0; i < 500; i++ {
				k := fmt.Sprintf("user-%d", i)
				ep, why := b.pickLB(lbT0, nil, lbHashReq("X-User", k), false)
				if why.NoKey {
					t.Fatal("key was present")
				}
				owner[k] = ep
				spread[ep]++
				if again, _ := b.pickLB(lbT0, nil, lbHashReq("X-User", k), false); again != ep {
					t.Fatalf("%s is not stable", k)
				}
			}
			for _, ep := range b.Eps {
				if spread[ep] < 40 {
					t.Errorf("%s took only %d of 500 keys: %v", ep.URL.Host, spread[ep], spread)
				}
			}
			// Take one endpoint out: only the keys it owned move.
			victim := b.Eps[2]
			victim.healthy.Store(false)
			moved := 0
			for k, ep := range owner {
				now, _ := b.pickLB(lbT0, nil, lbHashReq("X-User", k), false)
				if now == victim {
					t.Fatal("a down endpoint was picked")
				}
				if ep != victim && now != ep {
					moved++
				}
			}
			if typ == "ring" && moved != 0 {
				t.Errorf("ring hash moved %d keys that were not on the removed endpoint", moved)
			}
			if typ == "maglev" && moved != 0 {
				t.Errorf("maglev lookup moved %d keys that were not on the removed endpoint", moved)
			}
			victim.healthy.Store(true)
			// No key: random, and said so.
			_, why := b.pickLB(lbT0, nil, lbHashReq("", "x"), true)
			if !why.NoKey || !strings.Contains(why.String(), "not in the request") {
				t.Errorf("why %q", why.String())
			}
		})
	}
}

func TestRingMinimumSizeAndWeights(t *testing.T) {
	b := lbBackend(t, []any{m{"address": "10.0.0.1:80", "weight": 3}, "10.0.0.2:80"}, m{"algorithm": "consistentHash", "consistentHash": m{"on": "sourceIP", "minRingSize": 4096}})
	r := b.ringFor(4096)
	if len(r.pts) < 4096 {
		t.Fatalf("ring has %d points, want at least 4096", len(r.pts))
	}
	n := map[int32]int{}
	for _, p := range r.pts {
		n[p.idx]++
	}
	if n[0] != 3*n[1] {
		t.Fatalf("weight 3 endpoint should own 3x the points: %v", n)
	}
	if small := lbBackend(t, lbAddrs(5), nil).ringFor(1); len(small.pts) < 5 {
		t.Fatalf("every endpoint needs a point, got %d", len(small.pts))
	}
}

func TestConsistentHashSourceIPAndQuery(t *testing.T) {
	for _, on := range []m{{"on": "sourceIP"}, {"on": "query", "name": "user"}} {
		b := lbBackend(t, lbAddrs(4), m{"algorithm": "consistentHash", "consistentHash": on})
		seen := map[*Endpoint]bool{}
		for i := 0; i < 60; i++ {
			rq := lbHashReq("", fmt.Sprintf("192.0.2.%d", i))
			ep, _ := b.pickLB(lbT0, nil, rq, false)
			seen[ep] = true
			again, _ := b.pickLB(lbT0, nil, lbHashReq("", fmt.Sprintf("192.0.2.%d", i)), false)
			if again != ep {
				t.Fatalf("%v: unstable", on)
			}
		}
		if len(seen) < 3 {
			t.Errorf("%v: only %d endpoints used", on, len(seen))
		}
	}
}

func TestSlowStartRampsNewEndpoints(t *testing.T) {
	lb := m{"slowStart": m{"window": "100s", "minWeightPercent": 10}}
	b := lbBackend(t, lbAddrs(2), lb)
	b.Eps[1].added = lbT0 // joined a running gateway at lbT0
	at := func(d time.Duration) map[string]int {
		out := map[string]int{}
		for i := 0; i < 2000; i++ {
			ep, _ := b.pickLB(lbT0.Add(d), nil, nil, false)
			out[ep.URL.Host]++
		}
		return out
	}
	if got := at(0); got["10.0.0.2:80"] < 150 || got["10.0.0.2:80"] > 250 { // 10% floor of 1: about 1/11
		t.Fatalf("at the start the new endpoint gets about 9%%: %v", got)
	}
	if got := at(50 * time.Second); got["10.0.0.2:80"] < 550 || got["10.0.0.2:80"] > 750 { // 0.5/(1.5)
		t.Fatalf("half way it gets about a third: %v", got)
	}
	if got := at(100 * time.Second); got["10.0.0.2:80"] < 999 || got["10.0.0.2:80"] > 1001 {
		t.Fatalf("after the window the split is even: %v", got)
	}
}

func TestSlowStartAfterEjectionAndRecovery(t *testing.T) {
	b := lbBackend(t, lbAddrs(2), m{"slowStart": m{"window": "60s"}})
	rs := newResilience(ResilienceOptions{Now: func() time.Time { return lbT0 }})
	for i := 0; i < 5; i++ {
		rs.observe(b, b.Eps[0], true, lbT0)
	}
	until := lbT0.Add(30 * time.Second)
	if b.Eps[0].st.until != until {
		t.Fatalf("ejected until %v", b.Eps[0].st.until)
	}
	ep, _ := b.pickLB(until.Add(-time.Second), nil, nil, false)
	if ep != b.Eps[1] {
		t.Fatal("an ejected endpoint was picked")
	}
	// Right after the ejection ends the endpoint ramps up from the floor.
	c := b.cfg(nil)
	if f := b.Eps[0].slowFactor(c, until.Add(time.Second)); f > 0.2 {
		t.Fatalf("factor %v right after ejection", f)
	}
	if f := b.Eps[0].slowFactor(c, until.Add(61*time.Second)); f != 1 {
		t.Fatalf("factor %v after the window", f)
	}
	// An active check that brings an endpoint back also starts the ramp.
	b.Eps[1].recovered.Store(lbT0.Add(time.Hour).UnixNano())
	if f := b.Eps[1].slowFactor(c, lbT0.Add(time.Hour+time.Second)); f > 0.2 {
		t.Fatalf("factor %v after recovery", f)
	}
}

func TestEjectedEndpointsAreNeverPickedUnlessAllAre(t *testing.T) {
	for _, algo := range []string{"roundRobin", "random", "leastRequest"} {
		b := lbBackend(t, lbAddrs(3), m{"algorithm": algo})
		rs := newResilience(ResilienceOptions{})
		for i := 0; i < 5; i++ {
			rs.observe(b, b.Eps[1], true, lbT0)
		}
		r := seededRand(9)
		got := lbTally(b, 300, func() *lbReq { return lbRq(nil, "", r) })
		if got["10.0.0.2:80"] != 0 {
			t.Fatalf("%s picked the ejected endpoint: %v", algo, got)
		}
		b.Eps[0].healthy.Store(false)
		b.Eps[2].healthy.Store(false)
		ep, why := b.pickLB(lbT0, nil, lbRq(nil, "", r), false)
		if ep == nil || !why.AllDown || !strings.Contains(why.String(), "tried anyway") {
			t.Fatalf("%s: with every endpoint down one is still tried: %v %q", algo, ep, why.String())
		}
	}
}

func TestSkipAvoidsTriedEndpoints(t *testing.T) {
	b := lbBackend(t, lbAddrs(3), nil)
	skip := map[*Endpoint]bool{b.Eps[0]: true, b.Eps[1]: true}
	for i := 0; i < 5; i++ {
		if ep := b.choose(lbT0, skip); ep != b.Eps[2] {
			t.Fatalf("picked %s", ep.URL.Host)
		}
	}
	skip[b.Eps[2]] = true
	if ep := b.choose(lbT0, skip); ep == nil {
		t.Fatal("with everything tried an endpoint is still returned")
	}
}

func lbZoned(zone string, prio int, addr string) m {
	return m{"address": addr, "zone": zone, "priority": prio}
}

func TestPreferLocalZoneWithSpillover(t *testing.T) {
	lb := m{"algorithm": "random", "locality": m{"preferLocalZone": true, "minHealthyPercent": 60}}
	b := lbBackend(t, []any{lbZoned("a", 0, "10.0.0.1:80"), lbZoned("a", 0, "10.0.0.2:80"), lbZoned("a", 0, "10.0.0.3:80"), lbZoned("b", 0, "10.0.0.4:80")}, lb)
	r := seededRand(1)
	pick := func() map[string]int { return lbTally(b, 300, func() *lbReq { return lbRq(nil, "a", r) }) }
	if got := pick(); got["10.0.0.4:80"] != 0 {
		t.Fatalf("a healthy local zone serves alone: %v", got)
	}
	b.Eps[0].healthy.Store(false) // 2 of 3 local endpoints = 67% >= 60%
	if got := pick(); got["10.0.0.4:80"] != 0 {
		t.Fatalf("67%% healthy is still enough: %v", got)
	}
	b.Eps[1].healthy.Store(false) // 1 of 3 = 33% < 60%: spill
	got := pick()
	if got["10.0.0.4:80"] == 0 || got["10.0.0.3:80"] == 0 {
		t.Fatalf("under the threshold every zone serves: %v", got)
	}
	_, why := b.pickLB(lbT0, nil, lbRq(nil, "a", r), true)
	if !why.Spill || !strings.Contains(why.String(), "every zone serves") {
		t.Fatalf("why %q", why.String())
	}
	// No local zone configured: zones are ignored.
	if got := lbTally(b, 300, func() *lbReq { return lbRq(nil, "", r) }); got["10.0.0.4:80"] == 0 {
		t.Fatalf("no zone, no preference: %v", got)
	}
	// A zone with no endpoints at all is not a reason to refuse traffic.
	if got := lbTally(b, 50, func() *lbReq { return lbRq(nil, "c", r) }); got["10.0.0.3:80"]+got["10.0.0.4:80"] != 50 {
		t.Fatalf("unknown zone: %v", got)
	}
}

func TestLocalityZoneOfTheBlockWinsOverTheFlag(t *testing.T) {
	lb := m{"algorithm": "random", "locality": m{"preferLocalZone": true, "localZone": "b"}}
	b := lbBackend(t, []any{lbZoned("a", 0, "10.0.0.1:80"), lbZoned("b", 0, "10.0.0.2:80")}, lb)
	got := lbTally(b, 100, func() *lbReq { return lbRq(nil, "a", seededRand(1)) })
	if got["10.0.0.2:80"] != 100 {
		t.Fatalf("%v", got)
	}
}

func TestPriorityFailoverAndPanic(t *testing.T) {
	lb := m{"algorithm": "random", "priority": m{"healthyPercent": 70}}
	b := lbBackend(t, []any{lbZoned("", 0, "10.0.0.1:80"), lbZoned("", 0, "10.0.0.2:80"), lbZoned("", 0, "10.0.0.3:80"), lbZoned("", 0, "10.0.0.4:80"), lbZoned("", 1, "10.0.0.9:80")}, lb)
	r := seededRand(2)
	pick := func() map[string]int { return lbTally(b, 400, func() *lbReq { return lbRq(nil, "", r) }) }
	if got := pick(); got["10.0.0.9:80"] != 0 {
		t.Fatalf("priority 0 serves while healthy: %v", got)
	}
	b.Eps[0].healthy.Store(false) // 3 of 4 = 75% >= 70%
	if got := pick(); got["10.0.0.9:80"] != 0 {
		t.Fatalf("75%% is above the threshold: %v", got)
	}
	b.Eps[1].healthy.Store(false) // 50% < 70%: priority 1 joins
	got := pick()
	if got["10.0.0.9:80"] == 0 || got["10.0.0.3:80"] == 0 {
		t.Fatalf("both tiers should serve: %v", got)
	}
	_, why := b.pickLB(lbT0, nil, lbRq(nil, "", r), true)
	if why.Tiers != 2 || !strings.Contains(why.String(), "2 tiers") {
		t.Fatalf("why %q", why.String())
	}
	for _, i := range []int{2, 3} {
		b.Eps[i].healthy.Store(false)
	}
	if got := pick(); got["10.0.0.9:80"] != 400 {
		t.Fatalf("with priority 0 gone priority 1 takes everything: %v", got)
	}

	// Panic: too few healthy endpoints overall, so health is ignored.
	pb := lbBackend(t, lbAddrs(4), m{"algorithm": "random", "panicThreshold": 60})
	rs := newResilience(ResilienceOptions{})
	for i := 1; i < 4; i++ { // eject three of four
		pb.Eps[0].healthy.Store(true)
		for j := 0; j < 5; j++ {
			rs.observe(pb, pb.Eps[i], true, lbT0)
		}
	}
	got = lbTally(pb, 400, func() *lbReq { return lbRq(nil, "", r) })
	if len(got) != 4 {
		t.Fatalf("panic mode spreads over every endpoint: %v", got)
	}
	_, why = pb.pickLB(lbT0, nil, lbRq(nil, "", r), true)
	if !why.Panic {
		t.Fatalf("why %+v", why)
	}
	pb2 := lbBackend(t, lbAddrs(4), m{"algorithm": "random"})
	for j := 0; j < 5; j++ {
		rs.observe(pb2, pb2.Eps[1], true, lbT0)
	}
	if got := lbTally(pb2, 100, func() *lbReq { return lbRq(nil, "", r) }); got["10.0.0.2:80"] != 0 {
		t.Fatal("without a panic threshold an ejected endpoint is never picked")
	}
}

// ---- through the data path ----

func lbRoute(ann m, backendRefs ...m) map[string]m {
	rt := route("", rule("/", backendRefs...))
	if ann != nil {
		rt["setura.zyvor.dev/annotations"] = ann
	}
	return map[string]m{"r": rt}
}

func TestRuleAnnotationConsistentHashOverHTTP(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2", "e3")
	be := map[string]any{"svc": []any{ups["e1"].addr(), ups["e2"].addr(), ups["e3"].addr()}}
	ann := m{LoadBalancerKey: `{"algorithm":"consistentHash","consistentHash":{"on":"header","name":"X-User"}}`}
	s := startServer(t, snap(httpGateway(""), lbRoute(ann, ref("svc", 1)), be), nil)
	owner := map[string]string{}
	used := map[string]bool{}
	for i := 0; i < 40; i++ {
		u := fmt.Sprintf("user-%d", i)
		owner[u] = get(t, s, "x.test", "/", "X-User", u).Echo.Name
		used[owner[u]] = true
	}
	for u, want := range owner {
		if got := get(t, s, "x.test", "/", "X-User", u).Echo.Name; got != want {
			t.Fatalf("%s moved from %s to %s", u, want, got)
		}
	}
	if len(used) != 3 {
		t.Fatalf("40 users should reach all 3 endpoints: %v", used)
	}
	st := s.lbStatus()
	if len(st.Rules) != 1 || !strings.Contains(st.Rules[0].Algorithm, "consistentHash (ring on header x-user)") {
		t.Fatalf("status rules %+v", st.Rules)
	}
	bs := st.Backends["t/svc:80"]
	if bs == nil || bs.Last == nil || bs.Healthy != 3 || len(bs.Endpoints) != 3 {
		t.Fatalf("backend status %+v", bs)
	}
}

func TestConsistentHashCookieIsSetWhenAbsent(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2", "e3")
	be := map[string]any{"svc": []any{ups["e1"].addr(), ups["e2"].addr(), ups["e3"].addr()}}
	ann := m{LoadBalancerKey: `{"algorithm":"consistentHash","consistentHash":{"type":"maglev","on":"cookie","name":"lbid","ttl":"1h","path":"/"}}`}
	s := startServer(t, snap(httpGateway(""), lbRoute(ann, ref("svc", 1)), be), nil)
	first := get(t, s, "x.test", "/")
	sc := first.Header.Get("Set-Cookie")
	if !strings.HasPrefix(sc, "lbid=") || !strings.Contains(sc, "Max-Age=3600") || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Path=/") {
		t.Fatalf("Set-Cookie %q", sc)
	}
	val := strings.TrimPrefix(strings.SplitN(sc, ";", 2)[0], "lbid=")
	for i := 0; i < 10; i++ {
		r := get(t, s, "x.test", "/", "Cookie", "lbid="+val)
		if r.Echo.Name != first.Echo.Name {
			t.Fatalf("cookie holder moved from %s to %s", first.Echo.Name, r.Echo.Name)
		}
		if r.Header.Get("Set-Cookie") != "" {
			t.Fatal("the cookie is only set when the request has none")
		}
	}
}

func TestLeastRequestSendsToTheIdleEndpoint(t *testing.T) {
	arrived := make(chan string, 4)
	release := make(chan struct{})
	var once sync.Once
	mk := func(name string) string {
		u := newUpstreamFunc(t, func(w http.ResponseWriter, r *http.Request) {
			arrived <- name
			<-release
			w.Write([]byte(name))
		})
		return u
	}
	a, b := mk("a"), mk("b")
	be := map[string]any{"svc": []any{a, b}}
	ann := m{LoadBalancerKey: `"leastRequest"`}
	s := startServer(t, snap(httpGateway(""), lbRoute(ann, ref("svc", 1)), be), nil)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	done := make(chan string, 2)
	fire := func() {
		go func() {
			resp, err := client(s.Addr(8080), nil).Get("http://x.test/")
			if err != nil {
				done <- err.Error()
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			done <- string(b)
		}()
	}
	fire()
	first := <-arrived
	fire()
	second := <-arrived
	if first == second {
		t.Fatalf("both requests went to %s while the other endpoint was idle", first)
	}
	if n := s.Table().Backends["t/svc:80"].Eps[0].inflight.Load() + s.Table().Backends["t/svc:80"].Eps[1].inflight.Load(); n != 2 {
		t.Fatalf("in flight %d", n)
	}
	once.Do(func() { close(release) })
	<-done
	<-done
	waitFor(t, "in-flight drained", func() bool {
		bk := s.Table().Backends["t/svc:80"]
		return bk.Eps[0].inflight.Load()+bk.Eps[1].inflight.Load() == 0
	})
}

func TestServiceDefaultAndBackendOverride(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2")
	be := map[string]any{
		"plain":  []any{ups["e1"].addr(), ups["e2"].addr()},
		"custom": m{"endpoints": []any{ups["e1"].addr(), ups["e2"].addr()}, "loadBalancer": m{"algorithm": "random"}},
	}
	routes := map[string]m{
		"a": route("a.test", rule("/", ref("plain", 1))),
		"b": route("b.test", rule("/", ref("custom", 1))),
	}
	def, err := ParseLBFlag("leastRequest")
	if err != nil {
		t.Fatal(err)
	}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.LoadBalancer = def; o.Zone = "z1" })
	st := s.lbStatus()
	if st.Zone != "z1" || !strings.HasPrefix(st.Default, "leastRequest") {
		t.Fatalf("status %+v", st)
	}
	if got := st.Backends["t/plain:80"]; !strings.HasPrefix(got.Algorithm, "leastRequest") || !strings.Contains(got.Source, "default") {
		t.Fatalf("plain: %+v", got)
	}
	if got := st.Backends["t/custom:80"]; got.Algorithm != "random" || got.Source != "backend" {
		t.Fatalf("custom: %+v", got)
	}
	bad := New(Options{LoadBalancer: &LBConfig{Algorithm: "nope"}})
	defer bad.Close()
	if bad.lbErr == nil {
		t.Fatal("an invalid default must be refused")
	}
}

func TestInvalidRuleBlockTurnsRouteInvalid(t *testing.T) {
	be, _ := upstreams(t, "a")
	ann := m{LoadBalancerKey: `{"algorithm":"nope"}`}
	s := startServer(t, snap(httpGateway(""), lbRoute(ann, ref("a", 1)), be), nil)
	if r := get(t, s, "x.test", "/"); r.Status != 404 {
		t.Fatalf("a route with an invalid block is not served, got %d", r.Status)
	}
}

func TestExplainShowsAlgorithmHashKeyAndEndpoint(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2", "e3")
	be := map[string]any{"svc": []any{ups["e1"].addr(), ups["e2"].addr(), ups["e3"].addr()}}
	ann := m{LoadBalancerKey: `{"algorithm":"consistentHash","consistentHash":{"on":"header","name":"X-User"}}`}
	s := startServer(t, snap(httpGateway(""), lbRoute(ann, ref("svc", 1)), be), nil)
	explain := func(hdr ...string) *TraceLB {
		er, err := ParseExplainRequest("GET", "http://x.test:8080/", headerLines(hdr), "", "")
		if err != nil {
			t.Fatal(err)
		}
		er.Remote, er.Live, er.Now, er.Server = "127.0.0.1", true, s.res.now(), s.liveServerPolicy()
		tr := Explain(s.Table(), er)
		if tr.Winner == nil || len(tr.Winner.Backends) != 1 {
			t.Fatalf("no winner: %s", dumpTrace(tr))
		}
		return tr.Winner.Backends[0].LoadBalancer
	}
	lb := explain("X-User", "alice")
	if lb == nil || lb.Source != "rule" || lb.Hash != "header x-user" || lb.Ring != "ring" || lb.Endpoint == "" || !strings.Contains(lb.Algorithm, "consistentHash") {
		t.Fatalf("trace %+v", lb)
	}
	// The explained endpoint is the one the live request reaches.
	live := get(t, s, "x.test", "/", "X-User", "alice").Echo.Name
	for n, u := range ups {
		if lb.Endpoint == "http://"+u.addr() && n != live {
			t.Fatalf("explain says %s, the request went to %s", n, live)
		}
	}
	if lb := explain(); !strings.Contains(lb.Why, "not in the request") || lb.Endpoint != "" {
		t.Fatalf("without the header: %+v", lb)
	}
}

func TestWeightsAndZonesInSnapshotReachTheStatus(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2")
	be := map[string]any{"svc": m{"endpoints": []any{m{"address": ups["e1"].addr(), "weight": 3, "zone": "a"}, m{"address": ups["e2"].addr(), "zone": "b", "priority": 1}}}}
	s := startServer(t, snap(httpGateway(""), lbRoute(nil, ref("svc", 1)), be), nil)
	bs := s.lbStatus().Backends["t/svc:80"]
	if len(bs.Tiers) != 2 || bs.Endpoints[0].Weight != 3 || bs.Endpoints[0].Zone != "a" || bs.Endpoints[1].Priority != 1 {
		t.Fatalf("%+v", bs)
	}
	for i := 0; i < 5; i++ { // priority 1 stays idle while priority 0 is healthy
		if got := get(t, s, "x.test", "/").Echo.Name; got != "e1" {
			t.Fatalf("served by %s", got)
		}
	}
}

// newUpstreamFunc serves h and returns its host:port.
func newUpstreamFunc(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}
