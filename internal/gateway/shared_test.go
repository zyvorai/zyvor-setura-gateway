package gateway

import (
	"crypto/tls"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func sharedRule(rate string, shared m, extra m) m {
	r := rule("/", ref("a", 1))
	blk := m{"rate": rate}
	if shared != nil {
		blk["shared"] = shared
	}
	for k, v := range extra {
		blk[k] = v
	}
	r["setura.zyvor.dev/rate-limit"] = blk
	return r
}

// replica starts a gateway whose only route is the given rule, counting in fr.
func replica(t *testing.T, fr *fakeRedis, clk *fakeClock, ro func(*RedisOptions), rl m, be map[string]any) *Server {
	t.Helper()
	routes := map[string]m{"r": route("a.test", rl)}
	return startServer(t, snap(httpGateway(""), routes, be), func(o *Options) {
		o.Obs.Now = clk.now
		ropt := RedisOptions{Name: "default", Addr: fr.addr(), IOTimeout: 300 * time.Millisecond, DialTimeout: 300 * time.Millisecond}
		if ro != nil {
			ro(&ropt)
		}
		o.Redis = []RedisOptions{ropt}
	})
}

func newClock0() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func TestSharedLimitAcrossReplicas(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("3/s", m{"keyPrefix": "t:rl"}, nil)
	a := replica(t, fr, clk, nil, rl, be)
	b := replica(t, fr, clk, nil, rl, be)

	want := []struct {
		srv       *Server
		status    int
		remaining string
	}{{a, 200, "2"}, {b, 200, "1"}, {a, 200, "0"}, {b, 429, "0"}, {a, 429, "0"}}
	for i, w := range want {
		r := get(t, w.srv, "a.test", "/x")
		if r.Status != w.status || r.Header.Get("X-RateLimit-Limit") != "3" || r.Header.Get("X-RateLimit-Remaining") != w.remaining || r.Header.Get("X-RateLimit-Reset") != "1" {
			t.Fatalf("request %d: %d limit=%q remaining=%q reset=%q", i, r.Status, r.Header.Get("X-RateLimit-Limit"), r.Header.Get("X-RateLimit-Remaining"), r.Header.Get("X-RateLimit-Reset"))
		}
		if w.status == 429 && r.Header.Get("Retry-After") != "1" {
			t.Errorf("request %d: Retry-After %q", i, r.Header.Get("Retry-After"))
		}
	}
	for _, k := range fr.keys() {
		if !strings.HasPrefix(k, "t:rl:t/r#1:") {
			t.Errorf("key %q lacks the prefix and scope", k)
		}
	}
	// Refused requests gave their slot back: the previous window holds 3.
	// At +1s the whole previous window still counts, at +1.5s half of it.
	clk.add(time.Second)
	if r := get(t, a, "a.test", "/x"); r.Status != 429 {
		t.Fatalf("a full previous window still counts at the turn: %d", r.Status)
	}
	clk.add(500 * time.Millisecond)
	if r := get(t, b, "a.test", "/x"); r.Status != 200 || r.Header.Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("half the previous window has expired: %d remaining %q", r.Status, r.Header.Get("X-RateLimit-Remaining"))
	}
	clk.add(5 * time.Second)
	if r := get(t, a, "a.test", "/x"); r.Status != 200 || r.Header.Get("X-RateLimit-Remaining") != "2" {
		t.Fatalf("an idle client starts fresh: %d %q", r.Status, r.Header.Get("X-RateLimit-Remaining"))
	}
	// Each check is one MULTI / INCR / PEXPIRE / GET / EXEC pipeline, never Lua.
	var sawMulti bool
	for _, c := range fr.logged() {
		if strings.HasPrefix(c, "MULTI") {
			sawMulti = true
		}
		if strings.Contains(strings.ToUpper(c), "EVAL") {
			t.Errorf("Lua used: %s", c)
		}
	}
	if !sawMulti {
		t.Error("no MULTI seen")
	}
	for srv, ws := range map[*Server][]string{
		a: {`setura_gateway_shared_ratelimit_requests_total{route="t/r",rule="1",result="allowed"} 3`, `setura_gateway_shared_ratelimit_requests_total{route="t/r",rule="1",result="limited"} 2`},
		b: {`setura_gateway_shared_ratelimit_requests_total{route="t/r",rule="1",result="allowed"} 2`, `setura_gateway_shared_ratelimit_requests_total{route="t/r",rule="1",result="limited"} 1`},
	} {
		out := obsMetricsOf(srv)
		ws = append(ws, `setura_gateway_redis_up{redis="default"} 1`)
		for _, w := range ws {
			if !strings.Contains(out, w) {
				t.Errorf("metrics lack %s\n%s", w, out)
			}
		}
	}
}

func TestSharedLimitPerClientAndHeaderKey(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("1/s", m{}, m{"key": "header:X-Tenant"})
	s := replica(t, fr, clk, nil, rl, be)
	for _, c := range []struct {
		tenant string
		want   int
	}{{"one", 200}, {"two", 200}, {"one", 429}, {"two", 429}} {
		if r := get(t, s, "a.test", "/", "X-Tenant", c.tenant); r.Status != c.want {
			t.Fatalf("tenant %s: %d, want %d", c.tenant, r.Status, c.want)
		}
	}
	for _, k := range fr.keys() { // the client part is hashed: bounded key size whatever the header says
		if strings.Contains(k, "tenant") || strings.Contains(k, "one") {
			t.Errorf("key %q leaks the client value", k)
		}
	}
	long := strings.Repeat("x", 4000)
	get(t, s, "a.test", "/", "X-Tenant", long)
	for _, k := range fr.keys() {
		if len(k) > 120 {
			t.Errorf("key of %d bytes", len(k))
		}
	}
}

func TestSharedLimitAuthAndDB(t *testing.T) {
	fr := newFakeRedis(t, func(f *fakeRedis) { f.password, f.user = "s3cret", "gw" }, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("1/s", m{}, nil)
	good := replica(t, fr, clk, func(o *RedisOptions) { o.Username, o.Password, o.DB = "gw", "s3cret", 3 }, rl, be)
	if r := get(t, good, "a.test", "/"); r.Status != 200 || r.Header.Get("X-RateLimit-Limit") != "1" {
		t.Fatalf("authenticated: %d", r.Status)
	}
	if r := get(t, good, "a.test", "/"); r.Status != 429 {
		t.Fatalf("limit holds: %d", r.Status)
	}
	var auth, sel bool
	for _, c := range fr.logged() {
		auth = auth || c == "AUTH gw s3cret"
		sel = sel || c == "SELECT 3"
	}
	if !auth || !sel {
		t.Errorf("AUTH %v SELECT %v in %v", auth, sel, fr.logged())
	}
	// A wrong password never reaches the counter: the fallback answers and Redis stays unused.
	bad := replica(t, fr, clk, func(o *RedisOptions) { o.Username, o.Password = "gw", "wrong" }, rl, be)
	before := len(fr.keys())
	if r := get(t, bad, "a.test", "/"); r.Status != 200 || r.Header.Get("X-RateLimit-Limit") != "1" {
		t.Fatalf("fallback after a failed AUTH: %d", r.Status)
	}
	if len(fr.keys()) != before {
		t.Error("a failed AUTH still counted in Redis")
	}
	if !strings.Contains(obsMetricsOf(bad), `result="fallback_allowed"} 1`) {
		t.Errorf("fallback not counted:\n%s", obsMetricsOf(bad))
	}
}

func TestSharedLimitTLS(t *testing.T) {
	p := newPKI(t)
	certPEM, keyPEM := p.issue("redis.test")
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fr := newFakeRedis(t, nil, &tls.Config{Certificates: []tls.Certificate{pair}})
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("1/s", m{}, nil)
	ok := replica(t, fr, clk, func(o *RedisOptions) {
		o.TLS, o.ServerName, o.TLSConfig = true, "redis.test", &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12}
	}, rl, be)
	if r := get(t, ok, "a.test", "/"); r.Status != 200 || r.Header.Get("X-RateLimit-Limit") != "1" {
		t.Fatalf("over TLS: %d %v", r.Status, r.Header)
	}
	if r := get(t, ok, "a.test", "/"); r.Status != 429 {
		t.Fatalf("limit over TLS: %d", r.Status)
	}
	// An untrusted server certificate is a failure, so the local fallback answers.
	untrusted := replica(t, fr, clk, func(o *RedisOptions) {
		o.TLS, o.ServerName, o.TLSConfig = true, "redis.test", &tls.Config{RootCAs: newPKI(t).pool, MinVersion: tls.VersionTLS12}
	}, rl, be)
	if r := get(t, untrusted, "a.test", "/"); r.Status != 200 {
		t.Fatalf("fallback: %d", r.Status)
	}
	if !strings.Contains(obsMetricsOf(untrusted), `result="fallback_allowed"} 1`) || !strings.Contains(obsMetricsOf(untrusted), `setura_gateway_redis_up{redis="default"} 0`) {
		t.Errorf("untrusted certificate not reported:\n%s", obsMetricsOf(untrusted))
	}
}

func TestSharedLimitOutageFallbackAndRecovery(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("2/s", m{}, nil) // failOpen defaults to true, fallback to a local bucket
	s := replica(t, fr, clk, nil, rl, be)
	if r := get(t, s, "a.test", "/"); r.Status != 200 || r.Header.Get("X-RateLimit-Remaining") != "1" {
		t.Fatalf("up: %d", r.Status)
	}
	fr.setDown(true)
	// Redis is down: the per-replica bucket (2/s, burst 2) answers, so the limit still holds locally.
	var codes []int
	for i := 0; i < 3; i++ {
		codes = append(codes, get(t, s, "a.test", "/").Status)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("fallback statuses %v", codes)
	}
	out := obsMetricsOf(s)
	for _, w := range []string{`result="fallback_allowed"} 2`, `result="fallback_limited"} 1`, `setura_gateway_redis_up{redis="default"} 0`} {
		if !strings.Contains(out, w) {
			t.Errorf("metrics lack %s\n%s", w, out)
		}
	}
	if !strings.Contains(out, "setura_gateway_redis_errors_total{redis=\"default\"} 1") {
		t.Errorf("one failed attempt expected (the breaker spares Redis afterwards):\n%s", out)
	}
	// Redis comes back; the breaker waits out its cooldown (on the injected clock), then shared counting resumes.
	fr.setDown(false)
	if r := get(t, s, "a.test", "/"); r.Header.Get("X-RateLimit-Limit") == "" && r.Status == 200 {
		t.Log("still in cooldown")
	}
	clk.add(5 * time.Second)
	if r := get(t, s, "a.test", "/"); r.Status != 200 || r.Header.Get("X-RateLimit-Remaining") != "1" {
		t.Fatalf("after recovery: %d remaining %q", r.Status, r.Header.Get("X-RateLimit-Remaining"))
	}
	if !strings.Contains(obsMetricsOf(s), `setura_gateway_redis_up{redis="default"} 1`) {
		t.Error("redis_up did not recover")
	}
}

func TestSharedLimitFailClosedAndOpenNone(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	fr.setDown(true)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	closed := replica(t, fr, clk, nil, sharedRule("2/s", m{"failOpen": false}, nil), be)
	r := get(t, closed, "a.test", "/")
	if r.Status != 503 || r.Header.Get("Retry-After") == "" || !strings.Contains(r.Body, "unavailable") {
		t.Fatalf("fail closed: %d %v %q", r.Status, r.Header, r.Body)
	}
	if !strings.Contains(obsMetricsOf(closed), `result="unavailable"} 1`) {
		t.Errorf("unavailable not counted:\n%s", obsMetricsOf(closed))
	}
	open := replica(t, fr, clk, nil, sharedRule("1/s", m{"fallback": "none"}, nil), be)
	for i := 0; i < 4; i++ {
		if r := get(t, open, "a.test", "/"); r.Status != 200 {
			t.Fatalf("fail open without fallback: request %d got %d", i, r.Status)
		}
	}
	if !strings.Contains(obsMetricsOf(open), `result="open"} 4`) {
		t.Errorf("open not counted:\n%s", obsMetricsOf(open))
	}
}

func TestSharedLimitRedisTimeout(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	fr.setStall(true)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	s := replica(t, fr, clk, func(o *RedisOptions) { o.IOTimeout = 60 * time.Millisecond }, sharedRule("5/s", m{}, nil), be)
	start := time.Now()
	r := get(t, s, "a.test", "/")
	if r.Status != 200 {
		t.Fatalf("a stalled Redis must fall back, got %d", r.Status)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Errorf("took %s: the round trip deadline did not apply", time.Since(start))
	}
}

func TestSharedLimitPoolIsBounded(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	s := replica(t, fr, clk, func(o *RedisOptions) { o.PoolSize = 2 }, sharedRule("1000/s", m{}, nil), be)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := get(t, s, "a.test", "/"); r.Status != 200 {
				t.Errorf("status %d", r.Status)
			}
		}()
	}
	wg.Wait()
	fr.mu.Lock()
	max := fr.maxConn
	fr.mu.Unlock()
	if max > 2 {
		t.Errorf("%d simultaneous connections with a pool of 2", max)
	}
}

func TestSharedLimitUnknownRedisRejectsConfig(t *testing.T) {
	be, _ := upstreams(t, "a")
	routes := map[string]m{"r": route("a.test", sharedRule("1/s", m{"redis": "cache"}, nil))}
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	t.Cleanup(s.Close)
	cfg, err := ParseConfig(snap(httpGateway(""), routes, be), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Apply(&Loaded{Config: cfg, Hash: "h"})
	if err == nil || !strings.Contains(err.Error(), `shared.redis "cache" is not configured`) {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}

func TestSharedLimitBlockValidation(t *testing.T) {
	for name, blk := range map[string]string{
		"burst":     `{"rate":"1/s","burst":5,"shared":{}}`,
		"prefix":    `{"rate":"1/s","shared":{"keyPrefix":"a b"}}`,
		"fallback":  `{"rate":"1/s","shared":{"fallback":"x"}}`,
		"name":      `{"rate":"1/s","shared":{"redis":"a b"}}`,
		"unknown":   `{"rate":"1/s","shared":{"nope":1}}`,
		"replicas":  `{"rate":"1/s","shared":{"fallbackReplicas":-1}}`,
		"longprefx": `{"rate":"1/s","shared":{"keyPrefix":"` + strings.Repeat("p", 200) + `"}}`,
	} {
		if _, err := ParseRateLimitBlock([]byte(blk)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseRateLimitBlock([]byte(`{"rate":"100/m","shared":{"redis":"main","keyPrefix":"p","failOpen":false,"fallback":"none"}}`)); err != nil {
		t.Errorf("valid block refused: %v", err)
	}
}

func TestRESPClientAndFlagParsing(t *testing.T) {
	for in, want := range map[string]RedisOptions{
		"127.0.0.1:6379":                 {Name: "default", Addr: "127.0.0.1:6379"},
		"cache=redis.internal":           {Name: "cache", Addr: "redis.internal:6379"},
		"rediss://u:p@redis.test:6380/2": {Name: "default", Addr: "redis.test:6380", TLS: true, Username: "u", Password: "p", DB: 2},
		"main=redis://:pw@10.0.0.1:6379": {Name: "main", Addr: "10.0.0.1:6379", Password: "pw"},
	} {
		got, err := ParseRedisFlag(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://x:1", "redis://", "redis://h:1/x", "a=b=c:::"} {
		if _, err := ParseRedisFlag(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A reply with a Redis error is a value, not a transport failure.
	fr := newFakeRedis(t, nil, nil)
	c, _ := NewRedisClient(RedisOptions{Addr: fr.addr()})
	defer c.Close()
	vals, err := c.Do(t.Context(), []string{"PING"}, []string{"NOPE"}, []string{"INCR", "k"}, []string{"GET", "missing"})
	if err != nil || vals[0].str != "PONG" || !vals[1].isErr() || vals[2].num != 1 || !vals[3].nil_ {
		t.Fatalf("pipeline: %+v %v", vals, err)
	}
	// A server closing a pooled connection is retried on a fresh one.
	fr.dropAll()
	if _, err := c.Do(t.Context(), []string{"PING"}); err != nil {
		t.Fatalf("stale pooled connection: %v", err)
	}
	// A refusing server is an error, and the client reports it as down.
	fr.setDown(true)
	if _, err := c.Do(t.Context(), []string{"PING"}); err == nil || c.up.Load() {
		t.Fatalf("down server: %v up=%v", err, c.up.Load())
	}
}
