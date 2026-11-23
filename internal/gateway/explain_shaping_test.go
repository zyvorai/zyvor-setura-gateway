package gateway

import (
	"strings"
	"testing"
)

func TestWhyShowsRateLimitSourceAndCompression(t *testing.T) {
	fr := newFakeRedis(t, nil, nil)
	clk := newClock0()
	be, _ := upstreams(t, "a")
	rl := sharedRule("2/s", m{"keyPrefix": "why"}, nil)
	rl["setura.zyvor.dev/compress"] = m{"enabled": true, "encodings": l{"gzip"}, "minSize": 200}
	rl["setura.zyvor.dev/bandwidth"] = m{"response": "1MB/s"}
	raw := snap(httpGateway(""), map[string]m{"r": route("", rl)}, be)

	// offline: the policy and its source, no Redis involved
	tb := tableOf(t, raw, nil)
	er, _ := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	er.Remote = "10.0.0.9"
	w := Explain(tb, er).Winner
	rlm := w.RouteLimit
	if rlm == nil || rlm.Source != "shared" || !strings.Contains(rlm.Policy, `shared through Redis "default" (key prefix why)`) || !strings.Contains(rlm.Policy, "fails open to a per-replica token bucket") || rlm.Live {
		t.Fatalf("offline rate limit: %+v", rlm)
	}
	notes := strings.Join(w.Notes, "\n")
	for _, want := range []string{"responses are compressed (gzip; level 6)", "at least 200 bytes", "the rule's setura.zyvor.dev/compress block", "bandwidth is limited per request"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	er.Server = ExplainServer{}
	er.Server.Shape.Compress.Enabled = true
	plain := Explain(tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, be), nil), er).Winner
	if n := strings.Join(plain.Notes, "\n"); !strings.Contains(n, "source: gateway --compress") {
		t.Errorf("gateway flag as the source:\n%s", n)
	}

	// live: the running gateway reads the client's counters without counting a request
	s := replica(t, fr, clk, nil, rl, be)
	if r := get(t, s, "a.test", "/"); r.Status != 200 {
		t.Fatalf("first: %d", r.Status)
	}
	live := func() *TraceRateLimit {
		lr, _ := ParseExplainRequest("GET", "http://a.test:8080/", nil, "", "")
		lr.Live, lr.Now, lr.Server = true, clk.now(), s.liveServerPolicy()
		lr.Remote = "127.0.0.1"
		return Explain(s.Table(), lr).Winner.RouteLimit
	}
	got := live()
	if got == nil || !got.Live || got.Tokens == nil || *got.Tokens != 1 || got.Limited == nil || *got.Limited || !strings.Contains(got.Note, "1.0 of 2") {
		t.Fatalf("after one request: %+v", got)
	}
	if again := live(); *again.Tokens != 1 {
		t.Fatalf("explaining must not consume the limit: %+v", again)
	}
	get(t, s, "a.test", "/")
	if got = live(); got.Limited == nil || !*got.Limited {
		t.Fatalf("window full: %+v", got)
	}
	if r := get(t, s, "a.test", "/"); r.Status != 429 {
		t.Fatalf("explain said limited, got %d", r.Status)
	}
	// Redis down: the explanation says what answers instead
	fr.setDown(true)
	got = live()
	if got.Live || !strings.Contains(got.Note, "per-replica fallback bucket") {
		t.Fatalf("outage: %+v", got)
	}
}
