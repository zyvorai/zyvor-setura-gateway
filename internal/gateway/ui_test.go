package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const uiTestConfig = `{
  "schema": "setura.route-specs/v1", "namespace": "t",
  "resources": {
    "gateways.gateway.networking.k8s.io/gw": {"gatewayClassName": "setura", "listeners": [{"name": "web", "protocol": "HTTP", "port": 8080}]},
    "httproutes.gateway.networking.k8s.io/r": {"parentRefs": [{"name": "gw"}], "hostnames": ["a.test"],
      "rules": [{"backendRefs": [{"name": "b", "port": 80}]}]}
  },
  "backends": {"t/b:80": {"endpoints": ["127.0.0.1:1"]}}
}`

func withBuilder(t *testing.T) *UIInput {
	t.Helper()
	var seen UIInput
	old := UIStateBuilder
	UIStateBuilder = func(in UIInput) (any, error) { seen = in; return map[string]any{"ok": true}, nil }
	t.Cleanup(func() { UIStateBuilder = old })
	return &seen
}

func TestServerUIStateUsesLiveConfig(t *testing.T) {
	seen := withBuilder(t)
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	t.Cleanup(s.Close)
	if s.UIState() != nil {
		t.Fatal("state must be nil before the first configuration")
	}
	cfg, err := ParseConfig([]byte(uiTestConfig), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	if s.UIState() == nil {
		t.Fatal("state after apply")
	}
	var snap struct {
		Schema    string
		Namespace string
		Resources map[string]json.RawMessage
	}
	if err := json.Unmarshal(seen.Snapshot, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Schema != "setura.route-specs/v1" || snap.Namespace != "t" || len(snap.Resources) != 2 {
		t.Fatalf("snapshot %s", seen.Snapshot)
	}
	if seen.Stats == nil || seen.Reload == nil {
		t.Fatal("stats and reload info must be passed through")
	}
	if strings.Contains(string(seen.Snapshot), "127.0.0.1:1") {
		t.Fatal("backend endpoints must not be part of the dashboard snapshot")
	}
}

func TestStartUIRefusesOpenBind(t *testing.T) {
	s := New(Options{Admin: "off"})
	if err := s.StartUI(context.Background(), "0.0.0.0:0", "", nil); err == nil || !strings.Contains(err.Error(), "--token") {
		t.Fatalf("got %v", err)
	}
}

func TestStartUIServesAndEmitsReloadEvents(t *testing.T) {
	withBuilder(t)
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	t.Cleanup(s.Close)
	cfg, _ := ParseConfig([]byte(uiTestConfig), t.TempDir())
	s.Apply(&Loaded{Config: cfg, Hash: "h1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var diag bytes.Buffer
	if err := s.StartUI(ctx, "127.0.0.1:0", "", &diag); err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimSuffix(strings.TrimPrefix(strings.Fields(diag.String())[1], "http://"), "/")
	res, err := http.Get("http://" + addr + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
		t.Fatalf("%d %s", res.StatusCode, b)
	}
	// A reload shows up in the feed.
	time.Sleep(1200 * time.Millisecond)
	s.Apply(&Loaded{Config: cfg, Hash: "h2"})
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		res, _ := http.Get("http://" + addr + "/api/events")
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if strings.Contains(string(b), "configuration applied (generation 2)") {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("reload event never appeared in the feed")
}

func TestGatewayUIFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"run", "--config", "does-not-matter.json", "--ui", "0.0.0.0:9090", "--admin", "off"}, &out, &errb, nil)
	if code != 2 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "--token") {
		t.Fatalf("stderr %q", errb.String())
	}
	if !strings.Contains(usage, "--ui ADDR") {
		t.Fatal("usage must document --ui")
	}
}
