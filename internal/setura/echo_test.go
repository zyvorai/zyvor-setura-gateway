package setura

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEchoServesIdentityAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- ServeEcho(ctx, "127.0.0.1:0", "orders-v1", ready) }()
	addr := <-ready
	resp, err := http.Get("http://" + addr + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	is(t, resp.StatusCode, 200)
	is(t, resp.Header.Get("X-Setura-Backend"), "orders-v1")
	is(t, strings.TrimSpace(string(body)), "orders-v1")

	// the identity it serves is exactly what explain --backend asserts on
	code, out, errs := cli(t, nil, "explain", "http://"+addr+"/", "--backend", "orders-v1", "--color", "never")
	if code != 0 {
		t.Fatalf("explain against echo: exit %d\n%s%s", code, out, errs)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo did not stop after cancel")
	}
}

func TestEchoUsageErrors(t *testing.T) {
	if code, _, _ := cli(t, nil, "echo"); code != 2 {
		t.Errorf("missing --name: exit %d, want 2", code)
	}
	if code, _, _ := cli(t, nil, "echo", "--name", "x", "extra"); code != 2 {
		t.Errorf("stray argument: exit %d, want 2", code)
	}
}
