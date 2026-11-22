package setura

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestReplayBigLog replays a large access log named by SETURA_REPLAY_BIG and
// prints wall time and peak heap. Skipped unless set; the numbers in
// docs/replay.md come from it (go test -run TestReplayBigLog -v
// -cpuprofile cpu.out ./internal/setura).
func TestReplayBigLog(t *testing.T) {
	path := os.Getenv("SETURA_REPLAY_BIG")
	if path == "" {
		t.Skip("set SETURA_REPLAY_BIG to an access log to measure replay on it")
	}
	var peak uint64
	done := make(chan struct{})
	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > peak {
					peak = ms.HeapInuse
				}
			}
		}
	}()
	start := time.Now()
	rep, err := Replay(ReplayOptions{Log: path, Before: replayDir + "old.json", After: replayDir + "new.json", Limit: 10}, nil)
	close(done)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	el := time.Since(start)
	t.Logf("%d lines, %d requests, %.0f MB in %s (%.0f MB/s), peak heap %d MB, groups shown %d, merged %d",
		rep.Input.Lines, rep.Input.Requests, float64(st.Size())/1e6, el.Round(time.Millisecond), float64(st.Size())/1e6/el.Seconds(), peak>>20, len(rep.TopGroups), rep.Input.MergedShapes)
}
