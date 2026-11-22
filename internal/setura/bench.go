package setura

import (
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// BenchOptions controls a repeated-probe run.
type BenchOptions struct {
	Probe       ProbeOptions
	Requests    int // 0 means unlimited (needs Duration)
	Concurrency int
	Duration    time.Duration // 0 means no time limit
	MaxP99MS    float64       // 0 disables
	MaxErrRate  float64       // negative disables; 0..1 otherwise
}

// percentile uses the nearest-rank method on sorted samples.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// Bench issues probes with bounded concurrency and summarizes latency.
func Bench(o BenchOptions) (obj, error) {
	if o.Concurrency < 1 || o.Concurrency > 256 {
		return nil, userError("concurrency must be between 1 and 256")
	}
	if o.Requests < 0 || o.Requests > 1000000 || o.Duration < 0 || o.MaxP99MS < 0 || math.IsNaN(o.MaxP99MS) || o.MaxErrRate > 1 || math.IsNaN(o.MaxErrRate) {
		return nil, userError("invalid requests, duration or budget")
	}
	if o.Requests == 0 && o.Duration == 0 {
		return nil, userError("set --requests and/or --duration")
	}

	var (
		mu        sync.Mutex
		latencies []float64
		statuses  = map[string]int{}
		failures  int
		firstErr  string
		inputErr  error
		issued    int64
	)
	start := time.Now()
	var deadline time.Time
	if o.Duration > 0 {
		deadline = start.Add(o.Duration)
	}
	var wg sync.WaitGroup
	for w := 0; w < o.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if !deadline.IsZero() && time.Now().After(deadline) {
					return
				}
				if o.Requests > 0 && atomic.AddInt64(&issued, 1) > int64(o.Requests) {
					return
				}
				t0 := time.Now()
				r, err := Probe(o.Probe)
				ms := float64(time.Since(t0).Microseconds()) / 1000
				mu.Lock()
				latencies = append(latencies, ms)
				switch {
				case err != nil:
					statuses["error"]++
					failures++
					if firstErr == "" {
						firstErr = err.Error()
						inputErr = err // Probe only errors on invalid input
					}
				default:
					key := "error"
					if v := r.Step("http").Get("status"); v != nil {
						key = fmt.Sprint(v)
					}
					statuses[key]++
					if !r.OK {
						failures++
						if firstErr == "" {
							for _, name := range stages {
								if st := r.Step(name); st.State() == "failed" {
									firstErr = asStr(st.Get("reason"))
								}
							}
						}
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if inputErr != nil {
		return nil, inputErr
	}
	elapsed := time.Since(start)

	sort.Float64s(latencies)
	total := len(latencies)
	var sum float64
	for _, l := range latencies {
		sum += l
	}
	rate := 0.0
	if total > 0 {
		rate = float64(failures) / float64(total)
	}
	p99 := percentile(latencies, 99)
	hist := obj{}
	for k, v := range statuses {
		hist[k] = v
	}
	var violations []any
	if o.MaxP99MS > 0 && p99 > o.MaxP99MS {
		violations = append(violations, fmt.Sprintf("p99 %.1f ms exceeds budget %.1f ms", p99, o.MaxP99MS))
	}
	if o.MaxErrRate >= 0 && rate > o.MaxErrRate {
		violations = append(violations, fmt.Sprintf("error rate %.4f exceeds budget %.4f", rate, o.MaxErrRate))
	}
	if violations == nil {
		violations = []any{}
	}
	res := obj{
		"url": o.Probe.URL, "ok": len(violations) == 0, "requests": total, "concurrency": o.Concurrency,
		"errors": failures, "error_rate": math.Round(rate*10000) / 10000,
		"elapsed_ms": round1(float64(elapsed.Microseconds()) / 1000),
		"latency_ms": obj{"min": round1(percentile(latencies, 0)), "mean": 0.0, "p50": round1(percentile(latencies, 50)),
			"p90": round1(percentile(latencies, 90)), "p99": round1(p99), "max": round1(percentile(latencies, 100))},
		"status": hist, "violations": violations,
	}
	if total > 0 {
		asMap(res["latency_ms"])["mean"] = round1(sum / float64(total))
	}
	if elapsed > 0 {
		res["rps"] = round1(float64(total) / elapsed.Seconds())
	}
	if firstErr != "" {
		res["first_error"] = firstErr
	}
	return res, nil
}

func runBench(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	address := fs.String("address", "", "connect to this numeric IP, preserving Host and TLS identity")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	status := fs.Int("status", 200, "expected HTTP status")
	timeout := fs.Float64("timeout", 4, "per-request timeout in seconds")
	http2 := fs.Bool("http2", false, "negotiate ALPN h2 over TLS")
	requests := fs.Int("requests", 0, "total requests (default 100 unless --duration is set)")
	conc := fs.Int("concurrency", 4, "parallel workers")
	dur := fs.Duration("duration", 0, "stop issuing requests after this long, for example 10s")
	maxP99 := fs.Float64("max-p99-ms", 0, "exit 1 when p99 latency exceeds this many milliseconds")
	maxErr := fs.Float64("max-error-rate", -1, "exit 1 when the error rate (0..1) exceeds this")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura bench: expected URL")
		return 2, usageError{"URL"}
	}
	n := *requests
	if n == 0 && *dur == 0 {
		n = 100
	}
	p := NewProbe(pos[0])
	p.Address, p.CA, p.Status, p.Timeout, p.HTTP2 = *address, *ca, *status, *timeout, *http2
	res, err := Bench(BenchOptions{Probe: p, Requests: n, Concurrency: *conc, Duration: *dur, MaxP99MS: *maxP99, MaxErrRate: *maxErr})
	if err != nil {
		return 0, err
	}
	if *asJSON {
		if err := writeJSON(stdout, res); err != nil {
			return 0, err
		}
	} else {
		l := asMap(res["latency_ms"])
		fmt.Fprintf(stdout, "requests %v  concurrency %v  errors %v (rate %v)  rps %v\n", res["requests"], res["concurrency"], res["errors"], res["error_rate"], res["rps"])
		fmt.Fprintf(stdout, "latency ms  min=%v mean=%v p50=%v p90=%v p99=%v max=%v\n", l["min"], l["mean"], l["p50"], l["p90"], l["p99"], l["max"])
		hist := asMap(res["status"])
		for _, k := range sortedKeys(hist) {
			fmt.Fprintf(stdout, "status %-6s %v\n", k, hist[k])
		}
		if s, ok := res["first_error"]; ok {
			fmt.Fprintf(stdout, "first error: %v\n", s)
		}
		for _, v := range asList(res["violations"]) {
			fmt.Fprintf(stdout, "BUDGET EXCEEDED: %v\n", v)
		}
	}
	return boolExit(res["ok"] != true), nil
}
