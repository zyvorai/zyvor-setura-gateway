package setura

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A log-linear latency histogram: 8 sub-buckets per power of two of
// microseconds, so a percentile is accurate to about 9% and a 10 minute soak
// needs no per-request memory.
const (
	histSub  = 8
	histBins = 40 * histSub
)

type latHist struct {
	n    [histBins]int64
	max  int64
	sum  int64
	cnt  int64
	errs int64 // responses with an unexpected status plus transport failures
	terr int64 // transport failures: no response, so no latency sample
}

func histBin(us int64) int {
	if us < histSub {
		if us < 0 {
			us = 0
		}
		return int(us)
	}
	e := 0
	for v := us; v >= 2*histSub; v >>= 1 {
		e++
	}
	b := (e+1)*histSub + int((us>>uint(e))-histSub)
	if b >= histBins {
		b = histBins - 1
	}
	return b
}

// histUpper is the upper bound in microseconds of bin b.
func histUpper(b int) int64 {
	if b < histSub {
		return int64(b)
	}
	e := b/histSub - 1
	return (int64(histSub+b%histSub+1) << uint(e)) - 1
}

func (h *latHist) add(us int64) {
	h.n[histBin(us)]++
	h.cnt++
	h.sum += us
	if us > h.max {
		h.max = us
	}
}

func (h *latHist) merge(o *latHist) {
	for i := range h.n {
		h.n[i] += o.n[i]
	}
	h.cnt += o.cnt
	h.sum += o.sum
	h.errs += o.errs
	h.terr += o.terr
	if o.max > h.max {
		h.max = o.max
	}
}

// quantile returns the latency in milliseconds at percentile p (0-100).
func (h *latHist) quantile(p float64) float64 {
	if h.cnt == 0 {
		return 0
	}
	rank := int64(math.Ceil(p / 100 * float64(h.cnt)))
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for i, c := range h.n {
		seen += c
		if seen >= rank {
			up := histUpper(i)
			if up > h.max {
				up = h.max
			}
			return float64(up) / 1000
		}
	}
	return float64(h.max) / 1000
}

// runtimeSample is what the gateway's --pprof endpoint serves at /debug/runtime.
type runtimeSample struct {
	Goroutines int    `json:"goroutines"`
	HeapAlloc  uint64 `json:"heap_alloc_bytes"`
	HeapInuse  uint64 `json:"heap_inuse_bytes"`
	Sys        uint64 `json:"sys_bytes"`
	RSS        uint64 `json:"rss_bytes"`
	NumGC      uint32 `json:"num_gc"`
}

type sampleRow struct {
	T int `json:"t_seconds"`
	runtimeSample
}

func fetchSample(c *http.Client, u string) (runtimeSample, error) {
	var s runtimeSample
	resp, err := c.Get(u)
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	return s, json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&s)
}

func runLoad(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	address := fs.String("address", "", "connect to this numeric IP, preserving Host and TLS identity")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	insecure := fs.Bool("insecure", false, "skip TLS verification (load tests against throwaway certificates only)")
	http2 := fs.Bool("http2", false, "negotiate ALPN h2 over TLS")
	method := fs.String("method", "GET", "HTTP method")
	bodyN := fs.Int("body-bytes", 0, "send a request body of this many bytes")
	host := fs.String("host", "", "Host header (default: from the URL)")
	conc := fs.Int("concurrency", 32, "parallel keep-alive clients")
	dur := fs.Duration("duration", 10*time.Second, "how long to run")
	warm := fs.Duration("warmup", 0, "discard results for this long before measuring")
	rate := fs.Float64("rate", 0, "total requests per second cap, 0 = as fast as possible")
	status := fs.Int("status", 200, "expected HTTP status")
	sample := fs.String("sample-url", "", "gateway --pprof /debug/runtime URL to sample goroutines and memory from")
	every := fs.Duration("sample-interval", 5*time.Second, "sampling period for --sample-url")
	asJSON := fs.Bool("json", false, "print JSON")
	jsonOut := fs.String("json-out", "", "also write the JSON result to this file")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura load: expected URL")
		return 2, usageError{"URL"}
	}
	if *conc < 1 || *conc > 8192 || *dur <= 0 || *every <= 0 || *bodyN < 0 || *bodyN > 1<<24 || *rate < 0 {
		return 2, userError("invalid --concurrency, --duration, --sample-interval, --body-bytes or --rate")
	}
	u, err := url.Parse(pos[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return 2, userError("URL must be http:// or https:// with a host")
	}
	tc := &tls.Config{InsecureSkipVerify: *insecure, MinVersion: tls.VersionTLS12}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return 2, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return 2, userError("--ca has no certificates")
		}
		tc.RootCAs = pool
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if *address != "" {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(*address, port)
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: tc, MaxIdleConns: *conc, MaxIdleConnsPerHost: *conc, MaxConnsPerHost: 0,
		ForceAttemptHTTP2: *http2, IdleConnTimeout: 90 * time.Second, DisableCompression: true,
	}
	if !*http2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // stay on HTTP/1.1
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	body := strings.Repeat("x", *bodyN)

	var (
		stop    atomic.Bool
		measure atomic.Bool
		hs      = make([]latHist, *conc)
		codes   sync.Map
		firstE  atomic.Value
		wg      sync.WaitGroup
	)
	measure.Store(*warm == 0)
	var tick <-chan time.Time
	var gate chan struct{}
	if *rate > 0 {
		gate = make(chan struct{}, *conc)
		iv := time.Duration(float64(time.Second) / *rate)
		if iv < time.Microsecond {
			iv = time.Microsecond
		}
		t := time.NewTicker(iv)
		defer t.Stop()
		tick = t.C
		go func() {
			for !stop.Load() {
				<-tick
				select {
				case gate <- struct{}{}:
				default:
				}
			}
		}()
	}
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(h *latHist) {
			defer wg.Done()
			buf := make([]byte, 32<<10)
			for !stop.Load() {
				if gate != nil {
					<-gate
				}
				var rd io.Reader
				if *bodyN > 0 {
					rd = strings.NewReader(body)
				}
				req, err := http.NewRequest(*method, pos[0], rd)
				if err != nil {
					firstE.CompareAndSwap(nil, err.Error())
					return
				}
				if *host != "" {
					req.Host = *host
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				code := 0
				if err == nil {
					_, err = io.CopyBuffer(io.Discard, struct{ io.Reader }{resp.Body}, buf)
					resp.Body.Close()
					code = resp.StatusCode
				}
				us := time.Since(t0).Microseconds()
				if !measure.Load() {
					continue
				}
				if err != nil || code != *status {
					h.errs++
					if err != nil {
						h.terr++
						firstE.CompareAndSwap(nil, err.Error())
					}
				}
				if err == nil {
					h.add(us)
					v, _ := codes.LoadOrStore(code, new(atomic.Int64))
					v.(*atomic.Int64).Add(1)
				}
			}
		}(&hs[w])
	}

	var rows []sampleRow
	stopCh := make(chan struct{})
	var sampleMu sync.Mutex
	sampleDone := make(chan struct{})
	t0 := time.Now()
	if *sample != "" {
		sc := &http.Client{Timeout: 3 * time.Second}
		take := func() {
			s, err := fetchSample(sc, *sample)
			if err != nil {
				return
			}
			sampleMu.Lock()
			rows = append(rows, sampleRow{int(time.Since(t0).Seconds()), s})
			sampleMu.Unlock()
		}
		take()
		go func() {
			defer close(sampleDone)
			t := time.NewTicker(*every)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					take()
				case <-stopCh:
					return
				}
			}
		}()
	} else {
		close(sampleDone)
	}
	if *warm > 0 {
		time.Sleep(*warm)
		for i := range hs {
			hs[i] = latHist{}
		}
		measure.Store(true)
	}
	mStart := time.Now()
	time.Sleep(*dur)
	elapsed := time.Since(mStart)
	stop.Store(true)
	close(stopCh)
	if gate != nil {
		for i := 0; i < *conc; i++ {
			select {
			case gate <- struct{}{}:
			default:
			}
		}
	}
	wg.Wait()
	<-sampleDone
	if *sample != "" {
		if s, err := fetchSample(&http.Client{Timeout: 3 * time.Second}, *sample); err == nil {
			sampleMu.Lock()
			rows = append(rows, sampleRow{int(time.Since(t0).Seconds()), s})
			sampleMu.Unlock()
		}
	}
	tr.CloseIdleConnections()

	var all latHist
	for i := range hs {
		all.merge(&hs[i])
	}
	statuses := obj{}
	codes.Range(func(k, v any) bool { statuses[fmt.Sprint(k)] = v.(*atomic.Int64).Load(); return true })
	total := all.cnt + all.terr
	res := obj{
		"url": pos[0], "concurrency": *conc, "http2": *http2, "duration_s": round1(elapsed.Seconds()),
		"requests": total, "errors": all.errs, "rps": round1(float64(all.cnt) / elapsed.Seconds()),
		"latency_ms": obj{"mean": 0.0, "p50": r3(all.quantile(50)), "p90": r3(all.quantile(90)), "p99": r3(all.quantile(99)),
			"p99.9": r3(all.quantile(99.9)), "max": r3(float64(all.max) / 1000)},
		"status": statuses,
	}
	if all.cnt > 0 {
		asMap(res["latency_ms"])["mean"] = r3(float64(all.sum) / float64(all.cnt) / 1000)
	}
	if e, ok := firstE.Load().(string); ok {
		res["first_error"] = e
	}
	if len(rows) > 0 {
		first, last := rows[0], rows[len(rows)-1]
		var peakG int
		var peakRSS uint64
		for _, r := range rows {
			if r.Goroutines > peakG {
				peakG = r.Goroutines
			}
			if r.RSS > peakRSS {
				peakRSS = r.RSS
			}
		}
		res["runtime"] = obj{"first": first.runtimeSample, "last": last.runtimeSample, "peak_goroutines": peakG,
			"peak_rss_bytes": peakRSS, "samples": rows}
	}
	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			return 0, err
		}
		err = writeJSON(f, res)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return 0, err
		}
	}
	if *asJSON {
		if err := writeJSON(stdout, res); err != nil {
			return 0, err
		}
		return boolExit(all.errs > 0), nil
	}
	l := asMap(res["latency_ms"])
	fmt.Fprintf(stdout, "requests %d  errors %d  concurrency %d  duration %.1fs  rps %v\n", total, all.errs, *conc, elapsed.Seconds(), res["rps"])
	fmt.Fprintf(stdout, "latency ms  mean=%v p50=%v p90=%v p99=%v p99.9=%v max=%v\n", l["mean"], l["p50"], l["p90"], l["p99"], l["p99.9"], l["max"])
	for _, k := range sortedKeys(statuses) {
		fmt.Fprintf(stdout, "status %-6s %v\n", k, statuses[k])
	}
	if e, ok := res["first_error"]; ok {
		fmt.Fprintf(stdout, "first error: %v\n", e)
	}
	if len(rows) > 0 {
		f, la := rows[0], rows[len(rows)-1]
		fmt.Fprintf(stdout, "gateway goroutines %d -> %d  heap_inuse %.1f -> %.1f MiB  gc %d -> %d\n",
			f.Goroutines, la.Goroutines, mib(f.HeapInuse), mib(la.HeapInuse), f.NumGC, la.NumGC)
		if la.RSS > 0 {
			fmt.Fprintf(stdout, "gateway rss %.1f -> %.1f MiB\n", mib(f.RSS), mib(la.RSS))
		}
	}
	return boolExit(all.errs > 0), nil
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }
func r3(v float64) float64 { return math.Round(v*1000) / 1000 }
