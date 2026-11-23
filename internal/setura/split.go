package setura

import (
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Limits for "setura split". A traffic-split check sends real requests, so the
// request count and parallelism are capped and the expectation list is bounded.
const (
	maxSplitRequests    = 20000
	maxSplitConcurrency = 64
	maxSplitBackends    = 64
	maxSplitNameLen     = 253
	// splitZ is the two-sided normal quantile for a 0.1% false-alarm rate per
	// backend (z = 3.29). A correct split fails the check roughly one run in a
	// thousand per backend; a split that is wrong by more than the reported
	// tolerance fails almost every run.
	splitZ = 3.29
	// minSplitExpected is the smallest expected count (n*p) for the smallest
	// nonzero share. Below it the normal approximation is unreliable and the
	// check would pass splits that are clearly wrong.
	minSplitExpected = 10.0
	splitNone        = "(no identity)"
)

// SplitExpectation is one backend's expected share, normalised so shares sum to 1.
type SplitExpectation struct {
	Name  string
	Share float64
}

// ParseSplitExpectations parses NAME=WEIGHT items. Weights are proportional, as
// in Gateway API (9 and 1 mean the same as 90 and 10); a weight of 0 means the
// backend must receive no traffic.
func ParseSplitExpectations(items []string) ([]SplitExpectation, error) {
	if len(items) == 0 {
		return nil, userError("give at least one --expect NAME=WEIGHT")
	}
	if len(items) > maxSplitBackends {
		return nil, userErrorf("at most %d --expect items are allowed", maxSplitBackends)
	}
	seen := map[string]bool{}
	var out []SplitExpectation
	var sum float64
	for _, it := range items {
		name, w, ok := strings.Cut(it, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, userErrorf("--expect expects NAME=WEIGHT, got %q", clipStr(it, 40))
		}
		if len(name) > maxSplitNameLen {
			return nil, userErrorf("backend names are at most %d bytes", maxSplitNameLen)
		}
		for i := 0; i < len(name); i++ {
			if name[i] < 0x20 || name[i] == 0x7f {
				return nil, userError("backend names must not contain control characters")
			}
		}
		if name == splitNone {
			return nil, userErrorf("%q is reserved for responses without an identity header", splitNone)
		}
		if seen[name] {
			return nil, userErrorf("backend %q is listed twice", name)
		}
		seen[name] = true
		f, err := strconv.ParseFloat(strings.TrimSpace(w), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return nil, userErrorf("weight for %q must be a finite number, 0 or more", name)
		}
		if f > 1e9 {
			return nil, userErrorf("weight for %q is unreasonably large", name)
		}
		sum += f
		out = append(out, SplitExpectation{Name: name, Share: f})
	}
	if sum <= 0 {
		return nil, userError("at least one backend needs a weight above 0")
	}
	for i := range out {
		out[i].Share /= sum
	}
	return out, nil
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// minSplitRequests is how many successful responses the check needs before the
// smallest nonzero share has an expected count of at least minSplitExpected.
func minSplitRequests(exp []SplitExpectation) int {
	smallest := 1.0
	for _, e := range exp {
		if e.Share > 0 && e.Share < smallest {
			smallest = e.Share
		}
	}
	return int(math.Ceil(minSplitExpected / smallest))
}

// SplitVerdict compares observed counts with the expectation. observed maps an
// identity to a count; n is the number of attributed responses. Every expected
// backend is judged on its own, and any identity that was not expected fails.
func SplitVerdict(exp []SplitExpectation, observed map[string]int, n int) obj {
	ok := true
	var rows []any
	known := map[string]bool{}
	for _, e := range exp {
		known[e.Name] = true
		got := observed[e.Name]
		mean := float64(n) * e.Share
		tol := 0.0
		if e.Share > 0 && e.Share < 1 {
			tol = splitZ*math.Sqrt(float64(n)*e.Share*(1-e.Share)) + 0.5
		}
		pass := math.Abs(float64(got)-mean) <= tol
		if !pass {
			ok = false
		}
		rows = append(rows, obj{
			"backend": e.Name, "expected_pct": round1(e.Share * 100), "observed_pct": pct1(got, n),
			"observed": got, "expected_count": round1(mean),
			"tolerance_pct": round1(tol / math.Max(float64(n), 1) * 100), "ok": pass,
		})
	}
	var extra []string
	for k := range observed {
		if !known[k] && observed[k] > 0 {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		ok = false
		rows = append(rows, obj{"backend": k, "expected_pct": 0.0, "observed_pct": pct1(observed[k], n),
			"observed": observed[k], "expected_count": 0.0, "tolerance_pct": 0.0, "ok": false, "unexpected": true})
	}
	return obj{"ok": ok, "samples": n, "backends": rows}
}

func pct1(c, n int) float64 {
	if n == 0 {
		return 0
	}
	return round1(float64(c) / float64(n) * 100)
}

// SplitOptions describes one traffic-split verification.
type SplitOptions struct {
	Probe       ProbeOptions
	Expect      []SplitExpectation
	Requests    int
	Concurrency int
	Identity    string  // response header carrying the backend identity
	MaxErrRate  float64 // share of failed requests tolerated
}

// RunSplit sends o.Requests probes and judges the identity distribution.
func RunSplit(o SplitOptions) (obj, error) {
	if o.Requests < 1 || o.Requests > maxSplitRequests {
		return nil, userErrorf("--requests must be between 1 and %d", maxSplitRequests)
	}
	if o.Concurrency < 1 || o.Concurrency > maxSplitConcurrency {
		return nil, userErrorf("--concurrency must be between 1 and %d", maxSplitConcurrency)
	}
	if o.MaxErrRate < 0 || o.MaxErrRate > 1 || math.IsNaN(o.MaxErrRate) {
		return nil, userError("--max-error-rate must be between 0 and 1")
	}
	if o.Identity == "" {
		o.Identity = "X-Setura-Backend"
	}
	for i := 0; i < len(o.Identity); i++ {
		if !isTokenChar(o.Identity[i]) {
			return nil, userError("--identity-header must be a valid header name")
		}
	}
	if need := minSplitRequests(o.Expect); o.Requests < need {
		return nil, userErrorf("%d requests cannot verify a share this small: use at least %d (the smallest nonzero share needs an expected count of %d)", o.Requests, need, int(minSplitExpected))
	}
	counts := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan struct{})
	nerr, attributed := 0, 0
	var firstErr string
	var fatal error
	start := time.Now()
	for w := 0; w < o.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				p := o.Probe
				var ident string
				var have bool
				p.capture = func(r *http.Response) {
					have = true
					vals := r.Header.Values(o.Identity)
					if len(vals) == 0 {
						ident = splitNone
					} else {
						ident = clipStr(strings.Join(vals, ", "), maxSplitNameLen)
					}
				}
				rep, err := Probe(p)
				mu.Lock()
				switch {
				case err != nil:
					// Invalid options, not a network failure: stop and report it.
					if fatal == nil {
						fatal = err
					}
				case !rep.OK:
					nerr++
					if firstErr == "" {
						firstErr = failureReason(rep)
					}
				case have:
					counts[ident]++
					attributed++
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < o.Requests; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	if fatal != nil {
		return nil, fatal
	}

	res := SplitVerdict(o.Expect, counts, attributed)
	errRate := float64(nerr) / float64(o.Requests)
	res["requests"] = o.Requests
	res["errors"] = nerr
	res["error_rate"] = math.Round(errRate*10000) / 10000
	res["identity_header"] = o.Identity
	res["elapsed_ms"] = round1(float64(time.Since(start).Microseconds()) / 1000)
	if firstErr != "" {
		res["first_error"] = firstErr
	}
	if errRate > o.MaxErrRate {
		res["ok"] = false
		res["error_budget_exceeded"] = true
	}
	if attributed < minSplitRequests(o.Expect) {
		res["ok"] = false
		res["inconclusive"] = fmt.Sprintf("only %d responses were usable, fewer than the %d this split needs", attributed, minSplitRequests(o.Expect))
	}
	return res, nil
}

// failureReason returns the first failed stage's reason from a report.
func failureReason(r *Report) string {
	for _, name := range stages {
		if s := r.Steps[name]; s != nil && s.State() == "failed" {
			return name + ": " + asStr(s.Get("reason"))
		}
	}
	return "probe failed"
}

func runSplit(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	address := fs.String("address", "", "connect to this numeric IP, preserving Host and TLS identity")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	status := fs.Int("status", 200, "expected HTTP status; other responses count as errors")
	timeout := fs.Float64("timeout", 4, "per-request timeout in seconds")
	http2 := fs.Bool("http2", false, "negotiate ALPN h2 over TLS")
	requests := fs.Int("requests", 400, "requests to send")
	conc := fs.Int("concurrency", 4, "parallel workers")
	identity := fs.String("identity-header", "X-Setura-Backend", "response header that names the backend")
	maxErr := fs.Float64("max-error-rate", 0.01, "exit 1 when more than this share (0..1) of requests fail")
	method := fs.String("method", "", "request method (GET, HEAD, OPTIONS; others need --allow-unsafe-method)")
	unsafeMethod := fs.Bool("allow-unsafe-method", false, "allow POST, PUT, PATCH and DELETE (sent with no body)")
	var expect, reqHeaders stringList
	fs.Var(&expect, "expect", "expected share, NAME=WEIGHT (proportional, like backendRef weights); repeatable")
	fs.Var(&reqHeaders, "request-header", `send a request header, "Name: value"; repeatable`)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura split: expected URL")
		return 2, usageError{"URL"}
	}
	exp, err := ParseSplitExpectations(expect)
	if err != nil {
		return 0, err
	}
	rh, err := parseRequestHeaderFlags(reqHeaders)
	if err != nil {
		return 0, err
	}
	p := NewProbe(pos[0])
	p.Address, p.CA, p.Status, p.Timeout, p.HTTP2 = *address, *ca, *status, *timeout, *http2
	p.Method, p.AllowUnsafeMethod, p.RequestHeaders = *method, *unsafeMethod, rh
	res, err := RunSplit(SplitOptions{Probe: p, Expect: exp, Requests: *requests, Concurrency: *conc, Identity: *identity, MaxErrRate: *maxErr})
	if err != nil {
		return 0, err
	}
	if *asJSON {
		if err := writeJSON(stdout, res); err != nil {
			return 0, err
		}
	} else {
		fmt.Fprintf(stdout, "%v responses attributed of %v requests (%v errors) via %v\n", res["samples"], res["requests"], res["errors"], res["identity_header"])
		for _, r := range asList(res["backends"]) {
			m := asMap(r)
			mark := "ok  "
			if m["ok"] != true {
				mark = "FAIL"
			}
			note := ""
			if m["unexpected"] == true {
				note = "  (not expected)"
			}
			fmt.Fprintf(stdout, "%s %-24s expected %5v%% (+/- %v%%)  observed %5v%% (%v)%s\n", mark, m["backend"], m["expected_pct"], m["tolerance_pct"], m["observed_pct"], m["observed"], note)
		}
		if s, ok := res["first_error"]; ok {
			fmt.Fprintf(stdout, "first error: %v\n", s)
		}
		if s, ok := res["inconclusive"]; ok {
			fmt.Fprintf(stdout, "INCONCLUSIVE: %v\n", s)
		}
		if res["error_budget_exceeded"] == true {
			fmt.Fprintf(stdout, "ERROR BUDGET EXCEEDED: %v of requests failed, allowed %v\n", res["error_rate"], *maxErr)
		}
		fmt.Fprintln(stdout, "A statistical check: a correct split fails about once in a thousand runs per backend; it proves what this client saw through this path, not what the route declares.")
	}
	return boolExit(res["ok"] != true), nil
}
