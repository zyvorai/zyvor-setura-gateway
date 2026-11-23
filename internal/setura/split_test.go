package setura

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// splitServer answers with a backend picked by a deterministic cycle so the
// observed split is exact: pattern "a,a,a,b" gives 75/25.
func splitServer(t *testing.T, pattern []string, header string) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)-1) % len(pattern)
		switch pattern[i] {
		case "":
		case "!500":
			w.WriteHeader(500)
			return
		default:
			w.Header().Set(header, pattern[i])
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cycle(a string, na int, b string, nb int) []string {
	var p []string
	for i := 0; i < na; i++ {
		p = append(p, a)
	}
	for i := 0; i < nb; i++ {
		p = append(p, b)
	}
	return p
}

func TestParseSplitExpectationsHostile(t *testing.T) {
	long := strings.Repeat("n", maxSplitNameLen+1)
	var many []string
	for i := 0; i <= maxSplitBackends; i++ {
		many = append(many, "b"+strings.Repeat("x", i)+"=1")
	}
	cases := map[string]struct {
		in   []string
		want string
	}{
		"empty":           {nil, "at least one"},
		"no equals":       {[]string{"v1"}, "NAME=WEIGHT"},
		"empty name":      {[]string{"=5"}, "NAME=WEIGHT"},
		"negative":        {[]string{"a=-1", "b=2"}, "finite number"},
		"NaN":             {[]string{"a=NaN"}, "finite number"},
		"Inf":             {[]string{"a=Inf"}, "finite number"},
		"text":            {[]string{"a=ten"}, "finite number"},
		"huge":            {[]string{"a=1e12"}, "unreasonably large"},
		"all zero":        {[]string{"a=0", "b=0"}, "above 0"},
		"duplicate":       {[]string{"a=1", "a=2"}, "twice"},
		"long name":       {[]string{long + "=1"}, "at most"},
		"control char":    {[]string{"a\x07=1"}, "control"},
		"reserved":        {[]string{splitNone + "=1"}, "reserved"},
		"too many":        {many, "at most"},
		"newline in name": {[]string{"a\nb=1"}, "control"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSplitExpectations(c.in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
	exp, err := ParseSplitExpectations([]string{"v1=9", "v2=1", "gone=0"})
	if err != nil || exp[0].Share != 0.9 || exp[1].Share != 0.1 || exp[2].Share != 0 {
		t.Errorf("weights are proportional: %+v %v", exp, err)
	}
}

func TestSplitVerdictMath(t *testing.T) {
	exp, _ := ParseSplitExpectations([]string{"a=90", "b=10"})
	if v := SplitVerdict(exp, map[string]int{"a": 360, "b": 40}, 400); v["ok"] != true {
		t.Errorf("exact split must pass: %v", v)
	}
	// 3.29 sigma at n=400, p=.1 is about 19.7 requests: 65 is far outside.
	if v := SplitVerdict(exp, map[string]int{"a": 335, "b": 65}, 400); v["ok"] != false {
		t.Errorf("an 84/16 split is not 90/10 at n=400: %v", v)
	}
	// A small drift inside the tolerance passes (this is a statistical check).
	if v := SplitVerdict(exp, map[string]int{"a": 350, "b": 50}, 400); v["ok"] != true {
		t.Errorf("12.5%% against 10%% is within noise at n=400: %v", v)
	}
	if v := SplitVerdict(exp, map[string]int{"a": 300, "b": 40, "rogue": 60}, 400); v["ok"] != false {
		t.Errorf("an unexpected identity must fail: %v", v)
	}
	zero, _ := ParseSplitExpectations([]string{"a=1", "old=0"})
	if v := SplitVerdict(zero, map[string]int{"a": 399, "old": 1}, 400); v["ok"] != false {
		t.Errorf("a weight 0 backend that answers once must fail: %v", v)
	}
	if v := SplitVerdict(zero, map[string]int{"a": 400}, 400); v["ok"] != true {
		t.Errorf("weight 0 backend with no traffic passes: %v", v)
	}
	if v := SplitVerdict(exp, map[string]int{}, 0); v["ok"] != true {
		t.Errorf("no samples is handled without dividing by zero: %v", v)
	}
}

func TestRunSplitAgainstServer(t *testing.T) {
	srv := splitServer(t, cycle("orders-v1", 9, "orders-v2", 1), "X-Setura-Backend")
	exp, _ := ParseSplitExpectations([]string{"orders-v1=90", "orders-v2=10"})
	o := SplitOptions{Probe: NewProbe(srv.URL + "/"), Expect: exp, Requests: 200, Concurrency: 4, MaxErrRate: 0.01}
	res, err := RunSplit(o)
	if err != nil || res["ok"] != true || res["samples"] != 200 {
		t.Fatalf("90/10 server against 90/10: %v %v", res, err)
	}

	wrong, _ := ParseSplitExpectations([]string{"orders-v1=50", "orders-v2=50"})
	o.Expect = wrong
	if res, err = RunSplit(o); err != nil || res["ok"] != false {
		t.Fatalf("90/10 server against 50/50 must fail: %v %v", res, err)
	}

	// A custom identity header, and responses without it.
	srv2 := splitServer(t, cycle("a", 1, "", 1), "X-Served-By")
	exp2, _ := ParseSplitExpectations([]string{"a=1"})
	o2 := SplitOptions{Probe: NewProbe(srv2.URL + "/"), Expect: exp2, Requests: 50, Concurrency: 2, Identity: "X-Served-By", MaxErrRate: 0}
	if res, err = RunSplit(o2); err != nil || res["ok"] != false {
		t.Fatalf("half the answers without an identity must fail: %v %v", res, err)
	}
	if !strings.Contains(strings.Join(rowNames(res), ","), splitNone) {
		t.Errorf("missing identity must be reported as %q: %v", splitNone, rowNames(res))
	}

	// 500s count as errors, not as a backend.
	srv3 := splitServer(t, cycle("a", 9, "!500", 1), "X-Setura-Backend")
	exp3, _ := ParseSplitExpectations([]string{"a=1"})
	o3 := SplitOptions{Probe: NewProbe(srv3.URL + "/"), Expect: exp3, Requests: 100, Concurrency: 1, MaxErrRate: 0.01}
	if res, err = RunSplit(o3); err != nil || res["ok"] != false || res["error_budget_exceeded"] != true || res["errors"] != 10 {
		t.Fatalf("10%% errors against a 1%% budget: %v %v", res, err)
	}
	o3.MaxErrRate = 0.2
	if res, err = RunSplit(o3); err != nil || res["ok"] != true {
		t.Fatalf("errors inside the budget do not fail the split: %v %v", res, err)
	}
}

func rowNames(res obj) []string {
	var out []string
	for _, r := range asList(res["backends"]) {
		out = append(out, asStr(asMap(r)["backend"]))
	}
	return out
}

func TestRunSplitHostileOptions(t *testing.T) {
	exp, _ := ParseSplitExpectations([]string{"a=99", "b=1"})
	base := SplitOptions{Probe: NewProbe("http://127.0.0.1:1/"), Expect: exp, Requests: 2000, Concurrency: 2, MaxErrRate: 0.01}
	mut := map[string]struct {
		f    func(*SplitOptions)
		want string
	}{
		"too many requests": {func(o *SplitOptions) { o.Requests = maxSplitRequests + 1 }, "--requests"},
		"zero requests":     {func(o *SplitOptions) { o.Requests = 0 }, "--requests"},
		"too much conc":     {func(o *SplitOptions) { o.Concurrency = maxSplitConcurrency + 1 }, "--concurrency"},
		"zero conc":         {func(o *SplitOptions) { o.Concurrency = 0 }, "--concurrency"},
		"bad error rate":    {func(o *SplitOptions) { o.MaxErrRate = 2 }, "--max-error-rate"},
		"bad identity":      {func(o *SplitOptions) { o.Identity = "X Bad:" }, "--identity-header"},
		"too few requests":  {func(o *SplitOptions) { o.Requests = 200 }, "at least 1000"},
		"bad method":        {func(o *SplitOptions) { o.Probe.Method = "TRACE" }, "unsupported method"},
		"crlf header":       {func(o *SplitOptions) { o.Probe.RequestHeaders = map[string]string{"X-A": "a\r\nb"} }, "control character"},
	}
	for name, m := range mut {
		t.Run(name, func(t *testing.T) {
			o := base
			m.f(&o)
			_, err := RunSplit(o)
			if err == nil || !strings.Contains(err.Error(), m.want) {
				t.Fatalf("want %q, got %v", m.want, err)
			}
		})
	}
}

func TestSplitCLI(t *testing.T) {
	srv := splitServer(t, cycle("orders-v1", 3, "orders-v2", 1), "X-Setura-Backend")
	code, out, _ := cli(t, nil, "split", srv.URL+"/", "--expect", "orders-v1=75", "--expect", "orders-v2=25", "--requests", "200")
	if code != 0 || !strings.Contains(out, "orders-v1") || !strings.Contains(out, "statistical") {
		t.Errorf("pass: %d %s", code, out)
	}
	code, m := cliJSON(t, "split", srv.URL+"/", "--expect", "orders-v1=10", "--expect", "orders-v2=90", "--requests", "200", "--json")
	if code != 1 || m["ok"] != false {
		t.Errorf("fail: %d %v", code, m)
	}
	for _, args := range [][]string{{"split"}, {"split", srv.URL}, {"split", srv.URL, "--expect", "a"}, {"split", srv.URL, "--expect", "a=1", "--requests", "1"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v should be a usage error, got %d", args, code)
		}
	}
}
