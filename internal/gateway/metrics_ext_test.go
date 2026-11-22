package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// family is one parsed metric family of an exposition.
type family struct {
	typ    string
	help   string
	labels map[string]bool // label names seen on samples, without le
	n      int             // samples
}

var sampleRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*?)\})?\s+\S+`)
var labelRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="`)

func parseExposition(t *testing.T, text string) map[string]*family {
	t.Helper()
	fams := map[string]*family{}
	get := func(n string) *family {
		if fams[n] == nil {
			fams[n] = &family{labels: map[string]bool{}}
		}
		return fams[n]
	}
	for _, ln := range strings.Split(text, "\n") {
		switch {
		case ln == "" || ln == "# EOF":
		case strings.HasPrefix(ln, "# HELP "):
			p := strings.SplitN(ln[7:], " ", 2)
			if len(p) < 2 || strings.TrimSpace(p[1]) == "" {
				t.Errorf("empty HELP: %q", ln)
				continue
			}
			get(p[0]).help = p[1]
		case strings.HasPrefix(ln, "# TYPE "):
			p := strings.Fields(ln[7:])
			get(p[0]).typ = p[1]
		default:
			m := sampleRe.FindStringSubmatch(ln)
			if m == nil {
				t.Errorf("unparseable sample %q", ln)
				continue
			}
			name := m[1]
			for _, suf := range []string{"_bucket", "_sum", "_count"} {
				if f := fams[strings.TrimSuffix(name, suf)]; strings.HasSuffix(name, suf) && f != nil && f.typ == "histogram" {
					name = strings.TrimSuffix(name, suf)
				}
			}
			f := get(name)
			f.n++
			for _, lm := range labelRe.FindAllStringSubmatch(m[2], -1) {
				if lm[1] != "le" {
					f.labels[lm[1]] = true
				}
			}
		}
	}
	return fams
}

func (f *family) labelList() string {
	var l []string
	for k := range f.labels {
		l = append(l, k)
	}
	sort.Strings(l)
	return strings.Join(l, ",")
}

// metricsRig serves an HTTPS route with every optional subsystem on and seeds
// the counters that need config the rig does not have.
func metricsRig(t *testing.T) *Server {
	t.Helper()
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	t.Cleanup(collector.Close)
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	gw := httpsGateway(tlsListener("a", "a.mactra.test", "a-cert"))
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "a": m{"parentRefs": l{m{"name": "gw", "sectionName": "a"}}, "rules": l{rule("/", ref("a", 1))}}},
		"backends":  m{"t/a:80": be["a"]},
		"secrets":   m{"a-cert": p.files("a", "a.mactra.test")}})
	var buf syncBuf
	s := startServer(t, raw, func(o *Options) {
		o.AccessLog = &buf
		o.Obs.OTLPEndpoint = collector.URL
		o.Obs.RateLimit = RateLimitConfig{Rate: 1000, Per: time.Second, Key: "ip"}
		o.Resilience.Circuit = CircuitOptions{FailureThreshold: 3, OpenFor: time.Minute}
	})
	if r := req(t, tlsClient(s.Addr(8443), p, "a.mactra.test"), "https", "GET", "a.mactra.test", "/", ""); r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s.FlushAccessLog()
	s.ext.authOutcome("t/a", "allowed", "")
	s.ext.authOutcome("t/a", "denied", "unauthenticated")
	s.ext.bump(&s.ext.cors, "t/a")
	s.ext.bump(&s.ext.sess, "t/a")
	s.ext.bump(&s.ext.btls, "t/a:80")
	return s
}

func renderCatalog() string {
	var b strings.Builder
	for _, d := range MetricCatalog {
		b.WriteString(d.Name + " " + d.Type + " " + strings.Join(d.Labels, ",") + "\n")
	}
	return b.String()
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func obsMetricsOf(s *Server) string {
	rec := httptest.NewRecorder()
	s.metrics(rec, nil)
	return rec.Body.String()
}

// TestMetricsGolden pins the exposition: every family the rig produces is in
// MetricCatalog with the same type and label names, the catalog matches the
// golden file (so a rename fails here), and every catalog name still exists in
// the source.
func TestMetricsGolden(t *testing.T) {
	golden := filepath.Join("testdata", "metrics_catalog.golden")
	if os.Getenv("SETURA_UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(golden, []byte(renderCatalog()), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != renderCatalog() {
		t.Fatalf("MetricCatalog differs from %s (a metric was renamed, retyped or relabelled; update the golden file deliberately with SETURA_UPDATE_GOLDEN=1)\ngot:\n%s", golden, renderCatalog())
	}

	s := metricsRig(t)
	cat := map[string]MetricDef{}
	for _, d := range MetricCatalog {
		cat[d.Name] = d
	}
	fams := parseExposition(t, obsMetricsOf(s)+metricsOf(s))
	for name, f := range fams {
		d, ok := cat[name]
		if !ok {
			t.Errorf("exposed family %s is not in MetricCatalog", name)
			continue
		}
		if f.typ != d.Type {
			t.Errorf("%s: type %q, catalog %q", name, f.typ, d.Type)
		}
		if f.help == "" {
			t.Errorf("%s: no HELP", name)
		}
		if f.n > 0 && f.labelList() != strings.Join(sortedCopy(d.Labels), ",") {
			t.Errorf("%s: labels {%s}, catalog {%s}", name, f.labelList(), strings.Join(d.Labels, ","))
		}
	}
	// everything the rig enabled must be exposed.
	for _, d := range MetricCatalog {
		if _, ok := fams[d.Name]; ok {
			continue
		}
		switch d.When {
		case "", "connection history enabled", "rate limiting enabled", "access log enabled", "OTLP span export enabled", "a circuit breaker is in effect":
			t.Errorf("%s (%s) missing from the exposition", d.Name, d.When)
		}
	}
	// every name is still spelled out in the code (catches a rename in families the rig does not reach).
	srcs, _ := filepath.Glob("*.go")
	var all strings.Builder
	for _, f := range srcs {
		if !strings.HasSuffix(f, "_test.go") {
			b, _ := os.ReadFile(f)
			all.Write(b)
		}
	}
	for _, d := range MetricCatalog {
		// metrics_ext.go holds the catalog itself, so its families are pinned by the rig above.
		if _, ok := fams[d.Name]; !ok && strings.Count(all.String(), d.Name) < 2 {
			t.Errorf("%s no longer appears in the source", d.Name)
		}
	}
}

func TestMetricsNewSeries(t *testing.T) {
	s := metricsRig(t)
	out := metricsOf(s)
	for _, want := range []string{
		`setura_gateway_auth_requests_total{route="t/a",decision="allowed",reason=""} 1`,
		`setura_gateway_auth_requests_total{route="t/a",decision="denied",reason="unauthenticated"} 1`,
		`setura_gateway_cors_preflights_total{route="t/a"} 1`,
		`setura_gateway_session_persistence_hits_total{route="t/a"} 1`,
		`setura_gateway_backend_tls_handshake_failures_total{backend="t/a:80"} 1`,
		`setura_gateway_backend_requests_total{backend="t/a:80",code="2xx"} 1`,
		`setura_gateway_requests_in_flight 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s\n%s", want, out)
		}
	}
	m := regexp.MustCompile(`setura_gateway_cert_expiry_seconds\{listener="[^"]+"\} (-?\d+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no cert expiry series:\n%s", out)
	}
	if m[1] == "0" || strings.HasPrefix(m[1], "-") {
		t.Errorf("cert expiry %s, want a positive number of seconds", m[1])
	}
}

func TestOpenMetricsExemplars(t *testing.T) {
	s := metricsRig(t)
	rec := httptest.NewRecorder()
	rq := httptest.NewRequest("GET", "/metrics", nil)
	rq.Header.Set("Accept", "application/openmetrics-text;version=1.0.0,text/plain;q=0.5")
	s.serveMetrics(rec, rq)
	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/openmetrics-text") {
		t.Fatalf("content type %q", ct)
	}
	if !strings.HasSuffix(body, "# EOF\n") {
		t.Errorf("OpenMetrics output must end with # EOF")
	}
	if !regexp.MustCompile(`(?m)^setura_gateway_request_duration_seconds_bucket\{route="t/a",le="[^"]+"\} \d+ # \{trace_id="[0-9a-f]{32}"\} [0-9.e-]+ \d+\.\d{3}$`).MatchString(body) {
		t.Errorf("no trace_id exemplar on the duration histogram:\n%s", body)
	}
	if strings.Contains(body, "# TYPE setura_gateway_requests_total") || !strings.Contains(body, "# TYPE setura_gateway_requests counter") {
		t.Errorf("counter families must drop _total in OpenMetrics")
	}
	// plain Prometheus scrapes get no exemplars and no EOF
	rec = httptest.NewRecorder()
	s.serveMetrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rec.Body.String(), "trace_id") || strings.Contains(rec.Body.String(), "# EOF") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("text exposition changed")
	}
}

func TestMetricsAdminNegotiates(t *testing.T) {
	s, _ := obsServer(t, nil)
	s.opts.Admin = "127.0.0.1:0"
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	get(t, s, "x.test", "/ok")
	s.FlushAccessLog()
	rq, _ := http.NewRequest("GET", "http://"+s.AdminAddr()+"/metrics", nil)
	rq.Header.Set("Accept", "application/openmetrics-text")
	resp, err := http.DefaultClient.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/openmetrics-text") || !strings.Contains(string(b), "# EOF") {
		t.Errorf("admin /metrics ignored Accept: %q", resp.Header.Get("Content-Type"))
	}
}

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

func TestIsTLSHandshakeError(t *testing.T) {
	for msg, want := range map[string]bool{
		"tls: failed to verify certificate: x509: certificate signed by unknown authority": true,
		"remote error: tls: bad certificate":                                               true,
		"dial tcp 127.0.0.1:1: connect: connection refused":                                false,
	} {
		if got := isTLSHandshakeError(&strErr{msg}); got != want {
			t.Errorf("%q: %v", msg, got)
		}
	}
}

func TestMetricsCountAuthSessionAndCORS(t *testing.T) {
	hash, _ := HashPassword("pw", 1000)
	s, _ := authServer(t, m{"basic": m{"realm": "r", "users": l{m{"name": "bob", "hash": hash}}}}, nil)
	get(t, s, "a.test", "/")
	get(t, s, "a.test", "/", "Authorization", "Basic Ym9iOnB3") // bob:pw
	out := metricsOf(s)
	for _, want := range []string{`decision="denied",reason="unauthenticated"} 1`, `decision="allowed",reason=""} 1`} {
		if !strings.Contains(out, want) {
			t.Errorf("auth metrics lack %s\n%s", want, out)
		}
	}

	be, _ := twoEndpoints(t)
	s = startServer(t, snap(httpGateway(""), map[string]m{"r": sessionRule(m{"sessionName": "sid", "type": "Cookie"})}, be), nil)
	c := client(s.Addr(8080), nil)
	tok := cookieOf(req(t, c, "http", "GET", "x.test:8080", "/", "").Header, "sid")
	req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid="+tok)
	req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid="+tok)
	if !strings.Contains(metricsOf(s), `setura_gateway_session_persistence_hits_total{route="t/r"} 2`) {
		t.Errorf("session hits:\n%s", metricsOf(s))
	}

	be, _ = upstreams(t, "a")
	open := m{"type": "CORS", "cors": m{"allowOrigins": l{"*"}, "allowMethods": l{"*"}, "allowHeaders": l{"*"}}}
	s = startServer(t, snap(httpGateway(""), map[string]m{"open": route("open.test", withFilters(rule("/", ref("a", 1)), open))}, be), nil)
	req(t, client(s.Addr(8080), nil), "http", "OPTIONS", "open.test:8080", "/x", "", "Origin", "https://o.test", "Access-Control-Request-Method", "GET")
	s.FlushAccessLog()
	if !strings.Contains(metricsOf(s), `setura_gateway_cors_preflights_total{route="t/open"} 1`) {
		t.Errorf("cors:\n%s", metricsOf(s))
	}
}
