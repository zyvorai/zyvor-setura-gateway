package gateway

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ObsOptions configures observability and traffic protection.
type ObsOptions struct {
	AccessLogFormat string // "json" (default) or "text"
	AccessLogBuffer int    // queued lines before dropping (default 4096)
	OTLPEndpoint    string // OTLP/HTTP collector, "" disables span export
	OTLPInterval    time.Duration
	RateLimit       RateLimitConfig
	Now             func() time.Time // clock for rate limiting (tests)
}

// obs bundles the optional components; nil members are disabled.
type obs struct {
	access  *accessLogger
	otlp    *otlpExporter
	limiter *limiter
	once    sync.Once
}

func newObs(o *Options) *obs {
	x := &obs{}
	if o.AccessLog != nil {
		x.access = newAccessLogger(o.AccessLog, o.Obs.AccessLogFormat, o.Obs.AccessLogBuffer)
	}
	if o.Obs.OTLPEndpoint != "" {
		x.otlp = newOTLP(o.Obs.OTLPEndpoint, o.Obs.OTLPInterval)
	}
	x.limiter = newLimiter(o.Obs.RateLimit, o.Obs.Now)
	return x
}

func (x *obs) close() {
	x.once.Do(func() {
		if x.access != nil {
			x.access.close()
		}
		if x.otlp != nil {
			x.otlp.close()
		}
	})
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// metrics serves the Prometheus text exposition.
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	head := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	snap := s.stats.Snapshot()
	head("setura_gateway_requests_total", "counter", "Requests handled, including unmatched ones.")
	fmt.Fprintf(&b, "setura_gateway_requests_total %d\n", snap["requests"])
	head("setura_gateway_unmatched_requests_total", "counter", "Requests that matched no route.")
	fmt.Fprintf(&b, "setura_gateway_unmatched_requests_total %d\n", snap["unmatched"])
	head("setura_gateway_route_requests_total", "counter", "Requests per route and status class.")
	routes := snap["routes"].(map[string]Counter)
	keys := make([]string, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		classes := make([]string, 0, len(routes[k].Status))
		for c := range routes[k].Status {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		for _, c := range classes {
			fmt.Fprintf(&b, "setura_gateway_route_requests_total{route=\"%s\",code=\"%s\"} %d\n", esc(k), c, routes[k].Status[c])
		}
	}
	if l := s.obs.limiter; l != nil {
		allowed, limited, buckets := l.snapshot()
		head("setura_gateway_ratelimit_allowed_total", "counter", "Requests admitted by the rate limiter.")
		fmt.Fprintf(&b, "setura_gateway_ratelimit_allowed_total %d\n", allowed)
		head("setura_gateway_ratelimit_limited_total", "counter", "Requests refused with 429 by the rate limiter, per route.")
		for _, r := range sortedRoutes(limited) {
			fmt.Fprintf(&b, "setura_gateway_ratelimit_limited_total{route=\"%s\"} %d\n", esc(r), limited[r])
		}
		head("setura_gateway_ratelimit_buckets", "gauge", "Live token buckets.")
		fmt.Fprintf(&b, "setura_gateway_ratelimit_buckets %d\n", buckets)
	}
	if a := s.obs.access; a != nil {
		head("setura_gateway_accesslog_written_total", "counter", "Access log lines written.")
		fmt.Fprintf(&b, "setura_gateway_accesslog_written_total %d\n", a.written.Load())
		head("setura_gateway_accesslog_dropped_total", "counter", "Access log lines dropped because the buffer was full.")
		fmt.Fprintf(&b, "setura_gateway_accesslog_dropped_total %d\n", a.dropped.Load())
	}
	if x := s.obs.otlp; x != nil {
		head("setura_gateway_otlp_spans_exported_total", "counter", "Spans accepted by the OTLP collector.")
		fmt.Fprintf(&b, "setura_gateway_otlp_spans_exported_total %d\n", x.exported.Load())
		head("setura_gateway_otlp_spans_dropped_total", "counter", "Spans dropped (queue full or export failed).")
		fmt.Fprintf(&b, "setura_gateway_otlp_spans_dropped_total %d\n", x.dropped.Load())
	}
	io.WriteString(w, b.String())
}

type obsFlags struct {
	format, rate, key, otlp string
	burst                   int
}

func addObsFlags(fs *flag.FlagSet, f *obsFlags) {
	fs.StringVar(&f.format, "access-log-format", "json", "access log format: json or text")
	fs.StringVar(&f.otlp, "otlp-endpoint", "", "export spans to this OTLP/HTTP collector (host:port or URL)")
	fs.StringVar(&f.rate, "rate-limit", "", "local rate limit such as 100/s, 600/m (empty disables)")
	fs.IntVar(&f.burst, "rate-burst", 0, "rate limit bucket size (default: the per-second rate)")
	fs.StringVar(&f.key, "rate-key", "ip", "rate limit key: ip, route or header:NAME")
}

func (f *obsFlags) apply(o *Options) error {
	switch f.format {
	case "json", "text":
	default:
		return fmt.Errorf("--access-log-format %q: want json or text", f.format)
	}
	o.Obs.AccessLogFormat, o.Obs.OTLPEndpoint = f.format, f.otlp
	if f.rate == "" {
		return nil
	}
	rate, per, err := ParseRate(f.rate)
	if err != nil {
		return fmt.Errorf("--rate-limit: %w", err)
	}
	o.Obs.RateLimit = RateLimitConfig{Rate: rate, Per: per, Burst: f.burst, Key: f.key}
	if err := o.Obs.RateLimit.validate(); err != nil {
		return fmt.Errorf("--rate-key/--rate-burst: %w", err)
	}
	return nil
}
