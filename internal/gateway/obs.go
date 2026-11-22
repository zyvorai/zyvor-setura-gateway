package gateway

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
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
	OTLP            OTLPOptions // retry, backoff and queue size of span export
	RateLimit       RateLimitConfig
	// TrustedProxies are the peers whose X-Forwarded-For is believed when
	// working out the client address (rate-limit key, access log client_ip).
	TrustedProxies []netip.Prefix
	Now            func() time.Time // clock for rate limiting (tests)
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
		x.otlp = newOTLPOpts(o.Obs.OTLPEndpoint, o.Obs.OTLPInterval, o.Obs.OTLP)
	}
	x.limiter = newLimiter(o.Obs.RateLimit, o.Obs.Now)
	if x.limiter != nil {
		x.limiter.trusted = trustedNets(o.Obs.TrustedProxies)
	}
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
	if rf, ok := s.opts.AccessLog.(*rotatingFile); ok {
		head("setura_gateway_accesslog_rotations_total", "counter", "Access log rotations performed.")
		fmt.Fprintf(&b, "setura_gateway_accesslog_rotations_total %d\n", rf.rotations.Load())
		head("setura_gateway_accesslog_rotation_errors_total", "counter", "Access log rotation or compression failures.")
		fmt.Fprintf(&b, "setura_gateway_accesslog_rotation_errors_total %d\n", rf.errors.Load())
	}
	if x := s.obs.otlp; x != nil {
		head("setura_gateway_otlp_spans_exported_total", "counter", "Spans accepted by the OTLP collector.")
		fmt.Fprintf(&b, "setura_gateway_otlp_spans_exported_total %d\n", x.exported.Load())
		head("setura_gateway_otlp_spans_dropped_total", "counter", "Spans dropped (queue full or export failed).")
		fmt.Fprintf(&b, "setura_gateway_otlp_spans_dropped_total %d\n", x.dropped.Load())
		head("setura_gateway_otlp_export_failures_total", "counter", "Failed OTLP export attempts (each retry that fails counts).")
		fmt.Fprintf(&b, "setura_gateway_otlp_export_failures_total %d\n", x.failures.Load())
		head("setura_gateway_otlp_retries_total", "counter", "OTLP export retries performed.")
		fmt.Fprintf(&b, "setura_gateway_otlp_retries_total %d\n", x.retries.Load())
		head("setura_gateway_otlp_queue_length", "gauge", "Spans waiting in the bounded export queue.")
		fmt.Fprintf(&b, "setura_gateway_otlp_queue_length %d\n", len(x.ch))
	}
	io.WriteString(w, b.String())
}

type obsFlags struct {
	format, rate, key, otlp string
	burst, share            int
	trusted                 string
	otlpRetries, otlpQueue  int
	otlpBackoff             time.Duration
}

func addObsFlags(fs *flag.FlagSet, f *obsFlags) {
	fs.StringVar(&f.format, "access-log-format", "json", "access log format: json or text")
	fs.StringVar(&f.otlp, "otlp-endpoint", "", "export spans to this OTLP/HTTP collector (host:port or URL)")
	fs.StringVar(&f.rate, "rate-limit", "", "local rate limit such as 100/s, 600/m (empty disables)")
	fs.IntVar(&f.burst, "rate-burst", 0, "rate limit bucket size (default: the per-second rate)")
	fs.StringVar(&f.key, "rate-key", "ip", "rate limit key: ip, route or header:NAME")
	fs.IntVar(&f.share, "rate-limit-share", 0, "divide the rate by this many gateway replicas (approximates a shared limit)")
	fs.StringVar(&f.trusted, "trusted-proxies", "", "CIDRs/IPs whose X-Forwarded-For is believed for the client address")
	fs.IntVar(&f.otlpRetries, "otlp-retries", 0, "retries of a failed OTLP export (default 4, -1 = none)")
	fs.IntVar(&f.otlpQueue, "otlp-queue", 0, "OTLP spans buffered before dropping (default 2048)")
	fs.DurationVar(&f.otlpBackoff, "otlp-backoff", 0, "first OTLP retry wait, doubling (default 250ms)")
}

func (f *obsFlags) apply(o *Options) error {
	switch f.format {
	case "json", "text":
	default:
		return fmt.Errorf("--access-log-format %q: want json or text", f.format)
	}
	o.Obs.AccessLogFormat, o.Obs.OTLPEndpoint = f.format, f.otlp
	o.Obs.OTLP = OTLPOptions{Queue: f.otlpQueue, Retries: f.otlpRetries, Backoff: f.otlpBackoff}
	tp, err := ParseTrustedProxies(f.trusted)
	if err != nil {
		return fmt.Errorf("--trusted-proxies: %w", err)
	}
	o.Obs.TrustedProxies = tp
	if f.share < 0 {
		return fmt.Errorf("--rate-limit-share %d: want 1 or more", f.share)
	}
	if f.rate == "" {
		return nil
	}
	rate, per, err := ParseRate(f.rate)
	if err != nil {
		return fmt.Errorf("--rate-limit: %w", err)
	}
	o.Obs.RateLimit = RateLimitConfig{Rate: rate, Per: per, Burst: f.burst, Key: f.key, Share: f.share}
	if err := o.Obs.RateLimit.validate(); err != nil {
		return fmt.Errorf("--rate-key/--rate-burst: %w", err)
	}
	return nil
}
