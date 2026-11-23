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
	"sync/atomic"
	"time"
)

// ObsOptions configures observability and traffic protection.
type ObsOptions struct {
	AccessLogFormat string // "json" (default) or "text"
	AccessLogBuffer int    // queued lines before dropping (default 4096)
	OTLPEndpoint    string // OTLP/HTTP collector, "" disables span export
	OTLPInterval    time.Duration
	OTLP            OTLPOptions    // retry, backoff and queue size of span export
	Logs            LogSinkOptions // syslog, Loki and OTLP logs sinks for the access log
	LogQuery        bool           // keep the query string in logged paths (default: stripped)
	RateLimit       RateLimitConfig
	// TrustedProxies are the peers whose X-Forwarded-For is believed when
	// working out the client address (rate-limit key, access log client_ip).
	TrustedProxies []netip.Prefix
	Now            func() time.Time // clock for rate limiting (tests)
	// AccessLogExclude lists request paths kept out of the access log and its
	// sinks: exact, or a prefix when the pattern ends in "*". Excluded requests
	// still count in metrics, history and spans.
	AccessLogExclude []string
	// AccessLogSample N logs one request in N (0 or 1 = all); responses with a
	// 5xx status are always logged.
	AccessLogSample int
}

// obs bundles the optional components; nil members are disabled.
type obs struct {
	access  *accessLogger
	otlp    *otlpExporter
	limiter *limiter
	sinks   []*batchSink // access log sinks (syslog, Loki, OTLP logs)
	once    sync.Once

	exclude    []string
	sample     int64
	seq        atomic.Int64
	excluded   atomic.Int64
	sampledOut atomic.Int64
}

// ValidateLogExclude checks --access-log-exclude patterns.
func ValidateLogExclude(pats []string) error {
	for _, p := range pats {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("access log exclude pattern %q: want an absolute path such as /edge-health or a prefix such as /healthz*", p)
		}
	}
	return nil
}

// logSkipped reports whether the request stays out of the access log and
// counts the reason: an exclude pattern, or sampling.
func (x *obs) logSkipped(path string, status int) bool {
	for _, p := range x.exclude {
		if pre, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(path, pre) {
				x.excluded.Add(1)
				return true
			}
		} else if path == p {
			x.excluded.Add(1)
			return true
		}
	}
	if x.sample > 1 && status < 500 && (x.seq.Add(1)-1)%x.sample != 0 {
		x.sampledOut.Add(1)
		return true
	}
	return false
}

func newObs(o *Options) *obs {
	x := &obs{exclude: o.Obs.AccessLogExclude, sample: int64(o.Obs.AccessLogSample)}
	if o.AccessLog != nil {
		x.access = newAccessLogger(o.AccessLog, o.Obs.AccessLogFormat, o.Obs.AccessLogBuffer)
	}
	if o.Obs.OTLPEndpoint != "" {
		x.otlp = newOTLPOpts(o.Obs.OTLPEndpoint, o.Obs.OTLPInterval, o.Obs.OTLP)
	}
	x.sinks, _ = newLogSinks(o.Obs.Logs) // addresses were validated by the flags
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
		for _, k := range x.sinks {
			k.close()
		}
	})
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// metrics serves the Prometheus text exposition.
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.writeObsMetrics(w)
}

func (s *Server) writeObsMetrics(w io.Writer) {
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
	rls := s.table.Load().ruleLimiters()
	if l := s.obs.limiter; l != nil || len(rls) > 0 {
		var allowed int64
		var buckets int
		limited := map[string]int64{}
		if l != nil {
			allowed, limited, buckets = l.snapshot()
		}
		for _, rl := range rls { // the totals cover the gateway-wide and the per-rule limiters
			a, lim, n := rl.l.snapshot()
			allowed, buckets = allowed+a, buckets+n
			for r, v := range lim {
				limited[r] += v
			}
		}
		head("setura_gateway_ratelimit_allowed_total", "counter", "Requests admitted by the rate limiters.")
		fmt.Fprintf(&b, "setura_gateway_ratelimit_allowed_total %d\n", allowed)
		head("setura_gateway_ratelimit_limited_total", "counter", "Requests refused with 429 by the rate limiter, per route.")
		for _, r := range sortedRoutes(limited) {
			fmt.Fprintf(&b, "setura_gateway_ratelimit_limited_total{route=\"%s\"} %d\n", esc(r), limited[r])
		}
		head("setura_gateway_ratelimit_buckets", "gauge", "Live token buckets.")
		fmt.Fprintf(&b, "setura_gateway_ratelimit_buckets %d\n", buckets)
		if len(rls) > 0 {
			head("setura_gateway_route_ratelimit_allowed_total", "counter", "Requests admitted by a per-rule rate limit (setura.zyvor.dev/rate-limit).")
			for _, rl := range rls {
				a, _, _ := rl.l.snapshot()
				fmt.Fprintf(&b, "setura_gateway_route_ratelimit_allowed_total{route=\"%s\",rule=\"%d\"} %d\n", esc(rl.route), rl.rule, a)
			}
			head("setura_gateway_route_ratelimit_limited_total", "counter", "Requests refused with 429 by a per-rule rate limit.")
			for _, rl := range rls {
				_, lim, _ := rl.l.snapshot()
				var n int64
				for _, v := range lim {
					n += v
				}
				fmt.Fprintf(&b, "setura_gateway_route_ratelimit_limited_total{route=\"%s\",rule=\"%d\"} %d\n", esc(rl.route), rl.rule, n)
			}
		}
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
	logQuery                bool
	otlpProto               string
	syslog, loki, lokiLabel string
	lokiTenant, otlpLogs    string
	sinkQueue, sinkBatch    int
	sinkRetries             int
	sinkBackoff, sinkTick   time.Duration
	exclude                 stringList
	sample                  int
}

func addObsFlags(fs *flag.FlagSet, f *obsFlags) {
	fs.StringVar(&f.format, "access-log-format", "json", "access log format: json or text")
	fs.Var(&f.exclude, "access-log-exclude", "keep this path out of the access log: exact (/edge-health) or prefix (/healthz*); repeatable")
	fs.IntVar(&f.sample, "access-log-sample", 0, "log one request in N (5xx responses are always logged; default all)")
	fs.StringVar(&f.otlp, "otlp-endpoint", "", "export spans to this OTLP/HTTP collector (host:port or URL)")
	fs.BoolVar(&f.logQuery, "log-query", false, "keep query strings in logged paths (default: stripped, they often hold tokens)")
	fs.StringVar(&f.rate, "rate-limit", "", "local rate limit such as 100/s, 600/m (empty disables)")
	fs.IntVar(&f.burst, "rate-burst", 0, "rate limit bucket size (default: the per-second rate)")
	fs.StringVar(&f.key, "rate-key", "ip", "rate limit key: ip, route or header:NAME")
	fs.IntVar(&f.share, "rate-limit-share", 0, "divide the rate by this many gateway replicas (approximates a shared limit)")
	fs.StringVar(&f.trusted, "trusted-proxies", "", "CIDRs/IPs whose X-Forwarded-For is believed for the client address")
	fs.IntVar(&f.otlpRetries, "otlp-retries", 0, "retries of a failed OTLP export (default 4, -1 = none)")
	fs.IntVar(&f.otlpQueue, "otlp-queue", 0, "OTLP spans buffered before dropping (default 2048)")
	fs.StringVar(&f.otlpProto, "otlp-protocol", "http", "OTLP transport for spans and logs: http (JSON) or grpc (protobuf)")
	fs.StringVar(&f.otlpLogs, "otlp-logs-endpoint", "", "export the access log to this OTLP logs collector (host:port or URL)")
	fs.StringVar(&f.syslog, "syslog", "", "send the access log to syslog (RFC 5424): udp://HOST:PORT, tcp://HOST:PORT, unix:///path or unixgram:///path")
	fs.StringVar(&f.loki, "loki-url", "", "push the access log to Loki (http(s)://HOST:PORT, /loki/api/v1/push is appended)")
	fs.StringVar(&f.lokiLabel, "loki-labels", "", "Loki stream labels as k=v,k=v (default job=setura-gateway)")
	fs.StringVar(&f.lokiTenant, "loki-tenant", "", "Loki tenant sent as X-Scope-OrgID")
	fs.IntVar(&f.sinkQueue, "logsink-queue", 0, "log sink lines buffered per sink before dropping (default 8192)")
	fs.IntVar(&f.sinkBatch, "logsink-batch", 0, "log sink lines per delivery (default 256)")
	fs.DurationVar(&f.sinkTick, "logsink-interval", 0, "longest wait before a partial log sink batch is sent (default 1s)")
	fs.IntVar(&f.sinkRetries, "logsink-retries", 0, "retries of a failed log sink delivery (default 4, -1 = none)")
	fs.DurationVar(&f.sinkBackoff, "logsink-backoff", 0, "first log sink retry wait, doubling (default 250ms)")
	fs.DurationVar(&f.otlpBackoff, "otlp-backoff", 0, "first OTLP retry wait, doubling (default 250ms)")
}

func (f *obsFlags) apply(o *Options) error {
	switch f.format {
	case "json", "text":
	default:
		return fmt.Errorf("--access-log-format %q: want json or text", f.format)
	}
	if err := ValidateLogExclude(f.exclude); err != nil {
		return fmt.Errorf("--access-log-exclude: %w", err)
	}
	if f.sample < 0 {
		return fmt.Errorf("--access-log-sample %d: want 0 (all) or a positive N", f.sample)
	}
	o.Obs.AccessLogExclude, o.Obs.AccessLogSample = []string(f.exclude), f.sample
	o.Obs.AccessLogFormat, o.Obs.OTLPEndpoint, o.Obs.LogQuery = f.format, f.otlp, f.logQuery
	o.Obs.OTLP = OTLPOptions{Queue: f.otlpQueue, Retries: f.otlpRetries, Backoff: f.otlpBackoff, Protocol: f.otlpProto}
	if f.otlpProto != "" && f.otlpProto != "http" && f.otlpProto != "grpc" {
		return fmt.Errorf("--otlp-protocol %q: want http or grpc", f.otlpProto)
	}
	labels, err := ParseLabels(f.lokiLabel)
	if err != nil {
		return fmt.Errorf("--loki-labels: %w", err)
	}
	o.Obs.Logs = LogSinkOptions{Syslog: f.syslog, LokiURL: f.loki, LokiLabels: labels, LokiTenant: f.lokiTenant, OTLPLogs: f.otlpLogs, OTLPProtocol: f.otlpProto,
		Sink: SinkOptions{Queue: f.sinkQueue, Batch: f.sinkBatch, Interval: f.sinkTick, Retries: f.sinkRetries, Backoff: f.sinkBackoff}}
	if f.syslog != "" {
		if _, _, err := parseSyslogAddr(f.syslog); err != nil {
			return err
		}
	}
	if f.loki != "" {
		if _, err := lokiURL(f.loki); err != nil {
			return err
		}
	}
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
