package gateway

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/zyvor-setura-gateway/internal/contract"
)

const usage = `setura gateway - the built-in Gateway API data plane (no Envoy required)

Usage:
  setura gateway run --config FILE [flags]     serve a snapshot file, reloading it when it changes
  setura gateway run --kubernetes [flags]      run as an in-cluster controller and data plane
  setura gateway up FILE [flags]               local demo: start demo backends and serve FILE
  setura gateway hash --kind apikey|password   read a secret on stdin, print the hash to store in a config
  setura gateway ai-usage [--admin ADDR]       token usage, cost estimates, budgets and provider health of the AI routes of a running gateway
  setura gateway install [flags]               print Kubernetes YAML for the controller (never applies); --with-monitoring adds
                                               an admin Service port, ServiceMonitor, PrometheusRule alerts and the Grafana dashboard
  setura gateway install --check               check the cluster's Gateway API CRDs (missing or too old) through kubectl
  setura gateway status [-n NS | -A]           Gateways and routes with Accepted, Programmed and ResolvedRefs and the reason
  setura gateway rollout --config LIVE --new CANDIDATE --checks CHECKS   guarded rollout with automatic rollback
  setura gateway history --config LIVE         list config backups
  setura gateway rollback --config LIVE [--to ID]   restore a backup

Flags for run and up:
  --bind ADDR           listener bind address (default 127.0.0.1)
  --port-map A=B[,..]   serve spec port A on port B (0 = any free port); repeatable
  --port-offset N       add N to spec ports below 1024 (unprivileged remapping)
  --admin ADDR|off      admin endpoint (default 127.0.0.1:19000)
  --pprof ADDR          serve net/http/pprof and /debug/runtime on a loopback ADDR such as 127.0.0.1:6060 (default off)
  --admin-token TOKEN   bearer token for the admin endpoint (or SETURA_ADMIN_TOKEN); required to bind off loopback
  --admin-open-ready    leave /ready reachable without the token (kubelet probes)
  --ocsp-staple         fetch and staple OCSP responses for listener certificates (default off)
  --acme-dir DIR        enable ACME (RFC 8555): HTTPS listeners with a hostname and no certificateRefs get certificates
                        from a CA, stored in DIR (0600 files); renewed at 2/3 of the lifetime, hot-swapped into the listener
  --acme-directory URL  ACME directory (default: Let's Encrypt STAGING, which issues untrusted certificates)
  --acme-production     use the Let's Encrypt production directory (explicit on purpose)
  --acme-email ADDR     ACME account contact
  --acme-challenge http-01|tls-alpn-01   preferred challenge (default http-01 when a plain HTTP listener exists)
  --acme-dns-hook CMD   DNS-01 for wildcards: CMD present|cleanup DOMAIN VALUE (publish or remove the _acme-challenge TXT)
  --proxy-protocol N=CIDR[,..]   accept PROXY protocol v1/v2 on spec port N from these sources only; repeatable
                        (a backend option proxyProtocol: v1|v2 sends it upstream; see docs/certificates.md)
  --alt-svc VALUE       send an Alt-Svc header on HTTPS responses, to advertise an HTTP/3-capable edge in front (docs/http3.md)
  --client-allow-san PATTERN[,..]   with client certificate validation, accept only certificates with a DNS, URI or email SAN
                        matching PATTERN: exact or *.suffix, optionally dns:/uri:/email: prefixed; repeatable (or SETURA_CLIENT_ALLOW_SAN).
                        A Gateway's setura.zyvor.dev/client-allow annotation overrides it (docs/client-cert-authz.md)
  --client-allow-cn PATTERN[,..]    the same for the subject common name; a certificate matching a SAN or a CN entry is accepted
  --client-cert-xfcc    also forward the verified client certificate as an Envoy-style X-Forwarded-Client-Cert header
  --interval DUR        poll interval for config changes (default 1s; with --kubernetes only used by --poll, default 5s)
  --poll                with --kubernetes: poll instead of using watches
  --resync DUR          with --kubernetes: safety relist while watching (default 1m)
  --leader-elect        with --kubernetes: only the holder of a coordination.k8s.io Lease writes status
  --lease-name N, --lease-namespace NS, --lease-duration D (15s), --lease-renew-deadline D (10s),
  --lease-retry-period D (2s), --lease-identity ID   Lease settings for --leader-elect
  --service-name N, --service-namespace NS   Service whose address becomes Gateway status.addresses
  --expose-gateway-ports   with --kubernetes: add a Service port for every Gateway listener port
  --force               apply configurations that have lint errors
  --udp-idle-timeout DUR   close a UDP session after DUR without client datagrams (default 30s)
  --access-log FILE|-|off   access log (default "-", stdout)
  --access-log-format json|text   access log format (default json)
  --access-log-max-size SIZE    rotate the access log file past SIZE (100, 64k, 10MB, 1g; default off)
  --access-log-keep N           rotated files to keep (default: all)
  --access-log-gzip             gzip rotated files
  --access-log-exclude PATTERN  keep a path out of the access log and its sinks: exact (/edge-health) or prefix (/healthz*);
                        repeatable; excluded requests still count in metrics (docs/headers-and-logs.md)
  --access-log-sample N         log one request in N (5xx responses are always logged); the rest still count in metrics
                        (a file access log also rotates on SIGHUP; a file moved away by logrotate is reopened)
  --otlp-endpoint HOST:PORT|URL   export spans via OTLP/HTTP JSON (default off)
  --otlp-protocol http|grpc   OTLP transport for spans and logs: JSON over HTTP (default) or protobuf over gRPC
  --otlp-logs-endpoint HOST:PORT|URL   also export the access log to an OTLP logs collector
  --syslog ADDR         send the access log as RFC 5424 syslog: udp://HOST:PORT, tcp://HOST:PORT, unix:///path, unixgram:///path
  --loki-url URL, --loki-labels k=v,k=v, --loki-tenant ID   push the access log to Loki (/loki/api/v1/push is appended)
  --logsink-queue N, --logsink-batch N, --logsink-interval DUR, --logsink-retries N, --logsink-backoff DUR
                        bounded queue (8192), batch size (256), flush interval (1s), retries (4, -1 = none) and first
                        backoff (250ms, doubling) of the syslog, Loki and OTLP logs sinks; a full queue drops and counts
  --rate-limit N/s|N/m|N/h  local token-bucket rate limit (default off)
  --rate-burst N        bucket size (default: the per-second rate)
  --rate-key ip|route|header:NAME   what a bucket is keyed on (default ip)
  --rate-limit-share N  divide the rate by N, the declared replica count (an approximation of a
                        shared limit; no state is shared between replicas)
  --trusted-proxies CIDR[,..]   believe X-Forwarded-For only from these peers (client IP for rate
                        limits and access logs; appended to, not replaced, when forwarded)
  --max-request-body SIZE   refuse request bodies over SIZE (100, 64k, 10MB) with 413 (default no limit; a rule or
                        listener "setura.zyvor.dev/limits" block overrides it, see docs/limits.md)
  --max-header-bytes SIZE   refuse request headers over SIZE with 431 (default 1MB, Go's own limit)
  --header-read-timeout DUR   time a client has to send the request headers (default 10s)
  --idle-timeout DUR    close idle keep-alive connections after DUR (default off)
  --stream-idle-timeout DUR   cut a response that sends no byte for DUR, such as a stalled stream (default off)
  --normalize-path      remove . and .. path segments before routing (default off)
  --merge-slashes       collapse // in the request path before routing (default off)
  --reject-escaped-slashes   answer 400 to paths containing %2F or %5C (default off)
  --tls-min-version 1.2|1.3, --tls-max-version 1.2|1.3   TLS version bounds of HTTPS and terminating TLS
                        listeners (default 1.2 to 1.3; a listener's tls.options override them)
  --redis [NAME=]ADDR   Redis server for shared rate limits: HOST:PORT or redis[s]://[user:password@]HOST:PORT[/DB]; repeatable
                        (a rate-limit block's shared.redis picks one by NAME, default "default"; docs/shared-rate-limits.md)
  --redis-password-file F, --redis-tls, --redis-ca FILE   Redis password (or SETURA_REDIS_PASSWORD), TLS and its CA bundle
  --redis-timeout DUR, --redis-dial-timeout DUR, --redis-pool N   round trip deadline (250ms), connect deadline (1s), connections (16)
  --compress            compress responses with gzip or deflate on every route (default off; brotli and zstd are not available);
                        a rule or listener "setura.zyvor.dev/compress" block overrides it
  --compress-types T[,..]   content types (text/*, application/json, */*+json; default text, JSON, XML, JavaScript, SVG)
  --compress-encodings E[,..]   gzip,deflate in order of preference (default both)
  --compress-min-size SIZE, --compress-level 1-9   smallest body worth compressing (1KB) and the level (6)
  --max-connections N, --max-connections-per-ip N   most client connections per listener port, in total and per peer IP;
                        extra connections are closed (default no limit; a listener limits block overrides them)
  --tcp-keepalive-idle DUR, --tcp-keepalive-interval DUR, --tcp-keepalive-count N, --tcp-keepalive-off   TCP keepalive of client connections
  --h2-max-streams N, --h2-initial-window SIZE, --h2-max-frame-size SIZE, --h2-max-conn-window SIZE   HTTP/2 server settings
  --bandwidth-request RATE, --bandwidth-response RATE   pace each request and response body to RATE bytes per second
                        (1MB/s, 256k; a rule "setura.zyvor.dev/bandwidth" block overrides it; docs/traffic-shaping.md)
  --request-id preserve|generate|trust-upstream   X-Request-Id policy: keep a valid client id (default), always generate
                        one (the client's travels as X-Client-Request-Id), or let a valid backend id win on the response
  --otlp-retries N, --otlp-backoff DUR, --otlp-queue N   OTLP export retry count (default 4, -1 = none),
                        first backoff (250ms, doubling) and bounded span queue (2048)
  --retry-budget PCT    retries may not exceed PCT percent of recent requests (default 20)
  --retry-header        add X-Setura-Retries to responses (default off)
  --retry-cross-backend retries may move to another weighted backendRef (rule retry.crossBackend overrides)
  --retry-jitter F      randomise retry backoff by +/- F, 0-1 (default 0; rule retry.jitter overrides)
  --cb-max-requests N, --cb-max-pending N, --cb-max-connections N   circuit-breaker limits per backend
                        (a backend's circuitBreaker block overrides; default off)
  --cb-failures N, --cb-open-for DUR, --cb-probes N   open the circuit after N consecutive failures
                        for DUR (30s), then let N probes through (1)
  (a "resilience" block in the config file sets the same options; flags win over it)
  --outlier-failures N  consecutive 5xx/connect failures that eject an endpoint (default 5, 0 = off)
  --outlier-base-ejection DUR  first ejection time, doubling each time (default 30s)
  --outlier-max-ejection DUR   ejection time cap (default 5m)
  --health-path PATH    active-check every backend without its own healthCheck (default off)
  --health-interval DUR, --health-timeout DUR   defaults for those checks (5s, 2s)
                        (a backend healthCheck with protocol "grpc" probes grpc.health.v1)
  --log-query           keep query strings in logged and dashboard paths (default: stripped)
  --conn-history N      recent requests kept for /connections and the dashboard (default 500, 0 = off)
  --shadow-diff PCT     compare RequestMirror responses with the primary for PCT percent of requests;
                        a setura.zyvor.dev/shadow-diff block on the filter overrides it (default 0, see /shadow)
  --shadow-state FILE   snapshot shadow results (counters, recent mismatches) to FILE every 10s and
                        reload them at start (default off)
  --plans FILE          API plans (JSON, hot-reloaded): quotas, routes, prices and the identity to plan mapping; turns on
                        usage metering and quota enforcement (docs/metering-plans.md)
  --plans-interval DUR  how often the plan file is re-read (default 1s)
  --usage-state FILE    persist usage counters to FILE (atomic snapshots, reloaded at start) so a restart keeps the month
  --usage-interval DUR  usage snapshot period (default 30s; a final snapshot is written at shutdown)
  --usage-max-series N  cap on distinct day+identity+route+plan counters; more fold into an _overflow series (default 10000)
  --usage-retention-days N   days of counters kept (default 100)
  --learn FILE          learn an inventory of the endpoints served (path templates, methods, status codes, content
                        types, sizes, latency percentiles, parameter and header NAMES, never values or bodies) and
                        persist it to FILE; also togglable at runtime with POST /contract/learn on the admin endpoint
  --learn-max N         endpoints the learner keeps (default 5000); later ones are counted and dropped
  --contract-spec FILE  OpenAPI 3.x document (JSON or simple YAML) requests are checked against; reloaded when it changes
  --contract-enforce monitor|block   default mode for routes: monitor counts and logs requests whose method and path
                        are not in the spec, block answers 404 (unknown path) or 405 (unknown method); a route's
                        setura.zyvor.dev/contract annotation (off|monitor|block) overrides it (see docs/contract.md)
  --ai-prices FILE      JSON price table for AI route cost estimates: {"currency":"USD","models":{"gpt-4o":{"input":2.5,"output":10}}},
                        prices per million tokens, longest model prefix wins, "*" is the fallback; re-read when it changes (docs/ai-gateway.md)
  --ai-max-key-labels N most identities an AI route reports per series in /metrics, the rest are folded into "_other" (default 500)
  --ui ADDR             serve the read-only live dashboard, for example 127.0.0.1:9090 or :9090
                        (loopback only unless --ui-token is set)
  --ui-token TOKEN      bearer token for the dashboard (or SETURA_UI_TOKEN); required off loopback

Flags for install (output is plain YAML; docs/install-options.md):
  --namespace NS, --image IMG, --class NAME, --replicas N, --with-monitoring, --expose-gateway-ports
  --service-type ClusterIP|NodePort|LoadBalancer
  --node-port HTTP=30080,HTTPS=30443   map Service ports to node ports (names or numbers); repeatable
  --listener-port N     add a Service port for a Gateway listener port (7443, 8443, ...); repeatable
  --external-traffic-policy Local|Cluster   (NodePort and LoadBalancer)
  --host-network        pod on the node's network (ports 8080, 8443 and the listener ports)
  --arg FLAG            append one flag to the controller args, e.g. --arg --rate-limit=100; repeatable
  --resources requests.cpu=100m,requests.memory=64Mi,limits.cpu=500m,limits.memory=256Mi   any subset
  --node-selector K=V[,K=V]   schedule on labelled nodes; repeatable
  --admin-token-secret NAME   Secret holding the admin token (default setura-gateway-admin, key token); not printed
  --no-admin-secret           do not print the admin Secret (use --admin-token-secret NAME, or create setura-gateway-admin yourself)
  --create-admin-secret       print the Secret even with --admin-token-secret
  --crds                print the command that installs the Gateway API CRDs; --gateway-api-version vX.Y.Z (default ` + GatewayAPIVersion + `),
                        --gateway-api-channel standard|experimental
  --check               check the cluster's Gateway API CRDs instead of printing manifests (kubectl; global --context applies)
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type runFlags struct {
	opts       Options
	portMap    stringList
	accessLog  string
	interval   time.Duration
	bindFlagFS *flag.FlagSet
	obs        obsFlags
	outlier    int
	rotate     RotateOptions
	rotateSize string
	connHist   int
	uiAddr     string
	uiToken    string
	cert       certFlags
	limits     limitFlags
	shape      shapeFlags
	allowSAN   stringList
	allowCN    stringList
	xfcc       bool
}

func addRunFlags(fs *flag.FlagSet, f *runFlags) {
	fs.StringVar(&f.opts.Bind, "bind", "127.0.0.1", "listener bind address")
	fs.Var(&f.portMap, "port-map", "serve spec port A on port B, as A=B")
	fs.IntVar(&f.opts.PortOffset, "port-offset", 0, "add N to spec ports below 1024")
	fs.StringVar(&f.opts.Admin, "admin", DefaultAdmin, "admin address or off")
	fs.StringVar(&f.opts.Pprof, "pprof", "", "serve net/http/pprof and /debug/runtime on this loopback ADDR (default off)")
	fs.DurationVar(&f.interval, "interval", 0, "config poll interval")
	fs.BoolVar(&f.opts.Force, "force", false, "apply configurations that have lint errors")
	fs.StringVar(&f.accessLog, "access-log", "-", "access log file, - for stdout, off to disable")
	addObsFlags(fs, &f.obs)
	r := &f.opts.Resilience
	// Unset flags stay zero so the config file's resilience block (then the
	// built-in defaults) can fill them in; the real defaults are in the text.
	fs.IntVar(&r.RetryBudgetPercent, "retry-budget", 0, "retries as a percentage of recent requests (default 20)")
	fs.BoolVar(&r.RetryHeader, "retry-header", false, "add X-Setura-Retries to responses")
	fs.BoolVar(&r.RetryCrossBackend, "retry-cross-backend", false, "retries may move to another weighted backendRef")
	fs.Float64Var(&r.RetryJitter, "retry-jitter", 0, "randomise retry backoff by +/- this fraction (0-1)")
	fs.IntVar(&f.outlier, "outlier-failures", -1, "consecutive failures that eject an endpoint, 0 disables (default 5)")
	fs.DurationVar(&r.OutlierBaseEject, "outlier-base-ejection", 0, "first ejection duration (default 30s)")
	fs.DurationVar(&r.OutlierMaxEject, "outlier-max-ejection", 0, "maximum ejection duration (default 5m)")
	fs.StringVar(&r.HealthPath, "health-path", "", "default active health check path")
	fs.DurationVar(&r.HealthInterval, "health-interval", 0, "default active check interval (default 5s)")
	fs.DurationVar(&r.HealthTimeout, "health-timeout", 0, "default active check timeout (default 2s)")
	fs.IntVar(&r.Circuit.MaxRequests, "cb-max-requests", 0, "circuit breaker: concurrent requests per backend")
	fs.IntVar(&r.Circuit.MaxPending, "cb-max-pending", 0, "circuit breaker: requests allowed to wait for a slot")
	fs.IntVar(&r.Circuit.MaxConnections, "cb-max-connections", 0, "circuit breaker: upstream connections per backend")
	fs.IntVar(&r.Circuit.FailureThreshold, "cb-failures", 0, "circuit breaker: consecutive failures that open it")
	fs.DurationVar(&r.Circuit.OpenFor, "cb-open-for", 0, "circuit breaker: time open before probing (default 30s)")
	fs.IntVar(&r.Circuit.HalfOpenProbes, "cb-probes", 0, "circuit breaker: probe requests while half-open (default 1)")
	fs.StringVar(&f.rotateSize, "access-log-max-size", "", "rotate the access log file past this size (100, 64k, 10MB, 1g)")
	fs.IntVar(&f.rotate.Keep, "access-log-keep", 0, "rotated access log files to keep (default all)")
	fs.BoolVar(&f.rotate.Gzip, "access-log-gzip", false, "gzip rotated access log files")
	fs.DurationVar(&f.opts.UDPIdle, "udp-idle-timeout", 0, "idle timeout of UDP sessions on UDP listeners (default 30s)")
	fs.IntVar(&f.connHist, "conn-history", DefaultConnHistory, "recent requests kept for /connections, 0 disables")
	fs.IntVar(&f.opts.ShadowDiff, "shadow-diff", 0, "compare mirrored responses for PCT percent of requests (0 = only annotated mirrors)")
	fs.StringVar(&f.opts.ShadowState, "shadow-state", "", "persist shadow results to FILE (atomic snapshots, reloaded at start)")
	fs.StringVar(&f.opts.AdminToken, "admin-token", os.Getenv("SETURA_ADMIN_TOKEN"), "bearer token for the admin endpoint")
	fs.BoolVar(&f.opts.AdminOpenReady, "admin-open-ready", false, "leave /ready open without the admin token")
	fs.BoolVar(&f.opts.OCSPStaple, "ocsp-staple", false, "staple OCSP responses to listener certificates")
	addCertFlags(fs, &f.cert)
	addLimitFlags(fs, &f.limits)
	addShapeFlags(fs, &f.shape)
	fs.Var(&f.allowSAN, "client-allow-san", "accept only client certificates with a SAN matching PATTERN[,..] (exact or *.suffix; dns:/uri:/email: prefix optional); repeatable")
	fs.Var(&f.allowCN, "client-allow-cn", "accept only client certificates whose subject CN matches PATTERN[,..] (exact or *.suffix); repeatable")
	fs.BoolVar(&f.xfcc, "client-cert-xfcc", false, "also forward the verified client certificate as X-Forwarded-Client-Cert")
	fs.StringVar(&f.opts.Meter.PlansFile, "plans", "", "API plan file (JSON, hot-reloaded); enables usage metering and quotas")
	fs.DurationVar(&f.opts.Meter.PlansInterval, "plans-interval", 0, "plan file poll interval (default 1s)")
	fs.StringVar(&f.opts.Meter.StateFile, "usage-state", "", "persist usage counters to FILE (atomic snapshots, reloaded at start)")
	fs.DurationVar(&f.opts.Meter.StateInterval, "usage-interval", 0, "usage snapshot period (default 30s)")
	fs.IntVar(&f.opts.Meter.MaxSeries, "usage-max-series", 0, "cap on distinct usage counters before folding into _overflow (default 10000)")
	fs.IntVar(&f.opts.Meter.RetentionDays, "usage-retention-days", 0, "days of usage counters kept (default 100)")
	fs.StringVar(&f.opts.LearnFile, "learn", "", "learn the endpoint inventory and persist it to FILE")
	fs.IntVar(&f.opts.LearnMax, "learn-max", 0, "endpoints the learner keeps (default 5000)")
	fs.StringVar(&f.opts.ContractSpec, "contract-spec", "", "OpenAPI 3.x document requests are checked against")
	fs.StringVar(&f.opts.ContractEnforce, "contract-enforce", "", "monitor or block requests not in the contract spec (default off)")
	fs.StringVar(&f.opts.AI.PricesFile, "ai-prices", "", "JSON price table (per million tokens) for AI route cost estimates; re-read when it changes")
	fs.IntVar(&f.opts.AI.MaxKeyLabels, "ai-max-key-labels", 0, "most identities an AI route reports in /metrics, the rest are _other (default 500)")
	fs.StringVar(&f.uiAddr, "ui", "", "serve the read-only dashboard on ADDR")
	fs.StringVar(&f.uiToken, "ui-token", os.Getenv("SETURA_UI_TOKEN"), "bearer token for the dashboard")
}

func (f *runFlags) finish(stdout, stderr io.Writer, lint func([]byte) (bool, string)) (func(), error) {
	f.opts.PortMap = map[int]int{}
	for _, group := range f.portMap {
		for _, kv := range strings.Split(group, ",") {
			a, b, ok := strings.Cut(strings.TrimSpace(kv), "=")
			from, e1 := strconv.Atoi(a)
			to, e2 := strconv.Atoi(b)
			if !ok || e1 != nil || e2 != nil || from < 1 || to < 0 || to > 65535 {
				return nil, fmt.Errorf("--port-map %q: want SPEC=ACTUAL, for example 80=8080", kv)
			}
			f.opts.PortMap[from] = to
		}
	}
	if f.opts.ShadowDiff < 0 || f.opts.ShadowDiff > 100 {
		return nil, fmt.Errorf("--shadow-diff %d: want 0-100", f.opts.ShadowDiff)
	}
	switch {
	case f.outlier < 0: // unset
		f.opts.Resilience.OutlierFailures = 0
	case f.outlier == 0:
		f.opts.Resilience.OutlierFailures = -1
	default:
		f.opts.Resilience.OutlierFailures = f.outlier
	}
	if b := f.opts.Resilience.RetryBudgetPercent; b != 0 && (b < 1 || b > 100) {
		return nil, fmt.Errorf("--retry-budget %d: want 1-100", b)
	}
	if j := f.opts.Resilience.RetryJitter; j < 0 || j > 1 {
		return nil, fmt.Errorf("--retry-jitter %v: want 0-1", j)
	}
	if f.rotateSize != "" {
		n, err := ParseSize(f.rotateSize)
		if err != nil {
			return nil, fmt.Errorf("--access-log-max-size: %w", err)
		}
		f.rotate.MaxSize = n
	}
	if f.opts.AI.MaxKeyLabels < 0 {
		return nil, fmt.Errorf("--ai-max-key-labels %d: want 0 (default) or a positive count", f.opts.AI.MaxKeyLabels)
	}
	if p := f.opts.AI.PricesFile; p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("--ai-prices: %v", err)
		}
		if _, err := ParseAIPrices(raw); err != nil {
			return nil, fmt.Errorf("--ai-prices %s: %v (want {\"currency\":\"USD\",\"models\":{\"MODEL\":{\"input\":N,\"output\":N}}}, prices per million tokens)", p, err)
		}
	}
	if f.rotate.Keep < 0 {
		return nil, fmt.Errorf("--access-log-keep %d: want 0 or more", f.rotate.Keep)
	}
	if f.opts.LearnMax < 0 {
		return nil, fmt.Errorf("--learn-max %d: want 0 (default) or a positive count", f.opts.LearnMax)
	}
	switch f.opts.ContractEnforce {
	case "", ContractMonitor, ContractBlock:
	default:
		return nil, fmt.Errorf("--contract-enforce %q: want monitor or block", f.opts.ContractEnforce)
	}
	if f.opts.ContractEnforce != "" && f.opts.ContractSpec == "" {
		return nil, errors.New("--contract-enforce needs --contract-spec FILE")
	}
	if f.opts.ContractSpec != "" {
		if _, err := contract.LoadSpecFile(f.opts.ContractSpec); err != nil {
			return nil, fmt.Errorf("--contract-spec: %w", err)
		}
	}
	if f.connHist < 0 {
		return nil, fmt.Errorf("--conn-history %d: want 0 (off) or a positive count", f.connHist)
	}
	f.opts.ConnHistory = f.connHist
	if f.connHist == 0 {
		f.opts.ConnHistory = -1
	}
	if err := f.checkMeter(); err != nil {
		return nil, err
	}
	f.opts.Diag = stderr
	f.opts.Lint = lint
	san := []string(f.allowSAN)
	if len(san) == 0 {
		if env := os.Getenv("SETURA_CLIENT_ALLOW_SAN"); env != "" {
			san = []string{env}
		}
	}
	allow, err := ParseClientAllowFlags(san, f.allowCN)
	if err != nil {
		return nil, fmt.Errorf("--client-allow-san/--client-allow-cn: %w", err)
	}
	f.opts.ClientAllow, f.opts.ClientCertXFCC = allow, f.xfcc
	if err := f.cert.apply(&f.opts); err != nil {
		return nil, err
	}
	if err := f.limits.apply(&f.opts); err != nil {
		return nil, err
	}
	if err := f.shape.apply(&f.opts); err != nil {
		return nil, err
	}
	if err := f.obs.apply(&f.opts); err != nil {
		return nil, err
	}
	closeFn := func() {}
	switch f.accessLog {
	case "off", "":
	case "-":
		f.opts.AccessLog = stdout
	default:
		rf, err := newRotatingFile(f.accessLog, f.rotate)
		if err != nil {
			return nil, err
		}
		f.opts.AccessLog = rf
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		stopHup := make(chan struct{})
		go func() {
			for {
				select {
				case <-hup:
					if err := rf.Reopen(); err != nil {
						fmt.Fprintf(stderr, "access log: reopen on SIGHUP: %v\n", err)
					}
				case <-stopHup:
					return
				}
			}
		}()
		closeFn = func() { signal.Stop(hup); close(stopHup); rf.Close() }
	}
	return closeFn, nil
}

// Main runs "setura gateway ...". lint is the snapshot linter (nil disables
// the lint gate). It returns the process exit code: 0 ok, 2 usage or setup.
func Main(args []string, stdout, stderr io.Writer, lint func([]byte) (bool, string)) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("gateway "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fail := func(err error) int {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "setura gateway %s: %v\n", sub, err)
		return 2
	}
	var rf runFlags
	switch sub {
	case "run":
		cfgPath := fs.String("config", "", "snapshot file to serve")
		kube := fs.Bool("kubernetes", false, "run as an in-cluster controller")
		kopts := addKubeFlags(fs)
		addRunFlags(fs, &rf)
		if err := fs.Parse(rest); err != nil {
			return fail(err)
		}
		if fs.NArg() != 0 || (*cfgPath == "") == !*kube {
			return fail(errors.New("give exactly one of --config FILE or --kubernetes"))
		}
		closeLog, err := rf.finish(stdout, stderr, lint)
		if err != nil {
			return fail(err)
		}
		defer closeLog()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var src Source
		interval := rf.interval
		if *kube {
			if interval == 0 {
				interval = 5 * time.Second
			}
			kopts.ctl.portOffsetFn = func() (int, map[int]int) { return rf.opts.PortOffset, rf.opts.PortMap }
			ks, err := kopts.source(stderr)
			if err != nil {
				return fail(err)
			}
			src = ks
		} else {
			src = FileSource{*cfgPath}
		}
		if *cfgPath != "" {
			rf.opts.ConfigPath = *cfgPath
		}
		s := New(rf.opts)
		if err := s.startUIFlag(ctx, &rf, stderr); err != nil {
			return fail(err)
		}
		if err := s.Run(ctx, src, interval); err != nil {
			return fail(err)
		}
		return 0
	case "up":
		addRunFlags(fs, &rf)
		pos, err := parseInterleaved(fs, rest)
		if err != nil {
			return fail(err)
		}
		if len(pos) != 1 {
			return fail(errors.New("expected FILE"))
		}
		closeLog, err := rf.finish(stdout, stderr, lint)
		if err != nil {
			return fail(err)
		}
		defer closeLog()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := up(ctx, pos[0], rf.opts, rf.interval, stdout, stderr, &rf); err != nil {
			return fail(err)
		}
		return 0
	case "hash":
		return hashCmd(rest, os.Stdin, stdout, stderr)
	case "install":
		var io InstallOptions
		fs.StringVar(&io.Namespace, "namespace", "setura-system", "namespace for the controller")
		fs.StringVar(&io.Image, "image", "", "container image (default ghcr.io/zyvorai/zyvor-setura-gateway:VERSION)")
		fs.StringVar(&io.ClassName, "class", "setura", "GatewayClass name")
		fs.IntVar(&io.Replicas, "replicas", 1, "controller replicas")
		fs.BoolVar(&io.ExposePorts, "expose-gateway-ports", false, "run the controller with --expose-gateway-ports and grant it patch on its own Service")
		fs.BoolVar(&io.WithMonitoring, "with-monitoring", false, "also print an admin Service port, ServiceMonitor, PrometheusRule alerts and the Grafana dashboard ConfigMap")
		fs.StringVar(&io.ServiceType, "service-type", "", "Service type: ClusterIP (default), NodePort or LoadBalancer")
		fs.Func("node-port", "map Service ports to node ports, HTTP=30080,HTTPS=30443 or 7443=30743; repeatable (NodePort and LoadBalancer)", func(v string) (err error) {
			io.NodePorts, err = ParseNodePorts(v, io.NodePorts)
			return err
		})
		fs.Func("listener-port", "add a Service port for a Gateway listener port, for example 7443; repeatable", func(v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("want a port number")
			}
			io.ListenerPorts = append(io.ListenerPorts, n)
			return nil
		})
		fs.StringVar(&io.ExternalTrafficPolicy, "external-traffic-policy", "", "Service externalTrafficPolicy: Local (keeps client IPs) or Cluster")
		fs.BoolVar(&io.HostNetwork, "host-network", false, "run the pod on the node's network (binds node ports 8080, 8443 and the listener ports)")
		fs.Func("arg", "append one flag to the controller args, for example --arg --rate-limit=100; repeatable", func(v string) error {
			io.Args = append(io.Args, v)
			return nil
		})
		fs.Func("resources", "requests.cpu=100m,requests.memory=64Mi,limits.cpu=500m,limits.memory=256Mi (any subset)", func(v string) (err error) {
			io.Resources, err = ParseResources(v, io.Resources)
			return err
		})
		fs.Func("node-selector", "schedule the controller on nodes with these labels, KEY=VALUE[,KEY=VALUE]; repeatable", func(v string) (err error) {
			io.NodeSelector, err = ParseKeyValues("node-selector", v, io.NodeSelector)
			return err
		})
		fs.StringVar(&io.AdminTokenSecret, "admin-token-secret", "", "use this existing Secret (key token) for the admin token instead of printing one; re-applying then never rotates it")
		noAdmin := fs.Bool("no-admin-secret", false, "do not print the admin token Secret; create "+DefaultAdminSecret+" yourself (re-applying then never rotates the token)")
		fs.BoolVar(&io.CreateAdminSecret, "create-admin-secret", false, "print the admin token Secret even with --admin-token-secret (printed by default unless one of the two options above is given)")
		fs.BoolVar(&io.CRDs, "crds", false, "print the command that installs the Gateway API CRDs first")
		fs.StringVar(&io.GatewayAPIVersion, "gateway-api-version", "", "Gateway API release for --crds (default "+GatewayAPIVersion+")")
		fs.StringVar(&io.GatewayAPIChannel, "gateway-api-channel", "", "CRD channel for --crds: standard (default) or experimental (needed for TCPRoute and UDPRoute)")
		if _, err := parseInterleaved(fs, rest); err != nil {
			return fail(err)
		}
		explicit := false
		fs.Visit(func(fl *flag.Flag) {
			if fl.Name == "create-admin-secret" {
				explicit = true
			}
		})
		// Default: print the Secret as earlier versions did, so `setura gateway install | kubectl apply -f -`
		// starts the pod. Naming an existing Secret, or --no-admin-secret, opts out of a fresh token.
		if !explicit {
			io.CreateAdminSecret = io.AdminTokenSecret == "" && !*noAdmin
		}
		if err := io.Validate(); err != nil {
			return fail(err)
		}
		if !io.CreateAdminSecret {
			fmt.Fprintf(stderr, "setura: the admin token Secret %q is not printed; create it once (see the header of the output) or add --create-admin-secret\n", orDefault(io.AdminTokenSecret, DefaultAdminSecret))
		}
		fmt.Fprint(stdout, Install(io))
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// parseInterleaved lets flags and positionals mix, like the rest of Setura.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// Up serves a snapshot after starting an in-process demo upstream for every
// loopback backend endpoint that nothing is already listening on.
func Up(ctx context.Context, path string, opts Options, interval time.Duration, stdout, stderr io.Writer) error {
	return up(ctx, path, opts, interval, stdout, stderr, nil)
}

// startUIFlag starts the dashboard when --ui was given.
func (s *Server) startUIFlag(ctx context.Context, rf *runFlags, stderr io.Writer) error {
	if rf == nil || rf.uiAddr == "" {
		return nil
	}
	return s.StartUI(ctx, rf.uiAddr, rf.uiToken, stderr)
}

func up(ctx context.Context, path string, opts Options, interval time.Duration, stdout, stderr io.Writer, rf *runFlags) error {
	opts.ConfigPath = path
	src := FileSource{path}
	ld, err := src.Load(ctx)
	if err != nil {
		return err
	}
	var demos []*http.Server
	defer func() {
		for _, d := range demos {
			d.Close()
		}
	}()
	for _, key := range sortedKeys(ld.Config.Backends) {
		name := key[strings.Index(key, "/")+1:]
		if i := strings.LastIndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		for _, e := range ld.Config.Backends[key].Endpoints {
			u, err := parseEndpoint(e)
			if err != nil {
				return err
			}
			host, _, _ := net.SplitHostPort(u.Host)
			if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				continue
			}
			ln, err := net.Listen("tcp", u.Host)
			if err != nil {
				continue // something real is already there
			}
			srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: demoHandler(name)}
			demos = append(demos, srv)
			go srv.Serve(ln)
			fmt.Fprintf(stderr, "demo backend %-14s http://%s\n", name, u.Host)
		}
	}
	s := New(opts)
	if err := s.startUIFlag(ctx, rf, stderr); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, src, interval) }()
	for deadline := time.Now().Add(10 * time.Second); !s.Ready(); time.Sleep(10 * time.Millisecond) {
		select {
		case err := <-done:
			return err
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("gateway did not become ready")
		}
	}
	if cmd := demoHint(s); cmd != "" {
		fmt.Fprintf(stdout, "\ntry:\n  %s\n\nCtrl-C to stop.\n", cmd)
	}
	return <-done
}

func demoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s served %s %s (Host: %s)\n", name, r.Method, r.URL.RequestURI(), r.Host)
	})
}

// demoHint builds a ready-to-run explain command for the first route.
func demoHint(s *Server) string {
	t := s.Table()
	if t == nil || len(t.Cfg.Routes) == 0 {
		return ""
	}
	r := t.Cfg.Routes[0]
	host := "demo.test"
	if len(r.Hostnames) > 0 {
		host = strings.Replace(r.Hostnames[0], "*", "demo", 1)
	}
	path, backend := "/", ""
	if len(r.Rules) > 0 {
		if len(r.Rules[0].Matches) > 0 && r.Rules[0].Matches[0].Path != nil && r.Rules[0].Matches[0].Path.Value != "" {
			path = r.Rules[0].Matches[0].Path.Value
		}
		// Only suggest asserting a backend when exactly one can answer, so the
		// suggested command always passes (a canary split would fail ~10%).
		var live []string
		for _, b := range r.Rules[0].BackendRefs {
			if b.Weight == nil || *b.Weight > 0 {
				live = append(live, b.Name)
			}
		}
		if len(live) == 1 {
			backend = live[0]
		}
	}
	for _, l := range t.Listeners {
		if !l.Serving {
			continue
		}
		_, port, _ := net.SplitHostPort(s.Addr(l.L.Port))
		scheme := "http"
		if l.L.Protocol == "HTTPS" {
			scheme = "https"
		}
		cmd := fmt.Sprintf("setura explain %s://%s:%s%s --address 127.0.0.1", scheme, host, port, path)
		if backend != "" {
			cmd += " --backend " + backend
		}
		return cmd
	}
	return ""
}

// checkMeter validates the metering flags.
func (f *runFlags) checkMeter() error {
	m := &f.opts.Meter
	switch {
	case m.PlansFile == "" && (m.StateFile != "" || m.StateInterval != 0 || m.MaxSeries != 0 || m.RetentionDays != 0 || m.PlansInterval != 0):
		return errors.New("--usage-state, --usage-interval, --usage-max-series, --usage-retention-days and --plans-interval need --plans FILE")
	case m.PlansInterval < 0:
		return fmt.Errorf("--plans-interval %s: want a positive duration", m.PlansInterval)
	case m.StateInterval < 0:
		return fmt.Errorf("--usage-interval %s: want a positive duration", m.StateInterval)
	case m.MaxSeries < 0:
		return fmt.Errorf("--usage-max-series %d: want 1 or more", m.MaxSeries)
	case m.RetentionDays < 0:
		return fmt.Errorf("--usage-retention-days %d: want 1 or more", m.RetentionDays)
	}
	return nil
}
