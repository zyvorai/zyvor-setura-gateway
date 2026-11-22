package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Log sinks ship the access log to syslog (RFC 5424), Loki and an OTLP logs
// collector. Each sink owns a bounded queue and a goroutine: a request only
// copies its log line into the queue (or counts a drop when it is full) and
// never waits for the network. Failed batches are retried with exponential
// backoff and jitter, then dropped and counted.

const (
	defaultSinkQueue   = 8192
	defaultSinkBatch   = 256
	defaultSinkRetries = 4
	defaultSinkBackoff = 250 * time.Millisecond
	maxSinkBackoff     = 10 * time.Second
	defaultSinkTick    = time.Second
)

// SinkOptions tunes every log sink; zero values give the defaults.
type SinkOptions struct {
	Queue    int           // log lines buffered per sink before dropping (default 8192)
	Batch    int           // lines per delivery (default 256)
	Interval time.Duration // longest wait before a partial batch is sent (default 1s)
	Retries  int           // retries of a failed batch (default 4; negative disables)
	Backoff  time.Duration // first retry wait, doubling up to 10s (default 250ms)

	// After replaces time.After for retry waits (tests).
	After func(time.Duration) <-chan time.Time
}

// LogSinkOptions selects the sinks. Empty fields disable a sink.
type LogSinkOptions struct {
	Syslog       string            // udp://host:514, tcp://host:514, unix:///dev/log or unixgram:///dev/log
	LokiURL      string            // Loki base URL or full push URL
	LokiLabels   map[string]string // static stream labels (default job=setura-gateway)
	LokiTenant   string            // X-Scope-OrgID
	OTLPLogs     string            // OTLP collector for logs (host:port or URL)
	OTLPProtocol string            // "http" (default) or "grpc"
	Sink         SinkOptions
}

func (o LogSinkOptions) any() bool { return o.Syslog != "" || o.LokiURL != "" || o.OTLPLogs != "" }

// sinkErr classifies a delivery failure.
type sinkErr struct {
	err   error
	retry bool
	after time.Duration
}

func (e *sinkErr) Error() string { return e.err.Error() }
func (e *sinkErr) Unwrap() error { return e.err }

// sendFn delivers batch and returns how many leading lines were accepted.
type sendFn func(batch []logLine) (int, error)

type batchSink struct {
	name  string
	o     SinkOptions
	send  sendFn
	onEnd func()

	ch      chan logLine
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once

	sent, dropped, failures, retries atomic.Int64
}

func newBatchSink(name string, o SinkOptions, send sendFn, onEnd func()) *batchSink {
	if o.Queue <= 0 {
		o.Queue = defaultSinkQueue
	}
	if o.Batch <= 0 {
		o.Batch = defaultSinkBatch
	}
	if o.Interval <= 0 {
		o.Interval = defaultSinkTick
	}
	if o.Retries == 0 {
		o.Retries = defaultSinkRetries
	}
	if o.Backoff <= 0 {
		o.Backoff = defaultSinkBackoff
	}
	if o.After == nil {
		o.After = time.After
	}
	k := &batchSink{name: name, o: o, send: send, onEnd: onEnd, ch: make(chan logLine, o.Queue),
		done: make(chan struct{}), stopped: make(chan struct{})}
	go k.run()
	return k
}

// offer queues a copy of the line. It never blocks.
func (k *batchSink) offer(l *logLine) {
	select {
	case k.ch <- *l:
	default:
		k.dropped.Add(1)
	}
}

func (k *batchSink) run() {
	defer close(k.stopped)
	if k.onEnd != nil {
		defer k.onEnd()
	}
	tk := time.NewTicker(k.o.Interval)
	defer tk.Stop()
	var batch []logLine
	flush := func() {
		if len(batch) > 0 {
			k.deliver(batch)
			batch = nil
		}
	}
	for {
		select {
		case l := <-k.ch:
			batch = append(batch, l)
			if len(batch) >= k.o.Batch {
				flush()
			}
		case <-tk.C:
			flush()
		case <-k.done:
			for {
				select {
				case l := <-k.ch:
					batch = append(batch, l)
					if len(batch) >= k.o.Batch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (k *batchSink) closing() bool {
	select {
	case <-k.done:
		return true
	default:
		return false
	}
}

func (k *batchSink) deliver(batch []logLine) {
	wait := k.o.Backoff
	for attempt := 0; ; attempt++ {
		n, err := k.send(batch)
		if n > len(batch) {
			n = len(batch)
		}
		k.sent.Add(int64(n))
		batch = batch[n:]
		if err == nil || len(batch) == 0 {
			return
		}
		k.failures.Add(1)
		var se *sinkErr
		retry, after := true, time.Duration(0)
		if errors.As(err, &se) {
			retry, after = se.retry, se.after
		}
		if !retry || k.o.Retries < 0 || attempt >= k.o.Retries || k.closing() {
			k.dropped.Add(int64(len(batch)))
			return
		}
		d := wait
		if after > 0 {
			d = after
		}
		d += time.Duration(randIntn(int(d/4) + 1))
		if d > maxSinkBackoff {
			d = maxSinkBackoff
		}
		select {
		case <-k.o.After(d):
		case <-k.done:
			k.dropped.Add(int64(len(batch)))
			return
		}
		k.retries.Add(1)
		if wait *= 2; wait > maxSinkBackoff {
			wait = maxSinkBackoff
		}
	}
}

func (k *batchSink) close() {
	k.once.Do(func() { close(k.done) })
	<-k.stopped
}

// newLogSinks builds the sinks selected in o. A bad address is an error so
// the gateway refuses to start instead of silently logging nowhere.
func newLogSinks(o LogSinkOptions) ([]*batchSink, error) {
	var out []*batchSink
	if o.Syslog != "" {
		k, err := newSyslogSink(o.Syslog, o.Sink)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if o.LokiURL != "" {
		k, err := newLokiSink(o.LokiURL, o.LokiLabels, o.LokiTenant, o.Sink)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if o.OTLPLogs != "" {
		k, err := newOTLPLogsSink(o.OTLPLogs, o.OTLPProtocol, o.Sink)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// writeSinkMetrics emits the per-sink series.
func (x *obs) writeSinkMetrics(w io.Writer, head func(name, typ, help string)) {
	row := func(name, typ, help string, v func(*batchSink) int64) {
		head(name, typ, help)
		for _, k := range x.sinks {
			fmt.Fprintf(w, "%s{sink=\"%s\"} %d\n", name, k.name, v(k))
		}
	}
	row("setura_gateway_logsink_sent_total", "counter", "Log lines delivered to the sink.", func(k *batchSink) int64 { return k.sent.Load() })
	row("setura_gateway_logsink_dropped_total", "counter", "Log lines dropped by the sink (queue full or retries exhausted).", func(k *batchSink) int64 { return k.dropped.Load() })
	row("setura_gateway_logsink_failures_total", "counter", "Failed delivery attempts of the sink (each retry that fails counts).", func(k *batchSink) int64 { return k.failures.Load() })
	row("setura_gateway_logsink_retries_total", "counter", "Delivery retries performed by the sink.", func(k *batchSink) int64 { return k.retries.Load() })
	row("setura_gateway_logsink_queue_length", "gauge", "Log lines waiting in the sink's bounded queue.", func(k *batchSink) int64 { return int64(len(k.ch)) })
}

// ---- shared line helpers ----

func lineTime(l *logLine) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, l.Time); err == nil {
		return t
	}
	return time.Now()
}

// lineSeverity maps the status to an OTLP severity number and text.
func lineSeverity(l *logLine) (int, string) {
	switch {
	case l.Status >= 500:
		return 17, "ERROR"
	case l.Status >= 400:
		return 13, "WARN"
	}
	return 9, "INFO"
}

func lineJSON(l *logLine) []byte {
	b, _ := json.Marshal(l)
	return b
}

type lineAttr struct {
	k     string
	s     string
	n     int64
	isInt bool
}

func lineAttrs(l *logLine) []lineAttr {
	a := []lineAttr{{k: "http.request.method", s: l.Method}, {k: "http.response.status_code", n: int64(l.Status), isInt: true},
		{k: "url.path", s: l.Path}, {k: "server.address", s: l.Host}}
	for _, kv := range [][2]string{{"setura.route", l.Route}, {"setura.backend", l.Backend}, {"setura.request_id", l.RequestID}, {"client.address", l.ClientIP}} {
		if kv[1] != "" {
			a = append(a, lineAttr{k: kv[0], s: kv[1]})
		}
	}
	return a
}

// classifyHTTP turns an HTTP status into a sinkErr (nil for 2xx).
func classifyHTTP(resp *http.Response) error {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	c := resp.StatusCode
	if c/100 == 2 {
		return nil
	}
	se := &sinkErr{err: fmt.Errorf("HTTP %d", c)}
	if c == 429 || c == 502 || c == 503 || c == 504 {
		se.retry = true
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			se.after = time.Duration(n) * time.Second
		}
	}
	return se
}

func sinkPost(c *http.Client, url, ctype string, hdr map[string]string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return &sinkErr{err: err}
	}
	req.Header.Set("Content-Type", ctype)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return &sinkErr{err: err, retry: true}
	}
	return classifyHTTP(resp)
}

// ---- Loki ----

// lokiURL appends /loki/api/v1/push when the URL has no path.
func lokiURL(u string) (string, error) {
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	pu, err := url.Parse(u)
	if err != nil || pu.Host == "" {
		return "", fmt.Errorf("--loki-url %q: want http(s)://HOST:PORT[/loki/api/v1/push]", u)
	}
	if pu.Path == "" || pu.Path == "/" {
		pu.Path = "/loki/api/v1/push"
	}
	return pu.String(), nil
}

// encodeLoki renders a Loki push request: one stream per label set (the
// static labels plus level), each value [unix nanoseconds, line].
func encodeLoki(batch []logLine, static map[string]string) []byte {
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	by := map[string]*stream{}
	var order []string
	for i := range batch {
		l := &batch[i]
		_, lvl := lineSeverity(l)
		lbl := map[string]string{"level": strings.ToLower(lvl)}
		for k, v := range static {
			lbl[k] = v
		}
		key := lbl["level"]
		st := by[key]
		if st == nil {
			st = &stream{Stream: lbl}
			by[key] = st
			order = append(order, key)
		}
		st.Values = append(st.Values, [2]string{strconv.FormatInt(lineTime(l).UnixNano(), 10), string(lineJSON(l))})
	}
	sort.Strings(order)
	out := struct {
		Streams []*stream `json:"streams"`
	}{Streams: []*stream{}}
	for _, k := range order {
		out.Streams = append(out.Streams, by[k])
	}
	b, _ := json.Marshal(out)
	return b
}

func newLokiSink(raw string, labels map[string]string, tenant string, o SinkOptions) (*batchSink, error) {
	u, err := lokiURL(raw)
	if err != nil {
		return nil, err
	}
	if len(labels) == 0 {
		labels = map[string]string{"job": "setura-gateway"}
	}
	hdr := map[string]string{}
	if tenant != "" {
		hdr["X-Scope-OrgID"] = tenant
	}
	c := &http.Client{Timeout: 5 * time.Second}
	return newBatchSink("loki", o, func(batch []logLine) (int, error) {
		if err := sinkPost(c, u, "application/json", hdr, encodeLoki(batch, labels)); err != nil {
			return 0, err
		}
		return len(batch), nil
	}, c.CloseIdleConnections), nil
}

// ParseLabels parses "k=v,k=v" into a label map.
func ParseLabels(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("label %q: want name=value", p)
		}
		out[k] = v
	}
	return out, nil
}

// ---- OTLP logs ----

func jsonAttr(a lineAttr) string {
	if a.isInt {
		return attrI(a.k, int(a.n))
	}
	return attrS(a.k, a.s)
}

// encodeOTLPLogsJSON renders an ExportLogsServiceRequest in OTLP/JSON.
func encodeOTLPLogsJSON(batch []logLine) []byte {
	var b strings.Builder
	b.WriteString(`{"resourceLogs":[{"resource":{"attributes":[` + attrS("service.name", "setura-gateway") + `]},` +
		`"scopeLogs":[{"scope":{"name":"setura/gateway"},"logRecords":[`)
	for i := range batch {
		l := &batch[i]
		if i > 0 {
			b.WriteByte(',')
		}
		sev, text := lineSeverity(l)
		var attrs []string
		for _, a := range lineAttrs(l) {
			attrs = append(attrs, jsonAttr(a))
		}
		b.WriteString(`{"timeUnixNano":"` + strconv.FormatInt(lineTime(l).UnixNano(), 10) + `","severityNumber":` + strconv.Itoa(sev) +
			`,"severityText":` + jstr(text) + `,"body":{"stringValue":` + jstr(string(lineJSON(l))) + `},"attributes":[` + strings.Join(attrs, ",") + `]`)
		if l.TraceID != "" {
			b.WriteString(`,"traceId":` + jstr(l.TraceID))
			if l.SpanID != "" {
				b.WriteString(`,"spanId":` + jstr(l.SpanID))
			}
		}
		b.WriteByte('}')
	}
	b.WriteString(`]}]}]}`)
	return []byte(b.String())
}

func newOTLPLogsSink(endpoint, proto string, o SinkOptions) (*batchSink, error) {
	switch proto {
	case "", "http":
		if !strings.Contains(endpoint, "://") {
			endpoint = "http://" + endpoint
		}
		if i := strings.Index(endpoint, "://"); !strings.Contains(endpoint[i+3:], "/") {
			endpoint += "/v1/logs"
		}
		c := &http.Client{Timeout: 5 * time.Second}
		return newBatchSink("otlp_logs", o, func(batch []logLine) (int, error) {
			if err := sinkPost(c, endpoint, "application/json", nil, encodeOTLPLogsJSON(batch)); err != nil {
				return 0, err
			}
			return len(batch), nil
		}, c.CloseIdleConnections), nil
	case "grpc":
		u := otlpGRPCURL(endpoint, otlpLogsPath)
		c := grpcClient(u, 5*time.Second)
		return newBatchSink("otlp_logs", o, func(batch []logLine) (int, error) {
			if err := grpcExport(c, u, encodeLogsProto(batch)); err != nil {
				return 0, err
			}
			return len(batch), nil
		}, c.CloseIdleConnections), nil
	}
	return nil, fmt.Errorf("--otlp-protocol %q: want http or grpc", proto)
}

// ---- syslog (RFC 5424) ----

// parseSyslogAddr splits udp://h:p, tcp://h:p, unix://path, unixgram://path;
// a bare host:port means UDP.
func parseSyslogAddr(a string) (network, address string, err error) {
	if !strings.Contains(a, "://") {
		a = "udp://" + a
	}
	scheme, rest, _ := strings.Cut(a, "://")
	switch scheme {
	case "udp", "tcp":
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return "", "", fmt.Errorf("--syslog %q: want %s://HOST:PORT", a, scheme)
		}
		return scheme, rest, nil
	case "unix", "unixgram":
		if rest == "" {
			return "", "", fmt.Errorf("--syslog %q: want %s:///path", a, scheme)
		}
		return scheme, rest, nil
	}
	return "", "", fmt.Errorf("--syslog %q: scheme must be udp, tcp, unix or unixgram", a)
}

const (
	syslogFacilityLocal0 = 16
	syslogTimeFormat     = "2006-01-02T15:04:05.000000Z07:00"
)

func syslogSeverity(status int) int {
	switch {
	case status >= 500:
		return 3 // err
	case status >= 400:
		return 4 // warning
	}
	return 6 // info
}

// syslogField makes s a valid RFC 5424 header field: printable ASCII without
// spaces, at most max bytes, "-" when empty.
func syslogField(s string, max int) string {
	var b []byte
	for i := 0; i < len(s) && len(b) < max; i++ {
		if c := s[i]; c > 32 && c < 127 {
			b = append(b, c)
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

// syslogMessage formats one access line as an RFC 5424 message. The MSG part
// is the logfmt text form of the line.
func syslogMessage(l *logLine, host string, pid int) []byte {
	pri := syslogFacilityLocal0*8 + syslogSeverity(l.Status)
	msg := bytes.TrimRight(l.text(), "\n")
	hdr := fmt.Sprintf("<%d>1 %s %s setura-gateway %d ACCESS - ", pri, lineTime(l).UTC().Format(syslogTimeFormat),
		syslogField(host, 255), pid)
	return append([]byte(hdr), msg...)
}

func newSyslogSink(addr string, o SinkOptions) (*batchSink, error) {
	network, address, err := parseSyslogAddr(addr)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	pid := os.Getpid()
	stream := network == "tcp" || network == "unix"
	var conn net.Conn
	drop := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	send := func(batch []logLine) (int, error) {
		if conn == nil {
			c, err := net.DialTimeout(network, address, 3*time.Second)
			if err != nil {
				return 0, &sinkErr{err: err, retry: true}
			}
			conn = c
		}
		for i := range batch {
			m := syslogMessage(&batch[i], host, pid)
			if stream { // RFC 6587 octet counting
				m = append([]byte(strconv.Itoa(len(m))+" "), m...)
			}
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write(m); err != nil {
				drop()
				return i, &sinkErr{err: err, retry: true}
			}
		}
		return len(batch), nil
	}
	return newBatchSink("syslog", o, send, drop), nil
}
