package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// gRPC status codes used by retries.
var grpcCodeNames = map[string]int{
	"CANCELLED": 1, "UNKNOWN": 2, "INVALID_ARGUMENT": 3, "DEADLINE_EXCEEDED": 4, "NOT_FOUND": 5, "ALREADY_EXISTS": 6,
	"PERMISSION_DENIED": 7, "RESOURCE_EXHAUSTED": 8, "FAILED_PRECONDITION": 9, "ABORTED": 10, "OUT_OF_RANGE": 11,
	"UNIMPLEMENTED": 12, "INTERNAL": 13, "UNAVAILABLE": 14, "DATA_LOSS": 15, "UNAUTHENTICATED": 16,
}

// GRPCCode is a gRPC status code written as a number (0-16) or its name.
type GRPCCode int

// UnmarshalJSON accepts 14 or "UNAVAILABLE".
func (c *GRPCCode) UnmarshalJSON(raw []byte) error {
	var n int
	if json.Unmarshal(raw, &n) == nil {
		if n < 1 || n > 16 {
			return fmt.Errorf("gRPC status code %d is outside 1-16", n)
		}
		*c = GRPCCode(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("gRPC status code must be a number or a name")
	}
	n, ok := grpcCodeNames[strings.ToUpper(s)]
	if !ok {
		return fmt.Errorf("unknown gRPC status code %q", s)
	}
	*c = GRPCCode(n)
	return nil
}

// GRPCRetry is the retry block of a GRPCRoute rule. A call is retried only
// when the gateway can replay it (a unary call whose single message fits under
// the retry body limit) and the failure is a transport error or a
// Trailers-Only response carrying one of Codes (default UNAVAILABLE).
type GRPCRetry struct {
	Codes    []GRPCCode `json:"codes,omitempty"`
	Attempts *int       `json:"attempts,omitempty"`
	Backoff  string     `json:"backoff,omitempty"`
	Jitter   *float64   `json:"jitter,omitempty"`
}

// CGRPCRetry is a compiled GRPCRetry.
type CGRPCRetry struct {
	Codes    map[int]bool
	Attempts int
	Backoff  time.Duration
	Jitter   *float64
}

func compileGRPCRetry(r *GRPCRetry) (*CGRPCRetry, error) {
	c := &CGRPCRetry{Codes: map[int]bool{}, Attempts: defaultRetryTries, Backoff: defaultRetryBackoff, Jitter: r.Jitter}
	for _, code := range r.Codes {
		c.Codes[int(code)] = true
	}
	if len(c.Codes) == 0 {
		c.Codes[grpcUnavailable] = true
	}
	if r.Attempts != nil {
		if *r.Attempts < 0 || *r.Attempts > maxRetryAttempts {
			return nil, fmt.Errorf("retry.attempts: %d is outside 0-%d", *r.Attempts, maxRetryAttempts)
		}
		c.Attempts = *r.Attempts
	}
	if r.Backoff != "" {
		d, err := time.ParseDuration(r.Backoff)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("retry.backoff: %q is not a duration", r.Backoff)
		}
		c.Backoff = d
	}
	if r.Jitter != nil && (*r.Jitter < 0 || *r.Jitter > 1) {
		return nil, fmt.Errorf("retry.jitter: %v is outside 0-1", *r.Jitter)
	}
	return c, nil
}

// parseGRPCTimeout reads a grpc-timeout header value: up to 8 digits and a
// unit of H, M, S, m, u or n.
func parseGRPCTimeout(v string) (time.Duration, bool) {
	if len(v) < 2 || len(v) > 9 {
		return 0, false
	}
	n, err := strconv.ParseUint(v[:len(v)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	unit := map[byte]time.Duration{'H': time.Hour, 'M': time.Minute, 'S': time.Second, 'm': time.Millisecond, 'u': time.Microsecond, 'n': time.Nanosecond}[v[len(v)-1]]
	if unit == 0 {
		return 0, false
	}
	if n > uint64(1<<63-1)/uint64(unit) {
		return time.Duration(1<<63 - 1), true // a deadline this far away is no deadline
	}
	return time.Duration(n) * unit, true
}

// formatGRPCTimeout renders the time left as a grpc-timeout value (never
// zero or negative, so an expired deadline still reaches the backend as 1n).
func formatGRPCTimeout(d time.Duration) string {
	switch {
	case d >= time.Millisecond:
		ms := d.Milliseconds()
		if ms > 99999999 {
			ms = 99999999
		}
		return strconv.FormatInt(ms, 10) + "m"
	case d >= time.Microsecond:
		return strconv.FormatInt(d.Microseconds(), 10) + "u"
	}
	if d < 1 {
		d = 1
	}
	return strconv.FormatInt(int64(d), 10) + "n"
}

const unaryEOFWait = 50 * time.Millisecond

type peeked struct {
	b   byte
	n   int
	err error
}

// lateReader hands back the result of a read that was started to see whether
// the client had finished sending, then continues with the body.
type lateReader struct {
	ch   chan peeked
	body io.Reader
	done bool
}

func (l *lateReader) Read(p []byte) (int, error) {
	if !l.done {
		l.done = true
		r := <-l.ch
		if r.n > 0 && len(p) > 0 {
			p[0] = r.b
			return 1, nil
		}
		if r.err != nil {
			return 0, r.err
		}
	}
	return l.body.Read(p)
}

// bufferUnary reads a gRPC request body when it is a unary call that can be
// replayed: exactly one length-prefixed message no larger than limit bytes in
// total, with the client's end-of-stream already seen (within a short wait).
// Streaming calls, big messages and slow clients are never held up: the body
// stays readable as it was and ok is false.
func bufferUnary(r *http.Request, limit int64) (all []byte, ok bool) {
	orig := r.Body
	if orig == nil || orig == http.NoBody {
		return nil, false
	}
	restore := func(read []byte, tail io.Reader) {
		r.Body = replayBody{io.MultiReader(bytes.NewReader(read), tail), orig}
	}
	var hdr [5]byte
	if n, err := io.ReadFull(orig, hdr[:]); err != nil {
		restore(hdr[:n], errReader{err})
		return nil, false
	}
	size := int64(binary.BigEndian.Uint32(hdr[1:]))
	if size+5 > limit {
		restore(hdr[:], orig)
		return nil, false
	}
	buf := make([]byte, 5+size)
	copy(buf, hdr[:])
	if n, err := io.ReadFull(orig, buf[5:]); err != nil {
		restore(buf[:5+n], errReader{err})
		return nil, false
	}
	ch := make(chan peeked, 1)
	go func() {
		var one [1]byte
		n, err := orig.Read(one[:])
		ch <- peeked{one[0], n, err}
	}()
	select {
	case res := <-ch:
		switch {
		case res.n == 0 && errors.Is(res.err, io.EOF):
			r.Body = replayBody{bytes.NewReader(buf), orig}
			return buf, true
		case res.n > 0:
			restore(append(buf, res.b), orig)
		default:
			restore(buf, errReader{res.err})
		}
	case <-time.After(unaryEOFWait):
		restore(buf, &lateReader{ch: ch, body: orig})
	}
	return nil, false
}

// grpcTransport is the RoundTripper of one gRPC call. It reports outcomes to
// outlier detection and retries replayable calls.
type grpcTransport struct {
	s     *Server
	b     *Backend
	first *Endpoint
	retry *CGRPCRetry

	replay    []byte
	canReplay bool
	tried     map[*Endpoint]bool
	retries   int
}

func trailersOnly(resp *http.Response) (code int, ok bool) {
	v := resp.Header.Get("Grpc-Status")
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

func (t *grpcTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rs := t.s.res
	ctx := req.Context()
	var bud *budget
	if t.retry != nil {
		bud = rs.budgetFor(t.b.Key)
		bud.request(rs.now())
	}
	for attempt := 0; ; attempt++ {
		ep := t.first
		if attempt > 0 || ep == nil {
			ep = t.b.choose(rs.now(), t.tried)
		}
		t.tried[ep] = true
		out := req.Clone(ctx)
		out.URL.Scheme, out.URL.Host = ep.URL.Scheme, ep.URL.Host
		if t.retry != nil && t.canReplay {
			out.Body = io.NopCloser(bytes.NewReader(t.replay))
		}
		tr := t.s.grpcTr.get(ep.URL.Scheme, t.b.Insecure)
		resp, err := tr.RoundTrip(out)
		cancelled := err != nil && ctx.Err() != nil
		code, tonly := -1, false
		if err == nil {
			code, tonly = trailersOnly(resp)
		}
		if !cancelled {
			rs.observe(t.b, ep, err != nil || resp.StatusCode >= 500 || (tonly && code == grpcUnavailable), rs.now())
		}
		if t.retry == nil || !t.canReplay || cancelled || attempt >= t.retry.Attempts {
			return resp, err
		}
		retryable := false
		switch {
		case err != nil:
			retryable = t.retry.Codes[grpcUnavailable] // a transport failure is UNAVAILABLE
		case tonly:
			retryable = t.retry.Codes[code]
		}
		if !retryable {
			return resp, err
		}
		wait := t.retry.Backoff
		if j := t.retry.Jitter; j == nil && rs.opt().RetryJitter > 0 || j != nil && *j > 0 {
			f := rs.opt().RetryJitter
			if j != nil {
				f = *j
			}
			wait = time.Duration(float64(wait) * (1 + f*(2*float64(t.s.intn(1001))/1000-1)))
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= wait {
			return resp, err
		}
		if !bud.tryRetry(rs.now(), rs.opt().RetryBudgetPercent, rs.opt().RetryBudgetMin) {
			rs.bump(rs.denied, t.b.Key)
			return resp, err
		}
		if wait > 0 && rs.sleep(ctx, wait) != nil {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
		t.retries++
		rs.bump(rs.retries, t.b.Key)
	}
}

// fireGRPCMirrors sends fire-and-forget copies of a buffered unary call.
func (s *Server) fireGRPCMirrors(out *http.Request, body []byte, mirrors []*CMirror) {
	for _, m := range mirrors {
		if m.Percent <= 0 || (m.Percent < 100 && s.intn(100) >= m.Percent) {
			continue
		}
		ep := m.B.pick()
		if ep == nil {
			continue
		}
		u := *out.URL
		u.Scheme, u.Host = ep.URL.Scheme, ep.URL.Host
		req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header = out.Header.Clone()
		req.Header.Set("X-Setura-Mirror", "1")
		req.Host = out.Host
		tr := s.grpcTr.get(ep.URL.Scheme, m.B.Insecure)
		s.mirrorWG.Add(1)
		go func() {
			defer s.mirrorWG.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if resp, err := (&http.Client{Transport: tr}).Do(req.WithContext(ctx)); err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
			}
		}()
	}
}

// grpcHealthPath is the grpc.health.v1 check method.
const grpcHealthPath = "/grpc.health.v1.Health/Check"

func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// encodeHealthRequest is HealthCheckRequest{service=1} in a gRPC message frame.
func encodeHealthRequest(service string) []byte {
	var msg []byte
	if service != "" {
		msg = append(msg, 0x0a)
		msg = pbVarint(msg, uint64(len(service)))
		msg = append(msg, service...)
	}
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg)))
	return append(frame, msg...)
}

// decodeHealthStatus reads HealthCheckResponse{status=1} from one frame.
func decodeHealthStatus(body []byte) (int, error) {
	if len(body) < 5 || body[0] != 0 {
		return 0, errors.New("no usable gRPC frame")
	}
	n := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body)-5 < n {
		return 0, errors.New("truncated gRPC message")
	}
	msg, status := body[5:5+n], 0
	for len(msg) > 0 {
		tag, k := binary.Uvarint(msg)
		if k <= 0 {
			return 0, errors.New("malformed protobuf")
		}
		msg = msg[k:]
		switch tag & 7 {
		case 0:
			v, k := binary.Uvarint(msg)
			if k <= 0 {
				return 0, errors.New("malformed protobuf")
			}
			msg = msg[k:]
			if tag>>3 == 1 {
				status = int(v)
			}
		case 2:
			l, k := binary.Uvarint(msg)
			if k <= 0 || uint64(len(msg)-k) < l {
				return 0, errors.New("malformed protobuf")
			}
			msg = msg[k+int(l):]
		default:
			return 0, errors.New("unsupported protobuf wire type")
		}
	}
	return status, nil
}

// grpcHealthProbe calls grpc.health.v1.Health/Check on one endpoint; it is
// healthy only when the call succeeds and the answer is SERVING.
func (s *Server) grpcHealthProbe(ctx context.Context, c *healthConfig, b *Backend, ep *Endpoint) bool {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL.String()+grpcHealthPath, bytes.NewReader(encodeHealthRequest(c.service)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := (&http.Client{Transport: s.grpcTr.get(ep.URL.Scheme, b.Insecure)}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	st := resp.Header.Get("Grpc-Status")
	if st == "" {
		st = resp.Trailer.Get("Grpc-Status")
	}
	if st != "0" {
		return false
	}
	status, err := decodeHealthStatus(body)
	return err == nil && status == 1 // SERVING
}
