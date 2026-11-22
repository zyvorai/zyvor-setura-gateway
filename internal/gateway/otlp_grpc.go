package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// OTLP over gRPC, written by hand: protobuf encoding of the trace and logs
// export services, and the gRPC framing over the standard library's HTTP/2
// transport (h2c for http:// endpoints, ALPN h2 for https://). No generated
// code and no gRPC library.

const (
	otlpTracePath = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
	otlpLogsPath  = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
)

// protobuf wire helpers. Field numbers come from opentelemetry-proto v1.

func pbv(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbTag(b []byte, field, wire int) []byte { return pbv(b, uint64(field<<3|wire)) }

func pbLen(b []byte, field int, v []byte) []byte {
	b = pbTag(b, field, 2)
	b = pbv(b, uint64(len(v)))
	return append(b, v...)
}

func pbStr(b []byte, field int, v string) []byte {
	if v == "" {
		return b
	}
	return pbLen(b, field, []byte(v))
}

func pbInt(b []byte, field int, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = pbTag(b, field, 0)
	return pbv(b, v)
}

func pbFixed64(b []byte, field int, v uint64) []byte {
	b = pbTag(b, field, 1)
	return binary.LittleEndian.AppendUint64(b, v)
}

func pbFixed32(b []byte, field int, v uint32) []byte {
	b = pbTag(b, field, 5)
	return binary.LittleEndian.AppendUint32(b, v)
}

func pbMsg(b []byte, field int, m []byte) []byte { return pbLen(b, field, m) }

// pbKVString and pbKVInt encode a KeyValue with a string or int64 AnyValue.
func pbKVString(k, v string) []byte {
	var any []byte
	any = pbLen(any, 1, []byte(v)) // string_value, written even when empty
	return pbLen(pbStr(nil, 1, k), 2, any)
}

func pbKVInt(k string, v int64) []byte {
	var any []byte
	any = pbTag(any, 3, 0) // int_value
	any = pbv(any, uint64(v))
	return pbLen(pbStr(nil, 1, k), 2, any)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func pbResource(service string) []byte {
	return pbMsg(nil, 1, pbKVString("service.name", service))
}

// encodeOTLPProto renders an ExportTraceServiceRequest.
func encodeOTLPProto(batch []span) []byte {
	var spans []byte
	for _, sp := range batch {
		var m []byte
		m = pbLen(m, 1, unhex(sp.trace.TraceID))
		m = pbLen(m, 2, unhex(sp.trace.SpanID))
		m = pbStr(m, 3, sp.trace.State)
		if sp.trace.ParentID != "" {
			m = pbLen(m, 4, unhex(sp.trace.ParentID))
		}
		m = pbStr(m, 5, sp.name)
		m = pbInt(m, 6, 2) // SPAN_KIND_SERVER
		m = pbFixed64(m, 7, uint64(sp.start.UnixNano()))
		m = pbFixed64(m, 8, uint64(sp.end.UnixNano()))
		m = pbMsg(m, 9, pbKVString("http.request.method", sp.method))
		m = pbMsg(m, 9, pbKVString("url.path", sp.path))
		m = pbMsg(m, 9, pbKVString("server.address", sp.host))
		m = pbMsg(m, 9, pbKVInt("http.response.status_code", int64(sp.status)))
		m = pbMsg(m, 9, pbKVString("setura.request_id", sp.reqID))
		if sp.route != "" {
			m = pbMsg(m, 9, pbKVString("setura.route", sp.route))
		}
		if sp.backend != "" {
			m = pbMsg(m, 9, pbKVString("setura.backend", sp.backend))
		}
		if sp.status >= 500 {
			var st []byte
			st = pbStr(st, 2, sp.err)
			st = pbInt(st, 3, 2) // STATUS_CODE_ERROR
			m = pbMsg(m, 15, st)
		}
		spans = pbMsg(spans, 2, m)
	}
	scope := pbStr(nil, 1, "setura/gateway")
	var ss []byte
	ss = pbMsg(ss, 1, scope)
	ss = append(ss, spans...)
	var rs []byte
	rs = pbMsg(rs, 1, pbResource("setura-gateway"))
	rs = pbMsg(rs, 2, ss)
	return pbMsg(nil, 1, rs)
}

// otlpGRPCFrame wraps one message in the 5 byte gRPC length prefix.
func otlpGRPCFrame(msg []byte) []byte {
	f := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(f[1:], uint32(len(msg)))
	return append(f, msg...)
}

// grpcClient returns an HTTP client that speaks HTTP/2 to url: prior-knowledge
// h2c for http://, TLS with ALPN h2 for https://.
func grpcClient(url string, timeout time.Duration) *http.Client {
	var p http.Protocols
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		IdleConnTimeout: 90 * time.Second, MaxIdleConns: 4}
	if strings.HasPrefix(url, "https://") {
		p.SetHTTP2(true)
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	} else {
		p.SetUnencryptedHTTP2(true)
	}
	tr.Protocols = &p
	return &http.Client{Transport: tr, Timeout: timeout}
}

// grpc status codes that are worth another attempt.
func grpcRetryable(code int) bool {
	switch code {
	case 4, 8, 10, 14: // DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED, ABORTED, UNAVAILABLE
		return true
	}
	return false
}

// grpcExport sends one unary Export call. A nil error means grpc-status OK.
func grpcExport(c *http.Client, url string, msg []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(otlpGRPCFrame(msg)))
	if err != nil {
		return &sinkErr{err: err}
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", "zyvor-setura-gateway")
	resp, err := c.Do(req)
	if err != nil {
		return &sinkErr{err: err, retry: true}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) // trailers arrive after the body
	if resp.StatusCode != http.StatusOK {
		se := &sinkErr{err: fmt.Errorf("HTTP %d", resp.StatusCode)}
		if c := resp.StatusCode; c == 429 || c == 502 || c == 503 || c == 504 {
			se.retry = true
		}
		return se
	}
	gs := resp.Trailer.Get("Grpc-Status")
	if gs == "" {
		gs = resp.Header.Get("Grpc-Status") // trailers-only response
	}
	if gs == "" {
		return &sinkErr{err: errors.New("response has no grpc-status"), retry: true}
	}
	code, err := strconv.Atoi(gs)
	if err != nil {
		return &sinkErr{err: fmt.Errorf("invalid grpc-status %q", gs)}
	}
	if code == 0 {
		return nil
	}
	msgText := resp.Trailer.Get("Grpc-Message")
	if msgText == "" {
		msgText = resp.Header.Get("Grpc-Message")
	}
	return &sinkErr{err: fmt.Errorf("grpc-status %d %s", code, msgText), retry: grpcRetryable(code)}
}

// tryGRPC is otlpExporter.try for the gRPC protocol.
func (x *otlpExporter) tryGRPC(payload []byte) (retryAfter time.Duration, retryable bool) {
	err := grpcExport(x.client, x.url, payload)
	if err == nil {
		return -1, false
	}
	var se *sinkErr
	return 0, errors.As(err, &se) && se.retry
}

// encodeLogsProto renders an ExportLogsServiceRequest for access log lines.
func encodeLogsProto(batch []logLine) []byte {
	var recs []byte
	for i := range batch {
		l := &batch[i]
		t := lineTime(l)
		sev, text := lineSeverity(l)
		var m []byte
		m = pbFixed64(m, 1, uint64(t.UnixNano()))
		m = pbInt(m, 2, uint64(sev))
		m = pbStr(m, 3, text)
		m = pbMsg(m, 5, pbLen(nil, 1, lineJSON(l))) // body: AnyValue{string_value}
		for _, a := range lineAttrs(l) {
			if a.isInt {
				m = pbMsg(m, 6, pbKVInt(a.k, a.n))
			} else {
				m = pbMsg(m, 6, pbKVString(a.k, a.s))
			}
		}
		if l.TraceID != "" {
			m = pbFixed32(m, 8, 1)
			m = pbLen(m, 9, unhex(l.TraceID))
			if l.SpanID != "" {
				m = pbLen(m, 10, unhex(l.SpanID))
			}
		}
		recs = pbMsg(recs, 2, m)
	}
	var sl []byte
	sl = pbMsg(sl, 1, pbStr(nil, 1, "setura/gateway"))
	sl = append(sl, recs...)
	var rl []byte
	rl = pbMsg(rl, 1, pbResource("setura-gateway"))
	rl = pbMsg(rl, 2, sl)
	return pbMsg(nil, 1, rl)
}
