package setura

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// grpcDialHost maps the target host to the address actually dialed; tests
// replace it. SNI and certificate verification always use the original host.
var grpcDialHost = func(h string) string { return h }

const healthPath = "/grpc.health.v1.Health/Check"

var servingNames = map[int]string{0: "UNKNOWN", 1: "SERVING", 2: "NOT_SERVING", 3: "SERVICE_UNKNOWN"}

// pbVarint appends a protobuf varint.
func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// encodeHealthRequest encodes grpc.health.v1.HealthCheckRequest{service=1}
// inside a gRPC length-prefixed message frame.
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

// decodeHealthResponse reads one gRPC frame holding
// grpc.health.v1.HealthCheckResponse{status=1} and returns the status enum.
func decodeHealthResponse(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, errors.New("empty gRPC response body")
	}
	if len(body) < 5 {
		return 0, errors.New("truncated gRPC frame header")
	}
	if body[0] != 0 {
		return 0, errors.New("compressed gRPC responses are not supported")
	}
	n := int(binary.BigEndian.Uint32(body[1:5]))
	if n < 0 || len(body)-5 < n {
		return 0, errors.New("truncated gRPC message")
	}
	msg, status := body[5:5+n], 0
	for len(msg) > 0 {
		tag, k := binary.Uvarint(msg)
		if k <= 0 {
			return 0, errors.New("malformed protobuf tag")
		}
		msg = msg[k:]
		switch tag & 7 {
		case 0:
			v, k := binary.Uvarint(msg)
			if k <= 0 {
				return 0, errors.New("malformed protobuf varint")
			}
			msg = msg[k:]
			if tag>>3 == 1 {
				status = int(v)
			}
		case 2:
			l, k := binary.Uvarint(msg)
			if k <= 0 || uint64(len(msg)-k) < l {
				return 0, errors.New("malformed protobuf field")
			}
			msg = msg[k+int(l):]
		case 1:
			if len(msg) < 8 {
				return 0, errors.New("malformed protobuf field")
			}
			msg = msg[8:]
		case 5:
			if len(msg) < 4 {
				return 0, errors.New("malformed protobuf field")
			}
			msg = msg[4:]
		default:
			return 0, errors.New("unsupported protobuf wire type")
		}
	}
	return status, nil
}

// GRPCHealthOptions describes one grpc.health.v1.Health/Check call.
type GRPCHealthOptions struct {
	Target  string // HOST:PORT
	Service string
	CA      string
	Timeout float64
}

// GRPCHealth calls Health/Check over HTTP/2 with TLS. Input errors are
// returned; network and protocol failures are recorded in the result.
func GRPCHealth(o GRPCHealthOptions) (obj, error) {
	host, port, err := net.SplitHostPort(o.Target)
	if err != nil || host == "" {
		return nil, userError("expected HOST:PORT")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, userError("invalid port")
	}
	if !(o.Timeout > 0 && o.Timeout <= 60) || math.IsNaN(o.Timeout) {
		return nil, userError("timeout must be positive and at most 60 seconds")
	}
	if len(o.Service) > 1024 {
		return nil, userError("service name is too long")
	}
	cfg := &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}}
	if o.CA != "" {
		pem, err := os.ReadFile(o.CA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, userErrorf("no certificates found in %s", o.CA)
		}
		cfg.RootCAs = pool
	}
	timeout := time.Duration(o.Timeout * float64(time.Second))
	start := time.Now()
	res := obj{"target": o.Target, "service": o.Service, "ok": false}
	fail := func(err error) (obj, error) {
		res["error"] = err.Error()
		res["elapsed_ms"] = math.Round(float64(time.Since(start).Microseconds())/100) / 10
		return res, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(grpcDialHost(host), port))
	if err != nil {
		return fail(err)
	}
	defer raw.Close()
	tc := raw.(*tls.Conn)
	alpn := tc.ConnectionState().NegotiatedProtocol
	res["alpn"] = alpn
	if alpn != "h2" {
		return fail(fmt.Errorf("server did not negotiate h2 (ALPN %q)", alpn))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+o.Target+healthPath, bytes.NewReader(encodeHealthRequest(o.Service)))
	if err != nil {
		return nil, userErrorf("invalid target: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("User-Agent", "zyvor-setura")
	resp, err := h2Transport(raw, timeout).RoundTrip(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	res["http_status"] = resp.StatusCode
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fail(err)
	}
	// Trailers are populated once the body is fully read; a "trailers-only"
	// response carries grpc-status in the headers instead.
	gs := resp.Trailer.Get("Grpc-Status")
	gm := resp.Trailer.Get("Grpc-Message")
	if gs == "" {
		gs, gm = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP status %d", resp.StatusCode))
	}
	if gs == "" {
		return fail(errors.New("response has no grpc-status"))
	}
	code, err := strconv.Atoi(gs)
	if err != nil {
		return fail(fmt.Errorf("invalid grpc-status %q", gs))
	}
	res["grpc_status"] = code
	if gm != "" {
		res["grpc_message"] = gm
	}
	if code != 0 {
		return fail(fmt.Errorf("grpc-status %d %s", code, gm))
	}
	st, err := decodeHealthResponse(body)
	if err != nil {
		return fail(err)
	}
	name := servingNames[st]
	if name == "" {
		name = "UNKNOWN(" + strconv.Itoa(st) + ")"
	}
	res["status"] = name
	res["ok"] = st == 1
	res["elapsed_ms"] = math.Round(float64(time.Since(start).Microseconds())/100) / 10
	return res, nil
}

func runGRPCHealth(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	service := fs.String("service", "", "service name to check (empty checks the server overall)")
	useTLS := fs.Bool("tls", true, "use TLS with ALPN h2 (plaintext h2c is not supported)")
	ca := fs.String("ca", "", "trusted PEM CA bundle")
	timeout := fs.Float64("timeout", 4, "operation timeout in seconds")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "setura grpc-health: expected HOST:PORT")
		return 2, usageError{"target"}
	}
	if !*useTLS {
		fmt.Fprintln(stderr, "setura grpc-health: plaintext h2c is not supported; TLS is required")
		return 2, usageError{"tls"}
	}
	res, err := GRPCHealth(GRPCHealthOptions{Target: pos[0], Service: *service, CA: *ca, Timeout: *timeout})
	if err != nil {
		return 0, err
	}
	if *asJSON {
		if err := writeJSON(stdout, res); err != nil {
			return 0, err
		}
	} else {
		var parts []string
		for _, k := range []string{"status", "grpc_status", "alpn", "error"} {
			if v, ok := res[k]; ok {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		fmt.Fprintf(stdout, "%s %s\n", res["target"], strings.Join(parts, " "))
	}
	return boolExit(res["ok"] != true), nil
}
