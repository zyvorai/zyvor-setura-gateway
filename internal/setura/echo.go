package setura

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// EchoHandler answers every request with the backend name and the
// X-Setura-Backend identity header that explain, check and gate assert on.
// A gRPC call gets a successful unary answer carrying the same header, so
// "split --grpc" and "grpc-health" have a backend to talk to.
func EchoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Setura-Backend", name)
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			echoGRPC(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, name)
	})
}

// echoGRPC answers any unary call with status OK: Health/Check reports
// SERVING, every other method an empty message.
func echoGRPC(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxBody))
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	msg := []byte{0, 0, 0, 0, 0}
	if r.URL.Path == healthPath {
		msg = []byte{0, 0, 0, 0, 2, 0x08, 0x01} // status = SERVING
	}
	_, _ = w.Write(msg)
	w.Header().Set("Grpc-Status", "0")
}

// ServeEcho serves EchoHandler on addr until ctx is cancelled. It reports the
// bound address on ready so callers can listen on port 0.
func ServeEcho(ctx context.Context, addr, name string, ready chan<- string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if ready != nil {
		ready <- ln.Addr().String()
	}
	// HTTP/1.1 and cleartext HTTP/2 (h2c), which gRPC backends are dialled with.
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: EchoHandler(name), ReadHeaderTimeout: 5 * time.Second, Protocols: protos}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runEcho(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer) (int, error) {
	name := fs.String("name", "", "backend identity returned in X-Setura-Backend (required)")
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		fmt.Fprintln(stderr, "setura echo: unexpected arguments")
		return 2, usageError{"arguments"}
	}
	if *name == "" {
		fmt.Fprintln(stderr, "setura echo: --name is required")
		return 2, usageError{"name"}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ready := make(chan string, 1)
	errc := make(chan error, 1)
	go func() { errc <- ServeEcho(ctx, *listen, *name, ready) }()
	select {
	case addr := <-ready:
		fmt.Fprintf(stdout, "setura echo: %s answering on http://%s/\n", *name, addr)
	case err := <-errc:
		return 0, err
	}
	return 0, <-errc
}
