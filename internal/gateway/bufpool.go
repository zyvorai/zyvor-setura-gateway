package gateway

import (
	"io"
	"log"
	"sync"
)

// bufferPool lends httputil.ReverseProxy its 32 KiB copy buffer. Without a
// BufferPool the proxy allocates a fresh buffer for every response, which was
// about two thirds of the bytes allocated per proxied request.
type bufferPool struct{ p sync.Pool }

func newBufferPool() *bufferPool {
	return &bufferPool{p: sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}}
}

func (b *bufferPool) Get() []byte  { return *(b.p.Get().(*[]byte)) }
func (b *bufferPool) Put(x []byte) { b.p.Put(&x) }

var proxyBufPool = newBufferPool()

// discardLog is the ReverseProxy ErrorLog: errors surface through ErrorHandler
// and the access log, so the proxy's own logger writes nowhere. One shared
// logger avoids allocating one per request.
var discardLog = log.New(io.Discard, "", 0)

// statusClasses are the "Nxx" counter keys, indexed by status/100.
var statusClasses = [...]string{"0xx", "1xx", "2xx", "3xx", "4xx", "5xx", "6xx", "7xx", "8xx", "9xx"}
