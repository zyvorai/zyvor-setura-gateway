package gateway

import (
	"bytes"
	"io"
	"os"
	"sync"
)

// bodySpool tees a request body while the primary proxy reads it. Up to
// shadowWindow bytes stay in memory; beyond that the copy spills to a temporary
// file, so an upload of any size up to the ceiling is never held in memory for
// the mirror. It is an io.ReadCloser standing in for the request body. Past the
// ceiling the copy is dropped and onOver runs once; the primary is unaffected.
type bodySpool struct {
	src     io.ReadCloser
	ceiling int64
	onEOF   func() // runs once, when the body was read to its end within the ceiling
	onOver  func() // runs once, when the body outgrew the ceiling

	mu    sync.Mutex
	mem   []byte
	f     *os.File
	n     int64
	over  bool
	eof   bool
	fired bool
	refs  int
}

// newSpool starts with prefix (bytes already read from src) as the head.
func newSpool(src io.ReadCloser, prefix []byte, ceiling int64) *bodySpool {
	sp := &bodySpool{src: src, ceiling: ceiling, refs: 1}
	if len(prefix) > 0 {
		sp.add(prefix)
	}
	return sp
}

// add appends p to the copy and reports whether the copy was just abandoned.
func (sp *bodySpool) add(p []byte) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.over {
		return false
	}
	giveUp := func() bool {
		sp.over, sp.mem = true, nil
		sp.rm()
		return true
	}
	if sp.n+int64(len(p)) > sp.ceiling {
		return giveUp()
	}
	sp.n += int64(len(p))
	if sp.f == nil && len(sp.mem)+len(p) <= shadowWindow {
		sp.mem = append(sp.mem, p...)
		return false
	}
	if sp.f == nil {
		f, err := os.CreateTemp("", "setura-spool-*")
		if err != nil {
			return giveUp()
		}
		sp.f = f
		if _, err := f.Write(sp.mem); err != nil {
			return giveUp()
		}
		sp.mem = nil
	}
	if _, err := sp.f.Write(p); err != nil {
		return giveUp()
	}
	return false
}

// rm deletes the temporary file. Caller holds mu.
func (sp *bodySpool) rm() {
	if sp.f != nil {
		sp.f.Close()
		os.Remove(sp.f.Name())
		sp.f = nil
	}
}

func (sp *bodySpool) Read(p []byte) (int, error) {
	n, err := sp.src.Read(p)
	if n > 0 && sp.add(p[:n]) && sp.onOver != nil {
		sp.onOver()
	}
	if err == io.EOF {
		sp.mu.Lock()
		fire := !sp.over && !sp.fired
		sp.eof = true
		sp.fired = sp.fired || fire
		sp.mu.Unlock()
		if fire && sp.onEOF != nil {
			sp.onEOF()
		}
	}
	return n, err
}

func (sp *bodySpool) Close() error { return sp.src.Close() }

// size is the copied length.
func (sp *bodySpool) size() int64 {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.n
}

type spoolReader struct {
	io.Reader
	sp *bodySpool
	f  *os.File
}

func (r *spoolReader) Close() error {
	if r.f != nil {
		r.f.Close()
		r.f = nil
		r.sp.release()
	} else if r.sp != nil {
		r.sp.release()
		r.sp = nil
	}
	return nil
}

// open returns an independent reader over the finished copy and holds the
// spool until it is closed. It returns nil when the copy is unavailable.
func (sp *bodySpool) open() io.ReadCloser {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.over || !sp.eof {
		return nil
	}
	if sp.f == nil {
		return &spoolReader{Reader: bytes.NewReader(sp.mem)}
	}
	f, err := os.Open(sp.f.Name())
	if err != nil {
		return nil
	}
	sp.refs++
	return &spoolReader{Reader: io.LimitReader(f, sp.n), sp: sp, f: f}
}

// release drops one hold; the file is deleted with the last one.
func (sp *bodySpool) release() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.refs--
	if sp.refs <= 0 {
		sp.rm()
	}
}
