package gateway

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RotateOptions configures access-log rotation. The zero value never rotates
// by size and keeps every rotated file.
type RotateOptions struct {
	MaxSize int64 // rotate when the file would grow past this many bytes (0 = only on request)
	Keep    int   // rotated files to keep, newest first (0 = keep all)
	Gzip    bool  // compress rotated files
	Now     func() time.Time
}

// ParseSize parses "100", "64k", "10MB", "1g" (powers of 1024).
func ParseSize(v string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	mult := int64(1)
	for _, u := range []struct {
		suf  string
		mult int64
	}{{"kb", 1 << 10}, {"mb", 1 << 20}, {"gb", 1 << 30}, {"k", 1 << 10}, {"m", 1 << 20}, {"g", 1 << 30}, {"b", 1}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suf)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("size %q: want a number with an optional k, m or g suffix", v)
	}
	return n * mult, nil
}

// rotatingFile is an append-only log file that rotates by size or on request.
// Rotated files are named PATH.YYYYMMDDTHHMMSS.mmmZ (plus .gz when
// compressed), so they sort by age.
type rotatingFile struct {
	path string
	o    RotateOptions

	mu   sync.Mutex
	f    *os.File
	size int64
	seq  int

	wg        sync.WaitGroup
	rotations atomic.Int64
	errors    atomic.Int64
}

func newRotatingFile(path string, o RotateOptions) (*rotatingFile, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	r := &rotatingFile{path: path, o: o}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when it would push the file past MaxSize
// (a file is never rotated while empty, so an oversized line still lands).
func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.o.MaxSize > 0 && r.size > 0 && r.size+int64(len(p)) > r.o.MaxSize {
		if err := r.rotateLocked(); err != nil {
			r.errors.Add(1) // keep writing to the current file
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Rotate moves the current file aside and starts a new one.
func (r *rotatingFile) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateLocked()
}

func (r *rotatingFile) rotateLocked() error {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
	if r.size > 0 {
		r.seq++
		name := fmt.Sprintf("%s.%s-%03d", r.path, r.o.Now().UTC().Format("20060102T150405.000Z"), r.seq%1000)
		if err := os.Rename(r.path, name); err != nil {
			r.open() // keep logging somewhere
			return err
		}
		r.rotations.Add(1)
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			if r.o.Gzip {
				if err := gzipFile(name); err != nil {
					r.errors.Add(1)
				}
			}
			r.prune()
		}()
	}
	return r.open()
}

// Reopen is for SIGHUP: when something else (logrotate) moved the file away
// it reopens the path; when the file is still ours it rotates it.
func (r *rotatingFile) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil {
		cur, err1 := r.f.Stat()
		onDisk, err2 := os.Stat(r.path)
		if err1 == nil && err2 == nil && os.SameFile(cur, onDisk) {
			return r.rotateLocked()
		}
		r.f.Close()
		r.f = nil
	}
	return r.open()
}

// prune deletes rotated files beyond Keep, oldest first.
func (r *rotatingFile) prune() {
	if r.o.Keep <= 0 {
		return
	}
	matches, _ := filepath.Glob(r.path + ".*")
	var rotated []string
	for _, m := range matches {
		rest := strings.TrimPrefix(m, r.path+".")
		if len(rest) >= 16 && rest[8] == 'T' && !strings.HasSuffix(m, ".tmp") { // YYYYMMDDT...
			rotated = append(rotated, m)
		}
	}
	sort.Strings(rotated) // timestamps sort by age; .gz and plain never coexist for one stamp
	for len(rotated) > r.o.Keep {
		os.Remove(rotated[0])
		rotated = rotated[1:]
	}
}

// Close flushes pending compression and closes the file.
func (r *rotatingFile) Close() error {
	r.wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

func gzipFile(name string) error {
	in, err := os.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(name+".gz.tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name + ".gz.tmp")
		return err
	}
	if err := os.Rename(name+".gz.tmp", name+".gz"); err != nil {
		return err
	}
	return os.Remove(name)
}
