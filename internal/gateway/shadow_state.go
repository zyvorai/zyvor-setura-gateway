package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	shadowStateSchema          = "setura.shadow-state/v1"
	defaultShadowStateInterval = 10 * time.Second
)

type shadowRouteState struct {
	Sampled    int64            `json:"sampled"`
	Compared   int64            `json:"compared"`
	Matched    int64            `json:"matched"`
	Mismatched int64            `json:"mismatched"`
	Errors     int64            `json:"errors"`
	Dropped    int64            `json:"dropped"`
	Skipped    int64            `json:"skipped"`
	Cat        map[string]int64 `json:"categories,omitempty"`
	Deltas     []float64        `json:"deltas,omitempty"` // most recent latency deltas, oldest first
}

type shadowStateFile struct {
	Schema    string                       `json:"schema"`
	Saved     string                       `json:"saved"`
	Total     shadowRouteState             `json:"total"`
	Routes    map[string]*shadowRouteState `json:"routes"`
	Ring      []shadowEntry                `json:"recent"` // oldest first
	LastError string                       `json:"lastError,omitempty"`
}

func (r *shadowRoute) export() *shadowRouteState {
	st := &shadowRouteState{Sampled: r.Sampled, Compared: r.Compared, Matched: r.Matched, Mismatched: r.Mismatched,
		Errors: r.Errors, Dropped: r.Dropped, Skipped: r.Skipped}
	if len(r.Cat) > 0 {
		st.Cat = map[string]int64{}
		for k, v := range r.Cat {
			st.Cat[k] = v
		}
	}
	if r.dn <= len(r.deltas) {
		st.Deltas = append([]float64(nil), r.deltas...)
	} else { // the window wrapped: oldest entry is at dn % window
		i := r.dn % shadowDeltaWindow
		st.Deltas = append(append([]float64(nil), r.deltas[i:]...), r.deltas[:i]...)
	}
	return st
}

func (st *shadowRouteState) load() *shadowRoute {
	r := &shadowRoute{Sampled: st.Sampled, Compared: st.Compared, Matched: st.Matched, Mismatched: st.Mismatched,
		Errors: st.Errors, Dropped: st.Dropped, Skipped: st.Skipped}
	if len(st.Cat) > 0 {
		r.Cat = map[string]int64{}
		for k, v := range st.Cat {
			r.Cat[k] = v
		}
	}
	d := st.Deltas
	if len(d) > shadowDeltaWindow {
		d = d[len(d)-shadowDeltaWindow:]
	}
	r.deltas, r.dn = append([]float64(nil), d...), len(d)
	return r
}

// snapshot copies the counters and the recent-mismatch ring.
func (s *shadowState) snapshot(now time.Time) *shadowStateFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &shadowStateFile{Schema: shadowStateSchema, Saved: now.UTC().Format(time.RFC3339), Total: *s.total.export(),
		Routes: map[string]*shadowRouteState{}, LastError: s.lastErr}
	for k, r := range s.routes {
		f.Routes[k] = r.export()
	}
	n := len(s.ring)
	f.Ring = make([]shadowEntry, 0, n)
	for i := 0; i < n; i++ { // oldest first
		f.Ring = append(f.Ring, s.ring[(s.head+i)%n])
	}
	return f
}

// restore replaces the in-memory results with f.
func (s *shadowState) restore(f *shadowStateFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total = *f.Total.load()
	s.routes = map[string]*shadowRoute{}
	for k, r := range f.Routes {
		s.routes[k] = r.load()
	}
	ring := f.Ring
	if len(ring) > shadowRingSize {
		ring = ring[len(ring)-shadowRingSize:]
	}
	s.ring, s.head, s.lastErr = append([]shadowEntry(nil), ring...), 0, f.LastError
}

// writeShadowState writes f to path atomically: a temporary file in the same
// directory, fsynced, then renamed over the target.
func writeShadowState(path string, f *shadowStateFile) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".shadow-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error { tmp.Close(); os.Remove(name); return err }
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// loadShadowState reads a state file. A missing file is not an error.
func loadShadowState(path string) (*shadowStateFile, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f shadowStateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Schema != shadowStateSchema {
		return nil, fmt.Errorf("%s: unexpected schema %q", path, f.Schema)
	}
	return &f, nil
}

// shadowPersist snapshots shadow results to a file on an interval.
type shadowPersist struct {
	s    *Server
	path string
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// startShadowPersist reloads the state file and starts the periodic snapshot.
// It returns nil when no --shadow-state file is configured.
func (s *Server) startShadowPersist() *shadowPersist {
	path := s.opts.ShadowState
	if path == "" {
		return nil
	}
	if f, err := loadShadowState(path); err != nil {
		s.diag("shadow state: starting empty: %v", err)
	} else if f != nil {
		s.shadow.restore(f)
		s.diag("shadow state: restored %d compared requests from %s (saved %s)", f.Total.Compared, path, f.Saved)
	}
	iv := s.opts.ShadowStateInterval
	if iv <= 0 {
		iv = defaultShadowStateInterval
	}
	p := &shadowPersist{s: s, path: path, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		tk := time.NewTicker(iv)
		defer tk.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-tk.C:
				p.save()
			}
		}
	}()
	return p
}

func (p *shadowPersist) save() {
	if err := writeShadowState(p.path, p.s.shadow.snapshot(time.Now())); err != nil {
		p.s.diag("shadow state: write %s: %v", p.path, err)
	}
}

// close stops the loop and writes a final snapshot. Safe on nil.
func (p *shadowPersist) close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		close(p.stop)
		<-p.done
		p.save()
	})
}
