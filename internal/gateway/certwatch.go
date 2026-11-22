package gateway

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Certificate and CA bundle change detection.
//
// Kubernetes mode: every Secret and ConfigMap the last load fetched (listener
// certificates, client CA bundles, BackendTLSPolicy CAs, backend client
// certificates) gets its own watch, selected by metadata.name so that RBAC with
// resourceNames still works. A cert-manager renewal wakes the controller within
// a second or two instead of waiting for the safety resync.
//
// File mode: the polled file source remembers the size and modification time of
// the config and of every certificate, key and CA file it read, and answers a
// poll from that memory while nothing changed. No inotify, no content reads on
// a quiet system. Timestamps that are younger than racyWindow when the content
// was read are not trusted (the same "racy" rule git applies), so a rewrite
// within the filesystem's timestamp granularity is still seen.

const racyWindow = 2 * time.Second

// ---- file mode ----

type fileStamp struct {
	path    string
	size    int64
	mtime   time.Time
	missing bool
}

func stampOf(path string) fileStamp {
	st, err := os.Stat(path)
	if err != nil {
		return fileStamp{path: path, missing: true}
	}
	return fileStamp{path: path, size: st.Size(), mtime: st.ModTime()}
}

type fileMemo struct {
	stamps []fileStamp
	ld     *Loaded
}

var fileMemos sync.Map // absolute config path -> *fileMemo

// fileMemoFresh returns the remembered load when no watched file changed.
func fileMemoFresh(path string) *Loaded {
	v, ok := fileMemos.Load(path)
	if !ok {
		return nil
	}
	m := v.(*fileMemo)
	for _, s := range m.stamps {
		if stampOf(s.path) != s {
			return nil
		}
	}
	return m.ld
}

// fileMemoStore remembers ld unless some file is too fresh to trust.
func fileMemoStore(path string, files []string, readAt time.Time, ld *Loaded) {
	m := &fileMemo{ld: ld}
	for _, f := range files {
		s := stampOf(f)
		if !s.missing && readAt.Sub(s.mtime) < racyWindow {
			fileMemos.Delete(path)
			return
		}
		m.stamps = append(m.stamps, s)
	}
	fileMemos.Store(path, m)
}

// watchedFiles lists every file a config's TLS material comes from.
func watchedFiles(cfg *Config, config string) []string {
	files := []string{config}
	for _, k := range sortedKeys(cfg.Secrets) {
		for _, p := range []string{cfg.Secrets[k].CertFile, cfg.Secrets[k].KeyFile} {
			if p != "" {
				files = append(files, p)
			}
		}
	}
	for _, k := range sortedKeys(cfg.CACerts) {
		if p := cfg.CACerts[k].File; p != "" {
			files = append(files, p)
		}
	}
	return files
}

// ---- Kubernetes mode ----

var refPathRE = regexp.MustCompile(`^/api/v1/namespaces/([^/?]+)/(secrets|configmaps)/([^/?]+)$`)

// refWatches runs one watch per referenced Secret or ConfigMap.
type refWatches struct {
	mu     sync.Mutex
	ctx    context.Context
	wake   func()
	seen   map[string]bool
	active map[string]context.CancelFunc
}

func (r *refWatches) begin() {
	r.mu.Lock()
	r.seen = map[string]bool{}
	r.mu.Unlock()
}

func (r *refWatches) note(path string) {
	m := refPathRE.FindStringSubmatch(path)
	if m == nil {
		return
	}
	r.mu.Lock()
	if r.seen != nil {
		r.seen[m[1]+"/"+m[2]+"/"+m[3]] = true
	}
	r.mu.Unlock()
}

// syncRefWatches starts watches for newly referenced objects and stops those
// that are no longer referenced.
func (k *KubeSource) syncRefWatches() {
	r := &k.refs
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil || r.seen == nil || k.Poll {
		return
	}
	if r.active == nil {
		r.active = map[string]context.CancelFunc{}
	}
	for key := range r.seen {
		if r.active[key] != nil {
			continue
		}
		p := strings.SplitN(key, "/", 3)
		path := fmt.Sprintf("/api/v1/namespaces/%s/%s?fieldSelector=%s", url.PathEscape(p[0]), p[1], url.QueryEscape("metadata.name="+p[2]))
		ctx, cancel := context.WithCancel(r.ctx)
		r.active[key] = cancel
		k.wg.Add(1)
		go func() {
			defer k.wg.Done()
			k.watchLoop(ctx, []string{path}, true, r.wake)
		}()
	}
	for key, cancel := range r.active {
		if !r.seen[key] {
			cancel()
			delete(r.active, key)
		}
	}
}

// withQuery appends query parameters to a path that may already carry some.
func withQuery(path, query string) string {
	if strings.Contains(path, "?") {
		return path + "&" + query
	}
	return path + "?" + query
}

// ---- reload of listener certificates ----
//
// Listener certificates and client CA bundles are resolved into the routing
// table, so any change to them (file or Secret) produces a new table whose
// listeners hand the new certificate to the next handshake, while sockets and
// established connections stay. OCSP staples are keyed by certificate, not by
// table, so a reload that keeps a certificate keeps its staple, and a renewed
// certificate is fetched right after the swap (see ocspSync).
