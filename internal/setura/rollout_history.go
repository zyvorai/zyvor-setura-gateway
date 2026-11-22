package setura

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// historyDirName is created next to the live configuration file.
const historyDirName = ".setura-history"

// diffSummary counts resource level differences between two snapshots.
type diffSummary struct {
	Added   int      `json:"added"`
	Removed int      `json:"removed"`
	Changed int      `json:"changed"`
	Names   []string `json:"names,omitempty"`
}

func (d diffSummary) String() string {
	if d.Added+d.Removed+d.Changed == 0 {
		return "no resource changes"
	}
	s := fmt.Sprintf("%d changed, %d added, %d removed", d.Changed, d.Added, d.Removed)
	if len(d.Names) > 0 {
		n := d.Names
		more := ""
		if len(n) > 3 {
			n, more = n[:3], fmt.Sprintf(" +%d", len(d.Names)-3)
		}
		s += " (" + strings.Join(n, ", ") + more + ")"
	}
	return s
}

// snapshotKeys flattens resources and backends into comparable entries.
func snapshotKeys(raw []byte) (map[string]any, error) {
	var doc obj
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range asMap(doc["resources"]) {
		out[k] = v
	}
	for k, v := range asMap(doc["backends"]) {
		out["backend/"+k] = v
	}
	return out, nil
}

// summarizeDiff compares two snapshot documents.
func summarizeDiff(before, after []byte) diffSummary {
	a, errA := snapshotKeys(before)
	b, errB := snapshotKeys(after)
	if errA != nil || errB != nil {
		return diffSummary{}
	}
	var d diffSummary
	for _, k := range sortedKeys(b) {
		if av, ok := a[k]; !ok {
			d.Added++
			d.Names = append(d.Names, "+"+k)
		} else if !eq(av, b[k]) {
			d.Changed++
			d.Names = append(d.Names, "~"+k)
		}
	}
	for _, k := range sortedKeys(a) {
		if _, ok := b[k]; !ok {
			d.Removed++
			d.Names = append(d.Names, "-"+k)
		}
	}
	return d
}

// histMeta is the sidecar record stored with every backup.
type histMeta struct {
	ID          string      `json:"id"`
	Time        string      `json:"time"`
	Reason      string      `json:"reason"` // rollout or rollback: what replaced this config
	Generation  int64       `json:"generation"`
	Hash        string      `json:"hash"`
	LintOK      bool        `json:"lintOk"`
	LintSummary string      `json:"lintSummary,omitempty"`
	Diff        diffSummary `json:"diff"` // this backup compared with its replacement
}

type histStore struct{ dir string }

func newHistStore(config string) histStore {
	return histStore{dir: filepath.Join(filepath.Dir(config), historyDirName)}
}

// atomicWrite replaces path with data: write a temp file in the same
// directory, fsync it, rename over the target. Symlinks are followed so the
// link itself survives.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".setura-rollout-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func(err error) error { f.Close(); os.Remove(tmp); return err }
	if _, err := f.Write(data); err != nil {
		return cleanup(err)
	}
	if err := f.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if err := f.Sync(); err != nil {
		return cleanup(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func hashHex(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// add stores raw as a new backup and fills in meta's identity fields.
func (h histStore) add(raw []byte, m histMeta, now time.Time) (histMeta, error) {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return m, err
	}
	m.Hash = hashHex(raw)
	m.Time = now.UTC().Format(time.RFC3339)
	m.ID = now.UTC().Format("20060102T150405.000Z") + "-" + m.Hash[:8]
	if err := atomicWrite(filepath.Join(h.dir, m.ID+".json"), raw, 0o600); err != nil {
		return m, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := atomicWrite(filepath.Join(h.dir, m.ID+".meta.json"), append(b, '\n'), 0o600); err != nil {
		return m, err
	}
	return m, nil
}

// list returns backups, newest first.
func (h histStore) list() ([]histMeta, error) {
	ents, err := os.ReadDir(h.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []histMeta
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".meta.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(h.dir, e.Name()))
		if err != nil {
			continue
		}
		var m histMeta
		if json.Unmarshal(raw, &m) == nil && m.ID != "" {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// get resolves an ID (or unique prefix) and returns its contents.
func (h histStore) get(id string) ([]byte, histMeta, error) {
	all, err := h.list()
	if err != nil {
		return nil, histMeta{}, err
	}
	var hit []histMeta
	for _, m := range all {
		if m.ID == id {
			hit = []histMeta{m}
			break
		}
		if strings.HasPrefix(m.ID, id) {
			hit = append(hit, m)
		}
	}
	switch len(hit) {
	case 0:
		return nil, histMeta{}, userErrorf("no backup %q in %s", id, h.dir)
	case 1:
	default:
		return nil, histMeta{}, userErrorf("backup id %q is ambiguous (%d matches)", id, len(hit))
	}
	raw, err := os.ReadFile(filepath.Join(h.dir, hit[0].ID+".json"))
	return raw, hit[0], err
}

// prune keeps the newest keep backups.
func (h histStore) prune(keep int) {
	if keep < 1 {
		return
	}
	all, _ := h.list()
	for i := keep; i < len(all); i++ {
		os.Remove(filepath.Join(h.dir, all[i].ID+".json"))
		os.Remove(filepath.Join(h.dir, all[i].ID+".meta.json"))
	}
}

// lock serializes rollouts against one config. The returned func releases it.
func (h histStore) lock() (func(), error) {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(h.dir, "lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, userErrorf("another rollout holds %s; if it is stale (no rollout is running) delete it", p)
		}
		return nil, err
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
	return func() { os.Remove(p) }, nil
}
