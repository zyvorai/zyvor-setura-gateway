package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

// FileSource reads a snapshot-style JSON file.
type FileSource struct{ Path string }

// Load implements Source.
func (f FileSource) Load(context.Context) (*Loaded, error) {
	abs, err := filepath.Abs(f.Path)
	if err != nil {
		return nil, err
	}
	if ld := fileMemoFresh(abs); ld != nil {
		return ld, nil // nothing changed since the last full read (see certwatch.go)
	}
	readAt := time.Now()
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseConfig(raw, filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(raw)
	for _, k := range sortedKeys(cfg.Secrets) { // a rotated certificate file is a change too
		for _, p := range []string{cfg.Secrets[k].CertFile, cfg.Secrets[k].KeyFile} {
			if b, err := os.ReadFile(p); err == nil {
				h.Write(b)
			}
		}
	}
	for _, k := range sortedKeys(cfg.CACerts) { // so is a rotated CA bundle
		if p := cfg.CACerts[k].File; p != "" {
			if b, err := os.ReadFile(p); err == nil {
				h.Write(b)
			}
		}
	}
	ld := &Loaded{Config: cfg, Hash: hex.EncodeToString(h.Sum(nil)), Snapshot: raw}
	fileMemoStore(abs, watchedFiles(cfg, f.Path), readAt, ld)
	return ld, nil
}
