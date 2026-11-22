package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// meta is the package metadata shared by both formats.
type meta struct {
	Name, Version, Arch                   string
	Summary, Description                  string
	Maintainer, Homepage, License, Vendor string
	Section                               string
	Mtime                                 int64
}

func defaultMeta() meta {
	return meta{
		Name:    "setura",
		Summary: "Publish and diagnose Gateway API routes; built-in gateway",
		Description: "Zyvor Setura is a single static binary: a Kubernetes Gateway API data plane\n" +
			"and a verifier that probes routes from the client side. Source-available\n" +
			"under the Zyvor Production Licence v2.0; a paid Order is required for use.",
		Maintainer: "Zyvor AI Labs <sales@zyvor.dev>",
		Homepage:   "https://github.com/zyvorai/zyvor-setura-gateway",
		License:    "LicenseRef-Zyvor-Production-2.0",
		Vendor:     "Zyvor AI Labs Private Limited",
		Section:    "net",
	}
}

// entry is one installed path. Path is absolute ("/usr/bin/setura").
type entry struct {
	Path   string
	Mode   uint32 // permission bits only
	IsDir  bool
	Data   []byte
	Mtime  int64
	SHA256 string
	MD5    string
}

// collect walks root and returns every directory and file as an absolute
// install path, sorted by path. Intermediate directories are included.
func collect(root string, mtime int64) ([]entry, error) {
	var out []entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		e := entry{Path: "/" + filepath.ToSlash(rel), Mtime: mtime}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			e.IsDir, e.Mode = true, 0o755
		case info.Mode().IsRegular():
			e.Mode = 0o644
			if info.Mode()&0o111 != 0 {
				e.Mode = 0o755
			}
			if e.Data, err = os.ReadFile(p); err != nil {
				return err
			}
			h := sha256.Sum256(e.Data)
			e.SHA256 = hex.EncodeToString(h[:])
		default:
			return fmt.Errorf("%s: only regular files and directories are supported", p)
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is empty", root)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func splitPath(p string) (dir, base string) {
	i := strings.LastIndex(p, "/")
	return p[:i+1], p[i+1:]
}
