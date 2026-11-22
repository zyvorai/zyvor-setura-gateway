package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"strings"
	"time"
)

// gz compresses b deterministically (no name, zero mtime).
func gz(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// tarGz writes entries (and optional extra control files) as a root-owned
// gzip tar with "./" prefixed names, as dpkg expects.
func tarGz(files []entry, withDirs bool, mtime int64) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	ts := time.Unix(mtime, 0)
	for _, e := range files {
		h := &tar.Header{Name: "." + e.Path, ModTime: ts, Uid: 0, Gid: 0, Uname: "root", Gname: "root", Format: tar.FormatGNU}
		if e.IsDir {
			if !withDirs {
				continue
			}
			h.Typeflag, h.Name, h.Mode = tar.TypeDir, h.Name+"/", int64(e.Mode)
		} else {
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, int64(e.Mode), int64(len(e.Data))
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if !e.IsDir {
			if _, err := tw.Write(e.Data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return gz(buf.Bytes()), nil
}

// arArchive builds a System V/GNU ar archive with short member names.
func arArchive(members [][2]string, mtime int64) []byte {
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range members {
		name, data := m[0], m[1]
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name+"/", mtime, 0, 0, "100644", len(data))
		b.WriteString(data)
		if len(data)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

func debArch(a string) (string, error) {
	switch a {
	case "amd64", "arm64":
		return a, nil
	}
	return "", fmt.Errorf("unsupported arch %q", a)
}

func buildDeb(m meta, files []entry) ([]byte, error) {
	arch, err := debArch(m.Arch)
	if err != nil {
		return nil, err
	}
	data, err := tarGz(files, true, m.Mtime)
	if err != nil {
		return nil, err
	}
	var md5s strings.Builder
	size := 0
	for _, e := range files {
		if e.IsDir {
			continue
		}
		size += len(e.Data)
		fmt.Fprintf(&md5s, "%x  %s\n", md5.Sum(e.Data), strings.TrimPrefix(e.Path, "/"))
	}
	desc := strings.ReplaceAll(strings.TrimRight(m.Description, "\n"), "\n", "\n ")
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s\nInstalled-Size: %d\nSection: %s\nPriority: optional\nHomepage: %s\nDescription: %s\n %s\n",
		m.Name, strings.ReplaceAll(m.Version, "-", "~"), arch, m.Maintainer, (size+1023)/1024, m.Section, m.Homepage, m.Summary, desc)
	ctl := []entry{
		{Path: "/control", Mode: 0o644, Data: []byte(control)},
		{Path: "/md5sums", Mode: 0o644, Data: []byte(md5s.String())},
	}
	ctlTar, err := tarGz(ctl, false, m.Mtime)
	if err != nil {
		return nil, err
	}
	return arArchive([][2]string{
		{"debian-binary", "2.0\n"},
		{"control.tar.gz", string(ctlTar)},
		{"data.tar.gz", string(data)},
	}, m.Mtime), nil
}
