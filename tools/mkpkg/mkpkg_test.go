package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func stage(t *testing.T) []entry {
	t.Helper()
	root := t.TempDir()
	put := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	put("usr/bin/setura", "#!/bin/sh\necho hi\n", 0o755)
	put("usr/share/man/man1/setura.1.gz", "manpage", 0o644)
	put("usr/share/doc/setura/NOTICE", "odd", 0o600)
	files, err := collect(root, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func testMeta() meta {
	m := defaultMeta()
	m.Version, m.Arch, m.Mtime = "0.6.0", "arm64", 1700000000
	return m
}

func TestDeb(t *testing.T) {
	files := stage(t)
	deb, err := buildDeb(testMeta(), files)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(deb, []byte("!<arch>\n")) {
		t.Fatal("not an ar archive")
	}
	// walk members
	members := map[string][]byte{}
	var order []string
	p := deb[8:]
	for len(p) > 0 {
		hdr := p[:60]
		if string(hdr[58:]) != "`\n" {
			t.Fatalf("bad member trailer %q", hdr[58:])
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(hdr[:16])), "/")
		n, _ := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		members[name] = p[60 : 60+n]
		order = append(order, name)
		p = p[60+n:]
		if n%2 == 1 {
			p = p[1:]
		}
	}
	if strings.Join(order, ",") != "debian-binary,control.tar.gz,data.tar.gz" || string(members["debian-binary"]) != "2.0\n" {
		t.Fatalf("members %v", order)
	}
	untar := func(b []byte) map[string]string {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(zr)
		out := map[string]string{}
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return out
			}
			if err != nil {
				t.Fatal(err)
			}
			if h.Uid != 0 || h.Uname != "root" {
				t.Errorf("%s not root owned", h.Name)
			}
			body, _ := io.ReadAll(tr)
			out[h.Name] = fmt.Sprintf("%o:%s", h.Mode, body)
		}
	}
	data := untar(members["data.tar.gz"])
	if data["./usr/bin/setura"] != "755:#!/bin/sh\necho hi\n" || data["./usr/share/doc/setura/NOTICE"] != "644:odd" {
		t.Errorf("data: %v", data)
	}
	if _, ok := data["./usr/share/man/man1/"]; !ok {
		t.Errorf("missing dir entry: %v", data)
	}
	ctl := untar(members["control.tar.gz"])
	c := ctl["./control"]
	for _, want := range []string{"Package: setura", "Version: 0.6.0", "Architecture: arm64", "Maintainer: Zyvor AI Labs <sales@zyvor.dev>", "Installed-Size: 1\n", "\n Zyvor Setura is"} {
		if !strings.Contains(c, want) {
			t.Errorf("control lacks %q:\n%s", want, c)
		}
	}
	sum := fmt.Sprintf("%x  usr/bin/setura\n", md5.Sum([]byte("#!/bin/sh\necho hi\n")))
	if !strings.Contains(ctl["./md5sums"], sum) {
		t.Errorf("md5sums: %s", ctl["./md5sums"])
	}
	// reproducible
	again, _ := buildDeb(testMeta(), files)
	if !bytes.Equal(deb, again) {
		t.Error("deb is not reproducible")
	}
}

// rpm header reader for the test.
type rpmHdr struct {
	idx   map[uint32][3]uint32 // tag -> type, offset, count
	store []byte
	raw   []byte
}

func readHdr(t *testing.T, b []byte) (rpmHdr, []byte) {
	t.Helper()
	if !bytes.HasPrefix(b, []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}) {
		t.Fatal("bad header magic")
	}
	n := int(binary.BigEndian.Uint32(b[8:]))
	sz := int(binary.BigEndian.Uint32(b[12:]))
	h := rpmHdr{idx: map[uint32][3]uint32{}}
	for i := 0; i < n; i++ {
		e := b[16+16*i:]
		h.idx[binary.BigEndian.Uint32(e)] = [3]uint32{binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:]), binary.BigEndian.Uint32(e[12:])}
	}
	end := 16 + 16*n + sz
	h.store = b[16+16*n : end]
	h.raw = b[:end]
	return h, b[end:]
}

func (h rpmHdr) str(tag uint32) string {
	e := h.idx[tag]
	s := h.store[e[1]:]
	return string(s[:bytes.IndexByte(s, 0)])
}

func (h rpmHdr) strs(tag uint32) []string {
	e := h.idx[tag]
	s := h.store[e[1]:]
	var out []string
	for i := uint32(0); i < e[2]; i++ {
		j := bytes.IndexByte(s, 0)
		out = append(out, string(s[:j]))
		s = s[j+1:]
	}
	return out
}

func (h rpmHdr) u32(tag uint32) []uint32 {
	e := h.idx[tag]
	var out []uint32
	for i := uint32(0); i < e[2]; i++ {
		out = append(out, binary.BigEndian.Uint32(h.store[e[1]+4*i:]))
	}
	return out
}

func TestRPM(t *testing.T) {
	files := stage(t)
	rpm, err := buildRPM(testMeta(), files)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(rpm) != 0xedabeedb || rpm[4] != 3 || binary.BigEndian.Uint16(rpm[8:]) != 12 || binary.BigEndian.Uint16(rpm[78:]) != 5 {
		t.Fatalf("bad lead % x", rpm[:96])
	}
	if !strings.HasPrefix(string(rpm[10:]), "setura-0.6.0-1\x00") {
		t.Errorf("lead name %q", rpm[10:30])
	}
	sig, rest := readHdr(t, rpm[96:])
	pad := (8 - len(sig.raw)%8) % 8
	main, payload := readHdr(t, rest[pad:])

	// signature header: size, md5 and digests match what follows.
	if got := sig.u32(1000)[0]; int(got) != len(main.raw)+len(payload) {
		t.Errorf("sig size %d != %d", got, len(main.raw)+len(payload))
	}
	e := sig.idx[1004]
	md := md5.Sum(append(append([]byte{}, main.raw...), payload...))
	if !bytes.Equal(sig.store[e[1]:e[1]+16], md[:]) {
		t.Error("md5 mismatch")
	}
	if sig.str(273) != fmt.Sprintf("%x", sha256.Sum256(main.raw)) {
		t.Error("header sha256 mismatch")
	}
	// region trailers cover every entry.
	for _, h := range []struct {
		h   rpmHdr
		tag uint32
	}{{sig, 62}, {main, 63}} {
		e := h.h.idx[h.tag]
		tr := h.h.store[e[1]:]
		if int32(binary.BigEndian.Uint32(tr[8:])) != -int32(16*len(h.h.idx)) {
			t.Errorf("region %d trailer offset", h.tag)
		}
	}
	if main.str(1000) != "setura" || main.str(1001) != "0.6.0" || main.str(1022) != "aarch64" || main.str(1124) != "cpio" {
		t.Errorf("tags: %s %s %s", main.str(1000), main.str(1001), main.str(1022))
	}
	// file list matches the staged tree.
	bases, dirnames, idx := main.strs(1117), main.strs(1118), main.u32(1116)
	var paths []string
	for i := range bases {
		paths = append(paths, dirnames[idx[i]]+bases[i])
	}
	var want []string
	for _, f := range rpmOwned(testMeta(), files) {
		want = append(want, f.Path)
	}
	if strings.Join(paths, " ") != strings.Join(want, " ") {
		t.Errorf("paths %v want %v", paths, want)
	}
	// payload is a gzip newc cpio with the same names and contents.
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	cpio, _ := io.ReadAll(zr)
	if main.u32(1046)[0] != uint32(len(cpio)) || sig.u32(1007)[0] != uint32(len(cpio)) {
		t.Error("payload size tags")
	}
	got := map[string]string{}
	for len(cpio) > 0 {
		if string(cpio[:6]) != "070701" {
			t.Fatalf("cpio magic %q", cpio[:6])
		}
		f := func(i int) int { v, _ := strconv.ParseInt(string(cpio[6+8*i:14+8*i]), 16, 64); return int(v) }
		size, nlen := f(6), f(11)
		name := string(cpio[110 : 110+nlen-1])
		off := align(110+nlen, 4)
		got[name] = string(cpio[off : off+size])
		cpio = cpio[align(off+size, 4):]
	}
	if got["./usr/bin/setura"] != "#!/bin/sh\necho hi\n" || len(got) != len(rpmOwned(testMeta(), files))+1 {
		t.Errorf("cpio: %v", got)
	}
	if _, ok := got["TRAILER!!!"]; !ok {
		t.Error("no trailer")
	}
	again, _ := buildRPM(testMeta(), files)
	if !bytes.Equal(rpm, again) {
		t.Error("rpm is not reproducible")
	}
}

func TestBadArch(t *testing.T) {
	m := testMeta()
	m.Arch = "riscv"
	if _, err := buildDeb(m, nil); err == nil {
		t.Error("deb accepted riscv")
	}
	if _, err := buildRPM(m, nil); err == nil {
		t.Error("rpm accepted riscv")
	}
}
