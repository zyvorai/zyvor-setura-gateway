package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// RPM v3 package with a header-style signature, gzip cpio (newc) payload and
// SHA-256 file digests, written by hand from the format description.

const (
	tInt16 = 3
	tInt32 = 4
	tStr   = 6
	tBin   = 7
	tStrA  = 8
	tI18N  = 9

	tagRegionSig  = 62
	tagRegionMain = 63
)

type hdrTag struct {
	tag, typ, count uint32
	data            []byte
}

func tagStr(tag uint32, s string) hdrTag { return hdrTag{tag, tStr, 1, append([]byte(s), 0)} }
func tagI18N(tag uint32, s string) hdrTag {
	return hdrTag{tag, tI18N, 1, append([]byte(s), 0)}
}
func tagBin(tag uint32, b []byte) hdrTag { return hdrTag{tag, tBin, uint32(len(b)), b} }
func tagInt32(tag uint32, v ...uint32) hdrTag {
	b := make([]byte, 0, 4*len(v))
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return hdrTag{tag, tInt32, uint32(len(v)), b}
}
func tagInt16(tag uint32, v ...uint16) hdrTag {
	b := make([]byte, 0, 2*len(v))
	for _, x := range v {
		b = binary.BigEndian.AppendUint16(b, x)
	}
	return hdrTag{tag, tInt16, uint32(len(v)), b}
}
func tagStrArray(tag uint32, v ...string) hdrTag {
	var b []byte
	for _, s := range v {
		b = append(append(b, s...), 0)
	}
	return hdrTag{tag, tStrA, uint32(len(v)), b}
}

func align(n int, a int) int { return (n + a - 1) / a * a }

// buildHeader serialises tags as an RPM header structure with a region tag
// (62 for the signature header, 63 for the main header) covering all entries.
func buildHeader(tags []hdrTag, region uint32) []byte {
	sort.Slice(tags, func(i, j int) bool { return tags[i].tag < tags[j].tag })
	var store []byte
	type ent struct{ tag, typ, off, count uint32 }
	ents := make([]ent, 0, len(tags)+1)
	for _, t := range tags {
		switch t.typ {
		case tInt16:
			store = append(store, make([]byte, align(len(store), 2)-len(store))...)
		case tInt32:
			store = append(store, make([]byte, align(len(store), 4)-len(store))...)
		}
		ents = append(ents, ent{t.tag, t.typ, uint32(len(store)), t.count})
		store = append(store, t.data...)
	}
	n := len(ents) + 1
	trailer := make([]byte, 16)
	binary.BigEndian.PutUint32(trailer[0:], region)
	binary.BigEndian.PutUint32(trailer[4:], tBin)
	binary.BigEndian.PutUint32(trailer[8:], uint32(int32(-n*16)))
	binary.BigEndian.PutUint32(trailer[12:], 16)
	regionEnt := ent{region, tBin, uint32(len(store)), 16}
	store = append(store, trailer...)
	ents = append([]ent{regionEnt}, ents...)

	var b bytes.Buffer
	b.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	binary.Write(&b, binary.BigEndian, uint32(len(ents)))
	binary.Write(&b, binary.BigEndian, uint32(len(store)))
	for _, e := range ents {
		binary.Write(&b, binary.BigEndian, []uint32{e.tag, e.typ, e.off, e.count})
	}
	b.Write(store)
	return b.Bytes()
}

// cpioNewc writes the payload archive. Names carry a "./" prefix.
func cpioNewc(files []entry) []byte {
	var b bytes.Buffer
	write := func(ino int, mode uint32, mtime int64, data []byte, name string) {
		fmt.Fprintf(&b, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, 1, mtime, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		b.Write(make([]byte, align(110+len(name)+1, 4)-(110+len(name)+1)))
		b.Write(data)
		b.Write(make([]byte, align(len(data), 4)-len(data)))
	}
	for i, e := range files {
		mode := e.Mode | 0o100000
		if e.IsDir {
			mode = e.Mode | 0o040000
		}
		write(i+1, mode, e.Mtime, e.Data, "."+e.Path)
	}
	write(0, 0, 0, nil, "TRAILER!!!")
	return b.Bytes()
}

// rpmOwned drops directories the package must not own (/usr, /usr/bin, ...
// belong to the filesystem package); only the package's own doc directory is
// listed. Files keep their parents implicitly.
func rpmOwned(m meta, files []entry) []entry {
	own := "/usr/share/doc/" + m.Name
	var out []entry
	for _, e := range files {
		if e.IsDir && e.Path != own && !strings.HasPrefix(e.Path, own+"/") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func rpmArch(a string) (name string, num uint16, err error) {
	switch a {
	case "amd64":
		return "x86_64", 1, nil
	case "arm64":
		return "aarch64", 12, nil
	}
	return "", 0, fmt.Errorf("unsupported arch %q", a)
}

func buildRPM(m meta, files []entry) ([]byte, error) {
	arch, archNum, err := rpmArch(m.Arch)
	if err != nil {
		return nil, err
	}
	version := strings.ReplaceAll(m.Version, "-", "~")
	files = rpmOwned(m, files)
	const release = "1"
	payload := cpioNewc(files)
	compressed := gz(payload)

	var sizes, dirIdx, inodes []uint32
	var modes []uint16
	var mtimes []uint32
	var digests, bases, dirnames, links, langs, users, groups []string
	var devices, vflags, flags []uint32
	var rdev16 []uint16
	dirIndex := map[string]uint32{}
	total := 0
	for i, e := range files {
		dir, base := splitPath(e.Path)
		idx, ok := dirIndex[dir]
		if !ok {
			idx = uint32(len(dirnames))
			dirIndex[dir] = idx
			dirnames = append(dirnames, dir)
		}
		dirIdx = append(dirIdx, idx)
		bases = append(bases, base)
		mode := uint16(e.Mode | 0o100000)
		dig, size := e.SHA256, uint32(len(e.Data))
		if e.IsDir {
			mode, dig, size = uint16(e.Mode|0o040000), "", 4096
		} else {
			total += len(e.Data)
		}
		modes = append(modes, mode)
		sizes = append(sizes, size)
		digests = append(digests, dig)
		mtimes = append(mtimes, uint32(e.Mtime))
		links = append(links, "")
		langs = append(langs, "")
		users = append(users, "root")
		groups = append(groups, "root")
		devices = append(devices, 1)
		inodes = append(inodes, uint32(i+1))
		vflags = append(vflags, 0xffffffff)
		flags = append(flags, 0)
		rdev16 = append(rdev16, 0)
	}

	const rpmlibLE = 0x0100000A // RPMSENSE_RPMLIB | LESS | EQUAL
	tags := []hdrTag{
		tagStrArray(100, "C"),
		tagStr(1000, m.Name),
		tagStr(1001, version),
		tagStr(1002, release),
		tagI18N(1004, m.Summary),
		tagI18N(1005, m.Description),
		tagInt32(1006, uint32(m.Mtime)),
		tagStr(1007, "localhost"),
		tagInt32(1009, uint32(total)),
		tagStr(1011, m.Vendor),
		tagStr(1014, m.License),
		tagStr(1015, m.Maintainer),
		tagI18N(1016, "Unspecified"),
		tagStr(1020, m.Homepage),
		tagStr(1021, "linux"),
		tagStr(1022, arch),
		tagInt32(1028, sizes...),
		tagInt16(1030, modes...),
		tagInt16(1033, rdev16...),
		tagInt32(1034, mtimes...),
		tagStrArray(1035, digests...),
		tagStrArray(1036, links...),
		tagInt32(1037, flags...),
		tagStrArray(1039, users...),
		tagStrArray(1040, groups...),
		tagStr(1044, "(none)"),
		tagInt32(1045, vflags...),
		tagInt32(1046, uint32(len(payload))),
		tagStrArray(1047, m.Name),
		tagInt32(1048, rpmlibLE, rpmlibLE, rpmlibLE),
		tagStrArray(1049, "rpmlib(CompressedFileNames)", "rpmlib(PayloadFilesHavePrefix)", "rpmlib(FileDigests)"),
		tagStrArray(1050, "3.0.4-1", "4.0-1", "4.6.0-1"),
		tagInt32(1095, devices...),
		tagInt32(1096, inodes...),
		tagStrArray(1097, langs...),
		tagInt32(1112, 8),
		tagStrArray(1113, version+"-"+release),
		tagInt32(1116, dirIdx...),
		tagStrArray(1117, bases...),
		tagStrArray(1118, dirnames...),
		tagStr(1124, "cpio"),
		tagStr(1125, "gzip"),
		tagStr(1126, "9"),
		tagInt32(5011, 8), // FILEDIGESTALGO: SHA-256
	}
	hdr := buildHeader(tags, tagRegionMain)

	md := md5.New()
	md.Write(hdr)
	md.Write(compressed)
	s1 := sha1.Sum(hdr)
	s256 := sha256.Sum256(hdr)
	sig := buildHeader([]hdrTag{
		tagStr(269, fmt.Sprintf("%x", s1)),
		tagStr(273, fmt.Sprintf("%x", s256)),
		tagInt32(1000, uint32(len(hdr)+len(compressed))),
		tagBin(1004, md.Sum(nil)),
		tagInt32(1007, uint32(len(payload))),
	}, tagRegionSig)

	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[8:], archNum)
	copy(lead[10:], fmt.Sprintf("%s-%s-%s", m.Name, version, release))
	binary.BigEndian.PutUint16(lead[76:], 1) // os: Linux
	binary.BigEndian.PutUint16(lead[78:], 5) // signature type: header-style

	var out bytes.Buffer
	out.Write(lead)
	out.Write(sig)
	out.Write(make([]byte, align(len(sig), 8)-len(sig)))
	out.Write(hdr)
	out.Write(compressed)
	return out.Bytes(), nil
}
