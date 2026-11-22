// Command mkpkg builds a .deb or .rpm from a staged directory tree, using only
// the Go standard library (no dpkg, rpm, fpm or nfpm). It is used by
// scripts/package.sh and is not part of the setura binary.
//
//	mkpkg -format deb|rpm -root STAGE -out FILE -version X.Y.Z -arch amd64|arm64 [-mtime SECONDS]
//
// Every path under STAGE is installed at the same absolute path (STAGE/usr/bin/setura
// becomes /usr/bin/setura). Owners are root, modes come from the files with
// directories forced to 0755, and timestamps are -mtime (default
// SOURCE_DATE_EPOCH, else 0) so output is reproducible.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	var (
		format  = flag.String("format", "", "deb or rpm")
		root    = flag.String("root", "", "staged directory tree")
		out     = flag.String("out", "", "output file")
		version = flag.String("version", "", "package version, e.g. 0.6.0")
		arch    = flag.String("arch", "", "amd64 or arm64")
		mtime   = flag.Int64("mtime", defaultMtime(), "timestamp for every entry (default SOURCE_DATE_EPOCH or 0)")
	)
	flag.Parse()
	if *format == "" || *root == "" || *out == "" || *version == "" || *arch == "" {
		flag.Usage()
		os.Exit(2)
	}
	m := defaultMeta()
	m.Version = *version
	m.Arch = *arch
	m.Mtime = *mtime
	files, err := collect(*root, *mtime)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkpkg:", err)
		os.Exit(1)
	}
	var data []byte
	switch *format {
	case "deb":
		data, err = buildDeb(m, files)
	case "rpm":
		data, err = buildRPM(m, files)
	default:
		err = fmt.Errorf("unknown format %q", *format)
	}
	if err == nil {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkpkg:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", *out)
}

func defaultMtime() int64 {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}
