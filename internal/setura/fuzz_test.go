package setura

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Native fuzz targets for the readers of untrusted input: the migrate YAML
// decoder and the replay access-log parsers. `go test` runs every seed (inline
// f.Add values and testdata/fuzz/<Target>); explore with, for example,
//
//	go test ./internal/setura -run '^$' -fuzz FuzzDecodeManifests -fuzztime 30s
//
// SETURA_WRITE_SEEDS=1 go test -run TestWriteFuzzSeeds rewrites the committed
// seed files from the inline seeds and the examples/ directory.

func exampleSeeds(t testing.TB, glob string) [][]byte {
	var out [][]byte
	files, _ := filepath.Glob(filepath.Join("..", "..", "examples", glob))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if len(b) > 64<<10 {
				b = b[:64<<10]
			}
			out = append(out, b)
		}
	}
	return out
}

var yamlSeeds = []string{
	"a: 1\nb:\n  - x\n  - y: z\n",
	"---\nkind: Ingress\nmetadata: {name: a, labels: {k: v}}\n---\n# empty\n---\n",
	"base: &b {x: 1}\nuse:\n  <<: *b\n  y: 2\n",
	"s: |\n  line1\n  line2\nf: >-\n  folded\n  text\n",
	"? complex\n: value\n[1, 2, {a: b}]: x\n",
	"a: *missing\n",
	"- - - - [\n",
	"{\"kind\": \"List\", \"items\": []}",
	"k: 'it''s'\nj: \"esc \\u00e9 \\x41\"\ny: yes\nn: 0o17\nz: 0x1F\nd: 1e3\n",
	"\ufeffkey: value\r\n\ttab: bad\r\n",
	"a:\n b:\n  c:\n   d:\n    e: 1\n  x: 2\n",
}

func FuzzDecodeManifests(f *testing.F) {
	for _, s := range yamlSeeds {
		f.Add([]byte(s))
	}
	for _, b := range exampleSeeds(f, filepath.Join("migrate", "*.yaml")) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		docs, err := decodeManifests(data)
		if err != nil && docs != nil {
			t.Fatalf("error %v with %d documents", err, len(docs))
		}
	})
}

var logSeeds = []string{
	`{"time":"2026-01-02T03:04:05Z","listener":"web","host":"a.test","method":"GET","path":"/x?y=1","status":200,"route":"r","backend":"b"}`,
	`{"host":"a.test","path":"/\u00e9\"q","status":"200","extra":{"nested":[1,2,{"a":null}]}}`,
	`time=2026-01-02T03:04:05Z listener=web host=a.test method=GET path="/a b" status=502 route=r backend=b`,
	`host=x method=POST path=/ status=abc`,
	`127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://x/" "Mozilla/4.08"`,
	`10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 404 0`,
	`{`, `{"a"`, `{"path":"/x","status":` + strings.Repeat("9", 40) + `}`, `"`, `-`,
	`1.2.3.4 - - [x] "` + strings.Repeat("A", 4096) + `" 200 1`,
}

func FuzzReplayLogLine(f *testing.F) {
	for _, s := range logSeeds {
		f.Add([]byte(s), "default.test")
	}
	for _, b := range exampleSeeds(f, filepath.Join("replay", "access.jsonl")) {
		for _, l := range strings.Split(string(b), "\n")[:3] {
			f.Add([]byte(l), "")
		}
	}
	f.Fuzz(func(t *testing.T, line []byte, host string) {
		if len(line) == 0 { // the reader never passes an empty line
			return
		}
		var in interner
		var rec logRec
		ok := in.parseLogLine(line, &rec, host)
		if ok && rec.format == "" {
			t.Fatal("accepted a line without a format")
		}
		if ok && (rec.status < 0 || rec.status > 1<<20) {
			t.Logf("status %d", rec.status)
		}
		isGRPCLog(&rec)
	})
}

func TestWriteFuzzSeeds(t *testing.T) {
	if os.Getenv("SETURA_WRITE_SEEDS") != "1" {
		t.Skip("set SETURA_WRITE_SEEDS=1 to rewrite testdata/fuzz")
	}
	write := func(target, name, body string) {
		dir := filepath.Join("testdata", "fuzz", target)
		os.MkdirAll(dir, 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("go test fuzz v1\n"+body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, s := range yamlSeeds {
		write("FuzzDecodeManifests", "seed"+strconv.Itoa(i), "[]byte("+strconv.Quote(s)+")")
	}
	for i, b := range exampleSeeds(t, filepath.Join("migrate", "*.yaml")) {
		write("FuzzDecodeManifests", "example"+strconv.Itoa(i), "[]byte("+strconv.Quote(string(b))+")")
	}
	for i, s := range logSeeds {
		write("FuzzReplayLogLine", "seed"+strconv.Itoa(i), "[]byte("+strconv.Quote(s)+")\nstring(\"default.test\")")
	}
}
