package setura

import (
	"math"
	"strings"
	"testing"
)

func runYAMLCases(t *testing.T, cases []struct{ name, src, want string }) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := yamlJSON(t, c.src); got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestYAML11Scalars(t *testing.T) {
	runYAMLCases(t, []struct{ name, src, want string }{
		{"bools", "a: yes\nb: No\nc: on\nd: OFF\ne: y\nf: N\ng: True\n", `{"a":true,"b":false,"c":true,"d":false,"e":true,"f":false,"g":true}`},
		{"quoted stay strings", "a: \"yes\"\nb: 'on'\nc: \"0x10\"\nd: '1_000'\ne: \"~\"\n", `{"a":"yes","b":"on","c":"0x10","d":"1_000","e":"~"}`},
		{"tagged str", "a: !!str yes\nb: !!str 0x1F\n", `{"a":"yes","b":"0x1F"}`},
		{"tagged bool", "a: !!bool yes\n", `{"a":true}`},
		{"hex octal binary", "a: 0x1F\nb: 0755\nc: 0b101\nd: 0o17\ne: 010\nf: 08\n", `{"a":31,"b":493,"c":5,"d":15,"e":8,"f":8}`},
		{"underscores", "a: 1_000\nb: 0x_FF\nc: 1_0.5\n", `{"a":1000,"b":255,"c":10.5}`},
		{"words stay strings", "a: yesterday\nb: nope\nc: 1__\nd: _1\ne: 0x\nf: 12ab\n", `{"a":"yesterday","b":"nope","c":1,"d":"_1","e":"0x","f":"12ab"}`},
		{"in flow", "a: [yes, \"yes\", 0x10, no]\n", `{"a":[true,"yes",16,false]}`},
		{"keys keep text", "on: 1\ny: 2\n0x10: 3\n", `{"0x10":3,"on":1,"y":2}`},
		{"flow keys keep text", "m: {on: 1, 0x10: 2, \"no\": 3}\n", `{"m":{"0x10":2,"no":3,"on":1}}`},
	})
}

func TestYAML11Floats(t *testing.T) {
	for _, s := range []string{".inf", "-.inf", ".Inf", "+.INF", ".nan", ".NaN"} {
		docs, err := decodeManifests([]byte("a: " + s + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		f, ok := docs[0].(map[string]any)["a"].(float64)
		switch {
		case !ok:
			t.Errorf("%s decoded to %v", s, docs[0])
		case strings.Contains(strings.ToLower(s), "nan") != math.IsNaN(f):
			t.Errorf("%s: NaN mismatch (%v)", s, f)
		case !math.IsNaN(f) && !math.IsInf(f, 0):
			t.Errorf("%s: not infinite (%v)", s, f)
		}
	}
	if d, _ := decodeManifests([]byte("a: -.inf\n")); !math.IsInf(d[0].(map[string]any)["a"].(float64), -1) {
		t.Error("-.inf is not negative infinity")
	}
}

func TestYAMLExplicitKeys(t *testing.T) {
	runYAMLCases(t, []struct{ name, src, want string }{
		{"simple", "? a\n: 1\n? b\n: 2\n", `{"a":1,"b":2}`},
		{"no value", "? a\nb: 1\n", `{"a":null,"b":1}`},
		{"mixed with implicit", "x: 0\n? y\n: 1\nz: 2\n", `{"x":0,"y":1,"z":2}`},
		{"multi-line plain key", "? one\n  two\n: v\n", `{"one two":"v"}`},
		{"multi-line quoted key", "? \"one\n  two\"\n: v\n", `{"one two":"v"}`},
		{"literal key", "? |\n  line1\n  line2\n: v\n", `{"line1\nline2\n":"v"}`},
		{"key text kept", "? on\n: 1\n? 0x10\n: 2\n", `{"0x10":2,"on":1}`},
		{"nested value", "? k\n:\n  a: 1\n  b: [x, z]\n", `{"k":{"a":1,"b":["x","z"]}}`},
		{"value on marker line", "? k\n: v\n", `{"k":"v"}`},
		{"value mapping on marker line", "? k\n: a: 1\n  b: 2\n", `{"k":{"a":1,"b":2}}`},
		{"value sequence on marker line", "? k\n: - a\n  - b\n", `{"k":["a","b"]}`},
		{"value sequence at key indent", "? k\n:\n- a\n- b\n", `{"k":["a","b"]}`},
		{"sequence key", "? - a\n  - b\n: v\n", `{"[\"a\",\"b\"]":"v"}`},
		{"mapping key", "? a: 1\n  b: 2\n: v\n", `{"{\"a\":1,\"b\":2}":"v"}`},
		{"flow key over lines", "? [a,\n   b]\n: v\n", `{"[\"a\",\"b\"]":"v"}`},
		{"nested in mapping", "spec:\n  ? rules\n  : - x\n  other: 1\n", `{"spec":{"other":1,"rules":["x"]}}`},
		{"in sequence item", "- ? k\n  : v\n  z: 1\n- q\n", `[{"k":"v","z":1},"q"]`},
		{"comment after indicator", "? k # c\n: v # d\n", `{"k":"v"}`},
		{"question mark word", "a: ?b\n?c: 1\n", `{"?c":1,"a":"?b"}`},
	})
}
