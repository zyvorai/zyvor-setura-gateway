package setura

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestManCoversCommands(t *testing.T) {
	var b bytes.Buffer
	if err := Man(&b); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, c := range []string{"publish", "lint", "completion", "man", "version"} {
		if !strings.Contains(s, ".B "+c) {
			t.Errorf("man page missing %q", c)
		}
	}
}

func TestManFileInSync(t *testing.T) {
	want, err := os.ReadFile("../../man/setura.1")
	if err != nil {
		t.Skip("man/setura.1 not generated")
	}
	var b bytes.Buffer
	Man(&b)
	if b.String() != string(want) {
		t.Error("man/setura.1 is stale; run make man")
	}
}
