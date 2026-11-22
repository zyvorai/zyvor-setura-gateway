package setura

import (
	"strings"
	"testing"
)

func TestUnknownFlagSuggestsAndHints(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want []string
		deny []string
	}{
		{"flag typo", []string{"ui", "--listn", "127.0.0.1:0"}, 2,
			[]string{"unknown flag --listn", "Did you mean --listen?", "Next: setura ui -h"},
			[]string{"flag provided but not defined"}},
		{"no suggestion when far", []string{"ui", "--zzzzzzzz"}, 2,
			[]string{"unknown flag --zzzzzzzz", "Next: setura ui -h"}, []string{"Did you mean"}},
		{"help still works", []string{"ui", "-h"}, 0, []string{"--listen"}, nil},
		{"command typo", []string{"lnit"}, 2, []string{`Did you mean "init"?`, "Next: setura --help"}, nil},
		{"user error gets a hint", []string{"ui", "--interval", "10ms"}, 2, []string{"--interval must be at least 1s", "Next: setura ui -h"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb strings.Builder
			code := Main(tt.args, &out, &errb)
			got := errb.String()
			if code != tt.code {
				t.Errorf("exit %d want %d\n%s", code, tt.code, got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("stderr lacks %q:\n%s", w, got)
				}
			}
			for _, w := range tt.deny {
				if strings.Contains(got, w) {
					t.Errorf("stderr must not contain %q:\n%s", w, got)
				}
			}
			if strings.Count(got, "unknown flag") > 1 {
				t.Errorf("message duplicated:\n%s", got)
			}
		})
	}
}
