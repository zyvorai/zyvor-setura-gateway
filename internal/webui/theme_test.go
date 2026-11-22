package webui

import (
	"regexp"
	"strings"
	"testing"
)

// The theme switch is plain inline script and CSS: a keyboard-reachable
// button, a persisted choice and overrides that win over the OS preference.
func TestPageHasAccessibleThemeToggle(t *testing.T) {
	s := string(page)
	for _, want := range []string{
		`id="themebtn" type="button"`,    // a real button: focusable, Enter and Space activate it
		`aria-label="Theme: system"`,     // has an accessible name before the script runs
		`localStorage.getItem(KEY)`,      // restored on load
		`localStorage.setItem(KEY,m)`,    // persisted on change
		`setAttribute('aria-label',lbl)`, // name tracks the state
		`:root[data-theme="dark"]{`,      // forced dark
		`:root[data-theme="light"]{color-scheme:light}`,
		`:root:not([data-theme="light"])`, // the OS dark preference yields to a forced light
		`modes=['system','light','dark']`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Both dark variable sets must stay identical: forced dark and OS dark.
	re := regexp.MustCompile(`--bg:#000000;[^}]*`)
	blocks := re.FindAllString(s, -1)
	if len(blocks) != 2 || blocks[0] != blocks[1] {
		t.Errorf("the dark palette is not defined identically in both places: %d blocks", len(blocks))
	}
	// localStorage may be unavailable (private mode): every access is guarded.
	for _, want := range []string{"try{var v=localStorage.getItem(KEY)", "try{if(m==='system')localStorage.removeItem(KEY)"} {
		if !strings.Contains(s, want) {
			t.Errorf("localStorage access must be wrapped in try/catch: %q", want)
		}
	}
}
