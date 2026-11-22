package setura

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signLicence builds a key exactly like zyvor_licence.py sign_key: compact JSON
// in the reference field order, raw UTF-8, base64url without padding.
func signLicence(priv ed25519.PrivateKey, payload string) string {
	raw := []byte(payload)
	return "ZYV1." + b64u(raw) + "." + b64u(ed25519.Sign(priv, raw))
}

func licPayload(product, edition string, macs int, issued, expires int64, licensee string) string {
	return fmt.Sprintf(`{"v":1,"product":"%s","edition":"%s","id":"0011223344556677","licensee":"%s","email":"ops@acme.example","macs":%d,"issued":%d,"expires":%d}`,
		product, edition, licensee, macs, issued, expires)
}

func TestLicenceVerifyMatrix(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	keys := []ed25519.PublicKey{other, pub} // rotation: any key may verify
	now := time.Unix(1700000000, 0)
	day := int64(86400)

	cases := []struct {
		name, key, status, tier string
		valid                   bool
		clusters                int
	}{
		{"per cluster", signLicence(priv, licPayload("setura", "pro", 3, 1700000000-day, 1700000000+30*day, "Acme")), "valid", "per cluster", true, 3},
		{"team", signLicence(priv, licPayload("setura", "pro", 10, 1700000000-day, 1700000000+30*day, "Acme")), "valid", "team", true, 10},
		{"enterprise", signLicence(priv, licPayload("setura", "pro", 25, 1700000000-day, 1700000000+30*day, "Acme")), "valid", "enterprise", true, 25},
		{"trial", signLicence(priv, licPayload("setura", "trial", 1, 1700000000-day, 1700000000+30*day, "Acme")), "valid", "trial", true, 1},
		{"expired", signLicence(priv, licPayload("setura", "pro", 1, 1700000000-9*day, 1700000000-day, "Acme")), "expired", "per cluster", false, 1},
		{"expires now", signLicence(priv, licPayload("setura", "pro", 1, 0, 1700000000, "Acme")), "expired", "per cluster", false, 1},
		{"wrong product", signLicence(priv, licPayload("velora", "pro", 1, 0, 1700000000+day, "Acme")), "wrong product", "per cluster", false, 1},
		{"non ascii licensee", signLicence(priv, licPayload("setura", "pro", 1, 0, 1700000000+day, "Zoë Müller")), "valid", "per cluster", true, 1},
	}
	for _, c := range cases {
		r := VerifyLicence(c.key, keys, "setura", now)
		if r.Status != c.status || r.Valid != c.valid || r.Tier != c.tier || r.Clusters != c.clusters {
			t.Errorf("%s: got %+v", c.name, r)
		}
	}
	if r := VerifyLicence(cases[7].key, keys, "setura", now); r.IssuedTo != "Zoë Müller" {
		t.Errorf("licensee = %q", r.IssuedTo)
	}

	good := cases[0].key
	parts := strings.Split(good, ".")
	tamper := func(s string) string { // flip one character
		b := []byte(s)
		if b[10] == 'A' {
			b[10] = 'B'
		} else {
			b[10] = 'A'
		}
		return string(b)
	}
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	bad := map[string]string{
		"":             "bad format",
		"nope":         "bad format",
		"ZYV2.a.b":     "bad format",
		"ZYV1.only":    "bad format",
		"ZYV1.a.b.c":   "bad format",
		"ZYV1.!!!.!!!": "bad signature",
		"ZYV1." + tamper(parts[1]) + "." + parts[2]:                                       "bad signature",
		"ZYV1." + parts[1] + "." + tamper(parts[2]):                                       "bad signature",
		signLicence(otherPriv, licPayload("setura", "pro", 1, 0, 1700000000+day, "Acme")): "bad signature",
	}
	for k, want := range bad {
		if r := VerifyLicence(k, keys, "setura", now); r.Status != want || r.Valid {
			t.Errorf("%q: got %q want %q", k, r.Status, want)
		}
	}
	// Padded, standard-alphabet and whitespace-wrapped encodings are accepted like the reference.
	raw := []byte(licPayload("setura", "pro", 1, 0, 1700000000+day, "Acme"))
	padded := "ZYV1." + base64.StdEncoding.EncodeToString(raw) + "." + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	if r := VerifyLicence("  "+padded+"\n", keys, "setura", now); !r.Valid {
		t.Errorf("padded std base64: %+v", r)
	}
	if r := VerifyLicence(good, nil, "setura", now); r.Status != "bad signature" {
		t.Errorf("no embedded keys must not verify: %+v", r)
	}
}

func TestParseLicenceKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	text := "# comment\n\nsetura " + b64u(pub) + "\nvelora " + b64u(pub) + "\nsetura short\nsetura\n"
	got := parseLicenceKeys(text, "setura")
	if len(got) != 1 || !bytes.Equal(got[0], pub) {
		t.Fatalf("got %d keys", len(got))
	}
	for _, k := range parseLicenceKeys(licenceKeysFile, "setura") {
		if len(k) != ed25519.PublicKeySize {
			t.Fatal("bad embedded key")
		}
	}
}

func TestLicenceCommand(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	// The command verifies against the embedded list, so swap it for the test.
	old := licenceKeysFile
	licenceKeysFile = "setura " + b64u(pub) + "\n"
	defer func() { licenceKeysFile = old }()

	now := time.Unix(1700000000, 0)
	key := signLicence(priv, licPayload("setura", "pro", 5, 1699990000, 1700000000+10*86400, "Acme Ltd"))
	dir := t.TempDir()
	file := filepath.Join(dir, "k")
	if err := os.WriteFile(file, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SETURA_LICENCE_FILE": filepath.Join(dir, "absent")}
	getenv := func(k string) string { return env[k] }

	run := func(stdin string, args ...string) (int, string) {
		var o, e bytes.Buffer
		c := runLicence(args, strings.NewReader(stdin), &o, &e, getenv, now)
		return c, o.String()
	}
	if c, o := run("", "verify", key); c != 0 || !strings.Contains(o, "status    valid") || !strings.Contains(o, "per cluster") || !strings.Contains(o, "5 clusters") || !strings.Contains(o, "Acme Ltd") || !strings.Contains(o, "10 day(s) left") {
		t.Errorf("verify key: %d %s", c, o)
	}
	if c, _ := run("", "verify", "--file", file); c != 0 {
		t.Errorf("verify --file: %d", c)
	}
	if c, _ := run(key, "verify", "-"); c != 0 {
		t.Errorf("verify stdin: %d", c)
	}
	if c, o := run("", "verify", "--format", "json", key); c != 0 || !strings.Contains(o, `"status": "valid"`) {
		t.Errorf("json: %d %s", c, o)
	}
	if c, o := run("", "verify", "ZYV1.x.y"); c != 1 || !strings.Contains(o, "bad signature") {
		t.Errorf("bad: %d %s", c, o)
	}
	if c, _ := run("", "verify", "--file", filepath.Join(dir, "missing")); c != 2 {
		t.Errorf("missing file: %d", c)
	}
	for _, args := range [][]string{{}, {"bogus"}, {"verify"}, {"verify", "a", "b"}, {"show", "x"}, {"verify", "--format", "xml", key}} {
		if c, _ := run("", args...); c != 2 {
			t.Errorf("%v: want usage exit 2, got %d", args, c)
		}
	}
	// show: no key -> unlicensed (exit 1); env and file are found.
	if c, o := run("", "show"); c != 1 || !strings.Contains(o, "unlicensed") {
		t.Errorf("show none: %d %s", c, o)
	}
	env["SETURA_LICENCE_FILE"] = file
	if c, o := run("", "show"); c != 0 || !strings.Contains(o, "valid") {
		t.Errorf("show file: %d %s", c, o)
	}
	env["SETURA_LICENCE_KEY"] = "garbage"
	if c, _ := run("", "show"); c != 1 {
		t.Errorf("show garbage: %d", c)
	}
	if l := licenceLine(getenv, now); !strings.Contains(l, "unlicensed") || !strings.Contains(l, "bad format") {
		t.Errorf("line = %q", l)
	}
	delete(env, "SETURA_LICENCE_KEY")
	if l := licenceLine(getenv, now); !strings.Contains(l, "per cluster, 5 clusters, expires 2023-11-24") {
		t.Errorf("line = %q", l)
	}
}

func TestVersionVerboseIsAdvisory(t *testing.T) {
	t.Setenv("SETURA_LICENCE_KEY", "")
	t.Setenv("SETURA_LICENCE_FILE", filepath.Join(t.TempDir(), "none"))
	var o, e bytes.Buffer
	if c := Main([]string{"version", "--verbose"}, &o, &e); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if !strings.Contains(o.String(), "unlicensed (trial)") {
		t.Errorf("missing licence line:\n%s", o.String())
	}
}
