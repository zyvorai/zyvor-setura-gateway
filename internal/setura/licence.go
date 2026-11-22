package setura

import (
	"bufio"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// licenceProduct is the product name signed into every Setura licence key.
const licenceProduct = "setura"

//go:embed licence_keys.txt
var licenceKeysFile string

// Licence statuses printed by `setura licence`.
const (
	licValid        = "valid"
	licExpired      = "expired"
	licBadSignature = "bad signature"
	licWrongProduct = "wrong product"
	licBadFormat    = "bad format"
)

// licencePayload is the signed JSON of a ZYV1 key. The reference issuer is
// zyvor_licence.py: macs is the licensed unit count (clusters for Setura).
type licencePayload struct {
	V        int    `json:"v"`
	Product  string `json:"product"`
	Edition  string `json:"edition"`
	ID       string `json:"id"`
	Licensee string `json:"licensee"`
	Email    string `json:"email"`
	Macs     int    `json:"macs"`
	Issued   int64  `json:"issued"`
	Expires  int64  `json:"expires"`
	Seats    int    `json:"seats,omitempty"`
}

// LicenceResult is the outcome of verifying one key.
type LicenceResult struct {
	Status   string `json:"status"`
	Valid    bool   `json:"valid"`
	Tier     string `json:"tier,omitempty"`
	Product  string `json:"product,omitempty"`
	Edition  string `json:"edition,omitempty"`
	Clusters int    `json:"clusters,omitempty"`
	Seats    int    `json:"seats,omitempty"`
	IssuedTo string `json:"issuedTo,omitempty"`
	Email    string `json:"email,omitempty"`
	ID       string `json:"id,omitempty"`
	Issued   string `json:"issued,omitempty"`
	Expires  string `json:"expires,omitempty"`
	DaysLeft int64  `json:"daysLeft,omitempty"`
	decoded  bool
}

// licB64 decodes base64 like the reference unb64: either alphabet, padding optional.
func licB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	s += strings.Repeat("=", (4-len(s)%4)%4)
	return base64.StdEncoding.DecodeString(s)
}

// parseLicenceKeys reads "PRODUCT BASE64URL" lines and returns the Ed25519
// public keys for product.
func parseLicenceKeys(text, product string) []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || strings.HasPrefix(f[0], "#") || f[0] != product {
			continue
		}
		raw, err := licB64(f[1])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys
}

// VerifyLicence checks key offline against keys at time now. The order of
// checks matches the reference: format, signature, product and version, expiry.
func VerifyLicence(key string, keys []ed25519.PublicKey, product string, now time.Time) LicenceResult {
	parts := strings.Split(strings.TrimSpace(key), ".")
	if len(parts) != 3 || parts[0] != "ZYV1" {
		return LicenceResult{Status: licBadFormat}
	}
	raw, err1 := licB64(parts[1])
	sig, err2 := licB64(parts[2])
	if err1 != nil || err2 != nil {
		return LicenceResult{Status: licBadSignature}
	}
	ok := false
	for _, k := range keys {
		if ed25519.Verify(k, raw, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return LicenceResult{Status: licBadSignature}
	}
	var p licencePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return LicenceResult{Status: licBadSignature}
	}
	r := LicenceResult{
		Product: p.Product, Edition: p.Edition, Clusters: p.Macs, Seats: p.Seats,
		IssuedTo: p.Licensee, Email: p.Email, ID: p.ID, decoded: true,
		Issued:  time.Unix(p.Issued, 0).UTC().Format("2006-01-02"),
		Expires: time.Unix(p.Expires, 0).UTC().Format("2006-01-02"),
		Tier:    licenceTier(p),
	}
	if p.V != 1 || p.Product != product {
		r.Status = licWrongProduct
		return r
	}
	if now.Unix() >= p.Expires {
		r.Status = licExpired
		return r
	}
	r.Status, r.Valid = licValid, true
	r.DaysLeft = (p.Expires - now.Unix()) / 86400
	return r
}

// licenceTier names the pricing tier. The key carries no tier field, so it is
// derived from edition and the licensed cluster count: Team covers up to 10
// clusters, above that is Enterprise, anything else is per cluster.
func licenceTier(p licencePayload) string {
	switch {
	case p.Edition == "trial":
		return "trial"
	case p.Macs > 10:
		return "enterprise"
	case p.Macs == 10 || p.Seats > 0:
		return "team"
	case p.Edition == "pro":
		return "per cluster"
	}
	return p.Edition
}

// licenceKeyPath is where `setura licence show` looks when no key is given.
func licenceKeyPath(getenv func(string) string) string {
	if p := getenv("SETURA_LICENCE_FILE"); p != "" {
		return p
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "setura", "licence.key")
	}
	return ""
}

// findLicenceKey returns the configured key: SETURA_LICENCE_KEY, then the key file.
func findLicenceKey(getenv func(string) string) string {
	if k := strings.TrimSpace(getenv("SETURA_LICENCE_KEY")); k != "" {
		return k
	}
	if p := licenceKeyPath(getenv); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// licenceLine is the advisory status shown by `setura version --verbose`.
// It never blocks anything.
func licenceLine(getenv func(string) string, now time.Time) string {
	key := findLicenceKey(getenv)
	if key == "" {
		return "unlicensed (trial)"
	}
	r := VerifyLicence(key, parseLicenceKeys(licenceKeysFile, licenceProduct), licenceProduct, now)
	if !r.Valid {
		return "unlicensed (trial): configured key is " + r.Status
	}
	return fmt.Sprintf("%s, %s, expires %s", r.Tier, licenceUnits(r), r.Expires)
}

func licenceUnits(r LicenceResult) string {
	if r.Clusters == 1 {
		return "1 cluster"
	}
	return fmt.Sprintf("%d clusters", r.Clusters)
}

func writeLicenceText(w io.Writer, r LicenceResult) {
	fmt.Fprintf(w, "status    %s\n", r.Status)
	if !r.decoded {
		return
	}
	fmt.Fprintf(w, "tier      %s\n", r.Tier)
	fmt.Fprintf(w, "limit     %s\n", licenceUnits(r))
	fmt.Fprintf(w, "product   %s\n", r.Product)
	fmt.Fprintf(w, "edition   %s\n", r.Edition)
	fmt.Fprintf(w, "issued to %s <%s>\n", r.IssuedTo, r.Email)
	fmt.Fprintf(w, "issued    %s\n", r.Issued)
	fmt.Fprintf(w, "expires   %s", r.Expires)
	if r.Valid {
		fmt.Fprintf(w, " (%d day(s) left)", r.DaysLeft)
	}
	fmt.Fprintf(w, "\nid        %s\n", r.ID)
}

// runLicence implements `setura licence verify|show`. Exit 0 valid, 1 invalid, 2 usage.
func runLicence(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, now time.Time) int {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "show") {
		fmt.Fprintln(stderr, "usage: setura licence verify [KEY|--file F|-] [--format json]\n       setura licence show [--format json]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("licence "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "read the key from this file (- for stdin)")
	format := fs.String("format", "text", "text or json")
	pos, err := parse(fs, args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "setura licence: --format must be text or json")
		return 2
	}
	if len(pos) > 1 || (len(pos) == 1 && *file != "") || (sub == "show" && (len(pos) > 0 || *file != "")) {
		fmt.Fprintf(stderr, "setura licence %s: unexpected arguments\n", sub)
		return 2
	}
	var key string
	switch {
	case *file != "" || (len(pos) == 1 && pos[0] == "-"):
		var b []byte
		var err error
		if *file == "" || *file == "-" {
			b, err = io.ReadAll(io.LimitReader(stdin, 1<<16))
		} else {
			b, err = os.ReadFile(*file)
		}
		if err != nil {
			fmt.Fprintf(stderr, "setura licence: %s\n", err)
			return 2
		}
		key = string(b)
	case len(pos) == 1:
		key = pos[0]
	default:
		if key = findLicenceKey(getenv); key == "" {
			if sub == "show" {
				fmt.Fprintf(stdout, "status    unlicensed (trial)\nno key found: set SETURA_LICENCE_KEY or put one in %s\n", licenceKeyPath(getenv))
				return 1
			}
			fmt.Fprintln(stderr, "setura licence: no key given and none configured (SETURA_LICENCE_KEY, SETURA_LICENCE_FILE)")
			return 2
		}
	}
	r := VerifyLicence(key, parseLicenceKeys(licenceKeysFile, licenceProduct), licenceProduct, now)
	if *format == "json" {
		_ = writeJSON(stdout, r)
	} else {
		writeLicenceText(stdout, r)
	}
	if r.Valid {
		return 0
	}
	return 1
}
