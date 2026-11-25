package setura

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Domain registration expiry for "setura certs --domain-expiry", read with
// RDAP (RFC 9082, RFC 9083). The registry of a name is found in the IANA RDAP
// bootstrap file (RFC 9224). Looking a name up sends it to IANA's bootstrap
// host (the file only) and to that registry, so it happens only when asked for.

const (
	defaultRDAPBootstrap = "https://data.iana.org/rdap/dns.json"
	defaultWarnDomain    = 30
	maxRDAPBody          = 1 << 20
	maxRDAPLabels        = 5 // longest suffix of a host that is looked up
)

// Domain statuses. Anything but ok and skipped fails the run: an expiry that
// could not be read is not a passed check.
const (
	domainOK       = "ok"
	domainExpiring = "expiring"
	domainUnknown  = "unknown"
	domainSkipped  = "skipped"
)

// DomainRow is the registration expiry of the domain a target belongs to.
type DomainRow struct {
	Name     string `json:"name,omitempty"` // the registered domain that answered
	Status   string `json:"status"`         // ok, expiring, unknown or skipped
	DaysLeft *int   `json:"days_left,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// DomainOptions configures domain expiry lookups.
type DomainOptions struct {
	Bootstrap string // RDAP bootstrap file URL (default IANA)
	Server    string // RDAP base URL used instead of the bootstrap
	WarnDays  int    // expiring when fewer days are left
	Timeout   time.Duration
}

func (o DomainOptions) validate() error {
	for flagName, v := range map[string]string{"--rdap-url": o.Server, "--rdap-bootstrap": o.Bootstrap} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return userErrorf("%s must be an http or https URL", flagName)
		}
	}
	if o.WarnDays < 0 || o.WarnDays > 36500 {
		return userError("--warn-domain-days must be 0 to 36500")
	}
	return nil
}

type rdapAnswer struct {
	found   bool
	expires time.Time
	err     error
}

// rdapClient looks domains up one at a time (registries rate limit) and
// remembers every answer for the run.
type rdapClient struct {
	o        DomainOptions
	http     *http.Client
	services map[string]string // domain suffix -> base URL
	bootErr  error
	booted   bool
	cache    map[string]rdapAnswer
}

func newRDAPClient(o DomainOptions) *rdapClient {
	if o.Bootstrap == "" {
		o.Bootstrap = defaultRDAPBootstrap
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	return &rdapClient{o: o, http: &http.Client{Timeout: o.Timeout}, cache: map[string]rdapAnswer{}}
}

func (c *rdapClient) get(u string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "zyvor-setura")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPBody+1))
	if err == nil && len(body) > maxRDAPBody {
		err = fmt.Errorf("answer is larger than %d bytes", maxRDAPBody)
	}
	return resp.StatusCode, body, err
}

// loadBootstrap reads the RFC 9224 file once.
func (c *rdapClient) loadBootstrap() error {
	if c.booted {
		return c.bootErr
	}
	c.booted = true
	c.bootErr = func() error {
		code, body, err := c.get(c.o.Bootstrap)
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("HTTP %d", code)
		}
		var doc struct {
			Services [][][]string `json:"services"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("not a bootstrap file: %v", err)
		}
		c.services = map[string]string{}
		for _, s := range doc.Services {
			if len(s) != 2 {
				continue
			}
			base := ""
			for _, u := range s[1] { // HTTPS first (RFC 9224)
				if strings.HasPrefix(u, "https://") {
					base = u
					break
				}
				if base == "" && strings.HasPrefix(u, "http://") {
					base = u
				}
			}
			for _, label := range s[0] {
				if base != "" {
					c.services[strings.ToLower(label)] = base
				}
			}
		}
		if len(c.services) == 0 {
			return errors.New("the bootstrap file lists no DNS services")
		}
		return nil
	}()
	if c.bootErr != nil {
		c.bootErr = fmt.Errorf("RDAP bootstrap: %w", c.bootErr)
	}
	return c.bootErr
}

// serverFor picks the base URL with the longest label match for name.
func (c *rdapClient) serverFor(name string) (string, error) {
	if c.o.Server != "" {
		return c.o.Server, nil
	}
	if err := c.loadBootstrap(); err != nil {
		return "", err
	}
	for s := name; s != ""; {
		if base, ok := c.services[s]; ok {
			return base, nil
		}
		_, s, _ = strings.Cut(s, ".")
	}
	return "", fmt.Errorf("the RDAP bootstrap lists no server for .%s", name[strings.LastIndexByte(name, '.')+1:])
}

// query asks for one domain. found=false with no error means "not registered
// under this name" (404, or 400 for a name below a registration).
func (c *rdapClient) query(name string) rdapAnswer {
	if a, ok := c.cache[name]; ok {
		return a
	}
	a := func() rdapAnswer {
		base, err := c.serverFor(name)
		if err != nil {
			return rdapAnswer{err: err}
		}
		code, body, err := c.get(strings.TrimSuffix(base, "/") + "/domain/" + url.PathEscape(name))
		switch {
		case err != nil:
			return rdapAnswer{err: fmt.Errorf("RDAP query: %w", err)}
		case code == http.StatusNotFound || code == http.StatusBadRequest:
			return rdapAnswer{}
		case code != http.StatusOK:
			return rdapAnswer{err: fmt.Errorf("RDAP query: HTTP %d", code)}
		}
		var doc struct {
			LDHName string `json:"ldhName"`
			Events  []struct {
				Action string `json:"eventAction"`
				Date   string `json:"eventDate"`
			} `json:"events"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return rdapAnswer{err: fmt.Errorf("RDAP answer is not JSON: %v", err)}
		}
		if n := strings.TrimSuffix(doc.LDHName, "."); n != "" && !strings.EqualFold(n, name) {
			return rdapAnswer{err: fmt.Errorf("RDAP answered for %q, not %q", clipStr(n, 80), name)}
		}
		for _, e := range doc.Events {
			if e.Action != "expiration" {
				continue
			}
			t, err := time.Parse(time.RFC3339, e.Date)
			if err != nil {
				return rdapAnswer{err: fmt.Errorf("RDAP expiration date %q is not RFC 3339", clipStr(e.Date, 40))}
			}
			return rdapAnswer{found: true, expires: t}
		}
		return rdapAnswer{found: true}
	}()
	c.cache[name] = a
	return a
}

// Lookup finds the registration that host belongs to, trying the longest name
// first so that example.co.uk is found before co.uk would be asked.
func (c *rdapClient) Lookup(host string) DomainRow {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if net.ParseIP(h) != nil || strings.Contains(h, ":") {
		return DomainRow{Status: domainSkipped, Detail: "an IP address has no domain registration"}
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return DomainRow{Status: domainSkipped, Detail: "a single-label name has no domain registration"}
	}
	for _, l := range labels {
		ok := l != "" && len(l) <= 63
		for i := 0; ok && i < len(l); i++ {
			b := l[i]
			ok = b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
		}
		if !ok {
			return DomainRow{Status: domainUnknown, Detail: "not an ASCII domain name (use the xn-- form)"}
		}
	}
	for k := min(len(labels), maxRDAPLabels); k >= 2; k-- {
		name := strings.Join(labels[len(labels)-k:], ".")
		a := c.query(name)
		switch {
		case a.err != nil:
			return DomainRow{Name: name, Status: domainUnknown, Detail: clipStr(a.err.Error(), 200)}
		case !a.found:
			continue
		case a.expires.IsZero():
			return DomainRow{Name: name, Status: domainUnknown, Detail: "the registry publishes no expiration date over RDAP"}
		}
		days := daysUntil(a.expires)
		row := DomainRow{Name: name, Status: domainOK, DaysLeft: &days, Expires: a.expires.UTC().Format(time.RFC3339)}
		if days < c.o.WarnDays || !a.expires.After(time.Now()) {
			row.Status = domainExpiring
			row.Detail = fmt.Sprintf("the registration expires in under %d days", c.o.WarnDays)
		}
		return row
	}
	return DomainRow{Status: domainUnknown, Detail: "no RDAP record for this name or its parents"}
}
