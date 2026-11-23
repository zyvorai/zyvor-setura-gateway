package setura

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

const doctorGatewaySchema = "setura.doctor.gateway/v1"

// dgCheck is one finding of "setura doctor gateway".
type dgCheck struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	State   string   `json:"state"` // ok, warn, fail, skip
	Message string   `json:"message"`
	Fix     string   `json:"fix,omitempty"`
	Details []string `json:"details,omitempty"`
}

type dgReport struct {
	Schema  string    `json:"schema"`
	OK      bool      `json:"ok"`
	Verdict string    `json:"verdict"`
	Checks  []dgCheck `json:"checks"`
	Next    string    `json:"next,omitempty"`
}

type dgOptions struct {
	Config        string
	Admin         string
	AdminExplicit bool
	WarnCertDays  int
	Timeout       time.Duration
	// Kube adds the cluster checks (CRDs, Gateway and route status) through kubectl.
	Kube              bool
	KubeNS            string
	GatewayAPIVersion string
}

// dgEnv holds everything the checks touch outside the process, so tests can
// replace it.
type dgEnv struct {
	now      func() time.Time
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	listen   func(network, addr string) (net.Listener, error)
	client   *http.Client
	readFile func(string) ([]byte, error)
	token    func() string // SETURA_ADMIN_TOKEN
	cluster  *Cluster      // kubectl access for --kube
}

func defaultDGEnv(timeout time.Duration) dgEnv {
	d := &net.Dialer{Timeout: timeout}
	return dgEnv{
		now:    time.Now,
		dial:   d.DialContext,
		listen: net.Listen,
		client: &http.Client{Timeout: timeout, Transport: &http.Transport{
			// Only the Date header is read, so a certificate problem must not hide the clock.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     d.DialContext,
		}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		readFile: os.ReadFile,
		token:    func() string { return os.Getenv("SETURA_ADMIN_TOKEN") },
	}
}

func (r *dgReport) add(id, title, state, msg, fix string, details ...string) {
	r.Checks = append(r.Checks, dgCheck{ID: id, Title: title, State: state, Message: msg, Fix: fix, Details: details})
}

// worst folds states: fail beats warn beats ok.
func worst(states ...string) string {
	out := "ok"
	for _, s := range states {
		if s == "fail" || (s == "warn" && out == "ok") {
			out = s
		}
	}
	return out
}

type dgEndpoint struct {
	raw, addr string // addr is host:port
	scheme    string
	backends  []string
}

// parseDGEndpoint mirrors the gateway's endpoint syntax (host:port or http(s) URL).
func parseDGEndpoint(e string) (dgEndpoint, error) {
	scheme := "http"
	hp := e
	if strings.Contains(e, "://") {
		u, err := url.Parse(e)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return dgEndpoint{}, fmt.Errorf("endpoint %q is not host:port or an http(s) URL", e)
		}
		scheme, hp = u.Scheme, u.Host
	}
	if _, _, err := net.SplitHostPort(hp); err != nil {
		if scheme == "https" && !strings.Contains(e, "://") {
			return dgEndpoint{}, fmt.Errorf("endpoint %q is missing a port", e)
		}
		if !strings.Contains(e, "://") {
			return dgEndpoint{}, fmt.Errorf("endpoint %q is missing a port", e)
		}
		p := "80"
		if scheme == "https" {
			p = "443"
		}
		hp = net.JoinHostPort(strings.Trim(hp, "[]"), p)
	}
	return dgEndpoint{raw: e, addr: hp, scheme: scheme}, nil
}

// doctorGateway runs every check. Checks never panic on missing inputs: they skip.
func doctorGateway(o dgOptions, env dgEnv) *dgReport {
	rep := &dgReport{Schema: doctorGatewaySchema}
	ctx := context.Background()

	// Admin first (other checks use its answer), reported in order later.
	adm := probeAdmin(ctx, o, env)

	var cfg *builtin.Config
	var snap obj
	cfgOK := false
	switch {
	case o.Config == "":
		rep.add("config", "Config", "skip", "no --config given, so config checks were skipped", "Pass the file the gateway serves: setura doctor gateway --config setura.json")
	default:
		raw, err := env.readFile(o.Config)
		if err != nil {
			rep.add("config", "Config", "fail", "cannot read "+o.Config+": "+trimPathErr(err, o.Config), "Check the path and permissions of the config file.")
			break
		}
		abs, _ := filepath.Abs(o.Config)
		c, err := builtin.ParseConfig(raw, filepath.Dir(abs))
		if err != nil {
			rep.add("config", "Config", "fail", "the gateway cannot parse "+o.Config+": "+err.Error(), "Fix the JSON, then rerun. setura lint --snapshot "+o.Config+" shows more.")
			break
		}
		cfg, cfgOK = c, true
		_ = json.Unmarshal(raw, &snap)
		nr := len(c.Routes) + len(c.GRPCRoutes) + len(c.TLSRoutes)
		rep.add("config", "Config", "ok", fmt.Sprintf("%s reads cleanly: %s, %s, %s", o.Config,
			plural(len(c.Gateways), "gateway", "gateways"), plural(nr, "route", "routes"), plural(len(c.Backends), "backend", "backends")), "")
	}

	rep.Checks = append(rep.Checks, lintCheck(o, snap, cfgOK))
	rep.Checks = append(rep.Checks, portsCheck(o, cfg, cfgOK, adm, env))
	rep.Checks = append(rep.Checks, certsCheck(o, cfg, cfgOK, env))
	var eps []dgEndpoint
	if cfgOK {
		eps = endpointsOf(cfg)
	}
	rep.Checks = append(rep.Checks, backendsCheck(ctx, o, cfgOK, eps, env))
	rep.Checks = append(rep.Checks, clockCheck(ctx, cfgOK, eps, env))
	rep.Checks = append(rep.Checks, adm.check)
	rep.Checks = append(rep.Checks, ejectedCheck(ctx, o, adm, env))
	if o.Kube {
		rep.Checks = append(rep.Checks, crdsCheck(o, env), clusterStatusCheck(o, env), envoyPoliciesCheck(o, env))
	}

	fails, warns := 0, 0
	var firstFail, firstWarn *dgCheck
	for i := range rep.Checks {
		c := &rep.Checks[i]
		switch c.State {
		case "fail":
			fails++
			if firstFail == nil {
				firstFail = c
			}
		case "warn":
			warns++
			if firstWarn == nil {
				firstWarn = c
			}
		}
	}
	rep.OK = fails == 0
	switch {
	case fails > 0:
		rep.Verdict = plural(fails, "problem needs", "problems need") + " fixing"
		rep.Next = firstFail.Fix
	case warns > 0:
		rep.Verdict = plural(warns, "warning", "warnings") + ", nothing blocking"
		rep.Next = firstWarn.Fix
	default:
		rep.Verdict = "Gateway looks healthy"
	}
	if rep.Next == "" {
		if o.Config == "" {
			rep.Next = "setura doctor gateway --config setura.json --admin " + o.Admin
		} else {
			rep.Next = "setura connections --admin " + o.Admin
		}
	}
	return rep
}

func trimPathErr(err error, path string) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func lintCheck(o dgOptions, snap obj, cfgOK bool) dgCheck {
	c := dgCheck{ID: "lint", Title: "Lint"}
	if !cfgOK || snap == nil {
		c.State, c.Message = "skip", "skipped: no readable config"
		return c
	}
	rep, err := Lint(snap)
	if err != nil {
		c.State, c.Message, c.Fix = "fail", err.Error(), "setura lint --snapshot "+o.Config
		return c
	}
	e, _ := num(rep["errors"])
	w, _ := num(rep["warnings"])
	var first []string
	for _, f := range asList(rep["findings"]) {
		m := asMap(f)
		if len(first) < 3 {
			first = append(first, asStr(m["id"])+" "+asStr(m["message"]))
		}
	}
	switch {
	case e > 0:
		c.State, c.Message = "fail", plural(int(e), "lint error", "lint errors")+", "+plural(int(w), "warning", "warnings")
		c.Fix = "setura lint --snapshot " + o.Config
		c.Details = first
	case w > 0:
		c.State, c.Message = "warn", plural(int(w), "lint warning", "lint warnings")
		c.Fix = "setura lint --snapshot " + o.Config
		c.Details = first
	default:
		c.State, c.Message = "ok", "no lint findings"
	}
	return c
}

func tcpFamily(p string) bool { return strings.ToUpper(p) != "UDP" }

func portsCheck(o dgOptions, cfg *builtin.Config, cfgOK bool, adm adminProbe, env dgEnv) dgCheck {
	c := dgCheck{ID: "ports", Title: "Ports"}
	type use struct {
		proto string
		names []string
	}
	tcp, udp := map[int]*use{}, map[int]*use{}
	var problems, details []string
	if cfgOK {
		for _, g := range cfg.Gateways {
			for _, l := range g.Listeners {
				m := tcp
				if !tcpFamily(l.Protocol) {
					m = udp
				}
				p := strings.ToUpper(l.Protocol)
				if u := m[l.Port]; u != nil {
					if u.proto != p {
						problems = append(problems, fmt.Sprintf("port %d is declared as both %s and %s (%s)", l.Port, u.proto, p, g.Name+"/"+l.Name))
					}
					u.names = append(u.names, g.Name+"/"+l.Name)
				} else {
					m[l.Port] = &use{proto: p, names: []string{g.Name + "/" + l.Name}}
				}
			}
		}
	}
	if len(problems) > 0 {
		c.State, c.Message, c.Details = "fail", plural(len(problems), "listener port clash", "listener port clashes"), problems
		c.Fix = "Give each listener protocol its own port, or use one protocol per port."
		return c
	}
	var ports []int
	for p := range tcp {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	busy := 0
	for _, p := range ports {
		if p <= 0 {
			continue
		}
		ln, err := env.listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		switch {
		case err == nil:
			ln.Close()
			details = append(details, fmt.Sprintf("port %d is free", p))
		case errors.Is(err, syscall.EADDRINUSE):
			if adm.reachable {
				details = append(details, fmt.Sprintf("port %d is in use, by the running gateway", p))
			} else {
				busy++
				problems = append(problems, fmt.Sprintf("port %d is already in use by another process", p))
			}
		case errors.Is(err, syscall.EACCES):
			details = append(details, fmt.Sprintf("port %d needs privileges (the gateway can shift low ports with --port-offset)", p))
		default:
			details = append(details, fmt.Sprintf("port %d could not be checked: %v", p, err))
		}
	}
	// the admin port
	if _, port, err := net.SplitHostPort(o.Admin); err == nil && !adm.reachable && o.Admin != "off" {
		if ln, lerr := env.listen("tcp", o.Admin); lerr == nil {
			ln.Close()
		} else if errors.Is(lerr, syscall.EADDRINUSE) {
			problems = append(problems, "admin port "+port+" is in use by something that is not answering as the gateway admin API")
		}
	}
	switch {
	case len(problems) > 0:
		c.State = "fail"
		c.Message = plural(len(problems), "port clash", "port clashes")
		c.Details = append(problems, details...)
		c.Fix = "Stop the other process, or move the listener to a free port in the config."
	case len(ports) == 0 && !cfgOK:
		c.State, c.Message = "skip", "no config, so listener ports were not checked"
	case len(ports) == 0:
		c.State, c.Message = "ok", "no TCP listeners to check"
	default:
		c.State = "ok"
		c.Message = fmt.Sprintf("%s checked, no clashes", plural(len(ports), "listener port", "listener ports"))
		c.Details = details
	}
	_ = busy
	return c
}

func leafOf(pemData []byte) (*x509.Certificate, error) {
	for {
		var blk *pem.Block
		blk, pemData = pem.Decode(pemData)
		if blk == nil {
			return nil, errors.New("no certificate found in the PEM data")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
}

func certsCheck(o dgOptions, cfg *builtin.Config, cfgOK bool, env dgEnv) dgCheck {
	c := dgCheck{ID: "certs", Title: "Certificates"}
	if !cfgOK {
		c.State, c.Message = "skip", "skipped: no readable config"
		return c
	}
	if len(cfg.Secrets) == 0 {
		c.State, c.Message = "skip", "the config has no TLS certificates"
		return c
	}
	now := env.now()
	certs := map[string]*x509.Certificate{}
	states := []string{}
	var details []string
	var worstFix string
	soon := 0
	for _, k := range sortedKeys(cfg.Secrets) {
		s := cfg.Secrets[k]
		data := []byte(s.Cert)
		if s.CertFile != "" {
			b, err := env.readFile(s.CertFile)
			if err != nil {
				states = append(states, "fail")
				details = append(details, fmt.Sprintf("%s: cannot read %s", k, s.CertFile))
				worstFix = "Check that the certificate file exists and is readable."
				continue
			}
			data = b
		}
		leaf, err := leafOf(data)
		if err != nil {
			states = append(states, "fail")
			details = append(details, fmt.Sprintf("%s: %v", k, err))
			worstFix = "Replace the certificate with a valid PEM file."
			continue
		}
		certs[k] = leaf
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		switch {
		case now.After(leaf.NotAfter):
			states = append(states, "fail")
			details = append(details, fmt.Sprintf("%s expired on %s", k, leaf.NotAfter.UTC().Format("2006-01-02")))
			worstFix = "Renew the certificate " + k + " and let the gateway reload it."
		case days < o.WarnCertDays:
			states = append(states, "warn")
			soon++
			details = append(details, fmt.Sprintf("%s expires in %s (%s)", k, plural(max(days, 0), "day", "days"), leaf.NotAfter.UTC().Format("2006-01-02")))
			if worstFix == "" {
				worstFix = "Renew the certificate " + k + " before it expires."
			}
		default:
			details = append(details, fmt.Sprintf("%s valid for %s", k, plural(days, "more day", "more days")))
		}
	}
	// hostnames vs SAN
	for _, g := range cfg.Gateways {
		for _, l := range g.Listeners {
			if l.TLS == nil || l.Hostname == "" {
				continue
			}
			host := strings.Replace(l.Hostname, "*.", "wild.", 1)
			for _, ref := range l.TLS.CertificateRefs {
				leaf := certs[ref.Name]
				if leaf == nil {
					for k, v := range certs {
						if strings.HasSuffix(k, "/"+ref.Name) {
							leaf = v
						}
					}
				}
				if leaf != nil && leaf.VerifyHostname(host) != nil {
					states = append(states, "warn")
					details = append(details, fmt.Sprintf("listener %s/%s serves %s but its certificate does not cover that name", g.Name, l.Name, l.Hostname))
					if worstFix == "" {
						worstFix = "Reissue the certificate with " + l.Hostname + " in its subject alternative names."
					}
				}
			}
		}
	}
	c.State = worst(states...)
	c.Details = details
	switch c.State {
	case "fail":
		c.Message, c.Fix = "a certificate is expired or unusable", worstFix
	case "warn":
		c.Message, c.Fix = "a certificate needs attention soon", worstFix
		if soon > 0 {
			c.Message = fmt.Sprintf("%s expiring within %s", plural(soon, "certificate", "certificates"), plural(o.WarnCertDays, "day", "days"))
		}
	default:
		c.Message = fmt.Sprintf("%s, none expiring within %s", plural(len(certs), "certificate", "certificates"), plural(o.WarnCertDays, "day", "days"))
	}
	return c
}

func endpointsOf(cfg *builtin.Config) []dgEndpoint {
	by := map[string]*dgEndpoint{}
	var order []string
	for _, k := range sortedKeys(cfg.Backends) {
		for _, e := range cfg.Backends[k].Endpoints {
			ep, err := parseDGEndpoint(e)
			if err != nil {
				continue
			}
			key := ep.scheme + "|" + ep.addr
			if by[key] == nil {
				cp := ep
				by[key] = &cp
				order = append(order, key)
			}
			by[key].backends = append(by[key].backends, k)
		}
	}
	out := make([]dgEndpoint, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

func backendsCheck(ctx context.Context, o dgOptions, cfgOK bool, eps []dgEndpoint, env dgEnv) dgCheck {
	c := dgCheck{ID: "backends", Title: "Backends"}
	if !cfgOK {
		c.State, c.Message = "skip", "skipped: no readable config"
		return c
	}
	if len(eps) == 0 {
		c.State, c.Message = "skip", "the config declares no backend endpoints"
		return c
	}
	down := make([]error, len(eps))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range eps {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, o.Timeout)
			defer cancel()
			conn, err := env.dial(dctx, "tcp", eps[i].addr)
			if err != nil {
				down[i] = err
				return
			}
			conn.Close()
		}(i)
	}
	wg.Wait()
	perBackend := map[string][2]int{} // up, total
	var details []string
	for i, e := range eps {
		for _, b := range e.backends {
			v := perBackend[b]
			v[1]++
			if down[i] == nil {
				v[0]++
			}
			perBackend[b] = v
		}
		if down[i] != nil {
			details = append(details, fmt.Sprintf("%s is not reachable: %s", e.addr, shortDialErr(down[i])))
		}
	}
	allDown, someDown := 0, 0
	for _, v := range perBackend {
		if v[0] == 0 {
			allDown++
		} else if v[0] < v[1] {
			someDown++
		}
	}
	nUp := 0
	for _, d := range down {
		if d == nil {
			nUp++
		}
	}
	switch {
	case allDown > 0:
		c.State = "fail"
		c.Message = fmt.Sprintf("%s with no reachable endpoint", plural(allDown, "backend", "backends"))
		c.Fix = "Start the upstream or correct its address in backends. Test with: nc -vz " + firstDown(eps, down)
	case someDown > 0 || nUp < len(eps):
		c.State = "warn"
		c.Message = fmt.Sprintf("%d of %s unreachable; every backend still has a live endpoint", len(eps)-nUp, plural(len(eps), "endpoint", "endpoints"))
		c.Fix = "Check the unreachable endpoint: nc -vz " + firstDown(eps, down)
	default:
		c.State = "ok"
		c.Message = fmt.Sprintf("all %s reachable", plural(len(eps), "endpoint", "endpoints"))
	}
	c.Details = details
	return c
}

func firstDown(eps []dgEndpoint, down []error) string {
	for i, e := range eps {
		if down[i] != nil {
			h, p, _ := net.SplitHostPort(e.addr)
			return h + " " + p
		}
	}
	return "HOST PORT"
}

func shortDialErr(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func clockCheck(ctx context.Context, cfgOK bool, eps []dgEndpoint, env dgEnv) dgCheck {
	c := dgCheck{ID: "clock", Title: "Clock"}
	if !cfgOK || len(eps) == 0 {
		c.State, c.Message = "skip", "no backends to compare the clock with"
		return c
	}
	var states, details []string
	checked := 0
	var maxSkew time.Duration
	for _, e := range eps {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, e.scheme+"://"+e.addr+"/", nil)
		if err != nil {
			continue
		}
		resp, err := env.client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d, err := http.ParseTime(resp.Header.Get("Date"))
		if err != nil {
			continue
		}
		checked++
		skew := env.now().Sub(d)
		if a := skew.Abs(); a > maxSkew {
			maxSkew = a
		}
		switch a := skew.Abs(); {
		case a > time.Minute:
			states = append(states, "fail")
			details = append(details, fmt.Sprintf("%s differs by %s", e.addr, a.Round(time.Second)))
		case a > 5*time.Second:
			states = append(states, "warn")
			details = append(details, fmt.Sprintf("%s differs by %s", e.addr, a.Round(time.Second)))
		}
	}
	if checked == 0 {
		c.State, c.Message = "skip", "no backend answered with a Date header"
		return c
	}
	c.State = worst(states...)
	c.Details = details
	switch c.State {
	case "ok":
		c.Message = fmt.Sprintf("this host agrees with %s within 5 seconds", plural(checked, "backend", "backends"))
	default:
		c.Message = fmt.Sprintf("this host's clock differs from a backend by up to %s", maxSkew.Round(time.Second))
		c.Fix = "Sync the clock (NTP) on this host and the backend; skew breaks token and certificate validity checks."
	}
	return c
}

type adminProbe struct {
	reachable bool
	check     dgCheck
	base      string
}

func probeAdmin(ctx context.Context, o dgOptions, env dgEnv) adminProbe {
	p := adminProbe{check: dgCheck{ID: "admin", Title: "Admin API"}}
	if o.Admin == "off" {
		p.check.State, p.check.Message = "skip", "the admin API is switched off"
		return p
	}
	p.base = "http://" + o.Admin
	get := func(token string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/status", nil)
		if err != nil {
			return 0, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := env.client.Do(req)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	code, err := get("")
	if err != nil {
		if o.AdminExplicit {
			p.check.State, p.check.Message = "fail", "cannot reach the admin API at "+o.Admin
			p.check.Fix = "Start the gateway with --admin " + o.Admin + ", or correct the address."
		} else {
			p.check.State, p.check.Message = "skip", "no gateway answered on the default admin address "+o.Admin
			p.check.Fix = "Add --admin ADDR if the gateway runs elsewhere."
			p.check.Fix = ""
		}
		return p
	}
	p.reachable = true
	tok := env.token()
	switch {
	case code != http.StatusUnauthorized && code != http.StatusForbidden:
		p.check.State, p.check.Message = "ok", "reachable at "+o.Admin+", no token required"
		if h, _, e := net.SplitHostPort(o.Admin); e == nil {
			if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
				p.check.State = "warn"
				p.check.Message = "reachable at " + o.Admin + " from off-host without a token"
				p.check.Fix = "Start the gateway with --admin-token so the admin API is protected."
			}
		}
	case tok == "":
		p.check.State, p.check.Message = "warn", "the admin API at "+o.Admin+" needs a token and SETURA_ADMIN_TOKEN is not set"
		p.check.Fix = "export SETURA_ADMIN_TOKEN=YOUR_TOKEN, then rerun setura doctor gateway"
	default:
		code2, err := get(tok)
		switch {
		case err != nil:
			p.check.State, p.check.Message = "fail", "the admin API stopped answering: "+err.Error()
			p.check.Fix = "Check that the gateway is still running."
		case code2 == http.StatusUnauthorized || code2 == http.StatusForbidden:
			p.check.State, p.check.Message = "fail", "the admin API rejected SETURA_ADMIN_TOKEN"
			p.check.Fix = "Use the token the gateway was started with: export SETURA_ADMIN_TOKEN=YOUR_TOKEN"
		default:
			p.check.State, p.check.Message = "ok", "reachable at "+o.Admin+", protected, and SETURA_ADMIN_TOKEN is accepted"
		}
	}
	return p
}

// metric parses name{labels} value lines for one metric.
func metricRows(text, name string) []struct {
	labels string
	value  float64
} {
	var out []struct {
		labels string
		value  float64
	}
	for _, ln := range strings.Split(text, "\n") {
		if !strings.HasPrefix(ln, name+"{") {
			continue
		}
		i := strings.LastIndex(ln, "}")
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(ln[i+1:]), 64)
		if err != nil {
			continue
		}
		out = append(out, struct {
			labels string
			value  float64
		}{ln[len(name)+1 : i], v})
	}
	return out
}

func ejectedCheck(ctx context.Context, o dgOptions, adm adminProbe, env dgEnv) dgCheck {
	c := dgCheck{ID: "endpoints", Title: "Endpoint health"}
	if !adm.reachable || adm.check.State == "fail" || (adm.check.State == "warn" && env.token() == "" && strings.Contains(adm.check.Message, "needs a token")) {
		c.State, c.Message = "skip", "needs a reachable admin API to read endpoint health"
		return c
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adm.base+"/metrics", nil)
	if err != nil {
		c.State, c.Message = "skip", err.Error()
		return c
	}
	adminToken(req)
	resp, err := env.client.Do(req)
	if err != nil {
		c.State, c.Message = "skip", "could not read /metrics: "+err.Error()
		return c
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.State, c.Message = "skip", fmt.Sprintf("/metrics answered %d", resp.StatusCode)
		return c
	}
	text := string(b)
	healthy := metricRows(text, "setura_gateway_endpoint_healthy")
	ejected := metricRows(text, "setura_gateway_endpoint_ejected")
	if len(healthy) == 0 && len(ejected) == 0 {
		c.State, c.Message = "ok", "no endpoints are tracked yet"
		return c
	}
	var details []string
	nEj, nBad := 0, 0
	label := func(l string) string {
		return strings.NewReplacer(`backend="`, "", `",endpoint="`, " ", `"`, "").Replace(l)
	}
	for _, r := range ejected {
		if r.value > 0 {
			nEj++
			details = append(details, label(r.labels)+" is ejected from rotation")
		}
	}
	for _, r := range healthy {
		if r.value == 0 {
			nBad++
			details = append(details, label(r.labels)+" fails its health check")
		}
	}
	if nEj+nBad == 0 {
		c.State, c.Message = "ok", fmt.Sprintf("all %s healthy, none ejected", plural(len(healthy), "endpoint", "endpoints"))
		return c
	}
	c.State = "warn"
	c.Message = fmt.Sprintf("%d ejected, %d failing health checks", nEj, nBad)
	c.Details = details
	c.Fix = "setura connections --admin " + o.Admin + " --filter status=5xx"
	return c
}

// DoctorGatewayPretty renders the checklist, one verdict and a Next line.
func (u *ui) DoctorGatewayPretty(r *dgReport) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, c := range r.Checks {
		sym := u.okSym()
		switch c.State {
		case "fail":
			sym = u.failSym()
		case "warn":
			sym = u.warnSym()
		case "skip":
			sym = u.skipSym()
		}
		fmt.Fprintf(&b, "  %s %s %s\n", sym, pad(c.Title, 16), c.Message)
		if c.State != "ok" || len(c.Details) > 0 {
			for _, d := range c.Details {
				fmt.Fprintf(&b, "      %s\n", u.gray(d))
			}
		}
		if (c.State == "fail" || c.State == "warn") && c.Fix != "" {
			fmt.Fprintf(&b, "      %s %s\n", u.arrow(), u.gray(c.Fix))
		}
	}
	b.WriteString("\n")
	sym := u.okSym()
	switch {
	case !r.OK:
		sym = u.failSym()
	case strings.Contains(r.Verdict, "warning"):
		sym = u.warnSym()
	}
	fmt.Fprintf(&b, "  %s %s\n", sym, u.bold(r.Verdict))
	fmt.Fprintf(&b, "  %s %s\n\n", u.blue("Next:"), r.Next)
	return b.String()
}

// runDoctorGateway implements "setura doctor gateway".
func runDoctorGateway(rest []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) (int, error) {
	return runDoctorGatewayWith(NewCluster(""), rest, stdout, stderr, u, stdoutTTY)
}

// runDoctorGatewayWith is runDoctorGateway with the cluster --kube reads.
func runDoctorGatewayWith(cluster *Cluster, rest []string, stdout, stderr io.Writer, u *ui, stdoutTTY bool) (int, error) {
	fs := newFlagSet("doctor gateway", stderr)
	setCommandUsage(fs, "doctor", newUI(isTTY(stderr), termOptions{}, os.Getenv))
	var o dgOptions
	fs.StringVar(&o.Config, "config", "", "the gateway config file (setura.route-specs/v1 JSON) to check")
	fs.StringVar(&o.Admin, "admin", "", "gateway admin address (default "+builtin.DefaultAdmin+"; honours SETURA_ADMIN_TOKEN)")
	fs.IntVar(&o.WarnCertDays, "warn-cert-days", 14, "warn when a certificate expires within this many days")
	fs.DurationVar(&o.Timeout, "timeout", 3*time.Second, "timeout for each network check")
	fs.BoolVar(&o.Kube, "kube", false, "also check the cluster through kubectl: Gateway API CRDs (missing or too old) and Gateway and route status")
	fs.StringVar(&o.KubeNS, "namespace", "", "with --kube: only this namespace (default: all)")
	fs.StringVar(&o.GatewayAPIVersion, "gateway-api-version", "", "with --kube: Gateway API release to recommend (default "+builtin.GatewayAPIVersion+")")
	format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		fmt.Fprintf(stderr, "setura doctor gateway: unexpected argument %q\n", pos[0])
		exampleHint(stderr, "doctor")
		return 2, usageError{"arguments"}
	}
	pretty, ferr := wantPretty(*format, stdoutTTY)
	if ferr != nil {
		return 2, ferr
	}
	if o.Timeout <= 0 || o.WarnCertDays < 0 {
		return 0, userError("--timeout must be positive and --warn-cert-days must not be negative")
	}
	o.AdminExplicit = o.Admin != ""
	if o.Admin == "" {
		o.Admin = builtin.DefaultAdmin
	}
	if o.GatewayAPIVersion != "" {
		if _, err := builtin.ParseGatewayAPIVersion(o.GatewayAPIVersion); err != nil {
			return 0, userErrorf("--gateway-api-version: %v", err)
		}
	}
	env := defaultDGEnv(o.Timeout)
	env.cluster = cluster
	rep := doctorGateway(o, env)
	code := boolExit(!rep.OK)
	if pretty {
		fmt.Fprint(stdout, u.DoctorGatewayPretty(rep))
		return code, nil
	}
	return code, writeJSON(stdout, rep)
}

// crdsCheck is the "crds" check of doctor gateway --kube.
func crdsCheck(o dgOptions, env dgEnv) dgCheck {
	c := dgCheck{ID: "crds", Title: "Gateway API CRDs"}
	if env.cluster == nil {
		c.State, c.Message = "skip", "no cluster access"
		return c
	}
	items, err := clusterCRDs(env.cluster)
	if err != nil {
		c.State, c.Message, c.Fix = "fail", "cannot read the CRDs: "+err.Error(), "Check kubectl access: kubectl get crd"
		return c
	}
	r := checkCRDs(items, o.GatewayAPIVersion)
	c.State = "ok"
	for _, f := range r.Findings {
		switch f.State {
		case "fail":
			c.State = "fail"
		case "warn":
			if c.State == "ok" {
				c.State = "warn"
			}
		}
		if f.State == "fail" || f.State == "warn" {
			c.Details = append(c.Details, f.Feature+": "+f.Message)
		}
	}
	c.Message, c.Fix = r.Verdict, r.Next
	return c
}

// clusterStatusCheck is the "gateways" check of doctor gateway --kube.
func clusterStatusCheck(o dgOptions, env dgEnv) dgCheck {
	c := dgCheck{ID: "gateways", Title: "Gateways and routes"}
	if env.cluster == nil {
		c.State, c.Message = "skip", "no cluster access"
		return c
	}
	r, err := clusterStatus(env.cluster, o.KubeNS, false)
	if err != nil {
		c.State, c.Message, c.Fix = "fail", err.Error(), "Install the Gateway API CRDs first: setura gateway install --check"
		return c
	}
	c.Message = r.Verdict
	switch {
	case !r.OK:
		c.State, c.Fix = "fail", "setura gateway status shows every reason"
		for _, l := range [][]stItem{r.Gateways, r.Routes} {
			for _, it := range l {
				for _, p := range it.Problems {
					if len(c.Details) < 8 {
						c.Details = append(c.Details, it.Kind+" "+it.Namespace+"/"+it.Name+": "+p)
					}
				}
			}
		}
		for _, it := range r.Policies {
			for _, p := range it.Problems {
				if len(c.Details) < 8 {
					c.Details = append(c.Details, it.Kind+" "+it.Namespace+"/"+it.Name+": "+p)
				}
			}
		}
	case len(r.Gateways) == 0:
		c.State, c.Fix = "warn", r.Next
	default:
		c.State = "ok"
	}
	return c
}
