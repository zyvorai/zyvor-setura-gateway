package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Background is implemented by sources that run their own watches and leader
// election. Start returns the safety resync interval to use instead of the poll
// interval (0 means "keep polling"). Wait blocks until the background work has
// finished after the context ended (for example the Lease was released).
type Background interface {
	Start(ctx context.Context, wake func()) (resync time.Duration)
	Wait()
}

// kubeCtl holds the controller options that sit beside the API client.
type kubeCtl struct {
	Poll        bool          // --poll: no watches, the server polls
	Resync      time.Duration // safety relist while watching (Secrets are not watched)
	Lease       *LeaseConfig  // nil: no leader election, every replica writes status
	SvcName     string        // the install Service (Gateway status.addresses)
	SvcNS       string
	ExposePorts bool // --expose-gateway-ports
	PortOffset  int
	PortMap     map[int]int

	watchBackoff time.Duration // first reconnect delay (default 500ms)
	watchTimeout int           // server-side seconds per watch request (default 300)
	fallbackPoll time.Duration // wake interval while a watch is unavailable (default 5s)

	elect *elector
	wg    sync.WaitGroup
}

func (k *KubeSource) isLeader() bool { return k.elect == nil || k.elect.isLeader() }

type controllerFlags struct {
	poll         bool
	leaderElect  bool
	leaseName    string
	leaseNS      string
	leaseDur     time.Duration
	leaseRenew   time.Duration
	leaseRetry   time.Duration
	identity     string
	svcName      string
	svcNS        string
	exposePorts  bool
	resync       time.Duration
	portOffsetFn func() (int, map[int]int)
}

func podNamespace() string {
	if v := os.Getenv("POD_NAMESPACE"); v != "" {
		return v
	}
	if b, err := os.ReadFile(saDir + "/namespace"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "setura-system"
}

func addControllerFlags(fs *flag.FlagSet, c *controllerFlags) {
	ns := podNamespace()
	fs.BoolVar(&c.poll, "poll", false, "poll the Kubernetes API every --interval instead of using watches")
	fs.DurationVar(&c.resync, "resync", time.Minute, "safety relist interval while watching (picks up TLS Secret changes)")
	fs.BoolVar(&c.leaderElect, "leader-elect", false, "elect a status-writing leader through a coordination.k8s.io Lease (all replicas keep serving)")
	fs.StringVar(&c.leaseName, "lease-name", "setura-gateway", "Lease name for --leader-elect")
	fs.StringVar(&c.leaseNS, "lease-namespace", ns, "Lease namespace (default: POD_NAMESPACE or the pod's namespace)")
	fs.DurationVar(&c.leaseDur, "lease-duration", 15*time.Second, "how long a Lease is valid without renewal")
	fs.DurationVar(&c.leaseRenew, "lease-renew-deadline", 10*time.Second, "leader gives up after failing to renew for this long")
	fs.DurationVar(&c.leaseRetry, "lease-retry-period", 2*time.Second, "pause between Lease attempts")
	fs.StringVar(&c.identity, "lease-identity", "", "holder identity (default: POD_NAME or the hostname, plus a random suffix)")
	fs.StringVar(&c.svcName, "service-name", "setura-gateway", "Service whose address goes into Gateway status.addresses (empty: none)")
	fs.StringVar(&c.svcNS, "service-namespace", ns, "namespace of that Service")
	fs.BoolVar(&c.exposePorts, "expose-gateway-ports", false, "add a port to the Service for every Gateway listener port (needs services patch RBAC)")
}

func (c *controllerFlags) apply(k *KubeSource) {
	k.Poll, k.Resync = c.poll, c.resync
	k.SvcName, k.SvcNS = c.svcName, c.svcNS
	k.ExposePorts = c.exposePorts
	if c.portOffsetFn != nil {
		k.PortOffset, k.PortMap = c.portOffsetFn()
	}
	if c.leaderElect {
		id := c.identity
		if id == "" {
			id = os.Getenv("POD_NAME")
		}
		if id == "" {
			id, _ = os.Hostname()
		}
		id += fmt.Sprintf("_%08x", rand.Uint32())
		k.Lease = &LeaseConfig{Name: c.leaseName, Namespace: c.leaseNS, Identity: id,
			Duration: c.leaseDur, RenewDeadline: c.leaseRenew, RetryPeriod: c.leaseRetry}
	}
}

// watchTargets are the collections the data plane depends on. Optional ones may
// be missing (CRD not installed) or forbidden; each lists the API paths to try.
var watchTargets = []struct {
	paths    []string
	optional bool
}{
	{[]string{apiGatewayV1 + "/gatewayclasses"}, false},
	{[]string{apiGatewayV1 + "/gateways"}, false},
	{[]string{apiGatewayV1 + "/httproutes"}, false},
	{[]string{"/api/v1/services"}, false},
	{[]string{"/apis/discovery.k8s.io/v1/endpointslices"}, false},
	{[]string{apiGatewayV1 + "/grpcroutes"}, true},
	{[]string{apiGatewayV1 + "/listenersets"}, true},
	{[]string{apiGatewayV1 + "/tcproutes", "/apis/" + APIGroup + "/v1alpha2/tcproutes"}, true},
	{[]string{apiGatewayV1 + "/udproutes", "/apis/" + APIGroup + "/v1alpha2/udproutes"}, true},
	{[]string{apiGatewayV1 + "/backendtlspolicies", "/apis/" + APIGroup + "/v1alpha3/backendtlspolicies"}, true},
	{[]string{apiGatewayV1 + "/tlsroutes", "/apis/" + APIGroup + "/v1alpha3/tlsroutes", "/apis/" + APIGroup + "/v1alpha2/tlsroutes"}, true},
	{[]string{"/apis/gateway.networking.k8s.io/v1beta1/referencegrants"}, true},
	{[]string{"/api/v1/namespaces"}, true},
}

// Start implements Background: it starts leader election when configured and,
// unless Poll is set, one watch loop per collection.
func (k *KubeSource) Start(ctx context.Context, wake func()) time.Duration {
	if k.Lease != nil {
		k.elect = newElector(k, *k.Lease, wake)
		k.wg.Add(1)
		go func() { defer k.wg.Done(); k.elect.run(ctx) }()
	}
	if k.Poll {
		return 0
	}
	for _, t := range watchTargets {
		k.wg.Add(1)
		go func(paths []string, optional bool) {
			defer k.wg.Done()
			k.watchLoop(ctx, paths, optional, wake)
		}(t.paths, t.optional)
	}
	if k.Resync <= 0 {
		return time.Minute
	}
	return k.Resync
}

// Wait implements Background.
func (k *KubeSource) Wait() { k.wg.Wait() }

func (k *KubeSource) backoffMin() time.Duration {
	if k.watchBackoff > 0 {
		return k.watchBackoff
	}
	return 500 * time.Millisecond
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// errWatchUnavailable means the API cannot serve watches for this path.
var errWatchUnavailable = errors.New("watch not available")

// errGone means the resourceVersion is too old (410): relist.
var errGone = errors.New("resourceVersion expired (410 Gone)")

// watchLoop keeps one collection watched: list to learn a resourceVersion, watch
// from it, relist on 410, reconnect with backoff, and fall back to waking the
// server at a poll rate while watches do not work.
func (k *KubeSource) watchLoop(ctx context.Context, paths []string, optional bool, wake func()) {
	var rv, path string
	delay := k.backoffMin()
	for ctx.Err() == nil {
		if rv == "" {
			var err error
			rv, path, err = k.listVersion(ctx, paths)
			if err != nil {
				var ae *apiError
				if optional && errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusForbidden) {
					sleepCtx(ctx, 30*time.Second) // nothing to watch; Load treats it as absent
					continue
				}
				if ctx.Err() == nil {
					k.warn("watch %s: %v (retrying in %s)", paths[0], err, delay)
				}
				if !sleepCtx(ctx, jitter(delay)) {
					return
				}
				delay = min(delay*2, 30*time.Second)
				continue
			}
			wake() // changes may have landed between the controller's Load and this list
		}
		started := time.Now()
		err := k.stream(ctx, path, &rv, wake)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, errGone):
			rv = ""
			delay = k.backoffMin()
			wake()
			continue
		case errors.Is(err, errWatchUnavailable):
			k.warn("watch %s unavailable, polling instead", path)
			k.pollFallback(ctx, wake)
			rv = ""
			continue
		case err == nil && time.Since(started) > time.Second:
			delay = k.backoffMin() // clean timeout of a healthy stream: reconnect at once
			continue
		}
		if err != nil {
			k.warn("watch %s: %v (reconnecting in %s)", path, err, delay)
		}
		if !sleepCtx(ctx, jitter(delay)) {
			return
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func jitter(d time.Duration) time.Duration { return d/2 + time.Duration(rand.Int63n(int64(d/2)+1)) }

// pollFallback wakes the server at a poll rate for a minute, then lets the
// caller retry the watch.
func (k *KubeSource) pollFallback(ctx context.Context, wake func()) {
	every := k.fallbackPoll
	if every <= 0 {
		every = 5 * time.Second
	}
	end := time.Now().Add(12 * every)
	for time.Now().Before(end) {
		if !sleepCtx(ctx, every) {
			return
		}
		wake()
	}
}

// listVersion lists one item (cheap) to learn the collection's resourceVersion,
// trying each candidate path on 404.
func (k *KubeSource) listVersion(ctx context.Context, paths []string) (rv, path string, err error) {
	for _, p := range paths {
		b, e := k.do(ctx, http.MethodGet, p+"?limit=1", nil, "")
		var ae *apiError
		if errors.As(e, &ae) && ae.Status == http.StatusNotFound && len(paths) > 1 {
			err = e
			continue
		}
		if e != nil {
			return "", "", e
		}
		var l struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if e := json.Unmarshal(b, &l); e != nil {
			return "", "", fmt.Errorf("%s: %w", p, e)
		}
		return l.Metadata.ResourceVersion, p, nil
	}
	return "", "", err
}

// watchEvent is one line of a watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// stream runs one watch request until it ends. It advances *rv from every
// event and bookmark and calls wake for real changes. A clean end of stream
// (the server-side timeout) returns nil.
func (k *KubeSource) stream(ctx context.Context, path string, rv *string, wake func()) error {
	timeout := k.watchTimeout
	if timeout <= 0 {
		timeout = 300
	}
	q := url.Values{"watch": {"1"}, "allowWatchBookmarks": {"true"}, "timeoutSeconds": {fmt.Sprint(timeout)}}
	if *rv != "" {
		q.Set("resourceVersion", *rv)
	}
	rctx, cancel := context.WithTimeout(ctx, time.Duration(timeout+30)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, k.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	if tok := k.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	wc := *k.hc
	wc.Timeout = 0 // streams outlive the client's request timeout
	resp, err := wc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusGone:
		return errGone
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusForbidden:
		return errWatchUnavailable
	default:
		return fmt.Errorf("watch %s: HTTP %d", path, resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/") {
		return errWatchUnavailable
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev watchEvent
		if err := dec.Decode(&ev); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) || rctx.Err() != nil {
				return nil
			}
			return err
		}
		switch ev.Type {
		case "ERROR":
			var st struct {
				Code int `json:"code"`
			}
			json.Unmarshal(ev.Object, &st)
			if st.Code == http.StatusGone {
				return errGone
			}
			return fmt.Errorf("watch %s: error event %s", path, string(ev.Object))
		case "BOOKMARK", "ADDED", "MODIFIED", "DELETED":
		default:
			return errWatchUnavailable // a list or something else, not an event stream
		}
		var o struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		if json.Unmarshal(ev.Object, &o) == nil && o.Metadata.ResourceVersion != "" {
			*rv = o.Metadata.ResourceVersion
		}
		if ev.Type != "BOOKMARK" {
			wake()
		}
	}
}
