package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// LeaseConfig configures leader election through a coordination.k8s.io/v1 Lease.
// Only the leader writes status; every replica keeps serving traffic.
type LeaseConfig struct {
	Name, Namespace, Identity string
	Duration                  time.Duration // validity of a Lease without renewal
	RenewDeadline             time.Duration // the leader steps down after failing to renew for this long
	RetryPeriod               time.Duration // pause between attempts
}

const microTime = "2006-01-02T15:04:05.000000Z"

type leaseRecord struct {
	Holder      string
	DurationSec int
	AcquireTime string
	RenewTime   string
	Transitions int
	RV          string
}

type elector struct {
	k      *KubeSource
	cfg    LeaseConfig
	wake   func()
	leader atomic.Bool

	observed   leaseRecord // last record seen (holder, renewTime, transitions)
	observedAt time.Time   // local time it last changed: expiry is judged on our own clock
}

func newElector(k *KubeSource, cfg LeaseConfig, wake func()) *elector {
	if cfg.Duration <= 0 {
		cfg.Duration = 15 * time.Second
	}
	if cfg.RenewDeadline <= 0 || cfg.RenewDeadline >= cfg.Duration {
		cfg.RenewDeadline = cfg.Duration * 2 / 3
	}
	if cfg.RetryPeriod <= 0 {
		cfg.RetryPeriod = 2 * time.Second
	}
	if cfg.Name == "" {
		cfg.Name = "setura-gateway"
	}
	return &elector{k: k, cfg: cfg, wake: wake}
}

func (e *elector) isLeader() bool { return e.leader.Load() }

func (e *elector) set(v bool) {
	if e.leader.Swap(v) != v {
		if v {
			e.k.warn("leader election: acquired lease %s/%s as %s", e.cfg.Namespace, e.cfg.Name, e.cfg.Identity)
		} else {
			e.k.warn("leader election: lost lease %s/%s", e.cfg.Namespace, e.cfg.Name)
		}
		e.wake() // a new leader writes status at once
	}
}

func (e *elector) path() string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(e.cfg.Namespace) + "/leases"
}

func (e *elector) body(rec leaseRecord, holder string, create bool) []byte {
	md := map[string]any{"name": e.cfg.Name, "namespace": e.cfg.Namespace}
	if !create {
		md["resourceVersion"] = rec.RV
	}
	var h any
	if holder != "" {
		h = holder
	}
	b, _ := json.Marshal(map[string]any{"apiVersion": "coordination.k8s.io/v1", "kind": "Lease", "metadata": md,
		"spec": map[string]any{"holderIdentity": h, "leaseDurationSeconds": rec.DurationSec,
			"acquireTime": rec.AcquireTime, "renewTime": rec.RenewTime, "leaseTransitions": rec.Transitions}})
	return b
}

func (e *elector) get(ctx context.Context) (leaseRecord, bool, error) {
	b, err := e.k.do(ctx, http.MethodGet, e.path()+"/"+url.PathEscape(e.cfg.Name), nil, "")
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return leaseRecord{}, false, nil
	}
	if err != nil {
		return leaseRecord{}, false, err
	}
	var o struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Spec struct {
			Holder      *string `json:"holderIdentity"`
			DurationSec int     `json:"leaseDurationSeconds"`
			AcquireTime string  `json:"acquireTime"`
			RenewTime   string  `json:"renewTime"`
			Transitions int     `json:"leaseTransitions"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return leaseRecord{}, false, err
	}
	r := leaseRecord{DurationSec: o.Spec.DurationSec, AcquireTime: o.Spec.AcquireTime, RenewTime: o.Spec.RenewTime,
		Transitions: o.Spec.Transitions, RV: o.Metadata.ResourceVersion}
	if o.Spec.Holder != nil {
		r.Holder = *o.Spec.Holder
	}
	return r, true, nil
}

// attempt tries to acquire or renew once. held reports that we hold the lease
// now; lost that somebody else demonstrably does.
func (e *elector) attempt(ctx context.Context) (held, lost bool) {
	now := time.Now().UTC()
	nowS := now.Format(microTime)
	secs := int(e.cfg.Duration / time.Second)
	if secs < 1 {
		secs = 1
	}
	rec, found, err := e.get(ctx)
	if err != nil {
		return false, false
	}
	if !found {
		_, err := e.k.do(ctx, http.MethodPost, e.path(), e.body(leaseRecord{DurationSec: secs, AcquireTime: nowS, RenewTime: nowS}, e.cfg.Identity, true), "application/json")
		return err == nil, false
	}
	if e.observedAt.IsZero() || rec.Holder != e.observed.Holder || rec.RenewTime != e.observed.RenewTime || rec.Transitions != e.observed.Transitions {
		e.observed, e.observedAt = rec, time.Now()
	}
	valid := time.Duration(rec.DurationSec) * time.Second
	if rec.Holder != "" && rec.Holder != e.cfg.Identity && time.Since(e.observedAt) < valid {
		return false, true
	}
	next := leaseRecord{RV: rec.RV, DurationSec: secs, AcquireTime: rec.AcquireTime, RenewTime: nowS, Transitions: rec.Transitions}
	if rec.Holder != e.cfg.Identity {
		next.AcquireTime = nowS
		next.Transitions++
	}
	_, err = e.k.do(ctx, http.MethodPut, e.path()+"/"+url.PathEscape(e.cfg.Name), e.body(next, e.cfg.Identity, false), "application/json")
	if err != nil {
		var ae *apiError
		return false, errors.As(err, &ae) && ae.Status == http.StatusConflict && rec.Holder != e.cfg.Identity
	}
	e.observed, e.observedAt = next, time.Now()
	e.observed.Holder = e.cfg.Identity
	return true, false
}

// release gives the lease up so another replica need not wait for expiry.
func (e *elector) release() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, found, err := e.get(ctx)
	if err != nil || !found || rec.Holder != e.cfg.Identity {
		return
	}
	nowS := time.Now().UTC().Format(microTime)
	rec.DurationSec, rec.RenewTime = 1, nowS
	e.k.do(ctx, http.MethodPut, e.path()+"/"+url.PathEscape(e.cfg.Name), e.body(rec, "", false), "application/json")
}

func (e *elector) run(ctx context.Context) {
	var lastRenew time.Time
	for {
		held, lost := e.attempt(ctx)
		switch {
		case ctx.Err() != nil:
		case held:
			lastRenew = time.Now()
			e.set(true)
		case lost || (e.isLeader() && time.Since(lastRenew) > e.cfg.RenewDeadline):
			e.set(false)
		}
		if ctx.Err() != nil || !sleepCtx(ctx, jitter(e.cfg.RetryPeriod)) {
			break
		}
	}
	if e.isLeader() {
		e.release()
		e.leader.Store(false)
	}
}
