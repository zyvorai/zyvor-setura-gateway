package gateway

import (
	"fmt"
	"time"
)

// CircuitOptions are the gateway-wide circuit breaking defaults. Zero values
// leave a limit off; a backend's circuitBreaker block overrides each field.
type CircuitOptions struct {
	MaxRequests      int           // concurrent requests per backend
	MaxPending       int           // requests that may wait for a free slot
	MaxConnections   int           // upstream connections per backend (spread over its endpoints)
	FailureThreshold int           // consecutive failures that open the circuit
	OpenFor          time.Duration // how long it stays open before probing (default 30s)
	HalfOpenProbes   int           // concurrent probe requests while half-open (default 1)
}

// CircuitConfig is the JSON form of circuit breaking settings, used for a
// backend's circuitBreaker field and the resilience block. Negative numbers
// lift a default limit for one backend.
type CircuitConfig struct {
	MaxRequests      int    `json:"maxRequests,omitempty"`
	MaxPending       int    `json:"maxPending,omitempty"`
	MaxConnections   int    `json:"maxConnections,omitempty"`
	FailureThreshold int    `json:"failureThreshold,omitempty"`
	OpenFor          string `json:"openFor,omitempty"`
	HalfOpenProbes   int    `json:"halfOpenProbes,omitempty"`
}

func (c *CircuitConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.HalfOpenProbes < 0 {
		return fmt.Errorf("halfOpenProbes %d must not be negative", c.HalfOpenProbes)
	}
	if d, err := parseDur(c.OpenFor); err != nil || d < 0 {
		return fmt.Errorf("openFor %q is not a duration", c.OpenFor)
	}
	return nil
}

// options converts the JSON form (durations already validated).
func (c *CircuitConfig) options() CircuitOptions {
	d, _ := parseDur(c.OpenFor)
	return CircuitOptions{MaxRequests: c.MaxRequests, MaxPending: c.MaxPending, MaxConnections: c.MaxConnections,
		FailureThreshold: c.FailureThreshold, OpenFor: d, HalfOpenProbes: c.HalfOpenProbes}
}

// ResilienceConfig is the optional "resilience" block of a gateway config
// file. Precedence, highest first: command-line flags (or Options), this
// block, built-in defaults. A reload applies a changed block at once.
type ResilienceConfig struct {
	RetryBudget       *int           `json:"retryBudget,omitempty"`
	RetryHeader       *bool          `json:"retryHeader,omitempty"`
	RetryBodyLimit    *int64         `json:"retryBodyLimit,omitempty"`
	RetryCrossBackend *bool          `json:"retryCrossBackend,omitempty"`
	RetryJitter       *float64       `json:"retryJitter,omitempty"`
	Outlier           *OutlierConfig `json:"outlier,omitempty"`
	Health            *HealthDefault `json:"health,omitempty"`
	CircuitBreaker    *CircuitConfig `json:"circuitBreaker,omitempty"`
}

// OutlierConfig is the outlier block; failures 0 turns ejection off.
type OutlierConfig struct {
	Failures     *int   `json:"failures,omitempty"`
	BaseEjection string `json:"baseEjection,omitempty"`
	MaxEjection  string `json:"maxEjection,omitempty"`
}

// HealthDefault is the default active health check for backends without one.
type HealthDefault struct {
	Path     string `json:"path,omitempty"`
	Interval string `json:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
}

func (f *ResilienceConfig) validate() error {
	if f.RetryBudget != nil && (*f.RetryBudget < 1 || *f.RetryBudget > 100) {
		return fmt.Errorf("retryBudget %d: want 1-100", *f.RetryBudget)
	}
	if f.RetryBodyLimit != nil && *f.RetryBodyLimit < 0 {
		return fmt.Errorf("retryBodyLimit must not be negative")
	}
	if f.RetryJitter != nil && (*f.RetryJitter < 0 || *f.RetryJitter > 1) {
		return fmt.Errorf("retryJitter %v: want 0-1", *f.RetryJitter)
	}
	if o := f.Outlier; o != nil {
		for _, v := range []string{o.BaseEjection, o.MaxEjection} {
			if d, err := parseDur(v); err != nil || d < 0 {
				return fmt.Errorf("outlier: %q is not a duration", v)
			}
		}
	}
	if h := f.Health; h != nil {
		for _, v := range []string{h.Interval, h.Timeout} {
			if d, err := parseDur(v); err != nil || d < 0 {
				return fmt.Errorf("health: %q is not a duration", v)
			}
		}
	}
	if err := f.CircuitBreaker.validate(); err != nil {
		return fmt.Errorf("circuitBreaker: %w", err)
	}
	return nil
}

// merge fills every option the flags left unset from the file block.
func (f *ResilienceConfig) merge(o ResilienceOptions) ResilienceOptions {
	if f == nil {
		return o
	}
	if o.RetryBudgetPercent == 0 && f.RetryBudget != nil {
		o.RetryBudgetPercent = *f.RetryBudget
	}
	if f.RetryHeader != nil && *f.RetryHeader {
		o.RetryHeader = true
	}
	if o.RetryBodyLimit == 0 && f.RetryBodyLimit != nil {
		o.RetryBodyLimit = *f.RetryBodyLimit
	}
	if f.RetryCrossBackend != nil && *f.RetryCrossBackend {
		o.RetryCrossBackend = true
	}
	if o.RetryJitter == 0 && f.RetryJitter != nil {
		o.RetryJitter = *f.RetryJitter
	}
	if oc := f.Outlier; oc != nil {
		if o.OutlierFailures == 0 && oc.Failures != nil {
			o.OutlierFailures = *oc.Failures
			if *oc.Failures == 0 {
				o.OutlierFailures = -1
			}
		}
		if d, _ := parseDur(oc.BaseEjection); o.OutlierBaseEject == 0 {
			o.OutlierBaseEject = d
		}
		if d, _ := parseDur(oc.MaxEjection); o.OutlierMaxEject == 0 {
			o.OutlierMaxEject = d
		}
	}
	if h := f.Health; h != nil {
		if o.HealthPath == "" {
			o.HealthPath = h.Path
		}
		if d, _ := parseDur(h.Interval); o.HealthInterval == 0 {
			o.HealthInterval = d
		}
		if d, _ := parseDur(h.Timeout); o.HealthTimeout == 0 {
			o.HealthTimeout = d
		}
	}
	if c := f.CircuitBreaker; c != nil {
		o.Circuit = overlayCircuit(c.options(), o.Circuit) // flags win over the file
	}
	return o
}

// overlayCircuit returns base with every non-zero field of top applied.
func overlayCircuit(base, top CircuitOptions) CircuitOptions {
	if top.MaxRequests != 0 {
		base.MaxRequests = top.MaxRequests
	}
	if top.MaxPending != 0 {
		base.MaxPending = top.MaxPending
	}
	if top.MaxConnections != 0 {
		base.MaxConnections = top.MaxConnections
	}
	if top.FailureThreshold != 0 {
		base.FailureThreshold = top.FailureThreshold
	}
	if top.OpenFor != 0 {
		base.OpenFor = top.OpenFor
	}
	if top.HalfOpenProbes != 0 {
		base.HalfOpenProbes = top.HalfOpenProbes
	}
	return base
}

// setFile installs the config file's resilience block (nil clears it) and
// recomputes the effective options.
func (rs *resilience) setFile(f *ResilienceConfig) error {
	if f != nil {
		if err := f.validate(); err != nil {
			return fmt.Errorf("resilience: %w", err)
		}
	}
	rs.cur.Store(normalizeResilience(f.merge(rs.raw)))
	return nil
}
