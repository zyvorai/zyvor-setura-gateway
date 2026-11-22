package gateway

import (
	"encoding/json"
	"fmt"
)

// CheckRule reports why the built-in gateway would refuse an HTTPRoute rule
// because of the Gateway API 1.5 features it uses: a CORS or ExternalAuth
// filter, session persistence or backend timeouts. Lint rule SET019 calls it,
// so the linter and the data plane share one definition of "valid".
func CheckRule(raw []byte) error {
	var r Rule
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("rule does not parse: %w", err)
	}
	check := func(where string, fs []Filter) error {
		for _, f := range fs {
			switch f.Type {
			case "CORS":
				if err := validFilters([]Filter{f}); err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
			case "ExternalAuth":
				if f.ExternalAuth == nil {
					return fmt.Errorf("%s: ExternalAuth filter has no externalAuth block", where)
				}
				if err := f.ExternalAuth.validate(); err != nil {
					return fmt.Errorf("%s: %w", where, err)
				}
			}
		}
		return nil
	}
	if err := check("filters", r.Filters); err != nil {
		return err
	}
	for i, ref := range r.BackendRefs {
		if err := check(fmt.Sprintf("backendRefs[%d].filters", i), ref.Filters); err != nil {
			return err
		}
		if _, err := compileSession(ref.SessionPersistence); err != nil {
			return fmt.Errorf("backendRefs[%d]: %w", i, err)
		}
	}
	if _, err := compileSession(r.SessionPersistence); err != nil {
		return err
	}
	if r.Timeouts != nil {
		req, err := parseDur(r.Timeouts.Request)
		if err != nil {
			return fmt.Errorf("timeouts.request: %w", err)
		}
		bt, err := parseDur(r.Timeouts.BackendRequest)
		if err != nil {
			return fmt.Errorf("timeouts.backendRequest: %w", err)
		}
		if req > 0 && bt > req {
			return fmt.Errorf("timeouts.backendRequest %s must not exceed timeouts.request %s", r.Timeouts.BackendRequest, r.Timeouts.Request)
		}
	}
	return nil
}

// CheckBackendTLSPolicy reports a BackendTLSPolicy spec the gateway would not
// accept (shape only: references to ConfigMaps are resolved at run time).
func CheckBackendTLSPolicy(raw []byte) error {
	var spec backendTLSSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("policy does not parse: %w", err)
	}
	p := &BackendTLSPolicy{Targets: spec.TargetRefs, Validation: spec.Validation}
	res := (&Config{}).resolveBackendTLS(p, nil)
	if !res.Accepted.OK && res.Accepted.Reason != "NoValidCACertificate" {
		return fmt.Errorf("%s: %s", res.Accepted.Reason, res.Accepted.Message)
	}
	return nil
}
