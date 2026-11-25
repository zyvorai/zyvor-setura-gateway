package setura

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAlertCooldown = time.Minute
	defaultAlertRetries  = 3
	alertBackoffBase     = 500 * time.Millisecond
	alertRequestTimeout  = 10 * time.Second
	maxAlertStreak       = 1000
)

// alertSink is one notification destination. Its URL is a secret and must
// never reach a log line or an error message.
type alertSink struct {
	kind string // "webhook" or "slack"
	url  string
}

// alertConfig configures alerting for setura watch.
type alertConfig struct {
	Webhook  string
	Slack    string
	Cooldown time.Duration
	Retries  int // retries after the first attempt
	// Consecutive failed (or passed) probes before a failure (or recovery) is
	// announced; 0 means 1.
	FailAfter    int
	RecoverAfter int
}

// alertEvent is one transition delivered to the sinks.
type alertEvent struct {
	Failing   bool
	Target    string
	Stage     string
	Reason    string
	ElapsedMS float64
	Time      time.Time
	// Consecutive is the length of the streak that raised the alert, set only
	// when a threshold above 1 applies.
	Consecutive int
}

type alertState struct {
	failing  bool      // what recipients were last told
	lastSent time.Time // last successful delivery
	inflight bool
	failRun  int // consecutive failed probes
	okRun    int // consecutive passed probes
}

// alerter sends failure and recovery transitions, one notification per
// transition. Clock, sleep and HTTP client are injectable for tests.
type alerter struct {
	sinks    []alertSink
	cooldown time.Duration
	retries  int
	backoff  time.Duration
	client   *http.Client
	now      func() time.Time
	sleep    func(time.Duration)
	log      io.Writer

	failAfter    int
	recoverAfter int

	mu    sync.Mutex
	state map[string]*alertState
	wg    sync.WaitGroup
}

// validateAlertURL checks scheme and host without echoing the value.
func validateAlertURL(flagName, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return userErrorf("%s must be an http or https URL (value not shown, it is a secret)", flagName)
	}
	return nil
}

// newAlerter returns nil when no sink is configured.
func newAlerter(cfg alertConfig, log io.Writer) (*alerter, error) {
	var sinks []alertSink
	if cfg.Webhook != "" {
		if err := validateAlertURL("--alert-webhook", cfg.Webhook); err != nil {
			return nil, err
		}
		sinks = append(sinks, alertSink{"webhook", cfg.Webhook})
	}
	if cfg.Slack != "" {
		if err := validateAlertURL("--alert-slack", cfg.Slack); err != nil {
			return nil, err
		}
		sinks = append(sinks, alertSink{"slack", cfg.Slack})
	}
	if len(sinks) == 0 {
		return nil, nil
	}
	if cfg.Cooldown < 0 {
		return nil, userError("--alert-cooldown must not be negative")
	}
	if cfg.Retries < 0 || cfg.Retries > 10 {
		return nil, userError("--alert-retries must be between 0 and 10")
	}
	if cfg.FailAfter < 0 || cfg.FailAfter > maxAlertStreak || cfg.RecoverAfter < 0 || cfg.RecoverAfter > maxAlertStreak {
		return nil, userErrorf("--alert-after and --alert-recover-after must be between 1 and %d", maxAlertStreak)
	}
	return &alerter{
		sinks: sinks, cooldown: cfg.Cooldown, retries: cfg.Retries, backoff: alertBackoffBase,
		client: &http.Client{Timeout: alertRequestTimeout}, now: time.Now, sleep: time.Sleep, log: log,
		state: map[string]*alertState{}, failAfter: cfg.FailAfter, recoverAfter: cfg.RecoverAfter,
	}, nil
}

// observe folds one probe result in and, on a failure or recovery transition
// that is outside the cooldown, delivers it in the background. Repeated
// results in the same state send nothing. A transition suppressed by the
// cooldown is reconsidered on later probes, so a flap that settles back to the
// state recipients already know about produces no message at all.
func (a *alerter) observe(target string, ok bool, stage, reason string, elapsedMS float64) {
	now := a.now()
	a.mu.Lock()
	st := a.state[target]
	if st == nil {
		st = &alertState{}
		a.state[target] = st
	}
	failing := !ok
	if ok {
		st.okRun, st.failRun = st.okRun+1, 0
	} else {
		st.failRun, st.okRun = st.failRun+1, 0
	}
	run, need := st.okRun, a.recoverAfter
	if failing {
		run, need = st.failRun, a.failAfter
	}
	if st.inflight || failing == st.failing || run < need || (!st.lastSent.IsZero() && now.Sub(st.lastSent) < a.cooldown) {
		a.mu.Unlock()
		return
	}
	st.inflight = true
	a.mu.Unlock()
	ev := alertEvent{Failing: failing, Target: target, Stage: stage, Reason: reason, ElapsedMS: elapsedMS, Time: now}
	if need > 1 {
		ev.Consecutive = run
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		err := a.deliver(ev)
		a.mu.Lock()
		st.inflight = false
		if err == nil {
			st.failing, st.lastSent = ev.Failing, a.now()
		}
		a.mu.Unlock()
		if err != nil {
			a.logf("setura watch: alert for %s not delivered: %v\n", ev.Target, err)
		}
	}()
}

// wait blocks until in-flight deliveries finish.
func (a *alerter) wait() {
	if a != nil {
		a.wg.Wait()
	}
}

func (a *alerter) logf(format string, args ...any) {
	if a.log == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintf(a.log, format, args...)
}

// deliver sends ev to every sink; it returns an error when any sink failed.
func (a *alerter) deliver(ev alertEvent) error {
	var failed []string
	for _, s := range a.sinks {
		if err := a.send(s, ev); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", s.kind, err))
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// send posts to one sink with exponential backoff on network errors, 429 and
// 5xx. Other 4xx responses are permanent and not retried.
func (a *alerter) send(s alertSink, ev alertEvent) error {
	body, err := json.Marshal(alertPayload(s.kind, ev))
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt <= a.retries; attempt++ {
		if attempt > 0 {
			a.sleep(a.backoff << (attempt - 1))
		}
		var retry bool
		retry, last = a.post(s, body)
		if last == nil {
			return nil
		}
		if !retry {
			break
		}
	}
	return fmt.Errorf("%v", last)
}

func (a *alerter) post(s alertSink, body []byte) (retry bool, err error) {
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("could not build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "setura-watch")
	resp, err := a.client.Do(req)
	if err != nil {
		return true, scrubError(err, s.url)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return false, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// scrubError drops the request URL that net/http embeds in its errors and
// masks any remaining occurrence of the secret.
func scrubError(err error, secret string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if u, perr := url.Parse(secret); perr == nil {
		for _, s := range []string{secret, u.Host, u.Path, u.RawQuery} {
			if len(s) > 1 {
				msg = strings.ReplaceAll(msg, s, "[redacted]")
			}
		}
	}
	return errors.New(msg)
}

func (e alertEvent) kind() string {
	if e.Failing {
		return "failure"
	}
	return "recovery"
}

func (e alertEvent) summary() string {
	if !e.Failing {
		return fmt.Sprintf("%s recovered", e.Target)
	}
	s := fmt.Sprintf("%s is failing", e.Target)
	if e.Stage != "" {
		s += " at " + e.Stage
	}
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	return s
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// alertPayload builds the request body for a sink kind.
func alertPayload(kind string, e alertEvent) obj {
	if kind == "slack" {
		color, icon := "good", ":white_check_mark:"
		if e.Failing {
			color, icon = "danger", ":rotating_light:"
		}
		return obj{
			"text": icon + " setura: " + slackEscape(e.summary()),
			"attachments": []any{obj{"color": color, "fields": []any{
				obj{"title": "Event", "value": e.kind(), "short": true},
				obj{"title": "Target", "value": slackEscape(e.Target), "short": true},
				obj{"title": "Time", "value": e.Time.UTC().Format(time.RFC3339), "short": true},
			}}},
		}
	}
	p := obj{"source": "setura", "event": e.kind(), "target": e.Target, "time": e.Time.UTC().Format(time.RFC3339),
		"elapsed_ms": e.ElapsedMS, "message": e.summary()}
	if e.Failing {
		p["stage"], p["reason"] = e.Stage, e.Reason
	}
	if e.Consecutive > 0 {
		p["consecutive"] = e.Consecutive
	}
	return p
}
