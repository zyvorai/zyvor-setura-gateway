package setura

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	defaultLockHeartbeat = 5 * time.Second
	defaultLockTimeout   = time.Minute
)

// lockInfo is the content of the rollout lock file. The owner rewrites it
// atomically every heartbeat period, so a lock whose owner was killed (SIGKILL,
// power loss) is recognisable: its process is gone, or its heartbeat stopped.
type lockInfo struct {
	Pid       int    `json:"pid"`
	Host      string `json:"host"`
	Started   string `json:"started"`
	Heartbeat string `json:"heartbeat"`
	Token     string `json:"token"`
}

func (h histStore) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

func (h histStore) hostname() string {
	if h.host != "" {
		return h.host
	}
	n, _ := os.Hostname()
	return n
}

func (h histStore) timeout() time.Duration {
	if h.hbTimeout > 0 {
		return h.hbTimeout
	}
	return defaultLockTimeout
}

func (h histStore) period() time.Duration {
	if h.hbEvery > 0 {
		return h.hbEvery
	}
	return defaultLockHeartbeat
}

// pidAlive reports whether a process exists. known is false when the platform
// cannot tell.
func pidAlive(pid int) (alive, known bool) {
	if pid <= 0 {
		return false, true
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false, false
	}
	switch err := p.Signal(syscall.Signal(0)); {
	case err == nil:
		return true, true
	case errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH):
		return false, true
	case errors.Is(err, syscall.EPERM):
		return true, true
	}
	return false, false
}

func (h histStore) isAlive(pid int) (bool, bool) {
	if h.alive != nil {
		return h.alive(pid)
	}
	return pidAlive(pid)
}

func parseLock(raw []byte, mtime time.Time) lockInfo {
	var li lockInfo
	if json.Unmarshal(raw, &li) == nil && li.Pid != 0 {
		return li
	}
	// The first versions wrote just "PID\n".
	fmt.Sscanf(string(bytes.TrimSpace(raw)), "%d", &li.Pid)
	li.Heartbeat = mtime.UTC().Format(time.RFC3339Nano)
	return li
}

func (li lockInfo) describe(now time.Time) string {
	hb, err := time.Parse(time.RFC3339Nano, li.Heartbeat)
	age := "unknown"
	if err == nil {
		age = now.Sub(hb).Round(time.Second).String() + " ago"
	}
	host := li.Host
	if host == "" {
		host = "an unknown host"
	}
	return fmt.Sprintf("pid %d on %s, started %s, last heartbeat %s", li.Pid, host, li.Started, age)
}

// staleReason says why the lock owner is dead, or "" when it may be alive.
func (h histStore) staleReason(li lockInfo) string {
	now := h.clock()
	hb, hbErr := time.Parse(time.RFC3339Nano, li.Heartbeat)
	old := hbErr == nil && now.Sub(hb) > h.timeout()
	if li.Host == "" || li.Host == h.hostname() {
		alive, known := h.isAlive(li.Pid)
		switch {
		case known && !alive:
			return "its process is no longer running"
		case known && alive:
			return "" // never steal from a live owner, however old the heartbeat
		}
	}
	if old { // another host, or the platform cannot say: only the heartbeat speaks
		return fmt.Sprintf("its heartbeat is older than %s", h.timeout())
	}
	return ""
}

func newToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// lock serializes rollouts against one config. The returned func releases it.
func (h histStore) lock() (func(), error) { return h.lockWith(nil) }

// lockWith is lock that reports a takeover of a stale lock through note.
func (h histStore) lockWith(note func(string, ...any)) (func(), error) {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(h.dir, "lock")
	mine := lockInfo{Pid: os.Getpid(), Host: h.hostname(), Started: h.clock().UTC().Format(time.RFC3339), Token: newToken()}
	for attempt := 0; ; attempt++ {
		err := h.create(p, &mine)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			if errors.Is(rerr, os.ErrNotExist) && attempt < 5 {
				continue // released between our attempts
			}
			return nil, rerr
		}
		var mt time.Time
		if st, serr := os.Stat(p); serr == nil {
			mt = st.ModTime()
		}
		li := parseLock(raw, mt)
		why := h.staleReason(li)
		if why == "" {
			return nil, userErrorf("another rollout holds %s (%s); if you are sure no rollout is running, delete it", p, li.describe(h.clock()))
		}
		if attempt >= 5 {
			return nil, userErrorf("cannot take over the stale lock %s: it keeps changing", p)
		}
		// Move the stale lock aside atomically: of two would-be takers only one
		// rename succeeds. Then check that what we moved is what we judged.
		aside := fmt.Sprintf("%s.stale.%d", p, os.Getpid())
		if err := os.Rename(p, aside); err != nil {
			continue
		}
		moved, _ := os.ReadFile(aside)
		if !bytes.Equal(moved, raw) {
			// A fresh owner took the lock between our read and the rename: put it back.
			if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
				os.Rename(aside, p)
			} else {
				os.Remove(aside)
			}
			continue
		}
		os.Remove(aside)
		if note != nil {
			note("took over a stale rollout lock (%s): %s", li.describe(h.clock()), why)
		}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tk := time.NewTicker(h.period())
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				h.beat(p, mine)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		if raw, err := os.ReadFile(p); err == nil && parseLock(raw, time.Time{}).Token == mine.Token {
			os.Remove(p)
		}
	}, nil
}

// create writes the lock exclusively, with its first heartbeat.
func (h histStore) create(p string, li *lockInfo) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	li.Heartbeat = h.clock().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(li)
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(p)
	}
	return werr
}

// beat refreshes the heartbeat, but only while the lock is still ours.
func (h histStore) beat(p string, mine lockInfo) {
	raw, err := os.ReadFile(p)
	if err != nil || parseLock(raw, time.Time{}).Token != mine.Token {
		return
	}
	mine.Heartbeat = h.clock().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(mine)
	atomicWrite(p, append(b, '\n'), 0o600)
}
