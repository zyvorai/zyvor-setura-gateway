package gateway

import (
	"bufio"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRedis is an in-process Redis speaking RESP2 on 127.0.0.1:0: enough of
// AUTH, SELECT, MULTI/EXEC, INCR, GET, PEXPIRE, EXPIRE, DEL and PING for the
// shared rate limiter. Expiry is recorded, not enforced (windows are part of
// the key, so tests stay deterministic).
type fakeRedis struct {
	t        *testing.T
	ln       net.Listener
	password string
	user     string

	mu       sync.Mutex
	data     map[string]string
	ttl      map[string]int64 // milliseconds as asked
	cmds     []string
	conns    map[net.Conn]bool
	down     bool
	stall    bool // accept and read commands but never answer
	nconn    int  // currently open
	maxConn  int  // most simultaneously open
	accepted atomic.Int64
	db       map[net.Conn]int
}

func newFakeRedis(t *testing.T, mod func(*fakeRedis), tlsCfg *tls.Config) *fakeRedis {
	t.Helper()
	f := &fakeRedis{t: t, data: map[string]string{}, ttl: map[string]int64{}, conns: map[net.Conn]bool{}, db: map[net.Conn]int{}}
	if mod != nil {
		mod(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	f.ln = ln
	go f.serve()
	t.Cleanup(f.close)
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) close() {
	f.ln.Close()
	f.dropAll()
}

func (f *fakeRedis) dropAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for c := range f.conns {
		c.Close()
	}
}

// setDown makes the server refuse (close at once) every connection and drops the open ones.
func (f *fakeRedis) setDown(v bool) {
	f.mu.Lock()
	f.down = v
	f.mu.Unlock()
	if v {
		f.dropAll()
	}
}

func (f *fakeRedis) setStall(v bool) {
	f.mu.Lock()
	f.stall = v
	f.mu.Unlock()
}

func (f *fakeRedis) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.accepted.Add(1)
		f.mu.Lock()
		if f.down {
			f.mu.Unlock()
			c.Close()
			continue
		}
		f.conns[c] = true
		f.nconn++
		if f.nconn > f.maxConn {
			f.maxConn = f.nconn
		}
		f.mu.Unlock()
		go f.handle(c)
	}
}

func (f *fakeRedis) logged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *fakeRedis) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.data {
		out = append(out, k)
	}
	return out
}

func (f *fakeRedis) handle(c net.Conn) {
	defer func() {
		c.Close()
		f.mu.Lock()
		delete(f.conns, c)
		f.nconn--
		f.mu.Unlock()
	}()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	authed := f.password == ""
	var queue [][]string
	inMulti := false
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		f.mu.Lock()
		stall := f.stall
		f.cmds = append(f.cmds, strings.Join(args, " "))
		f.mu.Unlock()
		if stall {
			time.Sleep(2 * time.Second)
			return
		}
		cmd := strings.ToUpper(args[0])
		var reply string
		switch {
		case cmd == "AUTH":
			user, pass := "", args[len(args)-1]
			if len(args) == 3 {
				user = args[1]
			}
			if pass == f.password && user == f.user {
				authed = true
				reply = "+OK\r\n"
			} else {
				reply = "-WRONGPASS invalid username-password pair\r\n"
			}
		case !authed:
			reply = "-NOAUTH Authentication required.\r\n"
		case cmd == "SELECT":
			n, _ := strconv.Atoi(args[1])
			f.mu.Lock()
			f.db[c] = n
			f.mu.Unlock()
			reply = "+OK\r\n"
		case cmd == "PING":
			reply = "+PONG\r\n"
		case cmd == "MULTI":
			inMulti, queue = true, nil
			reply = "+OK\r\n"
		case cmd == "EXEC":
			if !inMulti {
				reply = "-ERR EXEC without MULTI\r\n"
				break
			}
			inMulti = false
			reply = "*" + strconv.Itoa(len(queue)) + "\r\n"
			for _, q := range queue {
				reply += f.exec(q)
			}
		case inMulti:
			queue = append(queue, args)
			reply = "+QUEUED\r\n"
		default:
			reply = f.exec(args)
		}
		w.WriteString(reply)
		// a pipelined burst is answered together; flush when no more input is buffered
		if r.Buffered() == 0 {
			w.Flush()
		}
	}
}

func (f *fakeRedis) exec(args []string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "INCR":
		n, _ := strconv.ParseInt(f.data[args[1]], 10, 64)
		n++
		f.data[args[1]] = strconv.FormatInt(n, 10)
		return ":" + strconv.FormatInt(n, 10) + "\r\n"
	case "DECR":
		n, _ := strconv.ParseInt(f.data[args[1]], 10, 64)
		n--
		f.data[args[1]] = strconv.FormatInt(n, 10)
		return ":" + strconv.FormatInt(n, 10) + "\r\n"
	case "GET":
		v, ok := f.data[args[1]]
		if !ok {
			return "$-1\r\n"
		}
		return "$" + strconv.Itoa(len(v)) + "\r\n" + v + "\r\n"
	case "PEXPIRE":
		ms, _ := strconv.ParseInt(args[2], 10, 64)
		f.ttl[args[1]] = ms
		return ":1\r\n"
	case "EXPIRE":
		s, _ := strconv.ParseInt(args[2], 10, 64)
		f.ttl[args[1]] = s * 1000
		return ":1\r\n"
	case "DEL":
		delete(f.data, args[1])
		return ":1\r\n"
	}
	return "-ERR unknown command '" + args[0] + "'\r\n"
}

func readCommand(r *bufio.Reader) ([]string, error) {
	v, err := readValue(r, 0)
	if err != nil {
		return nil, err
	}
	var args []string
	for _, a := range v.arr {
		args = append(args, a.str)
	}
	if len(args) == 0 {
		return nil, net.ErrClosed
	}
	return args, nil
}
