package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A small Redis client for the shared rate limiter: RESP2 over a plain or TLS
// connection, AUTH and SELECT on connect, a bounded connection pool and a
// deadline on every round trip. It speaks only what the limiter needs
// (pipelined commands, MULTI/EXEC, GET); it is not a general client.

// RedisOptions describe one Redis server a shared rate limit can use.
type RedisOptions struct {
	Name        string // the name a rate-limit block's shared.redis refers to (default "default")
	Addr        string // host:port
	Username    string
	Password    string
	DB          int
	TLS         bool
	CAFile      string        // extra CA bundle for TLS (default: system roots)
	ServerName  string        // TLS server name (default: the host of Addr)
	TLSConfig   *tls.Config   // overrides TLS, CAFile and ServerName (tests)
	DialTimeout time.Duration // default 1s
	IOTimeout   time.Duration // per round trip, default 250ms
	PoolSize    int           // most open connections, default 16
	MaxIdle     time.Duration // an idle connection older than this is closed (default 5m)
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DefaultRedisName names the Redis server used when a block does not say.
const DefaultRedisName = "default"

// ParseRedisFlag reads one --redis value: [NAME=]ADDR where ADDR is host:port
// or a redis:// or rediss:// URL (user:password@host:port/db).
func ParseRedisFlag(v string) (RedisOptions, error) {
	o := RedisOptions{Name: DefaultRedisName}
	v = strings.TrimSpace(v)
	if name, rest, ok := strings.Cut(v, "="); ok && !strings.Contains(name, "/") && !strings.Contains(name, ":") && name != "" {
		o.Name, v = name, rest
	}
	if v == "" {
		return o, errors.New("redis address is empty")
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") || u.Host == "" {
			return o, fmt.Errorf("redis %q: want host:port, redis://[user:password@]host:port[/db] or rediss://...", v)
		}
		o.TLS = u.Scheme == "rediss"
		o.Addr = u.Host
		if u.User != nil {
			o.Username = u.User.Username()
			o.Password, _ = u.User.Password()
		}
		if p := strings.Trim(u.Path, "/"); p != "" {
			db, err := strconv.Atoi(p)
			if err != nil || db < 0 {
				return o, fmt.Errorf("redis %q: database %q is not a number", v, p)
			}
			o.DB = db
		}
	} else {
		o.Addr = v
	}
	if _, _, err := net.SplitHostPort(o.Addr); err != nil {
		if !strings.Contains(o.Addr, ":") {
			o.Addr = net.JoinHostPort(o.Addr, "6379")
		} else {
			return o, fmt.Errorf("redis %q: %v", v, err)
		}
	}
	return o, nil
}

func (o *RedisOptions) withDefaults() {
	if o.Name == "" {
		o.Name = DefaultRedisName
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = time.Second
	}
	if o.IOTimeout <= 0 {
		o.IOTimeout = 250 * time.Millisecond
	}
	if o.PoolSize <= 0 {
		o.PoolSize = 16
	}
	if o.MaxIdle <= 0 {
		o.MaxIdle = 5 * time.Minute
	}
}

// respKind is the type byte of a RESP value.
type respKind byte

const (
	respSimple respKind = '+'
	respError  respKind = '-'
	respInt    respKind = ':'
	respBulk   respKind = '$'
	respArray  respKind = '*'
)

// respValue is one decoded reply.
type respValue struct {
	kind respKind
	str  string
	num  int64
	nil_ bool
	arr  []respValue
}

func (v respValue) isErr() bool { return v.kind == respError }

// intValue reads an integer reply (or a numeric bulk string).
func (v respValue) intValue() (int64, bool) {
	switch v.kind {
	case respInt:
		return v.num, true
	case respBulk, respSimple:
		n, err := strconv.ParseInt(v.str, 10, 64)
		return n, err == nil
	}
	return 0, false
}

const (
	maxRespBulk  = 512 << 20
	maxRespArray = 1 << 20
)

// writeCommand encodes args as a RESP array of bulk strings.
func writeCommand(w *bufio.Writer, args []string) {
	w.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		w.WriteString("$" + strconv.Itoa(len(a)) + "\r\n")
		w.WriteString(a)
		w.WriteString("\r\n")
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("redis: malformed line")
	}
	return line[:len(line)-2], nil
}

// readValue decodes one RESP2 reply.
func readValue(r *bufio.Reader, depth int) (respValue, error) {
	if depth > 8 {
		return respValue{}, errors.New("redis: reply nested too deeply")
	}
	line, err := readLine(r)
	if err != nil {
		return respValue{}, err
	}
	if line == "" {
		return respValue{}, errors.New("redis: empty reply")
	}
	kind, rest := respKind(line[0]), line[1:]
	switch kind {
	case respSimple, respError:
		return respValue{kind: kind, str: rest}, nil
	case respInt:
		n, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			return respValue{}, errors.New("redis: bad integer reply")
		}
		return respValue{kind: kind, num: n}, nil
	case respBulk:
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 || n > maxRespBulk {
			return respValue{}, errors.New("redis: bad bulk length")
		}
		if n == -1 {
			return respValue{kind: kind, nil_: true}, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return respValue{}, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return respValue{}, errors.New("redis: bulk string not terminated")
		}
		return respValue{kind: kind, str: string(buf[:n])}, nil
	case respArray:
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 || n > maxRespArray {
			return respValue{}, errors.New("redis: bad array length")
		}
		if n == -1 {
			return respValue{kind: kind, nil_: true}, nil
		}
		v := respValue{kind: kind, arr: make([]respValue, 0, n)}
		for i := 0; i < n; i++ {
			e, err := readValue(r, depth+1)
			if err != nil {
				return respValue{}, err
			}
			v.arr = append(v.arr, e)
		}
		return v, nil
	}
	return respValue{}, fmt.Errorf("redis: unexpected reply type %q", line[0])
}

type redisConn struct {
	c       net.Conn
	r       *bufio.Reader
	w       *bufio.Writer
	lastUse time.Time
}

// RedisClient is a pooled connection to one Redis server.
type RedisClient struct {
	o      RedisOptions
	tlsCfg *tls.Config
	sem    chan struct{} // one token per open connection
	mu     sync.Mutex
	idle   []*redisConn
	closed bool

	errors atomic.Int64
	up     atomic.Bool // the last round trip succeeded
	used   atomic.Bool // a round trip was ever tried
}

// NewRedisClient builds a client. Nothing is dialled until the first command.
func NewRedisClient(o RedisOptions) (*RedisClient, error) {
	o.withDefaults()
	if o.Addr == "" {
		return nil, errors.New("redis address is empty")
	}
	c := &RedisClient{o: o, sem: make(chan struct{}, o.PoolSize)}
	if o.TLS || o.TLSConfig != nil {
		cfg := o.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
			if o.CAFile != "" {
				pem, err := os.ReadFile(o.CAFile)
				if err != nil {
					return nil, fmt.Errorf("redis %s: %w", o.Name, err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("redis %s: %s holds no PEM certificate", o.Name, o.CAFile)
				}
				cfg.RootCAs = pool
			}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			host := o.ServerName
			if host == "" {
				host, _, _ = net.SplitHostPort(o.Addr)
			}
			cfg.ServerName = host
		}
		c.tlsCfg = cfg
	}
	return c, nil
}

// Name is the configured name.
func (c *RedisClient) Name() string { return c.o.Name }

func (c *RedisClient) dial(ctx context.Context) (*redisConn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.o.DialTimeout)
	defer cancel()
	dial := c.o.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	nc, err := dial(dctx, "tcp", c.o.Addr)
	if err != nil {
		return nil, err
	}
	if c.tlsCfg != nil {
		tc := tls.Client(nc, c.tlsCfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			nc.Close()
			return nil, err
		}
		nc = tc
	}
	rc := &redisConn{c: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	var setup [][]string
	if c.o.Password != "" {
		if c.o.Username != "" {
			setup = append(setup, []string{"AUTH", c.o.Username, c.o.Password})
		} else {
			setup = append(setup, []string{"AUTH", c.o.Password})
		}
	}
	if c.o.DB != 0 {
		setup = append(setup, []string{"SELECT", strconv.Itoa(c.o.DB)})
	}
	if len(setup) > 0 {
		vals, err := c.roundTrip(rc, setup)
		if err != nil {
			nc.Close()
			return nil, err
		}
		for _, v := range vals {
			if v.isErr() {
				nc.Close()
				return nil, fmt.Errorf("redis: %s", v.str)
			}
		}
	}
	return rc, nil
}

func (c *RedisClient) roundTrip(rc *redisConn, cmds [][]string) ([]respValue, error) {
	rc.c.SetDeadline(time.Now().Add(c.o.IOTimeout))
	for _, cmd := range cmds {
		writeCommand(rc.w, cmd)
	}
	if err := rc.w.Flush(); err != nil {
		return nil, err
	}
	out := make([]respValue, 0, len(cmds))
	for range cmds {
		v, err := readValue(rc.r, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (c *RedisClient) get(ctx context.Context) (*redisConn, error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.sem
		return nil, errors.New("redis client closed")
	}
	for len(c.idle) > 0 {
		rc := c.idle[len(c.idle)-1]
		c.idle = c.idle[:len(c.idle)-1]
		if time.Since(rc.lastUse) > c.o.MaxIdle {
			rc.c.Close()
			continue
		}
		c.mu.Unlock()
		return rc, nil
	}
	c.mu.Unlock()
	rc, err := c.dial(ctx)
	if err != nil {
		<-c.sem
		return nil, err
	}
	return rc, nil
}

func (c *RedisClient) put(rc *redisConn, healthy bool) {
	defer func() { <-c.sem }()
	if !healthy {
		rc.c.Close()
		return
	}
	rc.lastUse = time.Now()
	c.mu.Lock()
	if c.closed || len(c.idle) >= c.o.PoolSize {
		c.mu.Unlock()
		rc.c.Close()
		return
	}
	c.idle = append(c.idle, rc)
	c.mu.Unlock()
}

// Do sends the commands as one pipeline and returns one reply per command.
// A transport or protocol failure is an error; a Redis error reply (-ERR ...)
// is a value with isErr() set.
func (c *RedisClient) Do(ctx context.Context, cmds ...[]string) ([]respValue, error) {
	c.used.Store(true)
	var lastErr error
	// One retry on a stale pooled connection (the server may have closed it while idle).
	for attempt := 0; attempt < 2; attempt++ {
		rc, err := c.get(ctx)
		if err != nil {
			c.fail()
			return nil, err
		}
		vals, err := c.roundTrip(rc, cmds)
		if err == nil {
			c.put(rc, true)
			c.up.Store(true)
			return vals, nil
		}
		c.put(rc, false)
		lastErr = err
		if ctx.Err() != nil || !isStaleConn(err) {
			break
		}
	}
	c.fail()
	return nil, lastErr
}

func (c *RedisClient) fail() {
	c.errors.Add(1)
	c.up.Store(false)
}

func isStaleConn(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe")
}

// Close closes idle connections and refuses new commands.
func (c *RedisClient) Close() {
	c.mu.Lock()
	c.closed = true
	idle := c.idle
	c.idle = nil
	c.mu.Unlock()
	for _, rc := range idle {
		rc.c.Close()
	}
}
