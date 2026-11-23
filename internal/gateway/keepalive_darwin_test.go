package gateway

import "syscall"

// The standard library does not export TCP_KEEPINTVL and TCP_KEEPCNT on every
// darwin architecture, so the values from <netinet/tcp.h> are used.
const (
	keepIdleOpt  = syscall.TCP_KEEPALIVE
	keepIntvlOpt = 0x101
	keepCntOpt   = 0x102
)
