package gateway

import "syscall"

const (
	keepIdleOpt  = syscall.TCP_KEEPIDLE
	keepIntvlOpt = syscall.TCP_KEEPINTVL
	keepCntOpt   = syscall.TCP_KEEPCNT
)
