//go:build unix

package setura

import (
	"os/exec"
	"syscall"
)

// publish replaces this process with kubectl so signals reach it directly.
func publish(command []string) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, command, environ())
}
