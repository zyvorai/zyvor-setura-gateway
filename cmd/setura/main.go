// Command setura publishes a Kubernetes Gateway listener locally and verifies
// Gateway API routes from the client.
package main

import (
	"os"

	"github.com/zyvorai/zyvor-setura-gateway/internal/setura"
)

func main() {
	os.Exit(setura.Main(os.Args[1:], os.Stdout, os.Stderr))
}
