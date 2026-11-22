package setura

import (
	"net/http"
	"os"
)

// adminToken adds the gateway admin token to a request when SETURA_ADMIN_TOKEN
// is set, so `setura why --admin`, `connections`, `shadow` and `gateway rollout`
// work against an admin endpoint started with --admin-token. It is read from the
// environment only, never from a flag, so it does not reach shell history.
func adminToken(req *http.Request) {
	if t := os.Getenv("SETURA_ADMIN_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}
