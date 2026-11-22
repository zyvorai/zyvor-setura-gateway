# Contributing

Source contributions are by arrangement with Zyvor AI Labs. Write to [sales@zyvor.dev](mailto:sales@zyvor.dev) before starting work so we can agree the terms.

## Development

```sh
go version        # 1.22 or newer
make vet          # go vet and gofmt check
make test         # go test -race
make build        # bin/setura
make social       # re-render PNG images from assets/src (needs rsvg-convert)
```

- Keep the probe on the Go standard library only.
- New lint rules need a stable `SETnnn` ID, an entry in `Rules`, a README table row and a test in `internal/setura/features_test.go`.
- Exit codes are part of the interface: `0` passed, `1` observed failure, `2` usage or setup error.
