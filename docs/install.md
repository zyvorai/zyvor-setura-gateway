# Installing Zyvor Setura

Setura is source-available: a paid Order under the
[Zyvor Production Licence v2.0](../LICENSE) is required for use (a 30-day trial
is available on request); see [licensing.md](licensing.md).

Release archives are named `setura_VERSION_OS_ARCH.tar.gz` (darwin and linux,
amd64 and arm64) and contain `setura`, `man/setura.1`, `LICENSE`, `NOTICE` and
`README.md`. Each release also publishes `checksums.txt` (covering every
asset), `.deb` and `.rpm` packages for linux, a Helm chart, one SBOM per
archive, and a cosign bundle (`FILE.sigstore.json`) next to every file. The
release process is described in [release-process.md](release-process.md).

## install.sh

    sh install.sh                      # latest release into ~/.local/bin
    sh install.sh --version 0.6.0      # a specific release
    sh install.sh --prefix /usr/local  # system-wide (needs write access)
    sh install.sh --dry-run            # print the plan, change nothing
    sh install.sh --uninstall          # remove the binary and man page again
    sh install.sh --require-signature  # fail unless cosign verifies the release

The script prints what it will do, downloads the archive and `checksums.txt`,
verifies the sha256 and aborts on a mismatch before anything is installed.
When `cosign` is installed it also verifies the keyless signature on
`checksums.txt` (made by this repository's release workflow) and aborts if it
is missing or wrong; `--no-signature-check` skips that, `--require-signature`
makes cosign mandatory. Without cosign only the checksum is verified, which
catches corruption but not a compromised download host. It never uses sudo.
`SETURA_BASE_URL` overrides the download base for mirrors and tests
(`--version` is then required); `SETURA_COSIGN` names the cosign executable;
`sh scripts/test-install.sh` exercises it against a local fake release with a
fake cosign.

## Homebrew

A formula template lives in `packaging/homebrew/setura.rb`. After
`make dist VERSION=X.Y.Z`, render it with:

    scripts/update-homebrew.sh X.Y.Z

which writes `packaging/homebrew/Formula/setura.rb` with the sha256 values
from `dist/checksums.txt`. Publishing that file to a tap is a manual step.
The formula installs the man page and bash, zsh and fish completions.

## Linux packages (.deb, .rpm)

Attached to each release as `setura_X.Y.Z_amd64.deb`, `setura_X.Y.Z_arm64.deb`,
`setura-X.Y.Z-1.x86_64.rpm` and `setura-X.Y.Z-1.aarch64.rpm`.

    sudo dpkg -i setura_X.Y.Z_amd64.deb
    sudo rpm -i setura-X.Y.Z-1.x86_64.rpm

They install `/usr/bin/setura`, the man page, shell completions, and under
`/usr/share/doc/setura` the licence files and example systemd units
(`examples/systemd`, also in `packaging/systemd/`). Nothing is enabled or
started. The packages are built without dpkg or rpm by `tools/mkpkg`
(`make dist package`); the `.deb` is checked structurally in tests, the `.rpm`
has been checked structurally and with libarchive but not installed with
`rpm` itself.

## Kubernetes: Helm chart

    helm install setura oci://ghcr.io/zyvorai/charts/setura --version X.Y.Z
    helm install setura packaging/helm/setura          # from a checkout

With default values it creates the same objects as `setura gateway install`
(Namespace `setura-system`, ServiceAccount, ClusterRole, Role, bindings,
GatewayClass `setura`, Deployment, Service). `values.yaml` has an entry for
every `gateway install` option (`namespace`, `image`, `className`, `replicas`,
`exposeGatewayPorts`) plus optional `serviceMonitor` and `prometheusRule`
(Prometheus Operator CRDs; off by default). Printing the plain manifests
instead is still `setura gateway install`.

## Docker

    docker run --rm ghcr.io/zyvorai/zyvor-setura-gateway:latest version

Multi-arch images (linux/amd64, linux/arm64) are built by
`.github/workflows/image.yml` on version tags, signed with cosign and carry
provenance and SBOM attestations. Build locally with
`docker build --build-arg VERSION=dev -t setura:local .`.

## go install

    go install github.com/zyvorai/zyvor-setura-gateway/cmd/setura@latest

This build reports the source default version, not the release tag.

## Verifying downloads

    sha256sum -c --ignore-missing checksums.txt        # Linux
    shasum -a 256 -c --ignore-missing checksums.txt    # macOS

    cosign verify-blob --bundle checksums.txt.sigstore.json \
      --certificate-identity-regexp '^https://github\.com/zyvorai/zyvor-setura-gateway/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
    gh attestation verify setura_X.Y.Z_linux_amd64.tar.gz --repo zyvorai/zyvor-setura-gateway
    cosign verify ghcr.io/zyvorai/zyvor-setura-gateway:X.Y.Z \
      --certificate-identity-regexp '^https://github\.com/zyvorai/zyvor-setura-gateway/\.github/workflows/image\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

macOS `.pkg` installers signed and notarized on the Mac mini are attached to
releases by hand; see [release-process.md](release-process.md).

## Manual page

`setura man` prints the roff page; `make man` regenerates `man/setura.1`.

## SBOM and provenance

`make sbom` writes `bin/sbom.json`, a simple JSON inventory built from
`go version -m bin/setura` (main module, dependencies, GOOS/GOARCH, revision).
Releases attach one such file per archive (`setura_X.Y.Z_OS_ARCH.sbom.json`),
and the image carries a BuildKit SBOM attestation.


## Deploy the demo stack to a lab host

`scripts/deploy-remote.sh` deploys the built-in gateway, two identity backends and the dashboard the same way our other lab hosts are deployed: a static host binary run by `systemd --user` units (lingering, `Restart=always`), a health check, and a summary.

```sh
./scripts/deploy-remote.sh sus@80.79.5.173           # or: HOST USER
./scripts/deploy-remote.sh sus@80.79.5.173 --public  # also bind the gateway on all interfaces and open its port
./scripts/deploy-remote.sh sus@80.79.5.173 --status | --logs | --restart | --uninstall
./scripts/deploy-remote.sh sus@80.79.5.173 --container   # docker compose instead of systemd
```

- It cross-builds a static `linux/amd64` binary, uploads it, verifies the SHA-256 on the host, keeps the previous binary as `bin/setura.prev`, and swaps the config atomically (the gateway hot-reloads it).
- The gateway listens on `PORT` (default 18090), the dashboard on `PORT+1` and the admin API on `PORT+2`. The dashboard and admin API are always loopback. View the dashboard through a tunnel: `ssh -L 18091:127.0.0.1:18091 user@host`, then open `http://127.0.0.1:18091/`.
- Without `--public` nothing is exposed and no firewall rule changes. With it, the gateway port is opened in `ufw` or `firewalld`.
- It enables lingering for the SSH user so the units survive logout, which is the one system-level setting it changes.
- The smoke test checks the 90/10 canary split, a 404 for an unmatched path and the dashboard API.
- `--uninstall` removes the units and containers and leaves `~/zyvor-setura-gateway` (config and `.env`) in place.
- `--container` uses `compose.yaml`; the dashboard token is generated on the host into `.env` (mode 600) and never printed. If the SSH user is not in the `docker` group, it falls back to `sudo docker`.
