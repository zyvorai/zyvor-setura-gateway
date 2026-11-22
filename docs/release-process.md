# Release process

How a Setura release is cut, signed and verified. Nothing here runs from a
branch: releases start from a version tag.

## 1. Before tagging

1. Add a `## X.Y.Z` section to `CHANGELOG.md`. The release workflow takes the
   GitHub release body from that section (`scripts/release-notes.sh X.Y.Z`)
   and fails if it is missing or empty.
2. Bump `Version` in `internal/setura/cli.go`, the chart `version` and
   `appVersion` in `packaging/helm/setura/Chart.yaml`, and run `make man`.
3. `make vet test` and `go test -race -count=3 ./...` pass. Tag `vX.Y.Z`.

## 2. What the tag triggers

`release.yml` (no secrets beyond the built-in token; each job lists only the
permissions it needs):

| Job | Permissions | Does |
| --- | --- | --- |
| `build` | `contents: read` | tests, `make dist`, `.deb`/`.rpm` (`scripts/package.sh`), the Helm chart `.tgz`, one SBOM per archive (`scripts/sbom-dist.sh`), then `checksums.txt` over every asset |
| `publish` | `contents: write`, `id-token: write`, `attestations: write` | cosign keyless `sign-blob` of every asset (`FILE.sigstore.json` bundles, including `checksums.txt`), self-check with `cosign verify-blob`, SLSA build provenance via `actions/attest-build-provenance`, then `gh release create` |

`image.yml` builds the multi-arch image (linux/amd64, linux/arm64) with
BuildKit provenance and SBOM attestations, signs it by digest with cosign,
attaches GitHub build provenance, and pushes the Helm chart to
`oci://ghcr.io/zyvorai/charts`. `:latest` only moves for non-pre-release tags.

`pages.yml` publishes `site/` from `main`. It stages a copy with timestamps set
to the commit time, so one commit always produces one artifact.

Every third-party action is pinned to a full commit SHA with the tag in a
trailing comment (`# v7`). Update a pin by resolving the new tag
(`gh api repos/OWNER/REPO/commits/TAG --jq .sha`), never by editing the
comment alone.

## 3. Verify a release

    cosign verify-blob --bundle checksums.txt.sigstore.json \
      --certificate-identity https://github.com/zyvorai/zyvor-setura-gateway/.github/workflows/release.yml@refs/tags/vX.Y.Z \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
    sha256sum -c --ignore-missing checksums.txt
    gh attestation verify setura_X.Y.Z_linux_amd64.tar.gz --repo zyvorai/zyvor-setura-gateway
    cosign verify ghcr.io/zyvorai/zyvor-setura-gateway:X.Y.Z \
      --certificate-identity https://github.com/zyvorai/zyvor-setura-gateway/.github/workflows/image.yml@refs/tags/vX.Y.Z \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

`install.sh` does the first two steps itself (the signature when `cosign` is
installed). Signing the checksums covers every file listed in them.

## 4. Signing macOS builds on the Mac mini

The Linux assets are signed in CI. macOS code signing and notarization need
the Developer ID identities, which live only in the login keychain of the Mac
mini, so this step is manual and happens after the release exists:

    make dist VERSION=X.Y.Z                 # on a laptop (or download the release archives into dist/)
    scripts/sign-macos.sh X.Y.Z --dry-run   # check inputs, print the plan
    scripts/sign-macos.sh X.Y.Z             # sign, notarize, staple on the mini

What `scripts/sign-macos.sh` does, following the documented mini process:

- Reaches the mini with `ssh mini` (alias `m`). No other host or credentials.
- Identities: `Developer ID Application: ZYVORAI LABS PRIVATE LIMITED (NX667LTDQ2)`
  signs the `setura` binary (hardened runtime, secure timestamp);
  `Developer ID Installer: ZYVORAI LABS PRIVATE LIMITED (NX667LTDQ2)` signs
  the installer package.
- `pkgbuild --sign` fails over plain ssh (`errSecInteractionNotAllowed`: the ssh
  session cannot reach the keychain), so the script generates a `.command` and
  starts it in the mini's GUI session with `open -a Terminal`. The first time
  the Installer key is used a keychain dialog appears on the mini: click
  **Always Allow** once.
- Notarization: `xcrun notarytool submit FILE --keychain-profile Macora-Notary --wait`,
  then `xcrun stapler staple` and `spctl -a -t install`. The `Macora-Notary`
  profile already exists in the mini's login keychain. The App Store Connect
  API key (`.p8`) stays in `~/Downloads` on the mini and is never copied or
  read by the script. If the profile is ever lost, recreate it on the mini with
  `xcrun notarytool store-credentials`.
- It copies back only the finished packages to `dist/macos/` with a
  `checksums.txt`. Attach them by hand:
  `gh release upload vX.Y.Z dist/macos/*.pkg dist/macos/checksums.txt`.

These `.pkg` files are signed and notarized by Apple but are not covered by
the CI cosign signature or provenance (the CI runner cannot reach the mini).
The tarballs from CI remain the artifacts with a verifiable build chain; the
`.pkg` is the convenience for users who want Gatekeeper-clean installation.

## 5. After the release

- Render the Homebrew formula: `scripts/update-homebrew.sh X.Y.Z` (reads the
  release `checksums.txt` in `dist/`), then publish
  `packaging/homebrew/Formula/setura.rb` to the tap by hand.
- Add the `.deb`/`.rpm` to your own apt/yum repository if you run one; they are
  attached to the GitHub release.
- Install the Helm chart from OCI:
  `helm install setura oci://ghcr.io/zyvorai/charts/setura --version X.Y.Z`.
