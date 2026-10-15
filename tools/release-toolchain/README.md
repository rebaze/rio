# Reviewed release-tool builds

Actual local build output (Go 1.27.2, macOS arm64):

```text
BUILT AND AUDITED: cosign; 2 explicitly scoped advisory IDs
BUILT AND AUDITED: syft; 1 explicitly scoped advisory IDs
BUILT AND AUDITED: goreleaser; 2 explicitly scoped advisory IDs
```

[Inspect the generated verification sample](example/verification.json). The remaining IDs
are assessed below; these lines do not mean the binaries have no advisory matches.

Rio's release jobs build Cosign, Syft and GoReleaser from authenticated upstream Go
modules with explicit dependency locks. They retain symbols and scan each executable
before adding its directory to PATH. This replaces downloading an older-compiler binary
merely because its upstream tag is current. Rio itself remains a standalone static binary.

```sh
python3 tools/release-toolchain/build.py --output /tmp/rio-release-tools && \
PATH="/tmp/rio-release-tools:$PATH" python3 tools/demo-attest-sign/run.py /path/to/installed/rio
```

Choose a fresh output directory. Maintainer build requirements are Python 3.9+ and Go;
Go downloads the exact compiler in `manifest.json` if necessary. The installed-Rio signing
demo still needs no Rio source build. `--tool cosign` builds just the recipient verifier.

## Identity and dependency changes

`manifest.json` identifies each upstream tag, commit, Go module sum and original go.mod
sum. The adjacent tool modules declare the upstream executable as a Go tool and freeze
its resolved graph. The builder uses only the public Go proxy/checksum database, verifies
module contents, builds with `-mod=readonly`, and refuses changed lockfiles. It does not
edit upstream source or create a private fork. Embedded build metadata retains the actual
upstream module version and sum, instead of an unauditable `(devel)` main module.

Go 1.27.2 replaces the older compilers in downloaded assets. The locks update x/net to
0.60.0 in all three tools. Cosign also resolves gRPC 1.83.2, x/crypto 0.57.0, x/text 0.42.0
and klauspost/compress 1.18.7, with their required graph changes. Its version output and
other tools' metadata identify the local security rebuild. These are rebuilt tools, not
the unchanged upstream release executables.

Build subprocesses receive a restricted environment without application/cloud/GitHub
secrets. Output includes binary hashes, upstream identities, lock hashes, compiler/platform,
raw `govulncheck` JSON and embedded build metadata. The builder never installs globally,
modifies pins, publishes assets, or accepts an existing output directory.

## Precisely scoped residual findings

These findings remain visible in every scan and inventory. They are not global scanner
exclusions, and this is not a claim that the tools are safe for arbitrary commands.

| Advisory | Evidence and permitted scope |
|---|---|
| [GO-2026-6225](https://pkg.go.dev/vuln/GO-2026-6225) | Cosign's vulnerable Azure credential helper is selected by the registry `--k8s-keychain` option, default false. Rio uses blob signing/verification. GoReleaser's `ko` pipeline is disabled by the reviewed configuration. Neither command path calls the vulnerable credential exchange. |
| [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | Cosign's Rekor factory includes OpenPGP, but Rio's message-signature/DSSE paths select PKIX/X.509. Local recipient verification rejects legacy/mixed bundles. GoReleaser imports this code through the disabled `ko` pipeline. Syft has only a module-level finding: its reviewed Linux dependency graph contains no affected OpenPGP package imports. |

Evidence is pinned to these source revisions:

- [Cosign registry selection](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/cmd/cosign/cli/options/registry.go#L141),
  [PKIX signing](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/cosign/bundle/sign.go#L69).
- [GoReleaser skips unconfigured ko](https://github.com/goreleaser/goreleaser/blob/1942d44355492f44cd3774c57bd3c27fe544dfe9/internal/pipe/ko/ko.go#L67);
  the enabled artifact signer executes the explicitly configured external Cosign command.
- sigstore-go v1.2.2 `pkg/sign/transparency.go:255` selects `pki.X509`; Rekor v1.5.3
  `pkg/types/dsse/v0.0.1/entry.go` uses `x509.NewPublicKey` for DSSE.

A new advisory, module/version mismatch, affected package outside the reviewed prefix, or
newly reachable Syft OpenPGP code refuses the build. GoReleaser is invoked with the explicit
reviewed configuration path. These dispositions cover the current release invocations:
adding registry/Kubernetes credentials, ko, OpenPGP, alternative bundle formats or new
Cosign callers requires a fresh assessment in the reviewing PR.

## Scanner precision

The earlier downloaded Syft and GoReleaser binaries are stripped. Govulncheck v1.8.0
falls back to module-level precision when it cannot extract symbols (`internal/vulncheck/
binary.go:107–111`) and emits wildcard placeholders. Their original counts were conservative
module evidence, not proof that all affected functions were included or called. The original
Cosign binary has symbols. The historical audit retains these distinctions.

New builds are not stripped. The audit refuses wildcard fallback and retains module,
package and symbol precision separately. Even a real included symbol does not prove the
reviewed command executes that path; the table above documents that separate assessment.

## Updating and verifying

Update the upstream module and explicit fixes in each tool module, run `go mod tidy` there,
and update authenticated source identities and lock hashes. Review dependency changes,
not just version numbers. Reassess the residual findings and all reviewed invocations before
updating their hashes. Keep compiler requirements aligned with root and security modules.
The version watcher reads this manifest and checks the executable signing contracts too.

Run builder/watcher/change-filter tests, then build all tools and inspect their inventories.
Exercise real signing and recipient refusals, unchanged historical sample verification,
source-SBOM generation, GoReleaser configuration/build, and native downloaded-release checks.
CI builds/scans the tools; publication continues to require complete tagged-source validation
and the existing exact staged-byte/signature/attestation checks. Never suppress an unexpected
finding or publish because only a version-availability check passed.

Source-SBOM output is explicitly CycloneDX 1.6, matching Rio's embedded schema support,
rather than following a tool's changing default. Published-release verification checks out
the selected release for its authored notes only, and the workflow revision separately
for the reviewed tool recipe, verifier and demo. No historical checkout script is executed. Older release tags therefore need not contain this new builder.

Plain blob verification was assessed separately from signing. Modern sigstore-go verification
rejects unsupported Rekor entry types (`pkg/tlog/entry.go:249–268`). Cosign's legacy fallback
extracts raw signature/key fields and structurally unmarshals Rekord, then compares PEM bytes
(`pkg/cosign/verify.go:1501–1532`); it does not invoke the OpenPGP factory on an untrusted bundle.
The active graph registers DSSE, hashedrekord, intoto and rekord, not Helm/RPM Rekor handlers.
This verification evidence is necessary; X.509 signing alone would not establish safe handling
of hostile verification input.

Dependabot also proposes updates to these three tool modules. A changed graph intentionally
fails its lock hash or source-identity checks until the corresponding manifest and assessment
are reviewed. Such coordinated changes need maintainer review; they do not silently qualify
for the single-commit security auto-merge path. Daily full CI scans detect new advisories even
when no upstream tool version has changed.

The scanner is part of the audited inputs too: both `tools/security` module locks are
fingerprinted, the resolved `golang.org/x/vuln` version is checked, and the emitted
`scanner_version` must match. Inventories record that version and the scanner lock hashes.
A scanner implementation/dependency update therefore requires explicit reassessment, rather
than silently reusing an older precision or policy assumption. The vulnerability database
remains live so new advisory IDs still fail validation.
