# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No |

Only the most recent release of rio receives security updates. rio ships as a single static binary,
so upgrading is a matter of replacing it — see the install instructions in the README.

## Reporting a Vulnerability

If you discover a security vulnerability in rio, please report it responsibly:

1. **Email**: Send details to **security@rebaze.de**
2. **Do not** open a public GitHub issue for security vulnerabilities

### What to include

- Description of the vulnerability
- Steps to reproduce, ideally with the SBOM, manifest or mapping table that triggers it
- Affected version(s), from `rio --version`
- Potential impact

### Response timeline

- **48 hours** — acknowledgement of your report
- **30 days** — target resolution for critical vulnerabilities
- **90 days** — coordinated disclosure window

We will work with you to understand and address the issue before any public disclosure.

## What rio does with your input

rio reads files it did not write — CycloneDX documents, a manifest, a p2 mapping table — and these
are the paths most likely to carry a vulnerability. They are covered by fuzz targets in the test
suite. If you have found an input that crashes rio, hangs it, or makes it emit a coordinate that
resolves somewhere it should not, that is in scope and we want to hear about it.

Two properties are worth stating because a break in either is a security finding in itself:

- **rio makes no network calls.** Resolution happens against data it already has. A build of rio that
  reaches the network is a bug, and CI enforces this.
- **rio is self-contained.** It runs with `CGO_ENABLED=0` and shells out to nothing at runtime.

## Verifying a release

Release archives carry build provenance and an attested CycloneDX source SBOM, both verifiable with
`gh attestation verify`. A binary that does not verify against the `rebaze/rio` repository did not
come from us — please report that rather than running it.

## Scope

This policy covers vulnerabilities in rio's first-party code. Issues in upstream dependencies should
be reported to their respective maintainers; if a dependency issue affects rio specifically, tell us
as well so we can bump or work around it.

Supporting tools under `tools/` are not part of the rio binary and are not covered by the no-network
property above. Report issues in those as ordinary bugs unless they expose credentials or
compromise a release.

## Dependency updates and alert closure

Dependabot security updates are enabled for this repository. When GitHub finds a vulnerable
dependency with an available fix, Dependabot opens an upgrade PR. Weekly version updates also
cover Go modules and GitHub Actions through `.github/dependabot.yml`.

The required CI `build` check reviews every PR for newly introduced vulnerable dependencies at
any severity, including development dependencies. Changes to Go code, dependencies, or CI also
run `govulncheck`, the tests, vet, and a static build. A daily CI run and manual dispatch repeat
the Go checks so newly published advisories can be detected without a code change. The Go scan
uses the compiler selected by `go.mod`; it reports reachable vulnerabilities in that build,
not a guarantee about every platform or previously released binary.

Dependabot groups patch/minor security fixes separately for Go and GitHub Actions. The
`Auto-merge security updates` workflow checks the bot's verified single commit, security-group
metadata, and every dependency's update type. It waits for the required `build` and
`Analyze Go` checks to pass, then merges only that exact commit without bypassing branch
protection. It does not queue native auto-merge authorization that could survive a later edit.
Major updates, ordinary version updates, unknown metadata, and manually edited PRs require review.
The workflow uses only API metadata with the built-in token and never checks out PR code.
No additional secret, native auto-merge setting, or bot approval is required. Failed checks
leave the PR open; pushes and reopening rerun the workflow. If checks take longer than
20 minutes, rerun the automation job once they finish.

GitHub closes Dependabot alerts once the fixed dependency reaches the default branch.
Scorecard runs on pushes to `main` and uploads a new analysis, allowing code-scanning findings that are no longer present to close automatically.
Because a workflow-token merge does not trigger push workflows, the merge workflow explicitly
dispatches Scorecard afterward; its weekly schedule remains a fallback if dispatch fails.
A PR alone does not close an alert, and the workflow never dismisses alerts.
If no patched version exists or Dependabot cannot construct a fix, the alert remains open for
investigation. A Go standard-library finding requires a compiler upgrade; already published
static binaries require a new release.

The CycloneDX files directly under `testdata/` are synthetic input documents, not rio's dependency
inventory. `testdata/osv-scanner.toml` records the verified Commons Lang fixture finding by
advisory ID and reason. That exception applies only beside those fixtures; real dependencies
in `go.mod` remain scanned, and new fixture advisories still surface for review.
