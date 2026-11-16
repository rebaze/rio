# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No |

Only the most recent release of rio receives security updates. rio ships as a single static binary,
so upgrading is a matter of replacing it — see the install instructions in the README.

Historical Dependency-Track projects for unsupported releases are retained inactive, with their
original SBOMs and findings preserved. This is a support-lifecycle disposition, not a vulnerability
fix. Users of older binaries must upgrade; see the [historical triage evidence](tools/README.md#historical-security-triage).

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

- **read-only operations and normalization remain offline.** Root pipeline execution, explicit
  delivery and reconciliation may contact configured receivers and resolve credentials. Planning,
  normalization and receipt inspection/reporting must not do so.
- **rio is self-contained.** It runs with `CGO_ENABLED=0` and shells out to nothing at runtime.

## Verifying a release

Release archives carry build provenance and an attested CycloneDX source SBOM, both verifiable with
`gh attestation verify`. A binary that does not verify against the `rebaze/rio` repository did not
come from us — please report that rather than running it.

## Scope

This policy covers vulnerabilities in rio's first-party code. Issues in upstream dependencies should
be reported to their respective maintainers; if a dependency issue affects rio specifically, tell us
as well so we can bump or work around it.

Supporting tools under `tools/` are not part of the rio binary and may perform their documented network operations. Report issues in those as ordinary bugs unless they expose credentials or
compromise a release.

## Dependency updates and alert closure

Dependabot security updates are enabled for this repository. When GitHub finds a vulnerable
dependency with an available fix, Dependabot opens an upgrade PR. Weekly version updates also
cover Go modules and GitHub Actions through `.github/dependabot.yml`.

The required CI `build` check reviews every PR for newly introduced vulnerable dependencies at
any severity, including development dependencies. Changes to Go code, dependencies, or CI also
run `govulncheck` against both rio and the scanner itself, the tests, vet, and a static build. The scanner and its dependencies are
pinned in `tools/security/go.mod` and `go.sum`, which Dependabot also maintains. A daily CI run and manual dispatch repeat
the full validation suite so newly published advisories can be detected without a code change. Scheduled,
manual, and push runs have separate concurrency groups so they cannot cancel each other. The Go scan
uses the latest patch of the Go minor line selected by `.go-version`; it reports reachable vulnerabilities in that build,
not a guarantee about every platform or previously released binary.

Both Go modules declare the minimum patched compiler in `go.mod`. Current-tree CI and release
builds use `.go-version` with `setup-go`'s `check-latest: true`, so a new patch in that minor line is
picked up without waiting for a module upgrade PR or a runner-image refresh. New minor Go
versions require an explicit change to the selector and both module minimums. The diagnostic
`Test binary` workflow retains the compiler selected by the requested source revision's `go.mod`
so historical refs remain buildable. Dependabot does not maintain this compiler policy.

New advisories can still make an unchanged tree fail; keep that security gate enabled. Enable
[GitHub Actions failure notifications](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/notifications-for-workflow-runs)
and ensure a maintainer receives scheduled-run failures (GitHub routes scheduled notifications
to the workflow creator, the last cron editor, or the person who re-enabled it). Investigate the first failing step promptly;
rerunning an unchanged compiler against the same advisory will not repair it. Main requires
`CI complete` alongside `build`, `Analyze Go`, and `classify`, with enforcement applying to
administrators too, so failed platform or receiver checks also block merges. An independent
human-review requirement remains deferred until a second eligible maintainer exists (#164).
A clean source build does not repair binaries already downloaded by users: a
compiler security fix still needs a new patch release through the normal release process.

Rio monitors one fixed active `rio` / `main` project and retained published releases under
`Rio product`, within `rebaze`. Only canonical main CI publishes development inventory;
PRs, tags and reusable CI retain artifacts only. Preparation, gating and delivery use the
previously published Rio v0.10.2, pinned by tag, source commit and archive checksums in
`tools/self-sbom-rio.json`; the candidate is never the monitoring executable. Main is never
latest. Release latest promotion requires the exact published SBOM, a native acknowledgment
whose event token explicitly completed, and verified inventory and parent. Older reruns and
prereleases cannot roll latest backward.

The protected main publisher has no project-create/delete permission. Its receiver access
covers the managed Rio subtree through collection inheritance; the workflow confines uploads
to the fixed main UUID. The separate release lifecycle key can only view and update portfolio
metadata. Persistent receiver coordination
quarantines ambiguous main uploads until explicit reconciliation. These controls complement
the daily source and weekly released-binary `govulncheck` gates. The configured owner rule
and observed `owner:team-rio` tag support routing; actual notification delivery has not been
independently observed. [Workflow, permissions, evidence and recovery](tools/README.md#self-sbom-monitoring).

Published binaries are scanned separately. Every Monday the `Scan published release` workflow
downloads the latest release, verifies its archive checksums and build provenance, and runs the
same pinned `govulncheck` in binary mode on all six released binaries. A finding or a scanner error
fails the run. A finding in a published binary is fixed by a new release, never by replacing assets.

Dependabot groups patch/minor security fixes separately for Go and GitHub Actions. The
`Auto-merge security updates` workflow checks the bot's verified single commit, security-group
metadata, and every dependency's update type. It waits for the required `build` and
`Analyze Go` checks plus the `CI complete` aggregate to pass, then merges only that exact commit without bypassing branch
protection. The REST merge endpoint either merges that SHA immediately or refuses; it never
queues native auto-merge authorization that could survive a later edit.
Major updates, ordinary version updates, upstream maintainer changes, unknown metadata,
and manually edited PRs require review.
The workflow accepts only authenticated Dependabot events, reads API metadata with the
built-in token, and never checks out PR code. Human-triggered events require manual review;
a bot-looking commit author and a valid signature alone cannot authorize a merge.
It verifies that the body matches the triggering event and has not been edited outside
Dependabot. A combined snapshot of head, target branch, open/draft state, and body/editor/
timestamp is revalidated during the wait and immediately before merging; changes abort the merge.
No additional secret, native auto-merge setting, or bot approval is required. Failed checks
leave the PR open; subsequent Dependabot events rerun the workflow. If checks take longer
than 20 minutes, rerun the original Dependabot-triggered job once they finish; it retains the
original actor and event payload and revalidates the current PR before merging.

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

The captured v0.7.0 client-record example also contains synthetic Commons Lang 3.17.0
metadata in `tools/demo-client-record/example/` and its `normalized/` directory. Each directory
has its own advisory-specific `osv-scanner.toml`: the scanner does not apply the parent
exception to nested SBOMs. These are preserved input/output bytes bound to published sample
receipts, not installed Java libraries. No receipt, SBOM or digest is rewritten to silence a scan.

The handoff-checks demo SBOM `tools/demo-handoff-checks/fixtures/cart-api.cdx.json` carries synthetic
jackson-databind 2.17.1 metadata. Its directory has its own `osv-scanner.toml` listing the
advisories by ID; osv-scanner v2.7.0 reported eleven without that file and none with it on
2026-10-18, and Scorecard v5.6.0 reported a twelfth, GHSA-5gvw-p9qm-jgwh, which was added on
2026-11-09.

Verified on 2026-10-12 with Scorecard v5.5.0: after patching Go/x/text, scanning the repository
reported this one Commons Lang advisory; adding the two example-local dispositions produced
zero findings. The original `testdata/` exception alone was insufficient. This does not
suppress the advisory in other directories, other advisories, or actual module dependencies.
Re-run Scorecard after merging; local results do not close the hosted alert.

Verified on 2026-11-16 with Scorecard v5.6.0: eighteen advisories came entirely from four
synthetic demo SBOMs, not Rio's Go dependencies. The Cart API fixture now also records
`GHSA-mhm7-754m-9p8w`. The README use-case input and captured output each have their own
`osv-scanner.toml`, covering thirteen Jackson, three PostgreSQL JDBC and two Spring advisories
by exact ID. A clean source archive scans with zero findings; a real Maven manifest outside
those directories still reports its vulnerable dependencies. Fixture, SBOM and receipt bytes
remain unchanged. New advisory IDs still require review.

The Scorecard workflow retains its SARIF and same-run JSON analysis, and uploads code-scanning
evidence before enforcing its vulnerability result. JSON must show a completed, clean
Vulnerabilities check: SARIF omits Scorecard's inconclusive/runtime-error score of -1. A
vulnerability finding, execution error, malformed report or missing vulnerability-check
coverage fails the job. Separate governance findings, such as human-review
coverage and the Best Practices badge, keep their own tracked status; successful evidence
upload alone is not a clean vulnerability scan.

Release tools (cosign and GoReleaser) are the official upstream releases, installed by
their official GitHub Actions pinned to commit SHAs and with explicit tool versions. They run
only in CI and the release pipeline and are not part of the shipped binary. The daily
vulnerability scan covers Rio's own module and binary, not these third-party tools.
cyclonedx-gomod, which makes Rio's own SBOM, is built from the version pinned in
`tools/security/go.sum`, and CI scans it with govulncheck alongside govulncheck itself.
