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
