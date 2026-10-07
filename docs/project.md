# Project notes

[Get started](../README.md) · [Contributing instructions](../AGENTS.md)

## Why Rio exists

Rio began with Eclipse RCP builds whose p2 package identities prevented downstream tools from
matching dependencies to Maven packages. It now runs a manifest-driven SBOM workflow: select and
consume SBOMs, normalize/enrich metadata, evaluate configured handoff checks, deliver to selected
targets, and compile the actual results into one compact receipt for that invocation.

Rio is an evidence compiler for this SBOM workflow. The recipient can inspect what was consumed,
what changed, which checks ran, where delivery was attempted and what the receiver acknowledged.
Supplied source/build metadata remains a producer assertion. A passing SBOM gate does not establish
that software is safe to release, and an acknowledgment does not establish ingestion.

## Direction

Future work and priorities are tracked in [GitHub issues](https://github.com/rebaze/rio/issues),
separate from the current command contract. Proposed extensions need a concrete producer input,
a demonstrated gap in current SBOM workflow evidence, a recipient task and explicit verification
limits before they become implementation commitments.

Keep the one-invocation, one-compact-receipt contract. Evidence describes actual work, scoped
checks and observations; it preserves missing, failed and unknown results. Producers own build
execution and SBOM generation. External tools own optional input retention and signing.

Test-result ingestion, product release-eligibility evaluation, approval/exception engines and
publication enforcement are outside Rio's roadmap. Release consumers apply their own policies
to the evidence; deployment systems remain the source for what is running. Rio's own release
pipeline separately [checks staged assets before publication](../tools/README.md#verify-release-assets-before-publication).

## Scope

Normalization, planning and delivery inspection run locally without network calls, including
schema validation and p2 mapping. Schemas and built-in mappings are embedded; the binary has no
runtime dependency on external tools. Explicit native delivery and reconciliation communicate
with Dependency-Track or OCI registries. OCI provides unchanged SBOM storage and optional
exact-subject discovery, with acknowledgment and current content verification kept separate. Supporting mapping preparation and delivery examples live in
[tools/README.md](../tools/README.md).

Current exclusions include SBOM merging, component filtering, reading assembled release artifacts,
drift comparison, SPDX conversion, license normalization/scoring, vulnerability lookup, signing
inside the binary, full-input/diagnostic-bundle export, and general-purpose remote storage or
querying. Rio preserves dependency component membership. Release policy, scanner execution and
deployment tracking belong to the surrounding systems.

## Rio and rebaze

Rio is open source under [Apache-2.0](../LICENSE), maintained by [rebaze](https://www.rebaze.de/).
It can be used independently, without a hosted account. Rebaze also offers
[release-controls implementation](https://www.rebaze.de/release-controls/) in existing customer
toolchains; using those services does not require Rio.

## Build from source

Use the Go version declared in [go.mod](../go.mod). From a checkout:

```sh
make build     # builds ./rio with version metadata
make test      # go test ./...
make vet       # go vet ./...
```

Release builds use `CGO_ENABLED=0`. See [AGENTS.md](../AGENTS.md) for repository conventions,
feature demos, issue tracking and release instructions. [Issue #4](https://github.com/rebaze/rio/issues/4)
is the historical v1 implementation specification; current behavior is documented in the references.

[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio) ·
[Go module](../go.mod)

Root `rio` owns one pipeline invocation and compact receipt. Normalize, plan, record inspection/reporting and explicit local recovery remain offline; root delivery, standalone delivery and reconciliation construct native clients only for requested network work. Internal checkpoints/journals support recovery without becoming a public source archive. See the [receipt contract](output.md).
