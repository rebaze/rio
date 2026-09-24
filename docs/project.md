# Project notes

[Get started](../README.md) · [Contributing instructions](../AGENTS.md)

## Why Rio exists

Rio began with Eclipse RCP builds whose p2 package identities prevented downstream tools from
matching dependencies to Maven packages. It now also normalizes CycloneDX spec versions, checks
required fields, selects module SBOMs, and records supplied product and build metadata.

The goal is to make build evidence easier to inspect and use in release decisions. Today's CLI
handles SBOM normalization. A passing SBOM gate does not establish that software is safe to release.

## Direction

Future work is tracked in GitHub issues, separate from the current command contract:

| Area | Work |
|---|---|
| Validate the next consumer workflow | [#47](https://github.com/rebaze/rio/issues/47) |
| Strengthen SBOM handoff, repair provenance, requirements and retention | [#43](https://github.com/rebaze/rio/issues/43), [#44](https://github.com/rebaze/rio/issues/44), [#45](https://github.com/rebaze/rio/issues/45), [#46](https://github.com/rebaze/rio/issues/46) |
| Bind artifacts to SBOM evidence | [#52](https://github.com/rebaze/rio/issues/52) |
| Import artifact-level test results | [#53](https://github.com/rebaze/rio/issues/53) |
| Evaluate release requirements and scoped exceptions | [#54](https://github.com/rebaze/rio/issues/54), [#55](https://github.com/rebaze/rio/issues/55) |
| Demonstrate refusal of tested-A/shipped-B | [#56](https://github.com/rebaze/rio/issues/56) |

These are planned compiler capabilities. Rio does not currently compile release evaluations,
external test results, exceptions or deployment records. Deployment systems remain the source for
what is running. Rio's own release pipeline separately [checks staged assets before publication](../tools/README.md#verify-release-assets-before-publication).

## Scope

Normalization, planning and delivery inspection run locally without network calls, including
schema validation and p2 mapping. Schemas and built-in mappings are embedded; the binary has no
runtime dependency on external tools. Explicit native delivery and reconciliation communicate
with Dependency-Track. Supporting mapping preparation and delivery examples live in
[tools/README.md](../tools/README.md).

Current exclusions include SBOM merging, component filtering, reading assembled release artifacts,
drift comparison, SPDX conversion, license normalization/scoring, vulnerability lookup, signing,
and general-purpose remote storage or querying. Rio preserves dependency component membership. Release policy,
scanner execution and deployment tracking belong to the surrounding systems.

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

`rio record` and `rio record inspect` are offline. Collection selects an index and explicit delivery
journals, without loading rio.yaml or SBOM files. Inspection needs only the exported file. Both
preserve supplied producer claims and clearly distinguish internal evidence consistency from
identity authentication, ingestion, signing or full build-file retention. See the
[record contract](output.md#consolidated-recordjson-v1).
