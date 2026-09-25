# Output records

[Commands](cli.md) · [Manifest](manifest.md) · [Quick start](../README.md#quick-start)

A completed normalization run writes one `<id>.cdx.json` per artifact and an `index.json`.
`--attest` adds an unsigned `<id>.intoto.json` per artifact. Inputs are left in place.

- [The index](#indexjson)
- [What a record establishes](#what-a-record-establishes)
- [Changes inside each SBOM](#what-rio-writes-into-the-output-sbom)
- [Repair records](#reading-the-repair-records)
- [Statements](#normalization-attestations)

## index.json

The index identifies the current run's members. It records the tool/version and manifest digest,
then each artifact's ID, input/output paths and SHA-256 digests, spec versions, component count,
transform results, schema-validation status and gate findings. Optional selection, enrichment and
context records appear when applicable. The outer `schemaVersion` remains `1`.

Input paths are relative to the manifest directory; output paths are relative to the index.
Rio writes the index last. Exit 1 still produces the index and SBOMs for inspection; exit 2 writes
no new outputs. See [exit codes](cli.md#exit-codes) before deciding whether a run passed.

Use a fresh output directory for each CI run, or collect exactly the members of the current
index. Reused directories may retain files from earlier runs; Rio does not delete them.

## What a record establishes

A consumer can check an output file against its recorded digest, inspect the reported gate result,
and see repairs and gaps. A structurally valid record can report failed checks. The gate covers
SBOM fields, not software acceptance, vulnerability absence or compliance. rio does not add missing
components or scan for vulnerabilities; a passing gate does not establish SBOM completeness.

Unmapped components and dangling dependency references can coexist with `gate: "ok"`. A schema
version beyond the embedded schemas produces `schemaValidated: false`, even if the gate passes.
Missing or invalid inputs stop compilation with exit 2 and produce no new record.

The attestation subject is the normalized SBOM, not a built binary or deployment. Source assertions
and mapping entries are inputs to normalization, not independently verified facts. Retain the
original SBOM, context JSON when used, manifest and any external mapping table alongside the outputs if later inspection
or reproduction is required; rio does not package those inputs automatically. The index references
the manifest by digest but does not embed its requirements or identify the external table by digest.

## What rio writes into the output SBOM

**Component membership never changes.** v1 adds no component and removes none. Configured repairs
can rewrite dependency identities; enrichment updates subject and SBOM metadata. The dependency
component array in equals the component array out, member for member.

An input-versus-output diff still shows more than the repaired purls. rio appends itself to
`metadata.tools`, in whichever shape the document already uses: an entry in the flat array, or a
component under `tools.components`. It adds the repair and run records described below to
`metadata.properties`, and the identity evidence and dropped Eclipse qualifier to the components
they belong to. What it never changes is the set of components. A change there is a bug.

## Reading the repair records

The output document records the rule and before-and-after values for each repair. It does not yet
record which coordinate source won or preserve the mapping table's evidence metadata.
`metadata.properties` carries one property per repaired component:

```json
{ "name": "rebaze:normalize:repair",
  "value": "rule=repair-purl/p2 | from=pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=osgi.bundle | to=pkg:maven/com.google.code.gson/gson@2.8.9" }
```

The value is three pipe-separated fields:

- `rule=` the transform that made the change, as `<transform>/<ecosystem>`. It names who is
  answerable for the rewrite.
- `from=` the purl exactly as it was found in the input, qualifiers included.
- `to=` the purl rio wrote in its place.

Misses are recorded the same way, so they are as visible as hits:

```json
{ "name": "rebaze:normalize:unmapped",
  "value": "rule=repair-purl/p2 | purl=pkg:p2/com.example.internal@1.0.0.v20240101 | reason=no mapping entry" }
```

Here `purl=` is the purl as it was found in the input and `reason=` says why no coordinate was
written. An unmapped component can still pass the gate because both shapes are valid package URLs.
Unmapped is a count, not a failure. rio never guesses a groupId from a symbolic name, because a
wrong coordinate is worse than a missing one.

What happens to the version on a miss differs by shape, and deliberately. An unmapped `pkg:p2` purl
keeps its p2 type rather than asserting a Maven mapping. The Eclipse qualifier is stripped and
preserved as a property; the two halves of the transform are independent. An unmapped synthetic
purl is left byte-identical, because stripping the qualifier off
`pkg:maven/p2.eclipse.plugin/com.google.guava@30.1.0.v1` would make it indistinguishable from a
well-formed Maven coordinate, and a lenient consumer would act on a groupId that does not exist.

The same repair is also recorded on the component itself, as an `evidence.identity` entry:

```json
"evidence": {
  "identity": [
    { "field": "purl",
      "confidence": 0.9,
      "methods": [
        { "technique": "other", "confidence": 0.9,
          "value": "rio repair-purl/p2: pkg:p2/com.google.gson@2.8.9.v20220111-1409" }
      ] }
  ]
}
```

The `value` names the rule and the original purl, so a consumer holding only the normalized document
can still see what the identity used to be. If a component already carries `evidence.identity`, rio
appends to it and never overwrites an existing entry. The current implementation assigns `0.9`
to every repair; this is a fixed value, not a measured probability or independent verification.

Where an Eclipse build qualifier was dropped from a version, the component carries it as a
`rebaze:normalize:p2-qualifier` property, for example `v20230708-0916`. This preserves the version
detail from the input; it does not independently identify or verify the corresponding build bytes.

Alongside the per-component records, `metadata.properties` carries the run itself.
`rebaze:normalize:tool`, `rebaze:normalize:artifact-id`, `rebaze:normalize:manifest-sha256` and
`rebaze:normalize:input-sha256` are written on every run. `rebaze:normalize:spec-uplift` appears
only when the document was below the floor and was raised to it, and
`rebaze:normalize:subject-override` only when the manifest supplied a `subject` for the artifact,
carrying the `metadata.component` name and version it replaced.

## Normalization attestations

`rio normalize --attest` writes one unsigned, pretty-printed JSON statement named
`<artifact-id>.intoto.json` beside each normalized SBOM. It records the normalized file's digest
and the evidence for that normalization. The format is
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), with
this contract for each `index.artifacts[i]`:

| field | value |
|---|---|
| `_type` | `"https://in-toto.io/Statement/v1"` |
| `subject` | One-element array: `[{"name": artifact.output.path, "digest": {"sha256": artifact.output.sha256}}]` |
| `predicateType` | `"https://rebaze.com/attestation/sbom-normalization/v1"` |
| `predicate.tool` | The complete `index.tool` object: `name` and `version` |
| `predicate.manifest` | The complete `index.manifest` object: `path` and `sha256` |
| `predicate.artifact` | The complete `index.artifacts[i]` object |

The references in the table mean the actual JSON values from the same run's `index.json`.
`predicate.artifact` preserves every field: `id`, `input`, `output`, `specVersion`,
`schemaValidated`, `components`, `transforms`, `gate`, `gateFindings`, `integrityFindings`, and
`enrichment`, `context` and `selection` when present. Arrays retain the index's order and empty-array representation; absent optional
fields stay absent. There is no additional `schemaVersion` field in the statement or predicate;
the two type URIs identify their versions.

The subject is the normalized SBOM, identified by the lowercase SHA-256 digest of its bytes on
disk. `subject[0].name` and `predicate.artifact.output.path` are relative to the statement's
directory. Input paths are relative to the manifest's directory, as in the index. These paths
are local file references, not download URIs; independently checking an input digest requires
the original input file.

Statements are deterministic for the same input SBOMs, manifest, mapping tables and rio version.
rio writes all SBOMs and statements before writing `index.json` last. `--attest` leaves the SBOM and index bytes
unchanged and does not change the gate: a gate failure still writes every statement, with exit 0
under `--gate warn` and exit 1 under `--gate fail`. Usage or input errors (exit 2) write nothing.
Without the flag, rio writes no statements and preserves its existing output bytes.

rio does not sign statements or make network calls. An unsigned statement records a claim; it
is not cryptographic proof of who made it. Signing and verification belong to the surrounding
pipeline. A signature can authenticate a statement without proving its assertions true; see
[the planned signing tools](../tools/README.md#signing-and-verifying-normalization-attestations).

## Consolidated record.json v1

`rio record` writes one record of current evidence. It captures the complete normalization index
and only the delivery journals explicitly selected with `--delivery-record`. Existing index,
SBOM, statement and journal bytes remain unchanged. `rio record inspect --file record.json`
checks the file without its original workspace, configuration, SBOM files, credentials or network.

The root has exactly `schemaVersion: 1`, `kind: "rio-evidence-record"`, `tool`, `normalization`,
`deliveries`, `coverage` and `evidence`. `tool` identifies the collector; the index retains its own
normalizer version. All fields use lower camel case. Required arrays are always arrays, including
empty arrays. The encoding is compact JSON, with HTML escaping disabled and a final newline.
There is no collection timestamp, inferred shared build, worker hostname, Git checkout identity
or random export ID.

| Section | Contract |
| --- | --- |
| `normalization` | `evidenceId: "normalization-index"`, `indexSHA256`, the complete parsed original `index` (including additive fields), and `sbomBytesVerification: "not-performed"` |
| `deliveries[]` | `attemptId`, `artifactId`, original validated `intent`, all ordered `events`, `journal`, ordered `evidenceIds`, and `summary` |
| `journal` | `sha256` over concatenated exact committed event bytes, `eventCount`, `lastSequence` |
| `summary` | `acknowledgment` (`accepted`, `rejected`, or `unknown`); optional `latestActivity` and `lastObservation`, each carrying `sequence`, `observedAt` and the complete `observation` |
| `evidence[]` | `id`, `kind`, `mediaType: "application/json"`, raw-byte `sha256`, decoded `size`, `encoding: "base64"`, and strict standard-base64 `data` |

Evidence kinds are `normalization-index` and `delivery-event`. The index source ID is
`normalization-index`; event IDs are `delivery/<attemptId>/<20-digit sequence>`. The exact source
bytes, including original whitespace, are retained separately from readable JSON. Reformatting
readable objects is harmless; editing meaningful facts is refused unless the embedded evidence
supports them. Numbers are compared losslessly, including integers above 2^53.

Deliveries sort by artifact ID, then attempt ID. Evidence starts with the index and follows that
same delivery/event order. The index's artifact order is preserved. Coverage ID arrays are sorted.
Identical source bytes, collector version and collector notes produce identical output regardless
of argument order or source relocation. Each journal is captured under its own lock: this is not a
single global transactional instant. Later observations require a new snapshot at a new path.

Every selected attempt joins the exact raw index digest, artifact, output/payload digests, gate and
schema-validation facts. The inspector replays shared journal validation and offline adapter checks,
reconstructs readable facts and compares them. Failed gates, rejected submissions, intent-only
unknown histories and unavailable observations are valid evidence. `summary.latestVerification` optionally retains the latest OCI content observation with its event
sequence and time. Expected references remain predictions in the intent; current content or referrer
presence never upgrades the attempt’s historical acknowledgment. Mixed Dependency-Track and OCI
attempts join the same exact index. Last activity, latest verification and last query
are separate, selected by event sequence rather than wall-clock timestamps. `processing:false`
does not establish ingestion, vulnerability analysis or content retention.

Retries retain their original references. When the prior attempt is selected, its recorded digest
must match a valid committed prefix, so later reconciliation of that prior journal remains valid.
Source, effective target and declared policies must agree; credential/CA reference rotation is
permitted. Saved CA references retain their original POSIX, Windows drive or UNC spelling during
offline inspection, without applying the inspecting host's path rules. A missing selected ancestor remains visible without following its historical path hint.
Self-links, cycles, duplicate attempts (including copies/aliases) and mismatched sources refuse.

`coverage` always states:

- `deliverySelection: "explicit"` and `selectedDeliveryCount`.
- `artifactIdsWithoutSelectedDeliveries` and `retryAttemptIdsNotIncluded`.
- `sbomFiles`, `normalizationInputs`, `normalizationStatements`, `signatures`: `"not-included"`.
- `workerIdentity: "not-recorded"`, `authenticatedProducerIdentity: "not-established"`.
- `collectionNotes`: optional entries with `code: "orphan-temporary-files"`, `attemptId`, `count`
  and `assertion: "collector"`. These are checked collector claims about ignored uncommitted entries;
  the inspector does not independently establish their historical presence. Temp contents/names
  are not included.

Zero selected journals means no delivery evidence was selected; it does not establish that no
upload occurred. Supplied per-artifact source/build claims retain producer assertion status;
missing context remains absent. Existing `.intoto.json` statements are not collected in v1.
The record is unsigned: someone can replace both source bytes and hashes consistently. Passing
inspection establishes internal consistency, not authenticity or tamper-proofness, and does not
rehash external SBOM bytes. Full input/mapping/SBOM retention and reproduction (#46), signing
(#14) remain separate milestones. OCI delivery evidence is included in this same record. This file is intended for the same audience
as its source records: supplied metadata and internal names/URLs are preserved faithfully, without
reading or adding environment/credential values.

### Record limits and publication

Limits are 16 MiB raw index, 1 MiB per event, 10,000 events per journal and across the entire selected
set, 256 selected journals, 32 MiB total raw sources, 128 MiB serialized record, and 20,000 directory
entries per captured journal including ignored temps. Typed streaming validation applies before retaining nested event data; no additional collection-entry
limit narrows the existing event byte/schema contract.
Limits refuse; they never truncate evidence.
A streaming envelope preflight checks array counts before retaining their elements, and capture
applies remaining aggregate event capacity before reading any next-journal event.

The existing parent directory is required. An existing output file, directory or symlink refuses,
as do source/index/journal/output-lock collisions. Rio finishes capture, validation and bounded
serialization before creating output. A canonical sibling `<output>.lock` directory coordinates
exporters; existing locks are never automatically broken. Output preflight also briefly takes each
selected journal's shared sibling lock for metadata-only physical-identity checks, including
case aliases of a lock name that did not previously exist. These locks are released before
output locking/publication; no journal events are reopened. Rio writes a unique mode-0600 temporary
file, syncs/closes it, publishes with a same-directory hard link that cannot replace an existing
name, syncs the directory where supported, and reads/validates the published bytes. Filesystems
without hard-link support fail safely. Ordinary exits remove owned temp/lock entries; cleanup
failure is an execution failure. A final file is never deleted merely because later sync/readback
fails. Windows has no directory fsync through `os.File`; do not infer universal power-loss
protection. Inspect a possibly published file before retrying at a new path.
