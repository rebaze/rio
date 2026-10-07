# Compact run receipt and local outputs

[Generated JSON](../tools/demo-client-record/example/record.json) · [Offline HTML](../tools/demo-client-record/example/report.html) · [CLI](cli.md)

One execution produces one indented JSON document with `kind: "rio-run-receipt"` and `schemaVersion: 1`. The standard two-SBOM/build-URL-and-ID/verified-TLS example is **5,791 bytes**, below the 8,192-byte regression budget. That budget is a standard-fixture check, not a universal real-run cap.

## Field guide

| Field | Meaning |
|---|---|
| `rioVersion` | Binary version that recorded the invocation |
| `run` | Fresh ID, operation, actual known start/end, overall outcome, phase states, explicit overrides and optional prior link |
| `artifacts` | IDs, consumed input and generated output SHA-256/byte sizes, meaningful changes, effective checks and processing state |
| `targets` | Shared target type and configured receiver URL, stored once per label |
| `deliveries` | Selected pairs, resolved projects/repositories, attempt IDs/prior references, intended/submitted byte identities, transport and response observations |
| `exclusions` | Artifact/target filtering and declared artifact-set exclusion rules |
| `exceptions` | Concise failures, overrides, recovery gaps or persistence problems |

Operations are `pipeline`, `normalize`, `deliver` and `reconcile`. Overall `success` means requested execution succeeded, not that a server ingested the SBOM. Outcomes also include `failed`, `partial` and `incomplete`. A recovered interrupted run has no invented finish time. Phase states distinguish completed/passed, failed, partial/incomplete, not attempted, not configured, skipped, pre-existing and not applicable work.

Input paths refer to the original manifest context; output paths refer to the original run directory. Delivery of pre-existing outputs records the consumed normalized path. These paths/URLs are references, not promises of future access. Moving a receipt does not require moving any source file, and inspection never follows those references.

`bytes.artifactOutput` reuses an artifact's exact output digest/size. Optional role/media type describe the request representation. Otherwise a byte identity has its own SHA-256, byte size, media type, role and transformation where applicable. A zero byte size may be omitted and means zero; its digest must identify the empty bytes. OCI config/manifest wrappers have their own identities, rather than being equated with the SBOM.

### Changes and checks

Small metadata additions retain the exact value; replacement/removal retains before/after. `before: null` with `operation: add` denotes prior absence. Source labels distinguish manifest, context-file and context-default values; `assertion: producer` labels unsigned producer assertions, not authenticated facts. Spec changes retain `from` and `to`.

A metadata value whose compact JSON exceeds 1,024 bytes is explicitly represented as:

```json
{"representation":"sha256-of-json","sha256":"<full SHA-256>","bytes":12345}
```

This is a value digest and encoded length, **not the full value**. The digest covers Rio's compact JSON serialization (Go `encoding/json`, sorted object keys and its normal HTML-character escaping), not original source formatting.

Bulk changes retain operation/rule, traversal scope, evaluated/applied/unmapped/skipped counts, and unresolved reasons/counts. Applied and unmapped may overlap: a qualifier can be repaired while coordinates remain unresolved. Never add overlapping counters into a supposed component total. Unchanged dependency inventory, Rio bookkeeping and per-component rewrite ledgers are not copied into the receipt.

Checks retain effective component/subject requirements, traversal scope, policy mode, evaluated component count, schema status and concise finding counts. Empty component requirements/inventory are explicitly `not-evaluated`; unsupported schema versions are `not-available`. Absent checks are not passes. A warn policy does not change a recorded failed check into success. Standalone delivery labels checks as pre-existing rather than claiming to have performed earlier normalization checks.

### Delivery observations

Pair states distinguish `accepted`, `rejected`, `unknown`, `unattempted`, `error`, `evidence-gap`, and reconciliation's `observed`/`unavailable`. `requestMayHaveOccurred` remains conservative when a response or journal is missing. `intended` is the prepared byte identity; `submitted` contains distinct complete body writes actually observed during this adapter attempt. Absence of `submitted` does not prove zero bytes reached a receiver. Already-present OCI content can be accepted without any new body writes.

Transport records HTTP/HTTPS, certificate-verification policy and whether TLS was observed during any response in this invocation. Each response also retains its own optional TLS observation, so a later connection failure does not erase an earlier HTTPS response. Missing observation is not false; HTTP verification is not applicable. Response records preserve known status/time, acknowledgment/activity/content facts and allowlisted receiver references. DTrack retains its event token; OCI retains its applicable manifest/blob/tag/subject references. No arbitrary response bodies, API keys, environment dumps, private keys, source archives or complete SBOM inventories are embedded.

An accepted acknowledgment, observed processing activity and verified content are separate capabilities. A DTrack event token does not establish ingestion. Hashes identify bytes but neither authenticate the producer nor prove future retention. The receipt is unsigned. Inspection validates shape, reference bindings and consistency; it cannot detect every coherently forged unsigned receipt or replay absent originals.

## Bounds and deterministic serialization

The parser and publisher enforce 8 MiB UTF-8 JSON, at most 10,000 entries per collection, nesting depth 64, at most 250,000 JSON values, and 16 KiB per string/key. A token preflight enforces collection bounds before retaining oversized arrays. Individual metadata values over 1,024 compact-JSON bytes use the explicit digest representation above. Unsupported sizes are refused; attempts/claims are never silently dropped to meet a limit. Native adapter/index/journal limits also apply and can be tighter.

Captured facts serialize in stable order with indented readable JSON. Repeated real executions legitimately differ in run IDs, observed times and receiver facts. The report's digest is over the exact input JSON file, including its whitespace. HTML escapes supplied text, embeds styles and contains no scripts, external fonts or remote assets.

## Interruption and recovery

Output is reserved before requests. Publication syncs a temporary sibling and links it into an absent destination; it never replaces another receipt. Internal immutable checkpoints and attempt journals retain committed facts. A hard kill leaves incomplete state, not a fabricated successful receipt. On Windows, file sync/no-overwrite/readback apply, but directory fsync is unavailable, so power-loss durability has that platform limit.

If public receipt persistence fails after a request, Rio returns failure and reports the possible output and local run directory. Inspect what exists and recover locally; do not submit again merely to obtain a nicer receipt:

```sh
rio record recover --run target/rio/runs/RUN_ID --output recovered.json
```

The output must be fresh and outside the source run/journal namespaces. Recovery reads bounded committed local prefixes (64 MiB aggregate journal budget), never constructs clients, resolves credentials, removes locks or replays uploads. Incomplete runs stay incomplete even when a retained acknowledgment is recovered. Independently checkpointed live responses are preserved if journal evidence becomes unavailable. Missing journals/completion are evidence gaps, not proof no request occurred.

A retry or network reconciliation is a **new invocation** with a new receipt and prior ID/digest reference when available. Earlier public receipts do not change. Reconciliation receipts contain only current observations; prior acknowledgments are referenced rather than copied into a claim of current work.

## Local normalization outputs

Each execution owns `<out>/runs/<run-id>/`. Normalization creates one `<id>.cdx.json` per processed artifact and writes `index.json` last. Optional standalone `normalize --attest` creates unsigned `<id>.intoto.json` statements. The index is the local handoff for intentional `deliver --index ...`, not a client archive to embed in a receipt.

The index retains tool/manifest identity, input/output hashes and paths, selected members, exact normalization details and check results. Input paths are manifest-relative; output paths are index-relative. Enforced gate failures still write the processed SBOMs/index so findings can be examined. Invalid input/configuration may leave a failed receipt; no stale index from another run is substituted. `runDirectory` identifies current outputs; no mutable latest pointer is required.

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

The output document records the rule and before-and-after values for each repair. The local index normalization ledger also identifies coordinate sources and retained evidence metadata; the public receipt summarizes bulk repairs instead of copying that component ledger.
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

New repairs also add a confidence-free `evidence.identity` conclusion on CycloneDX 1.6:

```json
"evidence": {
  "identity": [
    { "field": "purl", "concludedValue": "pkg:maven/com.google.code.gson/gson@2.8.9" }
  ]
}
```

The metadata repair property retains the original purl and rule. Input identity evidence is
preserved, including any confidence the producer supplied. Rio no longer assigns its former
fixed `0.9`: a mapping category is an assertion, not a measured probability. The embedded
schemas require numeric confidence in method entries, so new assertions omit methods.
CycloneDX 1.5 supports a single identity object: Rio adds `{ "field": "purl" }` only when
none exists, and preserves an existing object. Detailed source evidence remains in the index.

### Normalization change evidence

New indexes keep index schema version 1 and add `artifacts[].normalization`, an independently
versioned extension (`version: 1`). Old indexes without it have **changes not recorded**, not
zero changes. Unknown extension versions must be labeled unsupported, not treated as complete.

`changes` lists stable JSON Pointer targets, `add`/`replace`/`remove` operations, rules, before
and after values, and available resolution sources. The enclosing artifact's input/output digests
bind the relationship. Changes cover uplift, purl rewrites, preserved p2 qualifiers, legacy subject
replacement, enrichment and supplied context. Component membership and repair counters retain
their existing meanings: one purl rewrite can change both coordinates and version but counts once.
Transform scope is top-level components; nested components are not implied repaired.

A repair's `resolution.kind` distinguishes `input-qualifier`, `component-property`,
`built-in-entry`, `external-table-entry`, and qualifier-only `input-version`. Its selector identifies
the chosen keys or table entry. Mapping `sha256` hashes the exact bytes loaded for that transform,
even if the file later changes. Optional `metadata.confidence` and `metadata.evidence` preserve
upstream categorical assertions such as `manifest-proven`; they are not translated into numbers.
Missing upstream metadata stays absent. Other supplied JSON values in those assertion fields
remain as recorded; a numeric value is an upstream assertion, not a probability assigned or verified
by Rio. Mapping tables with duplicate object names or invalid Unicode refuse before normalization
outputs are written, keeping retained source selectors unambiguous. Manifest and context changes bind their source digests.

`bookkeeping` separately records Rio's added tools, repair assertions and run properties.
`unmapped` retains per-component pointers and reasons. `skipped` aggregates reasons with an explicit
scope and count. Collection copies these retained facts without rereading or reprocessing SBOMs.
The JSON is a consistency record, not proof of authenticity or a complete input archive.

Run the [installed-binary ledger demonstration](../tools/demo-normalization-evidence/README.md)
for a synthetic override, qualifier-only miss, unchanged input and offline portable record.

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
`enrichment`, `context`, `selection`, `normalization` and `checks` when present. Arrays retain the index's order and empty-array representation; absent optional
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

Rio writes normalization statements offline and does not sign them. An unsigned statement records a claim; it
is not cryptographic proof of who made it. Signing and verification belong to the surrounding
pipeline. A signature can authenticate a statement without proving its assertions true; see
[the signing tools](../tools/README.md#signing-and-verifying-normalization-attestations).
