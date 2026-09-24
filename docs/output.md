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
