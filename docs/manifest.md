# Manifest reference

[Quick start](../README.md#quick-start) · [Commands](cli.md) · [Agent integration](agent-integration.md)

- [Explicit artifacts and defaults](#explicit-artifacts-and-defaults)
- [Output version and gate](#output-version-and-gate)
- [Module discovery](#discovering-module-artifacts)
- [Transforms and supplied metadata](#processing-options)

This reference follows `main`. Explicit artifact configuration is supported in v0.3.0;
`artifactSets`, manifest `enrichment` and `context` were added afterwards. Use a release containing
the feature you configure. Older binaries reject unknown keys; manifest `version: 1` alone does
not imply support for every optional field.

## Explicit artifacts and defaults

`rio.yaml` declares which SBOMs to process and how. Paths resolve from the manifest directory;
its SHA-256 is recorded in every output. Use explicit `artifacts` for individually
named inputs, [`artifactSets`](#discovering-module-artifacts) for module-based discovery, or both
in the same manifest.

```yaml
version: 1                        # must be 1; anything else is exit 2

artifacts:
  - id: rcp-client                # ^[a-z0-9][a-z0-9._-]*$, unique; used as the output
                                  # filename and as the DependencyTrack project name
    sbom: "com.example.product.client/target/**/bom.json"
                                  # glob relative to this file's directory;
                                  # must match exactly one file, or exit 2
    transforms:                   # ordered; each entry is one transform name plus its config
      - repair-purl:
          ecosystem: p2
          # table: mappings/p2-maven.json   # merged over the built-in mapping table

  - id: server-war
    sbom: "com.example.server.web/target/bom.json"
    # subject:                    # override metadata.component when the generator describes
    #   name: example-server         # the building module rather than the shipped artifact
    #   version: 3.2.0

output:
  specVersionFloor: "1.6"         # 1.5 or 1.6; defaults to 1.6

gate:
  require: [name, version, purl]  # subset of these three; defaults to all three
```

Each explicit artifact must resolve to exactly one regular SBOM file. Zero or multiple matches
fail with exit 2. An incomplete search also fails: an unreadable directory could hide another
match. Rio names the blocked path and writes no new output. It does not merge SBOMs.

## Output version and gate

`output.specVersionFloor` accepts `"1.5"` or `"1.6"` and defaults to `"1.6"`. Rio raises documents
below the floor to that version. Documents at or above the floor keep their spec version; other
configured processing still applies.

`gate.require` defaults to `[name, version, purl]`. It accepts any subset, including `[]`, and
checks every dependency component, including nested components. Required names and versions must
be nonblank; a required purl must be parseable as a package URL. Independently of this list, the
SBOM subject (`metadata.component`) must always have a nonblank name and version.

Gate failures are recorded under both CLI modes. `--gate warn` (the default) returns success;
`--gate fail` returns exit 1 after writing the results. See [exit codes](cli.md#exit-codes).

## Discovering module artifacts

Optional `artifactSets` discovers module **marker paths**, then requires exactly one SBOM for
**every selected module**. It does not match Maven `artifactId`, the SBOM subject name, or an SBOM
filename to decide which modules exist. No Maven invocation or POM parsing is involved; a suitable
marker filename other than `pom.xml` works too.

```yaml
version: 1
artifacts:                         # optional; explicit entries still work
  - id: desktop
    sbom: desktop/target/bom.json
artifactSets:                      # optional; sets-only or mixed manifests work
  - modules: "services/**/*server/pom.xml"
    sbom: "target/bom.json"
    idFrom: module-directory
    # exclude: ["services/experimental-server/pom.xml"]
    # transforms:
    #   - repair-purl: {ecosystem: p2, table: mappings/p2-maven.json}
    # enrichment: {producer: {name: Example}}
    # context: {file: build-context.json}
```

Adding `services/orders-server/pom.xml` and its `target/bom.json` adds an `orders-server` artifact
without editing YAML. `services/web-client/pom.xml` is outside this selector. A selected server
without an SBOM makes both `plan` and `normalize` fail with exit 2; normalize writes no new output.
Each module gets a separate normalized SBOM, gate result, index entry and optional statement.
SBOM contents are never combined.

- `modules`, `sbom` and `idFrom` are required nonblank strings. Only `idFrom: module-directory`
  is supported. At least one explicit artifact or set declaration is required overall.
- `modules` uses doublestar globs (`*`, `**`, prefix/suffix patterns) selecting regular marker files.
  Its paths and `exclude` marker-path globs are relative to the **manifest directory**. Exclusions
  apply before an SBOM is required. All patterns must be valid, including exclusions matching nothing.
- Only a set's `sbom` glob is relative to **each selected module root**, the marker's containing
  directory. The new selector fields reject absolute paths and literal `..` segments. Existing
  explicit-artifact path rules are unchanged. Zero roots after exclusions fails that set, even
  when other declarations match. Zero or multiple regular SBOM matches, unreadable relevant search
  paths and incomplete searches fail rather than returning a partial bundle.
- The Rio ID is exactly the module directory's basename and must match
  `^[a-z0-9][a-z0-9._-]*$`. It is an output identity; it does not change the SBOM's name, version,
  purl or components. Invalid names and duplicate IDs fail without renaming. Exclude the marker
  and use an explicit artifact for exceptions, including legacy `subject` overrides (unsupported
  on sets).
- Multiple markers in one lexical directory select one module, recording the lexically first
  matching marker. Distinct lexical roots pointing at the same physical directory are ambiguous
  and fail. Symlink cycles and unreadable searches fail. Overlapping sets and duplicate physical
  SBOM selection fail whenever a generated artifact is involved, including overlaps with explicit
  entries. Existing explicit-only duplicate-input behavior is unchanged.
- Explicit artifacts retain declaration order, followed by sets in declaration order. Within
  each set, modules sort lexically by manifest-relative forward-slash path. The working directory
  and filesystem enumeration order do not determine membership order.

Set-level `transforms`, `enrichment` and `context` apply uniformly to every generated artifact,
using the existing validation and merge/replace rules. Global output settings, the gate and root
enrichment defaults apply. **Transform configuration paths and `context.file` stay
manifest-relative**, not module-relative. Enrichment provenance uses
`artifactSets[0].enrichment...` for set declarations and `enrichment...` for inherited defaults.
A shared context document binds each entry by generated Rio ID and original SBOM SHA-256. Plan
reports context and transform configuration without reading context files or building transforms,
so a missing context file or p2 mapping table does not prevent planning.

`plan --json` still exposes one flat `artifacts` array, so existing plan consumers see every
expanded SBOM. Generated plan and index artifacts, and their statement artifact payloads, include
this optional record; explicit artifacts omit it:

```json
{
  "selection": {
    "version": 1,
    "kind": "artifactSet",
    "source": "artifactSets[0]",
    "module": "services/orders-server",
    "marker": "services/orders-server/pom.xml"
  }
}
```

These paths are manifest-relative and forward-slashed. The manifest digest identifies the exact
declaration; input and output digests identify SBOM bytes. Selection records describe filesystem
membership, not Maven build membership or source/build provenance. Modules with no selected marker
are outside this policy and cannot be diagnosed as missing. Maven profiles, reactors and `-pl`
are not interpreted. An old SBOM left in `target/` remains an input: this feature infers no freshness,
Git/CI claims or product metadata.

Plan is a preview, not a lock: a later invocation can see intentionally changed modules.
`index.json` defines the current run's members. Files from previous runs can remain in a reused
output directory; collecting the whole directory does not guarantee current membership. Prefer a
fresh output directory per run. The [runnable artifact sets demo](../tools/README.md#artifact-sets-demo)
shows automatic inclusion, missing-output refusal and module removal with fresh output directories.

This optional extension keeps manifest, plan and index outer versions at v1, and preserves
explicit-only output shapes. It requires a Rio release containing #71; older binaries reject the
unknown `artifactSets` key rather than silently ignoring it.

## Processing options

| Need | Configuration and reference |
|---|---|
| Convert p2 or synthetic Maven package URLs to Maven coordinates | [`transforms: repair-purl`](p2-repair.md) |
| Supply product, organization or SBOM metadata | [Root and per-artifact `enrichment`](enrichment.md) |
| Bind producer-supplied build/source assertions to an original SBOM digest | [Per-artifact `context`](context.md) |

Sets accept the same transforms, enrichment and context settings for each generated artifact.
Their auxiliary paths stay manifest-relative. The legacy `subject: {name, version}` override is
supported only on explicit artifacts. See the [output reference](output.md) for the resulting
records, changes and optional statements.
