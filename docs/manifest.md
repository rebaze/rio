# Manifest reference

[Quick start](quick-start.md) · [Commands](cli.md) · [Agent integration](agent-integration.md)

- [Explicit artifacts and defaults](#explicit-artifacts-and-defaults)
- [Output version and gate](#output-version-and-gate)
- [Requirement profiles (BSI TR-03183-2)](#requirement-profiles)
- [Module discovery](#discovering-module-artifacts)
- [Transforms and supplied metadata](#processing-options)

This reference describes Rio 0.7.0. `rio.yaml` defines input wiring, normalization/enrichment/context, effective gate policy and native targets for one root execution. Unknown keys are refused; manifest `version: 1` alone does not imply older binaries support every optional field. [Complete delivery-first configuration](quick-start.md).

## Explicit artifacts and defaults

`rio.yaml` declares which SBOMs to process and how. Paths resolve from the manifest directory;
its SHA-256 is recorded in every output. Use explicit `artifacts` for individually
named inputs, [`artifactSets`](#discovering-module-artifacts) for module-based discovery, or both
in the same manifest.

```yaml
version: 1                        # must be 1; anything else is exit 2

artifacts:
  - id: rcp-client                # ^[a-z0-9][a-z0-9._-]*$, unique; used as the output
                                  # filename and the artifact selector for delivery
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
  directory: target/rio           # optional; manifest-relative output root
  specVersionFloor: "1.6"         # 1.5 or 1.6; defaults to 1.6

gate:
  mode: fail                     # root default; explicit --gate overrides it
  require: [name, version, purl]  # subset of these three; defaults to all three
  # profile: bsi-tr-03183-2@2.1.0  # optional named requirement profile (see below)
  subject:
    require: [securityContact, digest]  # optional, either or both; defaults to []
```

Each explicit artifact must resolve to exactly one regular SBOM file. Zero or multiple matches
fail with exit 2. An incomplete search also fails: an unreadable directory could hide another
match. Rio names the blocked path and does not publish a successful normalized index/SBOM set. A failed execution receipt may still be written. It does not merge SBOMs.

## Output version and gate

`output.specVersionFloor` accepts `"1.5"` or `"1.6"` and defaults to `"1.6"`. Rio raises documents
below the floor to that version. Documents at or above the floor keep their spec version; other
configured processing still applies.

`gate.require` defaults to `[name, version, purl]`. It accepts any subset, including `[]`, and
checks every dependency component, including nested components. Required names and versions must
be nonblank; a required purl must be parseable as a package URL. Independently of this list, the
SBOM subject (`metadata.component`) must always have a nonblank name and version.

`gate.subject.require` opts into subject requirements beyond that. It accepts two values, each
at most once:

- `securityContact`: the subject must have a `security-contact` external reference whose URL is
  an absolute http(s) URL without credentials, or `mailto:` with one address. That is the same
  rule [enrichment](enrichment.md) applies, and the gate runs after enrichment, so a reviewed
  `enrichment.subject.securityContact` in `rio.yaml` satisfies it. A pass establishes only that a
  contact in a supported form is present. It does not identify who answers it, verify the
  mailbox or approve the release, and Rio never looks a contact up or invents one.
- `digest`: the subject must have a `distribution` external reference with a `SHA-256` hash of
  64 hex characters. The gate runs after context is applied, so `distributions` in the
  [build context file](context.md#shipped-files-distributions) satisfy it; a reference the SBOM
  generator wrote counts too. A pass establishes only that a digest is recorded. Rio does not
  hash the shipped files, and nothing proves they were built from the SBOM's components.

The [handoff-checks demo](../tools/demo-handoff-checks/) shows each outcome.

A failed requirement is printed with what its producer can do about it, and the receipt lists the
failed requirements under `checks.failed`. For example, with both values required and neither
present:

```text
rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
  subject.securityContact: the SBOM subject has no security-contact reference. Set the reviewed contact as enrichment.subject.securityContact in rio.yaml, or have the SBOM generator emit one. Rio does not look it up.
  subject.digest: the SBOM subject has no distribution digest. Add the shipped files under distributions in the build context file. Rio does not hash them.
```

`gate.mode` accepts `fail` or `warn`. Explicit `--gate` wins over the manifest. Root defaults to `fail`; standalone `normalize` retains its historical `warn` default only when no manifest mode is supplied. Failed checks remain failed in either mode. Enforced failure blocks every selected root upload and returns exit 1; warn can continue while recording the effective exception. Standalone `deliver` still requires its separate `--allow-failed-gate` override. See [exit codes](cli.md#exit-codes).

`output.directory` selects the output root relative to the manifest. Explicit `--out` is caller-relative and takes precedence. If both are omitted, the caller-relative default is `target/rio`. Every execution creates `runs/<run-id>/` under that root, with its own receipt and generated outputs. `--receipt PATH` changes only the public receipt destination. No enable flag or collection step is required.

### Requirement profiles

`gate.profile` names a published requirement set and checks every SBOM against it, in addition to
the checks above. It exists for a recipient who asks for an SBOM that meets
[BSI TR-03183-2](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html)
and wants to see that it was checked, without rechecking it by hand.

**The profile checks presence and form of fields only.** A pass does not establish that the
listed components, hashes or licences are correct or complete, and it is not a certification
against the TR. Rio compares nothing with the build, never hashes a file and never looks a value
up.

Current generators do not emit most of the fields the TR requires, so an SBOM straight from one
usually fails. The profile shows that gap rather than hiding it. This is the synthetic fixture
`testdata/profile/bsi-fail.cdx.json`, which passes the default gate, run with
`gate.profile: bsi-tr-03183-2@2.1.0`. The run exits 1 and prints one line per failed field, 18
in all; seven are shown:

```text
rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
  sbom.creator (BSI TR-03183-2 2.1.0 §5.2.1): the SBOM has no creator (metadata.manufacturer with a contact email or URL). Set enrichment.producer in rio.yaml, or have the SBOM generator emit one.
  sbom.timestamp (BSI TR-03183-2 2.1.0 §5.2.1): the SBOM has no timestamp (metadata.timestamp in RFC 3339 form). Have the SBOM generator emit it.
  subject.creator (BSI TR-03183-2 2.1.0 §5.2.2): the SBOM subject has no creator (manufacturer). Set enrichment.subject.manufacturer in rio.yaml, or have the SBOM generator emit one.
  subject.dependencies (BSI TR-03183-2 2.1.0 §5.2.2): the SBOM subject has no dependencies entry covered by a compositions entry. Have the SBOM generator emit it.
  subject.distributionLicences (BSI TR-03183-2 2.1.0 §5.2.2, §6.1): the SBOM subject has no concluded licence in SPDX form. Have the SBOM generator emit it.
  components.creator (BSI TR-03183-2 2.1.0 §5.2.2): 2 components have no creator (manufacturer), for example "pkg:generic/zlib@1.3.1". Have the SBOM generator emit it.
  components.deployableHash (BSI TR-03183-2 2.1.0 §5.2.2): 2 components have no SHA-512 hash on a distribution reference, for example "pkg:generic/zlib@1.3.1". Have the SBOM generator emit it, or mark components that do not exist as a file of their own (for example statically linked libraries) as assembled with rio:tr-03183-2:level. Rio does not hash files.
```

`rio plan` shows the profile before anything runs: a line `gate  profile bsi-tr-03183-2@2.1.0 (BSI TR-03183-2 2.1.0)`
and, when `gate.require` is empty, `gate  require nothing beyond the profile`,
and in `--json` output `gate.profile` as `{"name": "bsi-tr-03183-2@2.1.0", "guideline": "BSI TR-03183-2", "guidelineVersion": "2.1.0"}`
next to the effective `gate.require`.

```yaml
gate:
  profile: bsi-tr-03183-2@2.1.0
  require: [purl]                   # optional; adds to the profile
  subject:
    require: [securityContact]      # optional; adds to the profile
```

- `bsi-tr-03183-2@2.1.0` is the only known profile. The name pins the guideline version: a new TR
  version gets a new profile name, and an existing name keeps its meaning. Version 2.1.0 is the
  one dated 2025-08-20; section 7 of the TR requires the most recent version. An unknown value, or
  one without `@version`, fails at load and names the allowed value.
- Under a profile, an omitted `gate.require` means `[]`, not `[name, version, purl]`. The profile
  already demands a name and a version of every component, and the file components that a
  [build context](context.md#tr-file-components) writes have no purl. An explicit `gate.require`
  adds to the profile, so `require: [purl]` also demands purls, which the TR does not.
  `gate.subject.require` also adds to it.
- A profile with `output.specVersionFloor: "1.5"` fails at load ("BSI TR-03183-2 2.1.0 requires
  CycloneDX 1.6; set output.specVersionFloor to 1.6"). Otherwise a 1.5 input would stay at 1.5 and
  fail every run.
- Findings are reported in a fixed order: `sbom.*`, then `subject.*`, then `components.*`. Each
  message names the guideline version and section and says who can fix it.

#### Checked fields

The subject (`metadata.component`) is a component too (TR 3.2.1), so the per-component fields
apply to it with `subject.*` IDs. Every component is checked, including nested ones and the
subject's own nested components (the [file components](context.md#tr-file-components) rio writes
sit there, in `metadata.component.components`).

| ID | TR | Applies to | CycloneDX 1.6 | Rio checks |
|---|---|---|---|---|
| `sbom.specVersion` | §4 | SBOM | `specVersion` | 1.6 or higher. Schema validity is recorded separately as `checks.schema`. |
| `sbom.creator` | §5.2.1 | SBOM | `metadata.manufacturer` | a `contact[].email` with text on both sides of an `@`, or a `url[]` entry that is an absolute http(s) URL naming a host |
| `sbom.timestamp` | §5.2.1 | SBOM | `metadata.timestamp` | present, RFC 3339 date-time |
| `sbom.vulnerabilities` | §3.1 | SBOM | `vulnerabilities` | absent or empty (the TR says an SBOM must not carry vulnerability information) |
| `*.name` | §5.2.2 | every level | `name` | nonblank |
| `*.version` | §5.2.2 | every level | `version` | nonblank. Rio cannot tell the TR's "file modification date when no version exists" from a real version, so this is presence only. |
| `*.level` | none | every component | property `rio:tr-03183-2:level` | at most once, with a known value (see levels) |
| `*.creator` | §5.2.2 | every level | `manufacturer` | as `sbom.creator` |
| `*.filename` | §5.2.2 | full | property `bsi:component:filename` | exactly once, nonblank, no `/` or `\` (a file name, not a path) |
| `*.dependencies` | §5.2.2 | full, assembled, logical | `dependencies[]`, `compositions[]` | the component's `bom-ref` has its own `dependencies` entry (empty if it has none) and is listed in the `dependencies` or `assemblies` of a `compositions` entry whose `aggregate` is a string other than `not_specified` |
| `*.distributionLicences` | §5.2.2, §6.1 | full, assembled, logical | `licenses[]` | one entry with `acknowledgement: concluded` that is an `expression` in SPDX form, or a `license.id` that rio's embedded SPDX list knows as a licence. Licence identifiers must be licence IDs in that list, or be `LicenseRef-…` or `DocumentRef-…:LicenseRef-…`; the right side of `WITH` must be an exception ID in that list. An exception ID such as `LLVM-exception` is not a licence, alone or as a `license.id`. A `license.name` or licence text alone does not count (§6.1). |
| `*.deployableHash` | §5.2.2 | full | `externalReferences[type=distribution].hashes[alg=SHA-512]` | 128 hex characters |
| `*.executable` | §5.2.2 | full | property `bsi:component:executable` | exactly once, `executable` or `non-executable` |
| `*.archive` | §5.2.2 | full | property `bsi:component:archive` | exactly once, `archive` or `no archive` |
| `*.structured` | §5.2.2 | full | property `bsi:component:structured` | exactly once, `structured` or `unstructured` |

`*.level` carries no TR section because the property is rio's own. The `subject.*` and
`components.*` scopes also keep `name`, `version` and, when required, `purl`, `securityContact`
and `digest`, as without a profile.

#### Component levels

The TR describes a component at one of four levels, each with its own MUST fields, and CycloneDX
has no field that says which. Rio checks every component as **full** (a deployable file) unless:

- it has an external reference of type `bom` whose `url` is nonblank: it is **referenced**
  (described in another BOM). This wins over the property. A `bom` reference without a usable
  `url` identifies no BOM and is ignored. Rio infers this level and no other.
- it carries the property `rio:tr-03183-2:level` with the value `logical`, `identified` or
  `assembled`. A producer asserts this; rio does not infer it. The value `full` is not accepted,
  because it is the default.

| Level | Meaning | Fields checked beyond name and version |
|---|---|---|
| full | a deployable file | creator, filename, dependencies, distributionLicences, deployableHash, executable, archive, structured |
| logical | a product or app grouping files (TR 3.2.2) | creator, dependencies, distributionLicences |
| assembled | parts that cannot be recovered, such as a statically linked library (TR 3.2.1) | creator, dependencies, distributionLicences: a part assembled into another component is not a file, so its filename, hash and file properties are omitted |
| identified | first dependency outside the scope of delivery (TR 3.2.4) | creator |
| referenced | described in another BOM (TR 3.2.5) | creator |

An unusable property (more than once, an unknown value, or not a string) is a `*.level` finding,
and the component is then checked as full. The receipt counts the components at each level
(`checks.profileLevels`), so a recipient sees how much was relaxed and on whose word. The property
is an extension the TR permits (§3.1: an SBOM may be expanded as long as that introduces no
contradiction); a recipient's own TR tooling ignores it. `rio.yaml` cannot set a component's level.
The subject's level comes from the SBOM, or from `level` in the
[build context file](context.md#tr-file-components).

#### Not checked, and why

- **5.2.3 SBOM-URI and 5.2.4** (source code URI, URI of the deployable form, other unique
  identifiers, original licences). These are required only if they exist, and rio cannot tell an
  absent value from one that does not exist.
- **5.2.5 optional fields** (effective licence, source code hash, security.txt URL). These are
  optional. `gate.subject.require: [securityContact]` still works beside a profile.
- **5.1 level of detail** (recursive resolution down to the first component outside the scope of
  delivery), **3.1** (one SBOM per software version) and **3.2.1** (the linker's component is
  listed). These are facts about the build, not about the document.
- **Whether a value is true.** Rio checks that a file name, hash or licence is present and well
  formed, not that it is right, and a hash is never compared with a file.

The receipt records the profile and its level counts under `checks`; see
[checks](output.md#changes-and-checks). Nothing a profile checks changes the SBOM. The
[context reference](context.md#tr-file-components) shows how a producer supplies the shipped
files' SHA-512 and properties.

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
without an SBOM makes both `plan` and `normalize` fail with exit 2; normalization publishes no generated SBOM/index; it may retain a failed receipt.
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

Normalization records the effective artifact-set selectors, exclusions, membership, transform
options and output floor in the index's optional `normalizationScope` extension. Its manifest digest
binds those settings to the run. It describes only the selected scope, not every module in the repo.
The per-artifact `checks` extension makes `gate.require`, unconditional subject checks, actual
nested-component evaluation counts and the command's warn/fail mode inspectable offline.
An explicit empty `require: []` means component checks were not evaluated. See
[selection and check evidence](output.md#selected-scope-and-effective-checks).

## Delivery and selection

`delivery.targets` configures Dependency-Track or OCI receivers in this same manifest. Each target has a type, destination settings and optional `exclude` artifact IDs / per-artifact `overrides`. [Complete native schemas and examples](delivery.md). Credentials are named environment references, not embedded values; CA paths are manifest-relative.

Root runs configured targets after successful local stages. `--artifact` and `--target` narrow scope; omitted selectors mean all eligible members/targets. Excluded SBOM globs are not resolved by an artifact filter. Target exclusions and artifact-set exclusion rules remain visible in the receipt. `--skip-delivery` performs local work only. No targets means delivery is not configured, rather than a failed upload.

`rio plan` previews the same effective settings and routing offline without building transforms or opening context/SBOM contents. A project selected from the normalized subject stays explicitly unresolved until execution. Optional stage commands remain available, each with its own scoped receipt.
