# Integrate Rio into a project

This is the canonical integration guide for coding agents and humans configuring **another
project** to use Rio. Follow that project's instructions and the user's requested scope. Rio's
own [AGENTS.md](../AGENTS.md) is for developing Rio, not a file to copy into the target project.
No harness-specific skill, plugin, account or agent instruction filename is required.

The outcome is a small, reviewable configuration that covers the intended deliverables, preserves
existing decisions, and has been checked against available inputs. Rio reads local CycloneDX JSON
SBOMs; it does not build software, generate SBOMs, discover Git/CI facts, or upload results.

## 1. Inspect before asking

Read the target project's README and agent instructions, build files and scripts, release/CI
configuration, and any existing `rio.yaml`. Identify the actual build command and where it runs.
Inspect existing SBOM generator configuration and representative SBOMs when available. Check
`rio version`; use the project's existing installation/version pin when it supports the features
needed. Otherwise follow Rio's [installation instructions](../README.md#install) within the user's
scope. Integration does not require a Go toolchain or a Rio source checkout.

Establish these facts from project evidence, keeping unknowns explicit:

| Decision | Evidence to look for |
|---|---|
| Which deliverables belong in this bundle? | Release documentation, packaging jobs, explicit user intent |
| How is each SBOM produced? | Existing generator configuration and build/CI commands |
| Where is each input? | Output paths relative to the manifest, plus representative generated files |
| Do module markers express the desired selection policy? | Directory conventions and release policy, not only files left by a previous build |
| What must remain unchanged? | Existing IDs, subject overrides, transforms, enrichment/context, output floor, gate and CI consumers |
| Where should outputs go? | Existing output conventions, artifact collection and retention settings |

A Maven reactor, package name or existing SBOM list can help explain a project, but none by itself
establishes which deliverables the user wants in this bundle. Do not infer release membership by
finding only `**/bom.json`: that hides modules whose producer failed to write an SBOM.

## 2. Resolve only the remaining decisions

When the repository already establishes the answer, use it and briefly state the evidence.
Ask concise questions only when the answer affects the configuration or required build work.
Give a recommendation when the project supports one; do not guess a release policy.

Examples of useful questions:

- **Unclear membership:** “Do `api-server` and `preview-server` ship together, or is preview a
  development-only module? Both have SBOMs, so file presence cannot decide bundle membership.”
- **Missing producer:** “Reporting is a required deliverable, but its build has no SBOM step.
  Is there an existing generator command we should use, or should I add generation to its build?”
- **Conflicting output conventions:** “The release job collects `dist/evidence`, while the local
  script uses `target/rio`. I recommend a fresh run directory beneath `dist/evidence` for CI;
  should the local script use that location too?”

Do not ask the user to re-enter paths or commands already documented. Choose a conventional local
output location when it has no downstream consequence, and explain the choice. If a question
blocks membership or generation, continue independent inspection and preparation, but keep that
decision pending. A missing answer is not approval to exclude a deliverable.

## 3. Choose the smallest configuration that expresses the policy

Use the [manifest reference](manifest.md) for field semantics. Start with selection
and existing processing settings; add transforms or metadata only when the project needs them.

| Project situation | Configuration | Copyable example |
|---|---|---|
| Individually named inputs or a few unrelated outputs | Explicit `artifacts`, each resolving to exactly one SBOM | [explicit.yaml](../tools/demo-agent-integration/examples/explicit.yaml) |
| All qualifying modules should enter automatically | `artifactSets` selecting module markers first | [modules.yaml](../tools/demo-agent-integration/examples/modules.yaml) |
| Existing explicit artifacts plus discovered modules or exceptional identities | Mixed declarations, excluding exceptions from the set | [mixed.yaml](../tools/demo-agent-integration/examples/mixed.yaml) |

These files use synthetic paths. Adapt them to the inspected project; do not copy their product
names, override values or module inventory into a real project. The mixed example extends an
[existing manifest](../tools/demo-agent-integration/projects/mixed/rio.yaml), preserving its desktop
subject override, mapping path, output floor and gate. Its uppercase `Legacy-server` directory is
excluded from the set and declared explicitly as `legacy-server`.

Prefer `artifactSets` when marker paths express the agreed module policy. Select regular markers
such as `services/**/*server/pom.xml`; Rio matches the **marker path**, not Maven `artifactId`, SBOM
subject name or SBOM filename. It does not parse POMs, profiles or reactor options. Each selected
module must have exactly one regular SBOM. A module with no selected marker lies outside this
policy and cannot be diagnosed as missing.

Generated IDs are exactly module-directory basenames and must match
`^[a-z0-9][a-z0-9._-]*$`. Do not lowercase, sanitize or suffix them. Resolve exceptional names or
collisions with an explicit exclusion and artifact declaration agreed with the project's identity
conventions. Zero selected modules, duplicate IDs and physical overlaps involving generated
artifacts are errors. One normalized SBOM is produced per artifact; contents are not merged.

Keep these coordinate systems distinct:

| Setting | Base directory |
|---|---|
| Explicit `artifacts[].sbom` | Manifest directory |
| Set `modules` and `exclude` marker globs | Manifest directory |
| Set `sbom` | Each selected marker's containing directory |
| Transform configuration paths and `context.file`, including on sets | Manifest directory |
| CLI `--out` | Process working directory, unless absolute |

New set selector fields reject absolute paths and literal parent traversal. The main manifest
version stays `1`. Module discovery requires an installed Rio release containing **#71 / #72**;
older releases reject `artifactSets`. Check the actual binary with the proposed manifest. If it
rejects the key, report the version prerequisite and arrange an appropriate release upgrade;
do not silently replace automatic discovery with today's list of existing SBOMs. The complete
[onboarding demo](../tools/README.md#agent-integration-examples) requires that feature too.

### Preserve existing configuration and software identity

When `rio.yaml` exists, extend it with a minimal diff. Keep its comments, artifact IDs, declaration
order, processing settings and downstream output names unless the requested change requires
otherwise. Explain necessary changes and verify their consequences. Do not replace an existing
manifest with a stock template or weaken its gate to make the first run green.

Rio output IDs are not software coordinates. Keep input SBOM names, versions, purls and component
membership intact unless a specific configured operation is justified. Native Maven purls do not
need a p2 repair transform just because the build uses Maven. Where p2 repair is needed, follow the
[transform reference](p2-repair.md) and existing mapping configuration.

Add enrichment only from supplied or established project metadata. Preserve existing subject
replacement decisions; do not invent new ones from directory names. Add context only when an
explicit producer supplies the documented ID/original-SBOM-digest binding. Reading Git or CI
variables is not permission to manufacture source/build assertions. Optional context, enrichment
and statements are not prerequisites for a basic integration.

## 4. Validate with the real inputs

Run the project's established SBOM-producing build step when it is available and within scope.
If no producer exists, explain the gap and the specific module/output needed. Offer build
integration as work in that project's build system; do not add a runtime dependency to Rio or
use fabricated SBOMs to claim a successful integration. The demonstration producers copy
synthetic fixtures only and are not real generation recipes.

From the target project root, use the intended manifest and a fresh validation directory:

```sh
rio version
rio plan --manifest rio.yaml
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-validation.XXXXXXXX")
rio plan --manifest rio.yaml --out "$run_dir/normalized" --json > "$run_dir/plan.json"
rio normalize --manifest rio.yaml --out "$run_dir/normalized" --gate fail
```

Run and inspect these commands one at a time; stop and diagnose a failure. Compare the flat
`artifacts` array in `plan.json` with the intended deliverables, input paths, output names and
processing configuration. Generated entries include `selection` identifying their source set,
module and marker. Check the normalized `index.json` for the same ordered membership and inspect
its gate results, findings and schema-validation status. Review normalized subjects and components
against the originals, especially where existing transforms or overrides are involved.

Planning resolves file selection and describes settings without reading SBOM contents, context
files or external p2 tables. It can succeed before a context file or mapping table exists, but
selected SBOM files must already exist. A successful plan is not proof that normalization or the
gate passes, and a later invocation may see a changed filesystem.

| Exit | Meaning and next action |
|---|---|
| `0` | Command succeeded. For normalization, use `--gate fail` to make a passing exit meaningful for the configured gate. |
| `1` | Normalization wrote results but a gate failed under `--gate fail`. Inspect findings; do not collect it as a passing release bundle. |
| `2` | Usage/configuration/input failure; normalization writes no new outputs. Fix the named input or declaration and retry. |
| `3` | Internal or output-writing failure; inspect the diagnostic. Do not treat any partial outputs as a completed run. |

When a selected module has no SBOM, retain its selection and report the missing producer/output.
Do not narrow the selector, add an exclusion, remove requirements, or copy another module's SBOM
to conceal the failure. The [incomplete example](../tools/demo-agent-integration/examples/incomplete.yaml)
deliberately remains an exit-2 case until reporting has a real producer.

An SBOM left by an older build is still an input. Rio does not infer freshness from a successful
plan or normalize run. The surrounding producer/build must establish that the selected inputs
belong to the current build; context bindings do not independently prove those claims.

## 5. Fit the existing CI workflow

Keep the order explicit:

1. Provision the chosen Rio release and the project's existing build toolchain.
2. Run the actual build/SBOM producer; stop on failure.
3. Plan and check the selection.
4. Normalize with the agreed gate policy; stop on failure.
5. Collect the current run's index and normalized files using the existing CI artifact mechanism.

The [copyable CI shell step](../tools/demo-agent-integration/ci.sh) accepts the installed Rio binary
and the project's producer command as arguments. It creates a fresh directory, captures the plan,
normalizes with `--gate fail --attest`, and archives that run only after success. Its
[execution instructions](../tools/README.md#agent-integration-examples) explain how to adapt and
collect the resulting bundle. Adapt `--attest` and the output location to the project's needs;
statements are unsigned normalization records, not proof about a released executable.

**`index.json` defines current membership.** Reusing an output directory can leave files for removed
artifacts. Do not upload everything from an old directory and call it the current bundle. Use a
fresh directory, as the example does, or collect exactly the members of the current index.

Rio performs no network calls. Installation, dependency resolution, SBOM generation, p2 mapping
helpers and uploads are separate steps and may need network access. Preserve existing CI job
boundaries and permissions. A runnable local example does not establish that a remote CI job has
executed successfully. Retain original inputs and auxiliary files separately when reproducibility
is required; the example bundle does not automatically archive them.

## 6. Hand back a concrete result

End with a short report containing:

- Files changed and the selection policy, including exclusions and exceptional IDs.
- The Rio version, commands actually run, exit results and observed artifact membership.
- Where to inspect outputs and how CI collects the current run.
- Any outstanding decision, unavailable generator, missing input or CI validation, with the next
  concrete action. Distinguish a prepared configuration from a verified normalization run.

For example, for the incomplete fixture: “Configured both required server modules. Billing's
producer runs; reporting's does not exist yet. Plan and normalize both exit 2 naming reporting's
missing SBOM, with no normalized output. Next: choose and wire reporting's SBOM producer; then
rerun these commands.” Do not report that scenario as fully integrated.

The [synthetic examples and evaluation procedure](../tools/README.md#agent-integration-examples)
exercise this workflow across explicit, discovered, mixed, incomplete and ambiguous projects.
The procedure can be repeated in any harness; it is not a promise of identical agent behavior.
