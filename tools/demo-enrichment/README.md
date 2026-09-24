# Manifest enrichment demo

Run three small, offline examples with an **installed rio release containing #61**. You need a
POSIX shell and standard command-line tools (`cp`, `sed`, `find`, `mktemp`); no Go, source build,
Python, jq, credentials or network access is required. The organizations, products and dependency
are synthetic. The `.example.com` URLs illustrate metadata and are never fetched.

Get this directory from the matching release's tagged source archive, or copy it with its `inputs/`
subdirectory from a checkout. Extracting example files does not require building the source.
Keep the directory structure intact, then run:

```sh
cd tools/demo-enrichment
./run.sh                         # installed rio on PATH
# Or select the installed binary:
RIO_BIN=/absolute/path/to/rio ./run.sh
# A positional command or path also works:
./run.sh /absolute/path/to/rio
```

Older releases that do not support `enrichment` will reject the manifests. Use the examples and
binary from the same release. The script prints the binary version and creates a unique temporary
working directory for each run, so stale outputs cannot make a refusal look successful. All inputs,
logs, plans and results remain there; its location is printed when the script exits. Delete that
specific directory when you have finished inspecting it.

## What each case demonstrates

| Case | Manifest and input | Expected result |
|---|---|---|
| Shared defaults | `rio.yaml`; `inputs/console.cdx.json` and `inputs/agent.cdx.json` | Exit 0. Both subjects gain the shared group, version, manufacturer, supplier and contact URLs. Each artifact supplies its own name, purl and documentation URL. |
| Conflict | `conflict.yaml`; `inputs/legacy-console.cdx.json` | Exit 2. Existing name, version and purl disagree with the requested identity. No output files are written under `refused/`. |
| Explicit replacement | `replace.yaml`; the same legacy input | Exit 0. `replace: [subject.name, subject.version, subject.purl]` authorizes just those replacements. Changes retain their old values and manifest sources. |

The runner executes the real `rio plan` and `rio normalize` commands, displays the subject before
and after normalization, and checks the expected refusal and successful exit statuses. It does
not simulate rio. The refusal is an expected part of a successful demo.

## Inspect the retained directory

- `plan.json` contains resolved enrichment fields, the selectors identifying their defaults or
  artifact entries, and the per-field replacement policy. A plan reports intent; it does not read
  the SBOM content to detect conflicts.
- `enriched/console.cdx.json` and `enriched/agent.cdx.json` show the two enriched subjects.
  `metadata.manufacturer` identifies **Example Build Services**, the SBOM producer;
  `metadata.component.manufacturer` identifies **Example Products**, the product manufacturer;
  `metadata.component.supplier` identifies **Example Distribution**, the supplier.
- `metadata.licenses` declares `CC0-1.0` for the **SBOM data**. The third-party component's existing
  `MIT` license does not change.
- `enriched/index.json` and `replaced/index.json` carry enrichment changes with field, target,
  before/after values, manifest path/digest/selector and `assertion: "producer"`. The SBOMs carry
  corresponding `rebaze:normalize:enrichment` properties, each carrying `version: 1` in addition
  to the change fields. These are supplied assertions, not
  independent verification of the organizations or product.
- `*.intoto.json` statements beside each output include the same artifact record. They are
  unsigned normalization statements whose subject is the normalized SBOM.
- `conflict.log` contains the actual refusal. `replaced/console.cdx.json` contains the explicitly
  corrected identity. Its original `bom-ref`, `pkg:maven/com.example/legacy-console@0.9.0`, stays
  unchanged: it is a local identifier used by the dependency graph, not the new product purl.

Compare each result with `inputs/`: the `tiny-json` dependency (including its supplier, purl and
license), component membership and dependency graph are unchanged. The original generator
`synthetic-demo-generator` and timestamp `2025-01-15T12:00:00Z` remain. rio adds its own tool entry
and normalization records. The fixtures contain no p2 transforms, so there are no dependency
identity repairs to obscure this comparison.

## Boundaries

This demo uses CycloneDX 1.6 because `producer` and `subject.manufacturer` require 1.6. rio refuses
unsupported role fields at a 1.5 output; it does not silently turn a manufacturer into a supplier.
The default output floor is 1.6, and these manifests set it explicitly.

Artifact leaves override shared manifest leaves. A differing value already present in the SBOM
still needs an explicit field in `replace`; artifact precedence alone does not authorize a
replacement. An artifact's `replace` list replaces the inherited list, and `replace: []` clears
inherited replacement permission. Null or blank values do not remove defaults.

This feature does not discover source or CI/build facts, identify a compiled artifact by its hash,
generate external evidence references, normalize dependency licenses, or establish SBOM
completeness. Manifest authors remain responsible for their assertions. Retain the original SBOMs
and manifests with the results for later review.
