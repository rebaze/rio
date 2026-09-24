# CI build context demo

Run the committed synthetic fixtures with an **installed Rio release containing #62**. A POSIX
shell and standard `cp`, `cmp`, `grep`, `find`, `mktemp`, `mv`, `cat`, `sed` and `dirname` commands suffice. No Go,
Python, jq, source build, credentials or network are needed. Copy this complete directory from
the matching tagged source archive, or run it in a checkout:

```sh
./tools/demo-context/run.sh
RIO_BIN=/absolute/path/to/rio ./tools/demo-context/run.sh
./tools/demo-context/run.sh /absolute/path/to/rio
```

The script prints the Rio version and the unique temporary directory where it keeps **all**
inputs, plans, normalized SBOMs, indexes, unsigned statements and refusal logs. It runs real
`rio plan` and `rio normalize` commands. A successful demo includes exit 2 in each expected
refusal; the script checks both the diagnostic and that no output files were written. A binary
from an older release cannot pass by rejecting every manifest because the two-artifact
normalization and authorized replacement must succeed first and last.

| Case | Files | Expected result |
|---|---|---|
| Plan before production | `rio.yaml` | The script moves `context.json` aside; `plan --json` still reports each binding without opening the file or SBOMs. |
| Shared file | `context.json`, `inputs/console.cdx.json`, `inputs/agent.cdx.json` | Both IDs select their own entry and original-SBOM digest. The subjects gain distinct source `vcs` and build `build-system` references. Console reports explicit `clean`; agent defaults to `unknown`. |
| Repeat | same files and manifest | A second run produces byte-identical index and output SBOMs. |
| Stale bytes | `stale.yaml`, `context-stale.json` | The recorded digest is deliberately wrong; exit 2 with `sha256`, no output. |
| Missing claim | `missing.yaml`, `context-missing.json` | The selected entry omits required `build.url`; exit 2 with that field, no output. |
| Prior revision conflict | `conflict.yaml`, `inputs/prior-console.cdx.json`, `context-prior.json` | The prior Rio-owned revision differs. Only build ID removal and workspace change are authorized here, so exit 2 names `source.revision`. |
| Authorized snapshot | `replace.yaml`, same prior files | `source.revision`, `source.workspace` and `build.id` are explicitly listed under `replace`. The revision changes; omitted workspace becomes `unknown`; omitted old build ID is removed and audited. |

The two products use separate synthetic repositories (`widgets/console` and `agents/agent`) and
different CI runs. The entry's `generator` claim is kept in the context record; neither it nor
the new build timestamp rewrites the original `metadata.tools` or `metadata.timestamp`. Existing
#61 subject enrichment supplies version and purl before context is applied. The `tiny-json`
third-party component, its MIT license and the dependency graph are retained. No fixture
contains a real repository, credential or production build.

Inspect `plan-before-context.json`, `normalized/index.json`, each
`normalized/<id>.cdx.json`, and the paired unsigned `.intoto.json` statements. The context
record in the index, statement and `rebaze:normalize:context` property is the same v1 claim.
The `file.sha256` value identifies raw context bytes; `effective.sbom.sha256` identifies the
original SBOM bytes. `changes` distinguishes logical context claims from native subject
reference updates. Compare `replaced/index.json` with the committed prior fixture to see old
revision/workspace/build ID values in the audit. The three `*-refused.log` files retain exact
exit 2 diagnostics. The runner leaves its directory for inspection and prints its path at exit;
remove that specific directory yourself when finished.

`prior-context.json` is the retained historical producer file named by the prior owned record.
Its entry digest identifies the separately retained original `inputs/console.cdx.json` bytes;
`context-prior.json` then binds the newer `inputs/prior-console.cdx.json` fixture. This avoids
depending on the bytes of a normalized SBOM from any particular Rio release.

These are producer assertions, not authenticated source/build or built-artifact provenance.
The repository and CI URLs are example domains and are never fetched. Retain original SBOMs,
raw context JSON and manifest alongside results in a real workflow. The optional
[`rio-context.py`](../README.md#rio-contextpy) helper can produce a one-artifact context file
from explicit CI arguments; this showcase uses committed JSON fixtures and does not invoke it.
