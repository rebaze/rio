# Command reference

[Start here](../README.md#quick-start) · [Manifest](manifest.md) · [Output records](output.md)

Rio reads existing local CycloneDX JSON SBOMs. Run it after the project's SBOM-producing build.
This reference describes `main`; use a release containing the configuration features you need.

- [Installation](#install)
- [Commands and flags](#usage)
- [Preview a run](#rio-plan)
- [Plan JSON contract](#the-plan-json)
- [Exit codes](#exit-codes)

## Install

Single command, for pipelines:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
```

The script detects the platform, downloads the matching release binary and installs it. Set
`RIO_VERSION` to pin a release instead of taking the latest, and `RIO_INSTALL_DIR` to choose the
install directory, which otherwise is `/usr/local/bin` when that is writable and `$HOME/.local/bin`
when it is not. If `rio` is not on your PATH afterwards, add the chosen install directory to PATH
or invoke the binary by its full path.

The assignments go after the pipe, on `sh`. In front of `curl` they would be set for `curl`, which
does not read them, and the installer would run with neither.

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh \
  | RIO_VERSION=v0.3.0 RIO_INSTALL_DIR=/usr/local/bin sh
```

Homebrew:

```sh
brew install rebaze/tap/rio
```

From source, if you already have a Go toolchain:

```sh
go install github.com/rebaze/rio/cmd/rio@latest
```

## Usage

Run from the repository root, after the build has produced SBOMs.

```
rio normalize [flags]

  --manifest string   path to manifest (default "rio.yaml")
  --out string        output directory (default "target/rio")
  --gate string       "warn" or "fail" (default "warn")
  --attest            write an unsigned in-toto statement per artifact
  --quiet             suppress per artifact progress on stdout

rio plan [flags]

  --manifest string   path to manifest (default "rio.yaml")
  --out string        output directory (default "target/rio")
  --json              print the plan as JSON
  --quiet             suppress per artifact progress on stdout

rio version
```

For a Maven build already configured to produce SBOMs, a pipeline can run:

```sh
mvn -B verify
rio normalize --gate fail
DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=... \
  ./tools/rio-dtrack-upload.sh target/rio/index.json
```

That third step is not rio. rio does not upload anywhere; `tools/rio-dtrack-upload.sh` ships as an
example of what to do with `index.json` afterwards. Its environment variables, the DependencyTrack
permissions it needs, and how to nest artifacts under a parent project are documented in
[tools/README.md](../tools/README.md).

One line per artifact on stdout, then a summary. Machine detail belongs in `index.json`, not here.
Errors and warnings go to stderr. A run over the committed fixtures `testdata/tycho-rcp.cdx.json`
and `testdata/gate-missing-version.cdx.json` prints:

```
rcp-client  12 components   repaired 8    unmapped 1    gate ok
server-war   2 components   repaired 0    unmapped 0    gate FAIL (1 component missing version)
2 artifacts, 1 gate failure
```

## `rio plan`

`plan` prints what a `normalize` run would read, write and repair, and does none of it. It writes no
files and, like everything else here, makes no network calls.

```
$ rio plan
manifest  rio.yaml (sha256 a1b2c3d4e5f6...)

rcp-client
  read   target/bom.json
  write  target/rio/rcp-client.cdx.json
  repair-purl  ecosystem p2  table p2-maven.json

gate  require name, version, purl
```

Only the options a manifest actually set are shown; `--json` carries every one of them, resolved.
Exit 2 for the same manifest and glob problems `normalize` refuses, exit 0 otherwise. There is no
exit 1, because no gate runs.

A table that does not exist yet is reported on the line that names it, rather than being an error.
That is the point of the command: the table is built *from* the plan, so the first run in a
repository necessarily names one that is not there.

### The plan JSON

`rio plan --json` is a machine contract. It is what `tools/build-p2-table.py` reads to learn which
SBOMs to harvest, which table to write and under which scope filter, so that none of it has to be
restated on a command line where it could disagree with the manifest.

```json
{
  "planVersion": 1,
  "tool": { "name": "rio", "version": "0.3.0" },
  "manifest": { "path": "rio.yaml", "dir": "/abs/repo", "sha256": "a1b2c3..." },
  "out": "target/rio",
  "builtinTable": { "org.objectweb.asm": { "groupId": "org.ow2.asm", "artifactId": "asm" } },
  "artifacts": [
    {
      "id": "rcp-client",
      "input":  { "path": "target/bom.json" },
      "output": { "path": "rcp-client.cdx.json" },
      "transforms": [
        { "name": "repair-purl", "ecosystem": "p2", "table": "p2-maven.json",
          "groupPrefix": "p2.", "classifier": "osgi.bundle",
          "syntheticNamespace": "p2.eclipse.plugin" }
      ]
    }
  ],
  "gate": { "require": ["name", "version", "purl"] }
}
```

- `planVersion` is the compatibility lever, the role `version` plays in the manifest. A consumer
  checks it before anything else and refuses a number it does not know.
- Paths follow `index.json`'s convention: `input.path` is relative to the manifest's directory,
  `output.path` to `out`, and `table` is exactly as the manifest wrote it, since that is how rio
  resolves it.
- Every transform option is reported **resolved**, defaults filled in, so a consumer never carries
  its own copy of `p2.` or `osgi.bundle`.
- `builtinTable` is the mapping table compiled into this binary. An override always wins over it, so
  a generated table that repeats an entry verbatim would silently shadow any later fix rio makes to
  it; publishing the asset is what lets a generator stay a delta over it.
- `manifest.dir` is the one absolute path rio ever writes, and the one deliberate break from
  `index.json`'s rules. The index refuses absolute paths because it is a committed artifact whose
  digests are a contract; a plan is transient stdout that exists to be joined against, and making
  the consumer guess the base directory is worse.

When enrichment is configured, each artifact also has an optional `enrichment` object with its own
`version: 1` and resolved `fields`. Each field reports `field`, `value`, `source` (a manifest selector
such as `enrichment.producer.name` or `artifacts[0].enrichment.subject.name`) and `replace` (boolean).
Fields are sorted by name. Planning resolves declarations without reading SBOM content: it can
show replacement intent but cannot establish whether an existing value conflicts.

When an artifact binds context, the plan artifact has `context: {"version":1,
"file":"build-context.json","require":["source.repository"],"replace":[]}`. The path is
manifest-relative. Planning reports only that binding and never opens the context file or SBOM;
it can succeed before the producer writes the context file; the selected SBOM must already exist.

This is not `index.json` with fewer fields. The index describes a run that happened, and a run needs
the mapping table that the plan is read to produce, so the index can never describe the first run
in a repository.

## Exit codes

- **0** All artifacts processed. No gate failure, or `--gate warn`.
- **1** At least one artifact failed the gate, under `--gate fail`.
- **2** Usage or configuration error: missing manifest, invalid manifest, glob matched zero or
  several files, glob matched one file over a tree rio could not fully search, unreadable or
  schema-invalid SBOM.
- **3** Internal error.

Exit code 1 still writes every output file and the index: a human has to be able to see why the gate
failed. Exit code 2 writes nothing.
