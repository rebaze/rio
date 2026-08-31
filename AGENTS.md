# AGENTS.md

Guidance for coding agents working in this repository. This file is the single source of truth;
`CLAUDE.md` is a symlink to it so Claude Code picks it up without a second copy to keep in sync.

## Project Overview

`rio` is a Go CLI distributed as a single static binary. It reads a manifest, resolves each declared
artifact's SBOM, levels the CycloneDX spec version, repairs p2 coordinates to Maven coordinates,
checks a quality gate, and writes the results plus an `index.json`.

## Repository Layout

```
cmd/rio/main.go                 Entry point
internal/cli/                   Cobra commands; version/commit/date injected via ldflags
internal/sbom/                  CycloneDX document, embedded schemas, validation, uplift
internal/transform/             Transform seam; purl/p2 holds the p2 repair and its table
internal/{discover,gate,index,manifest}/
                                SBOM discovery, quality gate, index.json, manifest parsing
testdata/                       Fixtures for the test suite
install.sh                      Installer users curl; part of the product surface
Makefile                        Build helpers (build, run, test, vet, tidy, clean)
tools/                          Supporting tools that are not rio; see tools/README.md
.goreleaser.yaml                Cross-platform builds, cosign signing, Homebrew cask
.github/workflows/              CI, CodeQL, Scorecard, Release pipelines
```

Anything that supports rio without being part of it goes in `tools/`, together with its own
documentation in `tools/README.md`. The rule of thumb is the network: rio makes no network calls, so
work that needs one — building the p2 mapping table, uploading to DependencyTrack — is a tool rather
than a feature. The main `README.md` points at `tools/README.md` and does not document the tools
itself, so that rio's own documentation stays about rio.

## Build & Run

```bash
make build                      # builds ./rio with version ldflags
./rio
./rio --version
make test                       # go test ./...
make vet                        # go vet ./...
```

## Conventions

- Standard `internal/` package layout for non-exported packages
- Version, commit, and build date injected via ldflags at build time (see `cmd/root.go`)
- The binary must stay self-contained: `CGO_ENABLED=0`, no runtime dependencies on external tools

## Task Tracking

Tasks are tracked as GitHub issues on `rebaze/rio` — **not** as files in this repository. Never create
a `tasks/` directory or any other in-repo task list.

Use the `gh` CLI to work with them:

```bash
gh issue list                   # open tasks
gh issue view <n>               # read a task, including comments
gh issue create                 # file a new task
gh issue comment <n> --body ... # record progress or findings
```

- Reference the issue in the branch name and in commit messages (e.g. `Fixes #42`) so work links back
  to the ticket
- Close issues through the PR that resolves them rather than by hand

## Release

Releases are cut by pushing a `v*` tag. The release workflow runs GoReleaser, generates and attests a
CycloneDX source SBOM, verifies the attestations, and then publishes the Homebrew cask to
`rebaze/homebrew-tap`.

- **NEVER delete tags** — tags are immutable, even if a release is broken
- **NEVER re-create releases** on existing tags — instead, bump the version and create a new release
- When fixing a broken release, increment the micro (patch) version by default (e.g. `v0.1.0` → `v0.1.1`) unless told otherwise
