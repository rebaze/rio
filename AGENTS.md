# AGENTS.md

Guidance for coding agents working in this repository. This file is the single source of truth;
`CLAUDE.md` is a symlink to it so Claude Code picks it up without a second copy to keep in sync.

## Project Overview

`rio` is a Go CLI distributed as a single static binary. The implementation is not written yet — the
repository currently holds the build, CI, and release infrastructure plus a placeholder root command.

## Repository Layout

```
main.go                         Entry point
Makefile                        Build helpers (build, run, test, vet, tidy, clean)
cmd/                            Cobra CLI
  root.go                       Root command; version/commit/date injected via ldflags
.goreleaser.yaml                Cross-platform builds, cosign signing, Homebrew cask
.github/workflows/              CI, CodeQL, Scorecard, Release pipelines
```

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
