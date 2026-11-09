---
name: release
description: Use when asked to release, ship, tag or rehearse a release of rio ("release v0.9.1", "cut an rc", "/release"). Writes docs/releases/<tag>.md from the changes since the last tag, merges it, tags that commit, follows the release workflow to publication and verification, and records the verification evidence.
---

# Releasing rio

The human decision is the version and the notes. Ask for it **once**, together, then carry the
release through without further questions unless something fails. Pushing the tag publishes: the
`release` environment has no approval step.

Read the Release section of `AGENTS.md` first; its rules win over this file. Never delete a tag,
never re-create a release on an existing tag, and never mention Claude or AI in notes, commits or PRs.

## 1. Check the candidate

```bash
git fetch origin --tags --prune
SHA=$(git rev-parse origin/main)
gh run list --commit "$SHA" --json workflowName,status,conclusion
```

`CI`, `CodeQL` and `Installer tests` must have passed at `$SHA`. If one is still running, wait for
it (`gh run watch <id> --exit-status`). If one failed, stop and report it; do not release around it.

## 2. Propose the version

- Last tag: `git tag -l 'v*' --sort=-v:refname | head -1`; last stable tag: the first without `-`.
- Changes: `git log --first-parent --format='%h %s' <last-stable>..origin/main`, then
  `gh pr view <n>` for each PR, and the issues they fix, to understand what users get.
- rio is 0.x: a new user-visible capability or a behaviour change is a **minor** bump; only fixes,
  dependency updates, docs or CI is a **patch** bump. A rehearsal is `-rc1` (then `-rc2`, ...).
- If the user named a version, use it, but say so when the changes suggest another.

## 3. Write the notes

Write `docs/releases/<tag>.md`. The pipeline publishes its exact bytes as the GitHub release body.
Match the most recent file in `docs/releases/` in voice and shape:

- Line 1 is exactly `# Rio <tag>`. The body must not be empty.
- A bold one-line lead with the most important change for users.
- Then, per AGENTS.md "Time to Wow", a concrete example of what users get, before anything else:
  real output of a binary built from the candidate (`make build`, then the matching demo under
  `tools/`), trimmed, and labelled as synthetic data where it is. Never invent output.
- `## What changed`: one bullet per user-visible change, bold summary first, linking its issue.
  Pin repository links to the tag (`https://github.com/rebaze/rio/blob/<tag>/...`).
- Dependency, CI and release-tooling changes go in a short last section or are left out; they
  are not the lead. Name security-relevant dependency updates (with the advisory).
- A pre-release says on its lead line that it is a pre-release and that stable releases are for
  real use, and that the Homebrew cask is not updated.

Show the user the version and the full notes in one message and ask whether to ship. That is the
only question. If they asked not to be asked, ship without it.

## 4. Land the notes

```bash
git switch -c release-notes-<tag> origin/main
git add docs/releases/<tag>.md
git commit -m "Release notes for <tag>"
```

Commits here are signed. If `git commit` hangs or fails on 1Password, load the
`reading-1password-secrets` skill and sign with the service-account key as it describes.

Push, open a PR titled `Release notes for <tag>`, wait for its required checks
(`gh pr checks <n> --watch --required`), then `gh pr merge <n> --squash --delete-branch`.
The release commit is that merge commit: `REL=$(gh pr view <n> --json mergeCommit --jq .mergeCommit.oid)`.
Check `git rev-parse origin/main` after fetching equals `$REL`; if someone merged in between,
release `$REL` anyway, not the newer commit.

Then dispatch release preflight for the record and wait for it and for `Installer tests` at `$REL`:

```bash
gh workflow run release-preflight.yaml --ref main -f version=<tag>
gh run list --commit "$REL" --json databaseId,workflowName,status,conclusion
```

Both must pass at `$REL` (check the run's `headSha`, since the dispatch runs on main's head).

## 5. Tag

Create the tag on `$REL` through the API with the user's own `gh` login (only admins may create
`v*` tags; a ref created with a user token starts the release workflow):

```bash
gh api repos/rebaze/rio/git/refs -f ref=refs/tags/<tag> -f sha="$REL"
```

## 6. Follow the release

```bash
gh run list --workflow release.yaml --branch <tag> --json databaseId,status
gh run watch <id> --exit-status
```

It takes about 20 minutes: full CI and CodeQL, `build` (sign, notarize, attest, draft),
`publish`, and for stable tags `publish-tap` and `verify`. Run the watch in the background.

When something fails, read the failed job's log first (`gh run view <id> --log-failed`):

- **A flaky download or runner error before any draft exists:** `gh run rerun <id> --failed`.
- **`publish` failed:** fix the cause, then re-run only the failed jobs; `publish` re-checks the
  same draft.
- **`build` failed after the draft exists:** the draft must be deleted before all jobs are re-run.
  Deleting is the user's call: show them the draft (`gh release view <tag>`) and ask first.
- **Anything published with wrong bytes:** stop. The fix is a new patch tag and
  [docs/recovery.md](../../../docs/recovery.md); tell the user.

## 7. Check what users got

```bash
gh release view <tag> --json body,isDraft,isPrerelease,assets --jq '{isDraft,isPrerelease,assets:[.assets[].name]}'
gh release view <tag> --json body --jq .body | diff - docs/releases/<tag>.md && echo "notes are the release body"
```

For a stable tag, also record the verification evidence, as the last
`docs/release-verification/<tag>.md` does:

```bash
gh run download <id> --dir "$SCRATCH/evidence"   # published-ubuntu-latest, -macos-latest, -windows-latest, homebrew-install
```

- `docs/release-verification/<tag>/linux.json`, `macos.json`, `windows.json`: each
  `published-<os>/verification.json`.
- `homebrew-version.txt` and `homebrew-gatekeeper.txt`: from `homebrew-install`.
- `docs/release-verification/<tag>.md`: a short summary in the shape of the last one — the release
  commit and its PR, a table of the preflight, installer-tests and release runs with links, which
  platforms executed natively, that the summaries agree on the asset hashes and the notes hash,
  and anything that needed a re-run and why. Facts from the runs only.

Land it like the notes (branch `release-verification-<tag>`, PR "Record verified <tag> release
evidence", squash-merge). Pre-releases skip `verify`, so they get no evidence file.

## 8. Report

Tell the user, briefly: the release URL, the commit, whether the cask was updated, what was
verified, and anything that was re-run or still needs them.
