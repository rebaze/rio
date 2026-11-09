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
gh run list --commit "$SHA" --json workflowName,event,status,conclusion
gh workflow run ci.yaml --ref main    # full validation, while you write the notes
```

CI on a push to `main` runs only what the changed files touch, so a green push run is not a full
check: a docs-only commit skips the Go tests. A dispatched run validates everything. Start it now,
check that its `headSha` is `$SHA` (if `main` moved, start again from the top), and let it run while
you do steps 2 and 3.

Before you tag, the dispatched `CI` run and the push runs of `CodeQL` and `Installer tests` must
have passed at `$SHA`. If one failed, stop and report it; do not release around it. A tag cannot be
deleted, so a failure found after tagging costs the version.

To wait for a run, poll its status rather than trusting `gh run watch`, which can exit non-zero
while the run is still going; then read the conclusion:

```bash
until [ "$(gh run view <id> --json status --jq .status)" = completed ]; do sleep 30; done
gh run view <id> --json conclusion,headSha
```

## 2. Propose the version

- Last tag: `git -c versionsort.suffix=- tag -l 'v*' --sort=-v:refname | head -1`; last stable tag:
  the first without `-`. Without `versionsort.suffix`, `v0.9.0-rc1` sorts above `v0.9.0`.
- Changes: `git log --first-parent --format='%h %s' <last-stable>..origin/main`, then
  `gh pr view <n>` for each PR, and the issues they fix, to understand what users get.
- rio is 0.x: a new user-visible capability or a behaviour change is a **minor** bump; only fixes,
  dependency updates, docs or CI is a **patch** bump. A rehearsal is `-rc1` (then `-rc2`, ...).
- If the user named a version, use it, but say so when the changes suggest another.

## 3. Write the notes

Write `docs/releases/<tag>.md`. The pipeline publishes its exact bytes as the GitHub release body.

If `origin/main` already has that file, a draft written with the changes, it is the starting
point: never overwrite it. Keep its lead, example and wording where they are still right, and bring
it up to date: regenerate the example output with a binary built from the candidate, pin links to
the tag, and add every user-visible change that landed after the draft (check the change list from
step 2 against it). Show the user what you changed in the draft, not only the result.

Match the most recent file in `docs/releases/` in voice and shape:

- Line 1 is exactly `# Rio <tag>`. The body must not be empty.
- A bold one-line lead with the most important change for users.
- Then, per AGENTS.md "Time to Wow", a concrete example of what users get, before anything else:
  real output of a binary built from the candidate (`make build`, then the matching demo under
  `tools/`), trimmed, and labelled as synthetic data where it is. Never invent output. Trimming
  may drop fields but must keep the output's own structure and field names; say what was left
  out. Don't flatten or rename with `jq` and present the result as Rio's output.
- `## What changed`: one bullet per user-visible change, bold summary first, linking its issue.
  Pin repository links to the tag (`https://github.com/rebaze/rio/blob/<tag>/...`).
- Dependency, CI and release-tooling changes go in a short last section or are left out; they
  are not the lead. Name security-relevant dependency updates (with the advisory).
- A pre-release says on its lead line that it is a pre-release and that stable releases are for
  real use, and that the Homebrew cask is not updated.

Show the user the version and the full notes in one message and ask whether to ship. That is the
only question. If they asked not to be asked, ship without it.

## 4. Land the notes

If the notes were an existing draft that needed no change, there is nothing to land: `$REL` is
`$SHA`, and you go straight to step 5.

```bash
git switch -c release-notes-<tag> origin/main
git add docs/releases/<tag>.md
git commit -m "Release notes for <tag>"   # an updated draft is committed the same way
```

Commits here are signed. If `git commit` hangs or fails on 1Password, load the
`reading-1password-secrets` skill and sign with the service-account key as it describes.

Push, open a PR titled `Release notes for <tag>`, wait for its required checks
(`gh pr checks <n> --watch --required`), then `gh pr merge <n> --squash --delete-branch`.
The release commit is that merge commit: `REL=$(gh pr view <n> --json mergeCommit --jq .mergeCommit.oid)`.
Release `$REL`, never a newer head of `main`.

The squash merge carries whatever reached `main` while the notes PR waited, and the user approved
notes for `$SHA`. Check that the notes file is the only difference:

```bash
git fetch origin
git diff --name-only "$SHA" "$REL"    # must print only docs/releases/<tag>.md
```

If anything else changed, the release scope changed, and step 1's validation no longer covers it.
Start again at step 1 with the new head of `main` as `$SHA`: dispatch full CI on it, update the
notes for the new changes, show the user the difference and ask again, then land the update and
repeat this check against the new `$SHA`. Never tag a commit whose code differs from the
validated `$SHA`.

Tag only when step 1's checks have all passed at `$SHA` and `$REL` differs from it by the notes
file alone. Then the release commit adds only the notes to a validated commit, so tag it right away;
the release's own `validate` job runs the full CI on the tagged commit again. Release preflight is
not part of a release.

## 5. Tag

Create the tag on `$REL` through the API with the user's own `gh` login (only admins may create
`v*` tags; a ref created with a user token starts the release workflow):

```bash
gh api repos/rebaze/rio/git/refs -f ref=refs/tags/<tag> -f sha="$REL"
```

## 6. Follow the release

```bash
gh run list --workflow release.yaml --branch <tag> --json databaseId,status
```

It takes about 20 minutes: full CI and CodeQL, `build` (sign, notarize, attest, draft),
`publish`, and for stable tags `publish-tap` and `verify`. Wait for it in the background, by
polling its status as in step 1.

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
# Compare bytes: gh's --jq output adds a newline the body does not have.
gh release view <tag> --json body | python3 -c '
import json, subprocess, sys
body = json.load(sys.stdin)["body"].encode("utf-8")
notes = subprocess.run(["git", "show", sys.argv[1] + ":docs/releases/" + sys.argv[2] + ".md"],
                       check=True, capture_output=True).stdout
print("notes are the release body" if body == notes else "release body differs from the notes")
sys.exit(body != notes)
' "$REL" <tag>
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
  commit and its PR, a table of the full CI, CodeQL, installer-tests and release runs with links, which
  platforms executed natively, that the summaries agree on the asset hashes and the notes hash,
  and anything that needed a re-run and why. Facts from the runs only.

Land it like the notes (branch `release-verification-<tag>`, PR "Record verified <tag> release
evidence", squash-merge). Pre-releases skip `verify`, so they get no evidence file.

## 8. Report

Tell the user, briefly: the release URL, the commit, whether the cask was updated, what was
verified, and anything that was re-run or still needs them.
