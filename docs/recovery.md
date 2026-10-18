# Recovering from a broken release

What to do when a published Rio release must not be installed any more: it misbehaves, fails
[published-release verification](../tools/README.md#published-release-verification), the
[weekly published-release scan](../tools/README.md#published-release-scan) finds a vulnerability in
it, or an asset is suspected to be compromised.

## Rules that do not change

- Tags are never deleted or moved, and a release is never re-created (`AGENTS.md`). Since
  2026-10-18 releases are immutable and a tag ruleset blocks updating or deleting `v*` tags, so
  GitHub enforces this too.
- The fix is the next patch version through the normal release path. Withdrawal only protects
  users until the fix is published.

## Steps

**1. Decide and record.** The maintainer who decides to withdraw opens an issue
`Withdraw vX.Y.Z` stating what is broken, which platforms are affected, the decision, its time and
the earlier version users should fall back to. For a vulnerability, follow
[SECURITY.md](../SECURITY.md) and prepare a GitHub security advisory instead of a public issue.

**2. Stop new Homebrew installs.** Restore the cask of the earlier release in
[rebaze/homebrew-tap](https://github.com/rebaze/homebrew-tap):

```sh
python3 tools/revert-cask.py --to vPREVIOUS --output /absolute/new/rio.rb
```

A cask is Ruby that Homebrew executes, so matching archive hashes alone would not be enough. The
tool verifies the earlier release's `checksums.txt` with cosign against the release workflow's
identity, renders the cask from the template in `release.yaml` at that release's protected tag
with those checksums, and requires a byte-identical cask in the tap's history. A cask edited by
hand later, or one whose install hook differs, is refused; review the tap history by hand then.
The template at the tag matters: the v0.8.0 cask strips macOS quarantine, v0.8.1 and later are
notarized and do not, so today's template would install a v0.8.0 binary that Gatekeeper kills.
The tap's `main` accepts direct pushes only from the release app, so commit the file as
`Casks/rio.rb` on a branch with the message the tool prints, open a pull request in the tap and
merge it as a repository administrator. Homebrew does not downgrade existing installations: users who already installed the broken
version run `brew uninstall rio && brew install rebaze/tap/rio`.

**3. Point the installer at the earlier release.** `install.sh` installs the release GitHub marks
as latest. Mark the earlier release:

```sh
gh release edit vPREVIOUS --repo rebaze/rio --latest
```

If GitHub refuses the change for an immutable release, say so in the issue and the advisory, and
tell users to install with `RIO_VERSION=PREVIOUS`.

**4. Tell users.** Link the issue or advisory from the README's install section until the fix is
out. Release notes of an immutable release may not be editable; do not rely on them.

**5. Ship the fix.** Bump the patch version and release through the normal path. Publication
updates the cask and the latest marker forward again. Close the issue from the fix's PR and link the
fixed release.

## Rehearsal

On 2026-10-18 `revert-cask.py` rendered the casks for v0.8.0, v0.7.2, v0.8.1 and v0.3.0 from their
tags and signed checksums and found each byte-identical in the tap (`58ae66d`, `530f4c8`,
`788b64f`, `bfbd978`); the v0.8.0 cask keeps its quarantine step. For v0.3.0 it chose the cask the
workflow published, not the later hand edit. Nothing was pushed. Not rehearsed: pushing a reverted cask, installing it, and
changing the latest marker of an immutable release.

Since 2026-10-18 the ruleset "Only the release app updates main" protects the tap: only the release
app pushes directly, administrators update `main` through pull requests, and nobody force-pushes or
deletes it. A direct push by an administrator was rejected when it was set up. Not yet exercised:
the release app's push on the next release, and a recovery pull request. Requiring the rendered
cask to match the tap history still matters for history written before the ruleset; the template
itself comes from a tag that cannot be moved.
