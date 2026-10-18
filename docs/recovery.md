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

It verifies the earlier release's `checksums.txt` with cosign against the release workflow's
identity, takes the newest tap commit whose cask has that version, and refuses unless every
`sha256` in it equals the signed checksums. It restores the cask as it was published, because the
template changed between releases: the v0.8.0 cask strips macOS quarantine, v0.8.1 and later are
notarized and do not. Re-rendering an old release with today's template would install a binary
that Gatekeeper kills. Commit the file as `Casks/rio.rb` with the message the tool prints and push
it. Homebrew does not downgrade existing installations: users who already installed the broken
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

On 2026-10-18 `revert-cask.py --to v0.8.0` restored the cask from rebaze/homebrew-tap commit
`58ae66d`, byte-identical to the published v0.8.0 cask including its quarantine step, with all four
hashes equal to the cosign-verified v0.8.0 checksums; `--to v0.7.2` passed the same checks against
commit `530f4c8`. Nothing was pushed. Not rehearsed: pushing a reverted cask, installing it, and
changing the latest marker of an immutable release.

The tap's `main` branch has no branch protection. The hash check in `revert-cask.py` is what keeps
a changed tap history from being restored unnoticed.
