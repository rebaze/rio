# Source-SBOM monitoring demo

| Synthetic Go component | Real Dependency-Track 5.2.1 result, 2026-11-14 |
|---|---|
| `pkg:golang/stdlib@1.27.3` | inventory verified; `CVE-2026-97054` and `GO-2026-6859` found |
| `pkg:golang/stdlib@1.27.4` | inventory verified; no findings observed |

[Inspect the live verification JSON](live-verification.json). The SBOMs are deliberately
synthetic canaries; the receiver at `https://dependencytrack.rebaze.de` and its vulnerability
analysis were real. Each SBOM passed Rio's strict `bsi-tr-03183-2@2.1.0` profile. The result is
an observation from that run, not a promise that the fixed canary will remain finding-free.

[Inspect the local synthetic receiver result](example/verification.json) for the offline
version. It verifies delivery and inventory only; it does not simulate vulnerability analysis.
The [input template](stdlib.cdx.json.in) is directly inspectable and contains no installed
Go runtime or executable code.

[The deployed bounded-lifecycle verification](bounded-lifecycle-verification.json) separately
records Rio's real 14-component main and release inventories, release latest promotion, and
the archival of nine legacy CI snapshots. The synthetic canaries below remain an explicit
operator demo; normal PR and branch CI creates no Dependency-Track project.

## Run locally

Install Rio 0.10.x and Python 3.9+. From the repository root:

```sh
python3 tools/demo-self-sbom/run.py rio
```

A path to an installed release binary also works:

```sh
python3 tools/demo-self-sbom/run.py /path/to/rio --output /tmp/rio-monitoring-demo
```

CI and release jobs use the [pinned stable Rio v0.10.2 actor](../README.md#pinned-stable-rio-actor).
To exercise that same downloaded executable locally, supply its `bin/rio` path here. The
candidate source remains the inventory being monitored; the candidate executable is used only
by product tests.

The output directory must not exist. Without `--output`, the script creates a temporary
directory and prints its location. No Go toolchain, build from source, external receiver or
real credential is needed. The script starts a synthetic receiver on loopback, creates a
throwaway synthetic key and delivers both canaries through native Rio.

For each canary it retains the input SBOM, normalization manifest, strict-gate receipt,
normalized index/member, prepared delivery bundle, native delivery result/receipt and inventory
verification. The top-level `verification.json` summarizes both cases.

## Verify real receiver analysis

This command explicitly uploads two synthetic canaries to the named HTTPS receiver. It creates
project versions under `rio-sbom-monitoring-canary`, with a unique default run ID and suffixes
`-vulnerable` and `-fixed`:

```sh
python3 tools/demo-self-sbom/run.py rio \
  --url https://dependencytrack.rebaze.de --check-findings
```

Populate `DTRACK_API_KEY` from your secret store with an upload key allowed to create projects
and read their inventory. Populate `DTRACK_VERIFY_API_KEY` with a separate findings-reader key
having at least `VIEW_VULNERABILITY` and `VIEW_PORTFOLIO`. Do not put either value in command
arguments or committed files. The findings-reader key is needed only for `--check-findings`;
`--url` alone tests real delivery and inventory read-back without checking analysis.

The script waits up to 180 seconds by default (`--timeout` changes this). It checks that the
receiver has processed the one-component inventory, that the vulnerable canary reports
`GO-2026-6859` or its CVE alias, and that the fixed canary reports neither alias. A failure
retains evidence for inspection; a subsequent invocation creates a fresh run rather than
reusing an ambiguous upload. `--project-name` and `--run-id` let an operator select explicit
canary identities. Avoid reusing a run ID while another analysis is still in progress.

The monitoring configuration applies `owner:team-rio`. A deployed notification rule is
configured for that owner tag, and inventory read-back observed the tag. Actual notification
delivery has not been independently observed. See the [workflow and recovery details](../README.md#self-sbom-monitoring)
for Rio's own source SBOMs, exact published-byte verification and retained retry evidence.


## Relationship to production monitoring

This demo uses synthetic canaries in a separate `rio-sbom-monitoring-canary` project. The
committed summaries record direct canary delivery, inventory and (for the live run) observed
findings. They do not demonstrate production main coordination, token-specific import
completion or release latest promotion. A canary run needs its own suitable credential;
the restricted production main key cannot create these canary projects.

Production uses one active `rio` / `main` project and retained release versions under the
`Rio product` collection within `rebaze`. Main is never latest. Only canonical main CI uploads
development inventory; PR, tag and reusable CI observations remain checked artifacts. Source
revision and workflow build URL are embedded before native normalization, so the fixed `main`
project version does not hide which commit was consumed. Published stable releases are
promoted only after exact-asset, accepted-token completion and inventory verification.

The product collection's own latest flag supports the organization rollup separately from
the latest `rio` release flag. Persistent `rio-monitoring/main-import` coordination prevents
an earlier pending or ambiguous upload from being overwritten by another workflow. An
ambiguous submission needs explicit reconciliation; do not reset its marker blindly. See
[bounded projects and publication](../README.md#bounded-projects-and-publication) and
[persistent recovery](../README.md#persistent-import-coordination-and-recovery) for the current
production policy and the unchanged v0.10.2 bootstrap migration.
