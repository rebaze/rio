# One record of current evidence

Run with an installed Rio binary and Python 3.9+; no Go toolchain or source build is used:

```sh
python3 tools/demo-record/run.py /absolute/path/to/rio
# Windows:
python tools/demo-record/run.py C:\path\rio.exe
```

The script creates synthetic SBOMs, normalizes two artifacts (only one has supplied source/build
context), and creates real Rio delivery journals using a loopback **synthetic** receiver. It shows
an acknowledged upload, a lost-response unknown upload, an explicit retry, and reconciliation
observing processing, no processing, and an unavailable query. Receipt and activity remain separate.

The receiver is stopped before every collection or inspection. Separate before/after snapshots,
zero selected deliveries, missing selected retry ancestry, and a failed-gate snapshot are exported.
Only `record.json` is copied to a recipient directory, the complete source workspace is removed,
and inspection succeeds there. Corrupted source bytes and an edited readable summary each refuse.

The retained directory printed at the end contains snapshots, the recipient file, deliberate corrupt
examples and a command/exit walkthrough. All receiver responses are synthetic. No API secret value
is retained. The demo does not establish ingestion, authenticated producer identity or signatures;
SBOM bytes and normalization assets are not retained in these records.

Records retain additive normalization evidence when the producing Rio includes it. The
[normalization evidence demo](../demo-normalization-evidence/README.md) shows exact repair
sources and change pointers. Older indexes explicitly lack these details; collecting them with
a newer binary cannot reconstruct missing history.

The client-evidence version of this demo requires an installed release containing `record report`
(v0.6.0 or newer). It renders self-contained HTML after removing the source workspace. No JavaScript,
external fonts or network resources are needed to read it; retain the JSON for machine inspection.
