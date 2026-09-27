# An actual client record

[Read record.json](record.json), download [report.html](report.html) and open it locally, or
view the [screenshot of its repair table](report-preview.png). No server or credentials are needed.

These unedited synthetic outputs were produced by the published Rio v0.6.0 binary with
[the client handoff demo](../README.md). This is its initial successful snapshot, before
the separate bypass, partial-response and reconciliation examples. The report was rendered
from these exact JSON bytes. It contains two artifacts, three accepted acknowledgments and
one excluded pair. Loopback endpoints and receipts belong to the stopped synthetic receiver.

From the repository root with Rio v0.6.0 or newer installed:

```sh
rio record inspect --file tools/demo-client-record/example/record.json
rio record report --file tools/demo-client-record/example/record.json --output /tmp/rio-example-report.html
```

Use a fresh report output path. The JSON SHA-256 is
`47cbae7aa032112399c7b125ab22ecf39100006f15af0c6e91888a41a569a6c9`.
These are consistency checks on unsigned evidence, not authenticity or ingestion proof.
