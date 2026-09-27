# Independent invocation receipts

Run with Rio 0.7.0+ and Python 3.9+:

```sh
python3 tools/demo-record/run.py /absolute/path/to/rio
```

The synthetic receiver accepts the root pipeline's two SBOMs. The demo then makes an explicit lost-response attempt and retry, and performs three separate reconciliation invocations. Each has its own compact receipt; prior bytes stay unchanged, and reconciliation records only its new observation with a prior-attempt reference.

The demo retains failed gate facts, stops the receiver, removes its source workspace, and inspects/renders receipt-only copies. It refuses a dangling artifact reference and a contradictory acknowledgment, checks runtime-secret absence, and reports unsigned consistency rather than ingestion or authentication. There is no collection, source archive or merged history bundle.

See the [client-facing example](../demo-client-record/README.md) and [receipt field guide](../../docs/output.md).
