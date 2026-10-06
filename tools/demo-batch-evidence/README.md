# Compact batch receipts and offline recovery

Run with Rio 0.7.0+ and Python 3.9+:

```sh
python3 tools/demo-batch-evidence/run.py /absolute/path/to/rio
```

One root invocation routes two synthetic artifacts to two loopback targets with a configured exclusion. The receiver accepts one upload and loses the next response; the receipt preserves accepted, unknown and unattempted states. An unchanged standalone delivery refuses, while an explicit retry and a selected unattempted pair use fresh journals and independent receipts.

The demo then kills its own delivery child after the receiver observes its request. `record recover` reads committed local state with the receiver stopped and the working index deliberately corrupted. It leaves the run and delivery phase incomplete, preserves unknown response state, makes no request and **does not remove crash locks**. Earlier receipts remain byte-identical.

After removing the entire source workspace, the demo inspects and renders each independent receipt, refuses a contradictory acknowledgment, and checks secret-canary absence. The HTTP policy is explicit and limited to synthetic local receivers. No Go toolchain, external service, bundle collection or legacy record reader is required.
