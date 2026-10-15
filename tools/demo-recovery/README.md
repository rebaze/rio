# Failure and recovery receipts

Run with Rio 0.7.0+ and Python 3.9+; no Go toolchain or external receiver is needed:

```sh
python3 tools/demo-recovery/run.py /absolute/path/to/rio
```

One root invocation routes two synthetic artifacts to two loopback targets with a configured
exclusion. The receiver accepts the first upload and loses the next response, so the receipt
records accepted, unknown and unattempted pairs. Rio does not resubmit on its own: an unchanged
`deliver` refuses, and an explicit `--retry-of` plus a selected unattempted pair each write
their own receipt. Three `delivery reconcile` invocations observe the acknowledged upload
(processing, done, receiver error), each with its own receipt that references the original attempt.

The demo then kills a delivery child after the receiver has its request. With the receiver
stopped and the working index corrupted, `record recover` reads committed local state, leaves
the delivery incomplete with an unknown response, makes no request and **does not remove the
crash lock**. A failed quality gate is recorded and blocks delivery.

Finally it removes the source workspace and inspects/renders every retained receipt offline.
Earlier receipts stay byte-identical, a dangling artifact reference and a contradictory
acknowledgment are refused, and the synthetic API key appears in no output. Receipts are
unsigned; HTTP acceptance is not ingestion.
