# Synthetic Dependency-Track HTTPS demo

Run `python3 tools/demo-dtrack-tls/run.py /absolute/path/to/rio` with Python 3.9+ and
an installed Rio v0.7.0 or newer binary. On Windows use
`python tools/demo-dtrack-tls/run.py C:\path\rio.exe`. No Go toolchain, Docker,
OpenSSL executable or source build is needed to run it.

This starts a loopback HTTPS stub using the committed **SYNTHETIC-ONLY** certificate
and private key. These public test fixtures must never secure a real service or be
installed in a system trust store. The fixture certificate covers `127.0.0.1` and
`localhost`. Rio generates the receipts from synthetic receiver acknowledgments; these are
not real Dependency-Track integration evidence.

The happy path runs `rio --json` once with explicit `caFile` trust and retains its compact
pipeline receipt. Specialist invocations then verify default refusal of the self-signed
certificate, explicit certificate-verification bypass, saved intent and handshake
facts, refusal of policy drift, no upload replay, and absence of the synthetic API
key from outputs and receipts. Each execution retains its own receipt, including a separate
reconciliation receipt linked to the prior attempt. The demo shuts down the receiver, deletes
the working project and credentials, and inspects/renders every retained receipt offline.

`insecureSkipVerify: true` skips certificate-chain and hostname verification. It does
not claim the peer certificate was invalid, ignore TLS protocol failures or provide
content verification. The Go regression suite additionally uses a hostname-mismatched
certificate and tests redirects, broken TLS, and lost HTTP responses.

The run prints the retained synthetic receipt directory and pipeline receipt digest. See
[the native delivery guide](../README.md#native-verified-delivery) for policy and
recovery semantics. Release availability is stated in the main README.

Each receipt uses `kind: rio-run-receipt`, `schemaVersion: 1`. The demo renders self-contained
HTML after removing the source workspace. No JavaScript, external fonts or network resources
are needed to read it; retain the JSON for machine inspection.
