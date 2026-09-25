# Synthetic Dependency-Track HTTPS demo

Run `python3 tools/demo-dtrack-tls/run.py /absolute/path/to/rio` with Python 3.9+ and
an installed Rio binary containing `insecureSkipVerify` support. On Windows use
`python tools/demo-dtrack-tls/run.py C:\path\rio.exe`. No Go toolchain, Docker,
OpenSSL executable or source build is needed to run it.

This starts a loopback HTTPS stub using the committed **SYNTHETIC-ONLY** certificate
and private key. These public test fixtures must never secure a real service or be
installed in a system trust store. The fixture certificate covers `127.0.0.1` and
`localhost`. All receipts are invented test data, not real Dependency-Track evidence.

The demo verifies default refusal of the self-signed certificate, preferred explicit
`caFile` trust, explicit certificate-verification bypass, saved intent and handshake
facts, refusal of policy drift, no upload replay, and absence of the synthetic API
key from outputs and records. It shuts down the receiver, exports all three attempts,
deletes the working project, and inspects the retained portable record offline.

`insecureSkipVerify: true` skips certificate-chain and hostname verification. It does
not claim the peer certificate was invalid, ignore TLS protocol failures or provide
content verification. The Go regression suite additionally uses a hostname-mismatched
certificate and tests redirects, broken TLS, and lost HTTP responses.

The run prints the retained synthetic evidence directory and record digest. See
[the native delivery guide](../README.md#native-verified-delivery) for policy and
recovery semantics. Release availability is stated in the main README.
