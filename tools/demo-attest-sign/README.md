# Synthetic normalization signing demonstration

```text
Verified app.sigstore.json
Verified worker.sigstore.json
PASS: recipient verification, unchanged inputs, overwrite refusal, altered SBOM/statement refusal.
PASS: wrong trusted key, legacy bundle and mixed-format bundle refused.
```

This output was generated with installed Rio v0.7.0 and cosign v3.0.6.
Inspect the [signed bundle](example/app.sigstore.json), [original statement](example/app.intoto.json),
[normalized SBOM](example/app.cdx.json) and [test public key](example/SYNTHETIC-ONLY.pub).
The private synthetic key was deleted. The sample key is not a production trust anchor.

Run with installed Rio 0.7.0+, Python 3.9+, Bash, jq, cosign v3.0.6 and sha256sum or shasum:

```sh
python3 tools/demo-attest-sign/run.py /path/to/rio
```

No Go toolchain is required. The runner generates a disposable test key, normalizes both
synthetic fixtures into one isolated run, signs and verifies both statements, and checks
overwrite and tamper refusals. It deletes the private key even if a check fails and prints
the retained public evidence directory. Public-log upload is disabled.

Verify the committed example independently with cosign v3.0.6:

```sh
cd tools/demo-attest-sign/example
bash ../../rio-attest-verify.sh --public-key SYNTHETIC-ONLY.pub \
  --bundle app.sigstore.json app.cdx.json
```

The verifier snapshots inputs and refuses legacy/mixed bundle formats before cosign can choose
an embedded key. The demo also rejects a genuine bundle against an unrelated trusted public key.
Cosign warns that transparency-log verification is disabled. It still checks the signature,
predicate type and subject digest. The sample proves that this bundle is internally verifiable
with its test key; it does not authenticate a real producer or establish a trusted signing time.

See [key handling, output boundaries and recipient trust](../README.md#signing-and-verifying-normalization-attestations).
