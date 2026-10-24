# Handoff checks: security contact and digest

Run with Rio 0.9.0+ and Python 3.9+; no Go toolchain or external receiver is needed:

```sh
python3 tools/demo-handoff-checks/run.py /absolute/path/to/rio
```

One synthetic Cart API SBOM without a product security contact or a distribution digest goes
through six root invocations, each delivering to a loopback receiver:

| Scenario | `rio.yaml` | Result |
|---|---|---|
| `not-required` | no `gate.subject.require` | passes and is delivered; no contact is checked |
| `required-missing` | `gate.subject.require: [securityContact]` | exit 1, nothing delivered, the next step printed |
| `required-supplied` | plus `enrichment.subject.securityContact: mailto:security@example.com` | passes and is delivered with the reviewed contact |
| `required-unsupported` | the SBOM already holds `security@example.com`, not a URL | exit 1, nothing delivered, the value named |
| `digest-missing` | `gate.subject.require: [digest]` | exit 1, nothing delivered, the next step printed |
| `digest-supplied` | plus a `build-context.json` entry declaring two shipped files under `distributions` | passes and is delivered; the SBOM subject and the receipt list both files |

For the failures, the receipt's `checks.failed` lists `subject.securityContact` or
`subject.digest` and stderr says what to do, for example:

```text
rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
  subject.securityContact: the SBOM subject has no security-contact reference. Set the reviewed contact as enrichment.subject.securityContact in rio.yaml, or have the SBOM generator emit one. Rio does not look it up.
```

```text
rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
  subject.digest: the SBOM subject has no distribution digest. Add the shipped files under distributions in the build context file. Rio does not hash them.
```

The `digest-supplied` run writes a [build context file](../../docs/context.md) whose entry binds the
SBOM bytes and declares two files. Rio adds one `distribution` reference per file to the SBOM
subject, and the receipt lists them as producer assertions:

```text
== digest-supplied -> exit 0 - delivered
   checks.subjectRequirements: ['name', 'version', 'digest']
   receipt distribution: cart-api-1.4.0-linux-amd64.tar.gz sha256=d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 assertion=producer
   receipt distribution: cart-api-1.4.0.jar sha256=d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 assertion=producer
   SBOM distribution reference: https://downloads.example.com/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz SHA-256 d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
   SBOM distribution reference: cart-api-1.4.0.jar SHA-256 d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
```

A passing contact check establishes only that a contact in a supported form is present. It does
not identify who answers it, verify the mailbox or approve the release. A passing digest check
establishes only that the subject carries a SHA-256 distribution digest. Rio does not hash the
shipped files, and nothing proves they were built from the components the SBOM lists. The
address, file names and digests are synthetic.
