# Handoff checks: the security contact

Run with Rio 0.9.0+ and Python 3.9+; no Go toolchain or external receiver is needed:

```sh
python3 tools/demo-handoff-checks/run.py /absolute/path/to/rio
```

One synthetic Cart API SBOM without a product security contact goes through four root
invocations, each delivering to a loopback receiver:

| Scenario | `rio.yaml` | Result |
|---|---|---|
| `not-required` | no `gate.subject.require` | passes and is delivered; no contact is checked |
| `required-missing` | `gate.subject.require: [securityContact]` | exit 1, nothing delivered, the next step printed |
| `required-supplied` | plus `enrichment.subject.securityContact: mailto:security@example.com` | passes and is delivered with the reviewed contact |
| `required-unsupported` | the SBOM already holds `security@example.com`, not a URL | exit 1, nothing delivered, the value named |

For the failures, the receipt's `checks.failed` lists `subject.securityContact` and stderr says
what to do, for example:

```text
rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
  subject.securityContact: the SBOM subject has no security-contact reference. Set the reviewed contact as enrichment.subject.securityContact in rio.yaml, or have the SBOM generator emit one. Rio does not look it up.
```

A passing check establishes only that a contact in a supported form is present. It does not
identify who answers it, verify the mailbox or approve the release. The address is synthetic.
