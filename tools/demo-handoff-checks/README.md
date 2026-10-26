# Handoff checks: security contact, digest and BSI TR-03183-2 profile

Run with Rio 0.9.0+ and Python 3.9+; no Go toolchain or external receiver is needed:

```sh
python3 tools/demo-handoff-checks/run.py /absolute/path/to/rio
```

One synthetic Cart API SBOM without a product security contact or a distribution digest goes
through six root invocations, then a second one (labelled synthetic too) through two more,, each delivering to a loopback receiver:

| Scenario | `rio.yaml` | Result |
|---|---|---|
| `not-required` | no `gate.subject.require` | passes and is delivered; no contact is checked |
| `required-missing` | `gate.subject.require: [securityContact]` | exit 1, nothing delivered, the next step printed |
| `required-supplied` | plus `enrichment.subject.securityContact: mailto:security@example.com` | passes and is delivered with the reviewed contact |
| `required-unsupported` | the SBOM already holds `security@example.com`, not a URL | exit 1, nothing delivered, the value named |
| `digest-missing` | `gate.subject.require: [digest]` | exit 1, nothing delivered, the next step printed |
| `digest-supplied` | plus a `build-context.json` entry declaring two shipped files under `distributions` | passes and is delivered; the SBOM subject and the receipt list both files |
| `bsi-profile-missing` | `gate.profile: bsi-tr-03183-2@2.1.0`, no context; the SBOM carries what only a generator can (timestamp, licences, dependencies, component fields) | exit 1, nothing delivered; `sbom.creator`, `subject.creator`, `subject.filename`, `subject.deployableHash` and more are listed |
| `bsi-profile-repaired` | plus `enrichment.producer`, `enrichment.subject.manufacturer` and a `build-context.json` entry with `level: logical` and two shipped files with `sha256`, `sha512` and the three file booleans | passes and is delivered; the receipt names the profile and counts the components at each level |

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

The last two scenarios use `fixtures/cart-api-tr.cdx.json`, whose components are marked `assembled`.
The profile reads [Requirement profiles](../../docs/manifest.md#requirement-profiles); the shipped
files are described in [TR file components](../../docs/context.md#tr-file-components). The SBOM has
no creator and does not say what the subject is, so the first run fails. The repair supplies the
creators in `rio.yaml`, declares the subject `logical` and its two files in the build context file.
Output of a real run (the demo prints `sec.` for the section sign to stay ASCII):

```text
== bsi-profile-missing -> exit 1 - not delivered
   checks.gate: fail
   checks.failed: ['sbom.creator', 'subject.creator', 'subject.filename', 'subject.deployableHash', 'subject.executable', 'subject.archive', 'subject.structured']
   checks.profile: {"guideline": "BSI TR-03183-2", "guidelineVersion": "2.1.0", "name": "bsi-tr-03183-2@2.1.0"}
   checks.profileLevels: {"assembled": 2, "full": 1, "identified": 0, "logical": 0, "referenced": 0}
   rio: artifact "cart-api" failed the gate; gate mode fail, so nothing was delivered.
     sbom.creator (BSI TR-03183-2 2.1.0 sec.5.2.1): the SBOM has no creator (metadata.manufacturer with a contact email or URL). Set enrichment.producer in rio.yaml, or have the SBOM generator emit one.
     subject.creator (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no creator (manufacturer). Set enrichment.subject.manufacturer in rio.yaml, or have the SBOM generator emit one.
     subject.filename (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no filename (bsi:component:filename). Have the SBOM generator emit it, or, if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator.
     subject.deployableHash (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no SHA-512 hash on a distribution reference. Have the SBOM generator emit it, or, if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator; list the shipped files with sha512 under distributions in the build context file. Rio does not hash files.
     subject.executable (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no bsi:component:executable property (executable or non-executable). Have the SBOM generator emit it, or, if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator.
     subject.archive (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no bsi:component:archive property (archive or no archive). Have the SBOM generator emit it, or, if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator.
     subject.structured (BSI TR-03183-2 2.1.0 sec.5.2.2): the SBOM subject has no bsi:component:structured property (structured or unstructured). Have the SBOM generator emit it, or, if the subject is a product rather than one shipped file, declare it logical with level in the build context file or rio:tr-03183-2:level from the generator.
== bsi-profile-repaired -> exit 0 - delivered
   checks.gate: pass
   checks.profile: {"guideline": "BSI TR-03183-2", "guidelineVersion": "2.1.0", "name": "bsi-tr-03183-2@2.1.0"}
   checks.profileLevels: {"assembled": 2, "full": 2, "identified": 0, "logical": 1, "referenced": 0}
```

A passing contact check establishes only that a contact in a supported form is present. It does
not identify who answers it, verify the mailbox or approve the release. A passing digest check
establishes only that the subject carries a SHA-256 distribution digest. Rio does not hash the
shipped files, and nothing proves they were built from the components the SBOM lists. The
address, file names and digests are synthetic. A passing profile run shows that the TR's fields are
present and well formed, not that the SBOM is correct or the product certified; the digests of the
synthetic shipped files are declared, and the files do not exist.
