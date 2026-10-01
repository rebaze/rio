# Captured Juice Shop results

These receipts and HTML reports were generated with the installed **Rio 0.7.0**
release on 2026-10-01, using the walkthrough's source-built Juice Shop 20.2.0 SBOMs
and a disposable Dependency-Track 5.1.1 receiver. The receiver has been removed;
its captured loopback URL identifies that run and is not a live service to use.

| Sample | Receipt | Offline HTML | Full inspection output |
|---|---|---|---|
| Backend: 689 entries checked, zero findings, accepted HTTP 200 | [JSON](backend-record.json) | [Report](backend-report.html) | [Text](backend-inspect.txt) |
| Frontend: 672 entries checked, 559 findings, delivery unattempted | [JSON](frontend-record.json) | [Report](frontend-report.html) | [Text](frontend-inspect.txt) |

The supplier `rebaze demo distribution` and the `ci.example.org` build URL are
**synthetic demo assertions**, not upstream claims. The source build, generated
SBOM identities, quality results and backend acknowledgment are actual observations.
The receipt records HTTP acceptance; a separate receiver inventory check observed
654 stored backend components and no frontend project. This count is not the
number of source component entries, and acceptance alone does not prove ingestion.

[source.json](source.json) records the exact source revision, builder image and
architecture, Node/npm/SBOM generator versions, build times, input SBOM hashes and
lockfile hashes. [build-overrides.patch](build-overrides.patch) records the Angular
build-tool adjustment, and [pipeline.json](pipeline.json) binds the build context to
the input bytes. The receipts preserve the dirty workspace assertion and exact
metadata changes. Credentials, internal delivery journals and the large source
checkout are excluded from these public samples.

Inspect either receipt offline with an installed release and no Go toolchain:

```sh
rio record inspect --file tools/demo-juice-shop/example/backend-record.json
rio record inspect --file tools/demo-juice-shop/example/frontend-record.json
rio record report --file tools/demo-juice-shop/example/backend-record.json --output /tmp/juice-shop-backend.html
rio record report --file tools/demo-juice-shop/example/frontend-record.json --output /tmp/juice-shop-frontend.html
```

Choose unused output filenames when rendering. The committed HTML is self-contained;
download it and open it locally, or compare its contents with the corresponding JSON.

To capture fresh results, follow the [walkthrough](../README.md) with the installed
release: build a fresh directory, prepare the receiver, run each artifact separately,
inspect/render both receipts, check receiver inventory, and stop the receiver. Retain
`source.json`, `build-overrides.patch`, `pipeline.json`, both receipts and their
inspection/HTML output. This capture verified input/output byte identities, unchanged
dependency inventories, exact build metadata, credential absence, and inspection and
rendering from receipt-only directories after receiver shutdown. The local Rio binary
also produced the same backend success and frontend gate-failure outcomes.

The source and builder are pinned, but upstream dependency ranges resolve anew;
different input digests and component/finding counts are expected on future builds.
