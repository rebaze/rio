#!/usr/bin/env bash
# Verify only the v0.3 DSSE bundle format emitted by rio-attest-sign.sh.
# A legacy cosign bundle can override --key with its embedded key in v3.0.6.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: rio-attest-verify.sh --public-key FILE --bundle FILE SBOM-FILE

Verify a normalization statement with an independently trusted local public key.
Requires Bash 3.2+, jq and cosign v3.0.6. Only v0.3 Sigstore DSSE bundles are
accepted; legacy bundles and their embedded-key fallback are refused.
Public transparency-log verification is disabled for this private signing mode.
Exit 2: usage/input refusal; exit 1: verification failure; exit 0: verified.
HELP
}
refuse() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
public_key='' bundle='' blob=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --public-key|--bundle)
      option="$1"
      [ "$#" -ge 2 ] && [ -n "$2" ] || refuse "$option requires a file"
      case "$2" in --*) refuse "$option requires a file" ;; esac
      if [ "$option" = --public-key ]; then
        [ -z "$public_key" ] || refuse 'duplicate --public-key'
        public_key="$2"
      else
        [ -z "$bundle" ] || refuse 'duplicate --bundle'
        bundle="$2"
      fi
      shift 2 ;;
    --) shift; [ "$#" -eq 1 ] && [ -z "$blob" ] || refuse 'expected one SBOM file'; blob="$1"; shift ;;
    -*) refuse "unknown option: $1" ;;
    *) [ -z "$blob" ] || refuse 'expected one SBOM file'; blob="$1"; shift ;;
  esac
done
for dependency in jq cosign; do
  command -v "$dependency" >/dev/null 2>&1 || refuse "$dependency is required"
done
for file in "$public_key" "$bundle" "$blob"; do
  [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] && [ ! -L "$file" ] || refuse 'supply readable, nonempty regular public-key, bundle and SBOM files'
done
version=$(cosign version --json) || refuse 'cannot read cosign version'
[ "$(printf '%s' "$version" | jq -r '.gitVersion')" = v3.0.6 ] || refuse 'cosign v3.0.6 is required'
umask 077
stage=$(mktemp -d "${TMPDIR:-/tmp}/rio-attest-verify.XXXXXX") || refuse 'cannot create verification snapshot'
trap 'rm -rf "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$public_key" "$stage/signer.pub"
cp "$bundle" "$stage/bundle.json"
cp "$blob" "$stage/sbom.json"
# Strict top-level keys also reject case variants recognized by Go's legacy
# decoder. Validate the same private snapshot subsequently passed to cosign.
jq -e -s '
  length == 1 and (.[0] |
    keys == ["dsseEnvelope", "mediaType", "verificationMaterial"] and
    .mediaType == "application/vnd.dev.sigstore.bundle.v0.3+json" and
    (.verificationMaterial | type == "object") and
    (.dsseEnvelope | type == "object") and
    .dsseEnvelope.payloadType == "application/vnd.in-toto+json")
' "$stage/bundle.json" >/dev/null || refuse 'expected a v0.3 Sigstore DSSE bundle; legacy or mixed bundle formats are refused'
cosign verify-blob-attestation --key "$stage/signer.pub" --bundle "$stage/bundle.json" \
  --type https://rebaze.com/attestation/sbom-normalization/v1 --insecure-ignore-tlog \
  "$stage/sbom.json" </dev/null || exit 1
