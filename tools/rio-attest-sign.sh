#!/usr/bin/env bash
# Sign rio's existing statements with a local key, then verify each bundle.
# Requires Bash 3.2+, jq, cosign v3.0.6 and sha256sum or shasum.
# COSIGN_PASSWORD supplies the private-key password (may be explicitly empty).
# No keyless fallback, signing service configuration, or transparency-log upload.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: rio-attest-sign.sh --key FILE --public-key FILE OUTPUT-DIRECTORY

Sign every statement from a rio normalize --attest run, then verify each
<artifact-id>.sigstore.json bundle. Requires index.json and the matching SBOMs.
Both keys must be local files. Set COSIGN_PASSWORD (empty is allowed) so the
script can unlock the private key without prompting, in CI or on a workstation.
Requires cosign v3.0.6, jq, and sha256sum or shasum.

Public transparency-log upload is disabled. No keyless signing is attempted.
Existing bundles are refused; use a fresh normalize output directory to rerun.
Exit 2: usage/preflight error; exit 1: signing/verification failure; exit 0:
every bundle verified. Earlier verified bundles remain if a later artifact fails.
HELP
}
refuse() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
failed() { printf 'ERROR: %s (earlier verified bundles, if any, remain)\n' "$*" >&2; exit 1; }
key='' public_key='' directory=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --key|--public-key)
      option="$1"
      [ "$#" -ge 2 ] && [ -n "$2" ] || refuse "$option requires a file"
      case "$2" in --*) refuse "$option requires a file" ;; esac
      if [ "$option" = --key ]; then
        [ -z "$key" ] || refuse 'duplicate --key'
        key="$2"
      else
        [ -z "$public_key" ] || refuse 'duplicate --public-key'
        public_key="$2"
      fi
      shift 2 ;;
    --) shift; [ "$#" -eq 1 ] && [ -z "$directory" ] || refuse 'expected one output directory'; directory="$1"; shift ;;
    -*) refuse "unknown option: $1" ;;
    *) [ -z "$directory" ] || refuse 'expected one output directory'; directory="$1"; shift ;;
  esac
done
[ -n "$key" ] && [ -n "$public_key" ] || refuse 'supply --key and --public-key; no keyless fallback'
[ -n "$directory" ] && [ -d "$directory" ] || refuse 'supply an existing output directory'
for dependency in jq cosign; do
  command -v "$dependency" >/dev/null 2>&1 || refuse "$dependency is required"
done
if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash=(shasum -a 256)
else
  refuse 'sha256sum or shasum is required'
fi
version=$(cosign version --json) || refuse 'cannot read cosign version'
[ "$(printf '%s' "$version" | jq -r '.gitVersion')" = v3.0.6 ] || refuse 'cosign v3.0.6 is required (same pin as release.yaml)'
for file in "$key" "$public_key"; do
  [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] || refuse "key must be a readable, nonempty local file: $file"
done
# Absolute paths prevent a local filename from being interpreted as a KMS/URL.
key="$(cd -- "$(dirname "$key")" && pwd -P)/$(basename "$key")"
public_key="$(cd -- "$(dirname "$public_key")" && pwd -P)/$(basename "$public_key")"
directory="$(cd -- "$directory" && pwd -P)"
[ "${COSIGN_PASSWORD+x}" = x ] || refuse 'set COSIGN_PASSWORD to unlock the private key without prompting (empty is allowed)'
# Compare the public-key DER encoded inside PEM; wrapping and CRLF do not matter.
pem_body() {
  awk '
    { sub(/\r$/, "") }
    /^[[:space:]]*$/ { next }
    $0 == "-----BEGIN PUBLIC KEY-----" { if (state != 0) exit 1; state=1; next }
    $0 == "-----END PUBLIC KEY-----" { if (state != 1) exit 1; state=2; next }
    { if (state != 1 || $0 !~ /^[A-Za-z0-9+\/=]+$/) exit 1; printf "%s", $0; lines++ }
    END { if (state != 2 || lines == 0) exit 1 }
  '
}
derived=$(cosign public-key --key "$key" </dev/null) || refuse 'cannot unlock signing key; check --key and COSIGN_PASSWORD'
derived=$(printf '%s' "$derived" | pem_body) || refuse 'cosign returned an invalid public key'
expected=$(pem_body < "$public_key") || refuse '--public-key must contain one PEM PUBLIC KEY'
[ -n "$derived" ] && [ "$derived" = "$expected" ] || refuse '--public-key does not match the signing key'

regular() { [ -f "$1" ] && [ -r "$1" ] && [ ! -L "$1" ]; }
regular "$directory/index.json" || refuse 'index.json must be a readable regular file, not a symlink'
# All signing inputs are copied to a private staging directory before validation.
# Cosign signs exactly the statement we checked, even if the source is replaced.
umask 077
stage=$(mktemp -d "$directory/.rio-attest-XXXXXX") || refuse 'cannot create staging directory in output directory'
trap 'rm -rf "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$directory/index.json" "$stage/index.json"
jq -e -s '
  length == 1 and (.[0] |
    .schemaVersion == 1 and .tool.name == "rio" and
    (.artifacts | type == "array" and length > 0) and
    all(.artifacts[];
      (.id | type == "string" and test("^[a-z0-9][a-z0-9._-]*$")) and
      .output.path == (.id + ".cdx.json") and
      (.output.sha256 | type == "string" and test("^[a-f0-9]{64}$"))) and
    ([.artifacts[].id] | length == (unique | length)))
' "$stage/index.json" >/dev/null || refuse 'invalid index.json: expected unique artifacts with rio output paths and SHA-256 digests'
ids=$(jq -r '.artifacts[].id' "$stage/index.json")
shopt -s nullglob dotglob
statements=("$directory/"*.intoto.json)
count=$(jq '.artifacts | length' "$stage/index.json")
[ "${#statements[@]}" -eq "$count" ] || refuse 'statement set does not match index.json; missing or stale statements'
predicate_type=https://rebaze.com/attestation/sbom-normalization/v1
while IFS= read -r id; do
  statement="$directory/$id.intoto.json"
  blob="$directory/$id.cdx.json"
  bundle="$directory/$id.sigstore.json"
  regular "$statement" || refuse "$id: missing statement or symlink"
  regular "$blob" || refuse "$id: missing SBOM or symlink"
  [ ! -e "$bundle" ] && [ ! -L "$bundle" ] || refuse "$id: bundle already exists; use a fresh output directory"
  cp "$statement" "$stage/$id.intoto.json"
  cp "$blob" "$stage/$id.cdx.json"
  jq -e -s --arg id "$id" --arg predicate "$predicate_type" --slurpfile index "$stage/index.json" '
    length == 1 and (.[0] |
      ._type == "https://in-toto.io/Statement/v1" and .predicateType == $predicate and
      .subject == [{name:($id + ".cdx.json"),digest:{sha256:($index[0].artifacts[]|select(.id==$id)|.output.sha256)}}] and
      .predicate == {tool:$index[0].tool,manifest:$index[0].manifest,artifact:($index[0].artifacts[]|select(.id==$id))})
  ' "$stage/$id.intoto.json" >/dev/null || refuse "$id: statement does not match the normalization contract and index.json"
  digest=$("${hash[@]}" < "$stage/$id.cdx.json")
  digest=${digest%% *}
  expected=$(jq -r '.subject[0].digest.sha256' "$stage/$id.intoto.json")
  [ "$digest" = "$expected" ] || refuse "$id: SBOM SHA-256 does not match the statement"
done <<< "$ids"

printf 'Signing with a local key; transparency-log upload disabled.\n' >&2
while IFS= read -r id; do
  bundle="$stage/$id.sigstore.json"
  # v3.0.6 defaults to a TUF signing config. Disable that as well as log upload.
  cosign attest-blob --key "$key" --statement "$stage/$id.intoto.json" \
    --bundle "$bundle" --yes --tlog-upload=false --use-signing-config=false \
    "$stage/$id.cdx.json" </dev/null >/dev/null || failed "$id: signing failed"
  [ -s "$bundle" ] || failed "$id: cosign produced no bundle"
  cosign verify-blob-attestation --key "$public_key" --bundle "$bundle" \
    --type "$predicate_type" --insecure-ignore-tlog \
    "$stage/$id.cdx.json" </dev/null >/dev/null || failed "$id: verification failed"
  if ! cmp -s "$stage/index.json" "$directory/index.json" ||
    ! cmp -s "$stage/$id.intoto.json" "$directory/$id.intoto.json" ||
    ! cmp -s "$stage/$id.cdx.json" "$directory/$id.cdx.json"; then
    failed "$id: inputs changed during signing"
  fi
  # Same-filesystem hard link publishes atomically and never replaces old evidence.
  # Pass the parent directory: a raced destination directory must not receive
  # a nested bundle (ln treats a full destination path differently).
  ln "$bundle" "$directory/" || failed "$id: cannot publish verified bundle"
  printf 'Verified %s.sigstore.json\n' "$id"
done <<< "$ids"
