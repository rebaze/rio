#!/usr/bin/env bash
# Offline contract tests. Only cosign is replaced; JSON and file checks are real.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/rio-attest-sign.sh"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
pass=0 fail=0
check() {
  if "$@" >/dev/null; then pass=$((pass + 1)); else
    fail=$((fail + 1)); printf 'FAIL: %s\n%s\n' "$*" "${out:-}" >&2
  fi
}
workspace() {
  work="$(mktemp -d "$root/case.XXXXXX")"
  mkdir -p "$work/bin" "$work/output with spaces"
  dir="$work/output with spaces"
  printf '%s\n' 'private fixture' > "$work/private key"
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'YWJj' '-----END PUBLIC KEY-----' > "$work/public key"
  : > "$work/calls"
  cat > "$work/bin/cosign" <<'SHIM'
#!/usr/bin/env bash
set -eu
# JSON arrays preserve argument boundaries, including spaces.
jq -cn --args '$ARGS.positional' -- "$@" >> "$WORK/calls"
case "$1" in
  version) printf '{"gitVersion":"%s"}\n' "${VERSION:-v3.0.6}" ;;
  public-key)
    [ "${KEY_FAIL:-0}" = 0 ] || exit 1
    printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'YWJj' '-----END PUBLIC KEY-----'
    ;;
  attest-blob)
    shift
    bundle='' statement=''
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --bundle) bundle="$2"; shift ;;
        --statement) statement="$2"; shift ;;
      esac
      shift
    done
    [ "${SIGN_FAIL:-}" != "$(basename "$statement")" ] || exit 1
    cp "$statement" "$bundle"
    if [ "${INTERRUPT:-0}" = 1 ]; then kill -TERM "$PPID"; fi
    if [ "${CHANGE_INPUT:-0}" = 1 ]; then printf changed > "$WORK/output with spaces/a.cdx.json"; fi
    case "${CREATE_DESTINATION:-0}" in
      file) printf previous > "$WORK/output with spaces/a.sigstore.json" ;;
      directory) mkdir "$WORK/output with spaces/a.sigstore.json" ;;
      symlink) mkdir "$WORK/elsewhere"; ln -s "$WORK/elsewhere" "$WORK/output with spaces/a.sigstore.json" ;;
    esac
    ;;
  verify-blob-attestation)
    case "$*" in *"${VERIFY_FAIL:-NEVER-MATCH}"*) exit 1 ;; esac
    ;;
  *) exit 99 ;;
esac
SHIM
  chmod +x "$work/bin/cosign"
  # SHA-256 of exactly abc, independent of the script's hashing implementation.
  printf abc > "$dir/a.cdx.json"
  jq -n '{schemaVersion:1,tool:{name:"rio",version:"test"},manifest:{path:"rio.yaml",sha256:"manifest"},artifacts:[{id:"a",input:{path:"input.json",sha256:"input"},output:{path:"a.cdx.json",sha256:"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},specVersion:{input:"1.6",output:"1.6"},schemaValidated:true,components:0,transforms:[],gate:"ok",gateFindings:[]}]}' > "$dir/index.json"
  statement a
}
statement() {
  jq --arg id "$1" '{_type:"https://in-toto.io/Statement/v1",subject:[(.artifacts[]|select(.id==$id)|{name:.output.path,digest:{sha256:.output.sha256}})],predicateType:"https://rebaze.com/attestation/sbom-normalization/v1",predicate:{tool:.tool,manifest:.manifest,artifact:(.artifacts[]|select(.id==$id))}}' "$dir/index.json" > "$dir/$1.intoto.json"
}
edit() { jq "$2" "$1" > "$work/edit" && mv "$work/edit" "$1"; }
run() {
  out="$(WORK="$work" PATH="$work/bin:$PATH" COSIGN_PASSWORD=FIXTURE-SECRET \
    INTERRUPT="${INTERRUPT:-0}" CHANGE_INPUT="${CHANGE_INPUT:-0}" CREATE_DESTINATION="${CREATE_DESTINATION:-0}" \
    VERSION="${VERSION:-v3.0.6}" KEY_FAIL="${KEY_FAIL:-0}" SIGN_FAIL="${SIGN_FAIL:-}" VERIFY_FAIL="${VERIFY_FAIL:-}" \
    bash "$script" "$@" 2>&1)"
  code=$?
}
normal() { run --key "$work/private key" --public-key "$work/public key" "$dir"; }
no_sign() { check jq -e -s 'all(.[]; .[0] != "attest-blob")' "$work/calls"; }
refused() { check test "$code" -eq 2; no_sign; }

workspace
run --help
check test "$code" -eq 0
check test ! -s "$work/calls"
for args in '' '--bogus' '--key' '--public-key'; do
  # Each literal is intentionally one argument (or none).
  if [ -n "$args" ]; then run "$args"; else run; fi
  refused
done
run --key "$work/private key" "$dir"
refused
run --public-key "$work/public key" "$dir"
refused
run --key "$work/private key" --public-key "$work/public key" "$dir" extra
refused
saved_dir="$dir"; dir="$work/missing"; normal; refused; dir="$saved_dir"
VERSION=v3.1.3 normal
refused
KEY_FAIL=1 normal
refused
check test "${out#*FIXTURE-SECRET}" = "$out"
rm "$work/private key"
normal
refused

# Each corruption must stop the entire run before any signing occurs.
for defect in bad_json stream wrong_type wrong_predicate no_subject two_subjects bad_digest traversal absolute output_disagrees predicate_disagrees missing_sbom changed_sbom missing_statement extra_statement missing_index empty_index duplicate_id existing_bundle symlink_statement symlink_sbom; do
  workspace
  case "$defect" in
    bad_json) printf broken > "$dir/a.intoto.json" ;;
    stream) printf '{}\n' >> "$dir/a.intoto.json" ;;
    wrong_type) edit "$dir/a.intoto.json" '._type="wrong"' ;;
    wrong_predicate) edit "$dir/a.intoto.json" '.predicateType="wrong"' ;;
    no_subject) edit "$dir/a.intoto.json" '.subject=[]' ;;
    two_subjects) edit "$dir/a.intoto.json" '.subject += .subject' ;;
    bad_digest) edit "$dir/a.intoto.json" '.subject[0].digest.sha256="oops"' ;;
    traversal) edit "$dir/a.intoto.json" '.subject[0].name="../outside"' ;;
    absolute) edit "$dir/a.intoto.json" '.subject[0].name="/etc/passwd"' ;;
    output_disagrees) edit "$dir/a.intoto.json" '.predicate.artifact.output.path="b.cdx.json"' ;;
    predicate_disagrees) edit "$dir/a.intoto.json" '.predicate.tool.version="different"' ;;
    missing_sbom) rm "$dir/a.cdx.json" ;;
    changed_sbom) printf changed > "$dir/a.cdx.json" ;;
    missing_statement) rm "$dir/a.intoto.json" ;;
    extra_statement) cp "$dir/a.intoto.json" "$dir/stale.intoto.json" ;;
    missing_index) rm "$dir/index.json" ;;
    empty_index) edit "$dir/index.json" '.artifacts=[]' ;;
    duplicate_id) edit "$dir/index.json" '.artifacts += .artifacts' ;;
    existing_bundle) printf old > "$dir/a.sigstore.json" ;;
    symlink_statement) mv "$dir/a.intoto.json" "$work/outside"; ln -s "$work/outside" "$dir/a.intoto.json" ;;
    symlink_sbom) mv "$dir/a.cdx.json" "$work/outside"; ln -s "$work/outside" "$dir/a.cdx.json" ;;
  esac
  normal
  printf 'check %s\n' "$defect"
  refused
done

# A second artifact checks all-directory preflight, ordering, and gate-fail records.
workspace
edit "$dir/index.json" '.artifacts += [(.artifacts[0] | .id="b" | .output.path="b.cdx.json" | .gate="fail")]'
statement b
normal
refused
cp "$dir/a.cdx.json" "$dir/b.cdx.json"
normal
check test "$code" -eq 0
check test -s "$dir/a.sigstore.json"
check test -s "$dir/b.sigstore.json"
check cmp "$dir/a.intoto.json" "$dir/a.sigstore.json"
check jq -e -s '[.[]|select(.[0]=="attest-blob" or .[0]=="verify-blob-attestation")|.[0]] == ["attest-blob","verify-blob-attestation","attest-blob","verify-blob-attestation"]' "$work/calls"
check jq -e -s 'all(.[]|select(.[0]=="attest-blob"); index("--tlog-upload=false") != null and index("--use-signing-config=false") != null and index("--key") != null and index("--yes") != null)' "$work/calls"
check jq -e -s 'all(.[]|select(.[0]=="verify-blob-attestation"); index("--insecure-ignore-tlog") != null and index("https://rebaze.com/attestation/sbom-normalization/v1") != null)' "$work/calls"

for failure in sign verify; do
  workspace
  if [ "$failure" = sign ]; then SIGN_FAIL=a.intoto.json normal; else VERIFY_FAIL=a.cdx.json normal; fi
  check test "$code" -eq 1
  check test ! -e "$dir/a.sigstore.json"
  check test "$(find "$dir" -name '.rio-attest-*' | wc -l | tr -d ' ')" = 0
done

# Dependency refusal is tested with a restricted PATH, never the host's cosign.
for missing in cosign jq hash; do
  workspace
  mkdir "$work/restricted"
  for tool in bash jq cosign sha256sum shasum; do
    [ "$tool" != "$missing" ] || continue
    case "$missing:$tool" in hash:sha256sum|hash:shasum) continue ;; esac
    if [ "$tool" = cosign ]; then source_path="$work/bin/cosign"; else source_path=$(command -v "$tool" || true); fi
    [ -z "$source_path" ] || ln -s "$source_path" "$work/restricted/$tool"
  done
  out=$(WORK="$work" PATH="$work/restricted" COSIGN_PASSWORD='' bash "$script" --key "$work/private key" --public-key "$work/public key" "$dir" 2>&1)
  code=$?
  refused
  check test "${out#*required}" != "$out"
done
workspace
printf '%s\n' '-----BEGIN PUBLIC KEY-----' 'ZGVm' '-----END PUBLIC KEY-----' > "$work/public key"
normal
refused
check test "${out#*does not match}" != "$out"
workspace
printf YWJj > "$work/public key"
normal
refused
workspace
rm "$work/public key"
normal
refused
workspace
out=$(unset COSIGN_PASSWORD; WORK="$work" PATH="$work/bin:$PATH" bash "$script" --key "$work/private key" --public-key "$work/public key" "$dir" 2>&1)
code=$?
refused
check test "${out#*COSIGN_PASSWORD}" != "$out"

# Exercise the portable shasum fallback with sha256sum absent from PATH.
workspace
mkdir "$work/fallback"
for tool in bash jq cosign shasum awk cat basename dirname cp mktemp rm tr ln cmp; do
  if [ "$tool" = cosign ]; then source_path="$work/bin/cosign"; else source_path=$(command -v "$tool"); fi
  ln -s "$source_path" "$work/fallback/$tool"
done
out=$(WORK="$work" PATH="$work/fallback" COSIGN_PASSWORD='' bash "$script" --key "$work/private key" --public-key "$work/public key" "$dir" 2>&1)
code=$?
check test "$code" -eq 0
check test -s "$dir/a.sigstore.json"

# Reject control characters in IDs, including regex end-of-line corner cases.
workspace
edit "$dir/index.json" '.artifacts[0].id="a\n" | .artifacts[0].output.path="a\n.cdx.json"'
normal
refused

# Do not publish a verified snapshot if the caller's files changed meanwhile.
workspace
CHANGE_INPUT=1 normal
check test "$code" -eq 1
check test ! -e "$dir/a.sigstore.json"
workspace
CREATE_DESTINATION="file" normal
check test "$code" -eq 1
check test "$(cat "$dir/a.sigstore.json")" = previous
for destination in directory symlink; do
  workspace
  CREATE_DESTINATION="$destination" normal
  check test "$code" -eq 1
  check test ! -e "$dir/a.sigstore.json/a.sigstore.json"
done
workspace
INTERRUPT=1 normal
check test "$code" -eq 143
check test ! -e "$dir/a.sigstore.json"
check test "$(find "$dir" -name '.rio-attest-*' | wc -l | tr -d ' ')" = 0

# A later verification failure preserves earlier evidence but fails the run.
workspace
edit "$dir/index.json" '.artifacts += [(.artifacts[0] | .id="b" | .output.path="b.cdx.json")]'
statement b
cp "$dir/a.cdx.json" "$dir/b.cdx.json"
VERIFY_FAIL=b.cdx.json normal
check test "$code" -eq 1
check test -s "$dir/a.sigstore.json"
check test ! -e "$dir/b.sigstore.json"
check test "${out#*earlier verified bundles}" != "$out"

printf '\n%s checks, %s failures\n'  "$((pass + fail))" "$fail"
[ "$fail" -eq 0 ]
