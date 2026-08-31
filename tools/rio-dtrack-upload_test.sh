#!/usr/bin/env bash
#
# Offline tests for tools/rio-dtrack-upload.sh.
#
# No network: a curl shim on PATH records every invocation and replies from a
# canned script. Run it from the repository root:
#
#   ./tools/rio-dtrack-upload_test.sh
#
# The four cases that matter most are regressions this suite exists to pin:
# curl -F reading an SBOM-supplied value as a local file, the poll endpoint
# fallback latching across artifacts, a malformed index exiting 0 having
# uploaded nothing, and an empty field shifting the gate value into the path.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/rio-dtrack-upload.sh"

pass=0
fail=0

ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
no() {
  fail=$((fail + 1))
  printf 'FAIL %s\n' "$1"
  [ $# -gt 1 ] && printf '     %s\n' "$2"
  return 0
}

check() { # description, haystack, needle
  case "$2" in
    *"$3"*) ok "$1" ;;
    *) no "$1" "expected to find: $3" ;;
  esac
}

check_not() { # description, haystack, needle
  case "$2" in
    *"$3"*) no "$1" "did not expect to find: $3" ;;
    *) ok "$1" ;;
  esac
}

check_eq() { # description, got, want
  if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "got [$2] want [$3]"; fi
}

# workspace builds a sandbox holding a curl shim, an index and its SBOMs.
# $POLL_SCRIPT is a newline-separated list of HTTP codes the shim returns for
# successive token polls; the default answers every poll with a finished 200.
workspace() {
  work="$(mktemp -d)"
  mkdir -p "$work/bin" "$work/out"
  : > "$work/curl.log"

  cat > "$work/bin/curl" <<'SHIM'
#!/usr/bin/env bash
# Records argv, then answers from POLL_SCRIPT. Never touches the network.
printf '%s\n' "$*" >> "$WORK/curl.log"
url=""
for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
case "$url" in
  */api/v1/project/lookup*)
    # -o /dev/null -w '%{http_code}' means the script reads only the code.
    printf '%s\n' "${LOOKUP_CODE:-404}"
    ;;
  */api/v1/bom)
    code="${UPLOAD_CODE:-200}"
    if [ "$code" = "200" ]; then
      printf '{"token":"tok-1"}\n200\n'
    else
      printf 'The parent component could not be found.\n%s\n' "$code"
    fi
    ;;
  */token/*)
    n=$(( $(cat "$WORK/poll.n" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "$n" > "$WORK/poll.n"
    code=$(sed -n "${n}p" "$WORK/poll.codes" 2>/dev/null)
    [ -n "$code" ] || code=200
    if [ "$code" = "200" ]; then
      printf '{"processing":false}\n200\n'
    else
      printf '\n%s\n' "$code"
    fi
    ;;
  *) printf '\n404\n' ;;
esac
SHIM
  chmod +x "$work/bin/curl"
  printf '%s\n' "${POLL_SCRIPT:-200}" > "$work/poll.codes"
}

sbom() { # path, version
  cat > "$1" <<JSON
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"x","version":$2}}}
JSON
}

run() { # runs the script in the sandbox, capturing output and exit code
  out="$(WORK="$work" PATH="$work/bin:$PATH" \
    LOOKUP_CODE="${LOOKUP_CODE:-404}" UPLOAD_CODE="${UPLOAD_CODE:-200}" \
    DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=SEKRET-KEY \
    DTRACK_POLL_TIMEOUT=6 \
    DTRACK_PARENT_UUID="${PARENT_UUID:-}" \
    DTRACK_PARENT_NAME="${PARENT_NAME:-}" \
    DTRACK_PARENT_VERSION="${PARENT_VERSION:-}" \
    bash "$script" "$work/out/index.json" 2>&1)"
  code=$?
}

index() { cat > "$work/out/index.json"; }

# --- a crafted metadata.component.version must never become a file upload ----
workspace
printf 'SECRET-CONTENTS\n' > "$work/secret.txt"
sbom "$work/out/a.cdx.json" "\"@$work/secret.txt\""
index <<JSON
{"schemaVersion":1,"artifacts":[{"id":"a","output":{"path":"a.cdx.json"},"gate":"ok"}]}
JSON
run
log="$(cat "$work/curl.log")"
check "an SBOM-supplied version is sent with --form-string" "$log" \
  "--form-string projectVersion=@$work/secret.txt"
check_not "the version is never passed to -F, which would read it as a file" "$log" \
  "-F projectVersion="
check_not "the local file's contents never reach the request" "$log" "SECRET-CONTENTS"
check_eq "the upload still succeeds" "$code" "0"
rm -rf "$work"

# --- a 404 on one artifact's token must not disable polling for the next -----
# First artifact: both endpoints 404 (an unknown token on a 4.x server).
# Second artifact: the 4.x endpoint answers. It must be tried again.
POLL_SCRIPT="404
404
200"
workspace
unset POLL_SCRIPT
sbom "$work/out/a.cdx.json" '"1.0.0"'
sbom "$work/out/b.cdx.json" '"2.0.0"'
index <<JSON
{"schemaVersion":1,"artifacts":[
 {"id":"a","output":{"path":"a.cdx.json"},"gate":"ok"},
 {"id":"b","output":{"path":"b.cdx.json"},"gate":"ok"}]}
JSON
run
polls="$(grep -c 'token/' "$work/curl.log")"
third="$(grep 'token/' "$work/curl.log" | sed -n 3p)"
check_eq "three token polls were made" "$polls" "3"
check "the second artifact starts again on the 4.x endpoint" "$third" "/api/v1/bom/token/"
check "the first artifact warns that status was unreadable" "$out" "WARN  a"
check "the second artifact is reported processed" "$out" "b processed"
check_eq "the run still succeeds" "$code" "0"
rm -rf "$work"

# --- a malformed or empty index must never exit 0 having uploaded nothing ----
for bad in 'not json at all' '{"schemaVersion":1}' '{"artifacts":[]}'; do
  workspace
  printf '%s\n' "$bad" > "$work/out/index.json"
  run
  if [ "$code" = "0" ]; then
    no "a broken index ($bad) fails the run" "exited 0 having uploaded nothing"
  else
    ok "a broken index ($bad) fails the run"
  fi
  check_not "nothing was uploaded" "$(cat "$work/curl.log")" "/api/v1/bom"
  rm -rf "$work"
done

# --- an empty output.path must be named, not silently shifted ---------------
workspace
sbom "$work/out/a.cdx.json" '"1.0.0"'
index <<JSON
{"schemaVersion":1,"artifacts":[{"id":"a","output":{},"gate":"ok"}]}
JSON
run
check "an entry with no output.path says so" "$out" "index entry has no output.path"
check_not "the gate value is not reported as a filename" "$out" "missing $work/out/ok"
check_eq "the run fails" "$code" "1"
rm -rf "$work"

# --- the ordinary path, and the gate blocking an upload ---------------------
workspace
sbom "$work/out/a.cdx.json" '"1.0.0"'
sbom "$work/out/b.cdx.json" '"2.0.0"'
index <<JSON
{"schemaVersion":1,"artifacts":[
 {"id":"a","output":{"path":"a.cdx.json"},"gate":"ok"},
 {"id":"b","output":{"path":"b.cdx.json"},"gate":"fail"}]}
JSON
run
check "the passing artifact uploads" "$out" "OK    a -> a 1.0.0"
check "a failed rio gate blocks the upload" "$out" "SKIP  b: rio gate failed"
check_not "the blocked artifact is never posted" "$(cat "$work/curl.log")" "b.cdx.json"
check_eq "a blocked upload fails the run" "$code" "1"
check_not "the API key never reaches the output" "$out" "SEKRET-KEY"
rm -rf "$work"

# --- a missing SBOM, and a missing subject version --------------------------
workspace
sbom "$work/out/a.cdx.json" 'null'
index <<JSON
{"schemaVersion":1,"artifacts":[
 {"id":"a","output":{"path":"a.cdx.json"},"gate":"ok"},
 {"id":"gone","output":{"path":"gone.cdx.json"},"gate":"ok"}]}
JSON
run
check "an SBOM with no metadata.component.version is skipped" "$out" \
  "SKIP  a: no metadata.component.version"
check "a missing output file is reported" "$out" "FAIL  gone: missing"
check_eq "both failures fail the run" "$code" "1"
rm -rf "$work"

# --- the parent project ------------------------------------------------------

one_artifact() {
  workspace
  sbom "$work/out/a.cdx.json" '"1.0.0"'
  index <<'JSON'
{"schemaVersion":1,"artifacts":[{"id":"a","output":{"path":"a.cdx.json"},"gate":"ok"}]}
JSON
}

# A uuid is sent as parentUUID, and as --form-string like every other data field.
one_artifact
PARENT_UUID=8b1f9e10-0f6a-4a7e-9c2f-3d4e5a6b7c8d run
log="$(cat "$work/curl.log")"
check "a parent uuid is sent as parentUUID" "$log"   "--form-string parentUUID=8b1f9e10-0f6a-4a7e-9c2f-3d4e5a6b7c8d"
check_not "and never as -F, which would read a leading @ as a file" "$log" "-F parentUUID="
check_eq "the upload still succeeds" "$code" "0"
unset PARENT_UUID; rm -rf "$work"

# A name, with and without a version.
one_artifact
PARENT_NAME="RCP Product" run
log="$(cat "$work/curl.log")"
check "a parent name is sent as parentName" "$log" "--form-string parentName=RCP Product"
check_not "no parentVersion when none was given" "$log" "parentVersion="
unset PARENT_NAME; rm -rf "$work"

one_artifact
PARENT_NAME="RCP Product" PARENT_VERSION="2026.1" run
log="$(cat "$work/curl.log")"
check "parentName and parentVersion travel together" "$log"   "--form-string parentName=RCP Product --form-string parentVersion=2026.1"
unset PARENT_NAME PARENT_VERSION; rm -rf "$work"

# No parent configured means no parent fields and no lookup request at all.
one_artifact
run
log="$(cat "$work/curl.log")"
check_not "no parentUUID when no parent is configured" "$log" "parentUUID"
check_not "no parentName when no parent is configured" "$log" "parentName"
check_not "no lookup request when no parent is configured" "$log" "project/lookup"
check_eq "the plain upload is unaffected" "$code" "0"
rm -rf "$work"

# Settings that DependencyTrack would silently ignore are refused up front.
one_artifact
PARENT_UUID=abc PARENT_NAME=def run
check "a uuid and a name together is refused" "$out" "not both"
check_eq "and the run fails before uploading" "$code" "2"
check_not "nothing was uploaded" "$(cat "$work/curl.log")" "/api/v1/bom"
unset PARENT_UUID PARENT_NAME; rm -rf "$work"

one_artifact
PARENT_VERSION=2026.1 run
check "a parent version without a name is refused" "$out" "needs DTRACK_PARENT_NAME"
check_eq "and the run fails before uploading" "$code" "2"
unset PARENT_VERSION; rm -rf "$work"

# DependencyTrack applies a parent only when it creates the project, so an
# existing project must not look like it was re-parented.
one_artifact
LOOKUP_CODE=200 PARENT_NAME="RCP Product" run
check "an existing project warns that the parent is not applied" "$out"   "already exists, so the parent is not applied"
check "and says what to do instead" "$out" "Re-parent it"
check_eq "the upload still happens" "$code" "0"
unset PARENT_NAME; rm -rf "$work"

one_artifact
LOOKUP_CODE=404 PARENT_NAME="RCP Product" run
check_not "a new project does not warn" "$out" "already exists"
unset PARENT_NAME; rm -rf "$work"

# A lookup that cannot answer must not fail an upload that would have worked.
one_artifact
LOOKUP_CODE=500 PARENT_NAME="RCP Product" run
check_not "an unreadable lookup does not warn" "$out" "already exists"
check_eq "and does not fail the run" "$code" "0"
unset PARENT_NAME; rm -rf "$work"

# A missing parent is a 404 on the upload; say what it means.
one_artifact
UPLOAD_CODE=404 PARENT_NAME="RCP Product" PARENT_VERSION="2026.1" run
check "a 404 explains that the parent must already exist" "$out" "must exist before an artifact"
check "and names the parent it looked for" "$out" "RCP Product 2026.1"
check_eq "the artifact fails" "$code" "1"
unset PARENT_NAME PARENT_VERSION; rm -rf "$work"

# The same 404 without a parent configured stays plain.
one_artifact
UPLOAD_CODE=404 run
check_not "no parent hint when no parent was configured" "$out" "must exist before an artifact"
rm -rf "$work"

printf '\n%d checks, %d failures\n' "$((pass + fail))" "$fail"
[ "$fail" -eq 0 ]
