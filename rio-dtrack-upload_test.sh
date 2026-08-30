#!/usr/bin/env bash
#
# Offline tests for rio-dtrack-upload.sh.
#
# No network: a curl shim on PATH records every invocation and replies from a
# canned script. Run it from the repository root:
#
#   ./rio-dtrack-upload_test.sh
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
  */api/v1/bom)
    printf '{"token":"tok-1"}\n200\n'
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
    DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=SEKRET-KEY \
    DTRACK_POLL_TIMEOUT=6 \
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

printf '\n%d checks, %d failures\n' "$((pass + fail))" "$fail"
[ "$fail" -eq 0 ]
