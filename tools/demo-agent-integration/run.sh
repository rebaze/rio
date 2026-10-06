#!/bin/sh
# Reference onboarding walkthrough; not a live agent evaluation.
# Requires Rio v0.7.0+, POSIX sh, and standard utilities. Python 3.9+; no Go/Maven/jq.
set -eu
if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Install a Rio release v0.7.0+ or set RIO_BIN: %s\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac

# Python 3.9+ reads the structured execution result; paths may contain spaces.
result_dir() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runDirectory"])' "$1"
}
inspect_result() {
  receipt=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipt"]["path"])' "$1")
  "$rio_bin" record inspect --file "$receipt" --json > "$1.inspection.json"
  python3 - "$1" "${2:-success}" <<'PY_CHECK'
import json, sys
result = json.load(open(sys.argv[1]))
record = json.load(open(sys.argv[1] + ".inspection.json"))["record"]
assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
assert record["run"]["id"] == result["runId"]
assert record["run"]["operation"] == "normalize"
assert record["run"]["outcome"] == result["outcome"] == sys.argv[2]
PY_CHECK
}

demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-onboarding.XXXXXXXX")
trap 'printf "\nInputs, logs and outputs retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/projects/." "$run_dir/"
"$rio_bin" version

check_members() {
  sed -n 's/^      "id": "\([^"]*\)",$/\1/p' "$1" > "$run_dir/actual-members"
  printf '%s\n' "$2" > "$run_dir/expected-members"
  if ! cmp -s "$run_dir/expected-members" "$run_dir/actual-members"; then
    printf 'FAIL: unexpected artifact membership in %s\n' "$1" >&2
    cat "$run_dir/actual-members" >&2
    exit 1
  fi
}

printf '\nReference walkthrough: apply the documented configurations to synthetic projects.\n'
for scenario in explicit modules mixed; do
  printf '\n%s project\n' "$scenario"
  project_dir=$run_dir/$scenario
  if [ -f "$project_dir/rio.yaml" ]; then
    cp "$project_dir/rio.yaml" "$project_dir/rio.before.yaml"
  fi
  cp "$demo_dir/examples/$scenario.yaml" "$project_dir/rio.yaml"
  (
    cd "$project_dir"
    sh build.sh
  )
  # Deliberately invoke Rio from outside the project to exercise manifest-relative inputs.
  "$rio_bin" plan --manifest "$project_dir/rio.yaml" --out "$project_dir/normalized" --json > "$project_dir/plan.json"
  "$rio_bin" normalize --manifest "$project_dir/rio.yaml" --out "$project_dir/normalized" --gate fail --json > "$project_dir/result.json"
  output_dir=$(result_dir "$project_dir/result.json")
  inspect_result "$project_dir/result.json"
  case "$scenario" in
    explicit) expected=desktop ;;
    modules) expected='billing-server
orders-server' ;;
    mixed) expected='desktop
legacy-server
billing-server
orders-server' ;;
  esac
  check_members "$output_dir/index.json" "$expected"
  cmp -s "$project_dir/rio.yaml" "$demo_dir/examples/$scenario.yaml"
done

printf '\nIncomplete project: reporting stays selected, so both commands refuse.\n'
cp "$demo_dir/examples/incomplete.yaml" "$run_dir/incomplete/rio.yaml"
(cd "$run_dir/incomplete" && sh build.sh)
for command in plan normalize; do
  status=0
  "$rio_bin" "$command" --manifest "$run_dir/incomplete/rio.yaml" --out "$run_dir/incomplete/refused" --json > "$run_dir/incomplete/$command-result.json" 2> "$run_dir/incomplete/$command.log" || status=$?
  cat "$run_dir/incomplete/$command.log"
  if [ "$status" -ne 2 ]; then
    printf 'FAIL: incomplete project must exit 2 without normalized output.\n' >&2
    exit 1
  fi
  grep -q reporting-server "$run_dir/incomplete/$command.log"
  if [ "$command" = normalize ]; then
    inspect_result "$run_dir/incomplete/$command-result.json" failed
    output_dir=$(result_dir "$run_dir/incomplete/$command-result.json")
    [ ! -e "$output_dir/index.json" ]
    [ -z "$(find "$output_dir" -name '*.cdx.json' -print)" ]
  else
    [ ! -e "$run_dir/incomplete/refused" ]
  fi
done

printf '\nAmbiguous project: no reference manifest is supplied.\n'
(cd "$run_dir/ambiguous" && sh build.sh)
[ ! -e "$run_dir/ambiguous/rio.yaml" ]
printf 'The agent must ask which of api-server and preview-server belongs in the release.\n'
printf 'See EVALUATION.md for a fresh-session agent exercise and scoring procedure.\n'

printf '\nCI example: producer -> plan -> pipeline -> automatic receipt\n'
(cd "$run_dir/modules" && sh "$demo_dir/ci.sh" "$rio_bin" sh build.sh)
printf '\nPASS: reference configurations, missing-output refusal and CI receipt verified.\n'
printf 'This walkthrough does not evaluate a live agent or validate any real project build.\n'
