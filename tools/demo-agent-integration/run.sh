#!/bin/sh
# Reference onboarding walkthrough; not a live agent evaluation.
# Requires Rio containing #71, POSIX sh, and standard utilities. No Go/Python/Maven/jq.
set -eu
if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Install a Rio release containing #71 or set RIO_BIN: %s\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac
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
  "$rio_bin" normalize --manifest "$project_dir/rio.yaml" --out "$project_dir/normalized" --gate fail
  case "$scenario" in
    explicit) expected=desktop ;;
    modules) expected='billing-server
orders-server' ;;
    mixed) expected='desktop
legacy-server
billing-server
orders-server' ;;
  esac
  check_members "$project_dir/normalized/index.json" "$expected"
  cmp -s "$project_dir/rio.yaml" "$demo_dir/examples/$scenario.yaml"
done

printf '\nIncomplete project: reporting stays selected, so both commands refuse.\n'
cp "$demo_dir/examples/incomplete.yaml" "$run_dir/incomplete/rio.yaml"
(cd "$run_dir/incomplete" && sh build.sh)
for command in plan normalize; do
  status=0
  "$rio_bin" "$command" --manifest "$run_dir/incomplete/rio.yaml" --out "$run_dir/incomplete/refused" > "$run_dir/incomplete/$command.log" 2>&1 || status=$?
  cat "$run_dir/incomplete/$command.log"
  if [ "$status" -ne 2 ] || [ -e "$run_dir/incomplete/refused" ]; then
    printf 'FAIL: incomplete project must exit 2 without normalized output.\n' >&2
    exit 1
  fi
  grep -q reporting-server "$run_dir/incomplete/$command.log"
done

printf '\nAmbiguous project: no reference manifest is supplied.\n'
(cd "$run_dir/ambiguous" && sh build.sh)
[ ! -e "$run_dir/ambiguous/rio.yaml" ]
printf 'The agent must ask which of api-server and preview-server belongs in the release.\n'
printf 'See EVALUATION.md for a fresh-session agent exercise and scoring procedure.\n'

printf '\nCI example: producer -> plan -> normalize -> fresh bundle\n'
(cd "$run_dir/modules" && sh "$demo_dir/ci.sh" "$rio_bin" sh build.sh)
printf '\nPASS: reference configurations, missing-output refusal and CI collection verified.\n'
printf 'This walkthrough does not evaluate a live agent or validate any real project build.\n'
