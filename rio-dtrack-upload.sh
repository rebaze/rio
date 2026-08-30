#!/usr/bin/env bash
#
# Uploads the SBOMs listed in a rio normalize index.json to DependencyTrack.
#
# Usage:
#   DTRACK_URL=https://dtrack.example.com \
#   DTRACK_API_KEY=... \
#   ./rio-dtrack-upload.sh [path/to/index.json]
#
# Optional:
#   DTRACK_PROJECT_PREFIX   prepended to the artifact id, e.g. "tkse/"
#   DTRACK_POLL             1 to wait for processing to finish (default 1)
#   DTRACK_POLL_TIMEOUT     seconds to wait per upload (default 120)
#   DTRACK_UPLOAD_FAILED    1 to upload artifacts that failed the rio gate
#
# API key needs: BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO.

set -euo pipefail

: "${DTRACK_URL:?set DTRACK_URL}"
: "${DTRACK_API_KEY:?set DTRACK_API_KEY}"

INDEX="${1:-target/rio/index.json}"
PREFIX="${DTRACK_PROJECT_PREFIX:-}"
POLL="${DTRACK_POLL:-1}"
POLL_TIMEOUT="${DTRACK_POLL_TIMEOUT:-120}"
UPLOAD_FAILED="${DTRACK_UPLOAD_FAILED:-0}"

DTRACK_URL="${DTRACK_URL%/}"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }
[ -f "$INDEX" ] || { echo "no index at $INDEX" >&2; exit 2; }

base_dir="$(cd "$(dirname "$INDEX")" && pwd)"
rc=0

# 4.x serves the upload token status at /api/v1/bom/token/{token}; newer builds
# also expose /api/v1/event/token/{token}. Start on the 4.x path and switch on
# the first 404, so one run adapts to whichever instance it is pointed at.
poll_path="/api/v1/bom/token"

upload() {
  local id="$1" sbom="$2" gate="$3"
  local name version token http body

  name="${PREFIX}${id}"

  # The project version is the release the SBOM describes, never the CI build
  # number: DependencyTrack holds releases, the records hold builds.
  version="$(jq -r '.metadata.component.version // empty' "$sbom")"
  if [ -z "$version" ]; then
    echo "SKIP  $id: no metadata.component.version in $sbom" >&2
    return 1
  fi

  # Multipart POST rather than the base64 PUT: no whole-file encoding in shell.
  # A transport failure is reported per artifact instead of aborting the run
  # under set -e, so one unreachable moment does not strand the rest.
  body="$(curl -sS -X POST "${DTRACK_URL}/api/v1/bom" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    -H "Accept: application/json" \
    -F "projectName=${name}" \
    -F "projectVersion=${version}" \
    -F "autoCreate=true" \
    -F "bom=@${sbom}" \
    -w '\n%{http_code}')" || {
    echo "FAIL  $id: upload request to ${DTRACK_URL} failed" >&2
    return 1
  }

  http="$(printf '%s' "$body" | tail -n1)"
  body="$(printf '%s' "$body" | sed '$d')"

  # DependencyTrack answers 200, but a proxy in front of it may rewrite the
  # accepted upload to 201, so treat both as success.
  case "$http" in
    200 | 201) ;;
    *)
      echo "FAIL  $id: HTTP $http ${body}" >&2
      return 1
      ;;
  esac

  token="$(printf '%s' "$body" | jq -r '.token // empty')"
  echo "OK    $id -> ${name} ${version} (gate=${gate}, token=${token:-none})"

  if [ "$POLL" != "1" ] || [ -z "$token" ]; then
    return 0
  fi

  local waited=0 resp code
  while [ "$waited" -lt "$POLL_TIMEOUT" ]; do
    resp="$(curl -sS "${DTRACK_URL}${poll_path}/${token}" \
      -H "X-Api-Key: ${DTRACK_API_KEY}" \
      -H "Accept: application/json" \
      -w '\n%{http_code}')" || resp=""
    code="$(printf '%s' "$resp" | tail -n1)"
    resp="$(printf '%s' "$resp" | sed '$d')"

    # Old path gone: this is a newer build, retry once on the event endpoint
    # and keep every later poll of this run there.
    if [ "$code" = "404" ] && [ "$poll_path" = "/api/v1/bom/token" ]; then
      poll_path="/api/v1/event/token"
      continue
    fi

    case "$code" in
      200 | 201) ;;
      *)
        # The upload itself was accepted; only the status query is unavailable.
        echo "WARN  $id: cannot read token status (HTTP ${code:-none})" >&2
        return 0
        ;;
    esac

    if [ "$(printf '%s' "$resp" | jq -r '.processing // empty')" != "true" ]; then
      echo "      $id processed"
      return 0
    fi
    sleep 3
    waited=$((waited + 3))
  done

  echo "WARN  $id: still processing after ${POLL_TIMEOUT}s" >&2
  return 0
}

while IFS=$'\t' read -r id out gate; do
  [ -n "$id" ] || continue

  case "$out" in
    /*) sbom="$out" ;;
    *) sbom="${base_dir}/${out}" ;;
  esac

  if [ ! -f "$sbom" ]; then
    echo "FAIL  $id: missing $sbom" >&2
    rc=1
    continue
  fi

  # A failed rio gate blocks the upload, otherwise the gate is decoration.
  if [ "$gate" = "fail" ] && [ "$UPLOAD_FAILED" != "1" ]; then
    echo "SKIP  $id: rio gate failed" >&2
    rc=1
    continue
  fi

  upload "$id" "$sbom" "$gate" || rc=1
done < <(jq -r '.artifacts[] | [.id, .output.path, (.gate // "unknown")] | @tsv' "$INDEX")

exit "$rc"
