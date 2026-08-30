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
  #
  # --form-string, not -F, for every field whose value is data: curl reads a
  # leading @ or < in an -F value as "send this local file". projectVersion
  # comes straight out of the SBOM, which is generator- and dependency-
  # influenced content, so a crafted metadata.component.version of
  # "@/home/runner/.netrc" would post the runner's credentials to DTRACK_URL.
  # Only bom= is a real file reference.
  body="$(curl -sS -X POST "${DTRACK_URL}/api/v1/bom" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    -H "Accept: application/json" \
    --form-string "projectName=${name}" \
    --form-string "projectVersion=${version}" \
    --form-string "autoCreate=true" \
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

  # 4.x serves the upload token status at /api/v1/bom/token/{token}; newer
  # builds also expose /api/v1/event/token/{token}. Try the 4.x path and fall
  # back once, per artifact.
  #
  # Per artifact, not once per run: a 404 does not mean "this instance is a
  # newer build". An unknown or already consumed token 404s on a 4.x server
  # too, and latching on that would silently stop polling every later artifact
  # whose status was perfectly readable.
  local waited=0 resp code poll_path="/api/v1/bom/token" fell_back=0
  while [ "$waited" -lt "$POLL_TIMEOUT" ]; do
    resp="$(curl -sS "${DTRACK_URL}${poll_path}/${token}" \
      -H "X-Api-Key: ${DTRACK_API_KEY}" \
      -H "Accept: application/json" \
      -w '\n%{http_code}')" || resp=""
    code="$(printf '%s' "$resp" | tail -n1)"
    resp="$(printf '%s' "$resp" | sed '$d')"

    if [ "$code" = "404" ] && [ "$fell_back" = "0" ]; then
      poll_path="/api/v1/event/token"
      fell_back=1
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

# Read the index into a file first. Process substitution hides jq's exit
# status from set -e and from pipefail, so a malformed or shape-changed
# index.json made the script exit 0 having uploaded nothing: exactly the "a run
# that processed nothing looks identical to a clean run" failure rio is built
# to avoid.
rows="$(mktemp)"
trap 'rm -f "$rows"' EXIT

# Unit separator rather than tab: bash treats tab as IFS *whitespace*, so runs
# of tabs collapse and an empty output.path would shift the gate value into the
# path field, reporting a missing file named "ok".
if ! jq -r '.artifacts[]
      | [(.id // ""), (.output.path // ""), (.gate // "unknown")]
      | join("\u001f")' "$INDEX" > "$rows" 2>/dev/null; then
  echo "cannot read $INDEX: not a rio normalize index.json" >&2
  exit 2
fi

if [ ! -s "$rows" ]; then
  echo "no artifacts listed in $INDEX; nothing was uploaded" >&2
  exit 2
fi

while IFS=$'\x1f' read -r id out gate; do
  [ -n "$id" ] || continue

  if [ -z "$out" ]; then
    echo "FAIL  $id: index entry has no output.path" >&2
    rc=1
    continue
  fi

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
done < "$rows"

exit "$rc"
