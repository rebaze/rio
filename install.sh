#!/usr/bin/env sh
#
# install.sh - install the rio CLI with one command.
#
#   curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
#
# POSIX sh only. This has to work on a bare CI runner under dash or busybox
# ash, so there are no bashisms, no `local`, and no `set -o pipefail` (which
# is not POSIX). The only things it needs on the box are curl or wget, tar,
# and one of sha256sum, shasum or openssl.
#
# It fetches nothing but public release assets and accepts no credential, so
# no token can end up in an argument list, in `ps` output, or in a CI log.
#
# Environment:
#   RIO_VERSION       version or tag to install, e.g. 0.1.0 or v0.1.0.
#                     Default: the latest published release.
#   RIO_INSTALL_DIR   directory to install into. Default: /usr/local/bin when
#                     it is writable, otherwise $HOME/.local/bin.
#
# Everything a human reads goes to stderr, so stdout stays clean for a caller
# that wants to capture it.

set -eu

# A set CDPATH makes `cd` print the directory it landed in, which would end up
# inside the command substitution that resolves the install directory below.
unset CDPATH

rio_repo="rebaze/rio"
rio_releases_url="https://github.com/${rio_repo}/releases"
rio_api_latest_url="https://api.github.com/repos/${rio_repo}/releases/latest"

# Testing seam: install_test.sh overrides this so the "is the system bin dir
# writable" probe is deterministic on any machine. Not a public knob.
rio_system_bin="${RIO_SYSTEM_BIN:-/usr/local/bin}"

# Set by pick_http_client, read by the http_* helpers. A plain global because
# POSIX sh has no `local` and command substitution cannot export upwards.
rio_http_client=""

# Cleaned up by the EXIT trap installed in main.
rio_tmp=""
rio_staged=""

log() { printf '%s\n' "$*" >&2; }

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  # stderr, like every other message here, so that piping the script's stdout
  # somewhere never mixes prose into the pipe.
  cat >&2 <<EOF
install.sh - install the rio CLI.

Usage:
  curl -sSL https://raw.githubusercontent.com/${rio_repo}/main/install.sh | sh
  ./install.sh [--help]

Environment:
  RIO_VERSION       version or tag to install, e.g. 0.1.0 or v0.1.0.
                    Default: the latest release at
                    ${rio_releases_url}/latest
  RIO_INSTALL_DIR   directory to install rio into.
                    Default: /usr/local/bin when writable, else
                    \$HOME/.local/bin (created if missing).

Examples:
  RIO_VERSION=0.1.0 sh install.sh
  RIO_INSTALL_DIR=\$HOME/bin sh install.sh

The download is verified against the release's checksums.txt before anything
is installed. The installer never uses sudo; if the target directory is not
writable it says so and stops.

Supported: linux and darwin on amd64 and arm64. Windows builds are published
as rio_<version>_windows_<arch>.zip at ${rio_releases_url}
EOF
}

# --- platform ----------------------------------------------------------------

detect_os() { # uname -s output
  case "$1" in
    Linux) printf 'linux\n' ;;
    Darwin) printf 'darwin\n' ;;
    MINGW* | MSYS* | CYGWIN* | Windows*)
      die "unsupported operating system: $1. Windows builds are published as rio_<version>_windows_<arch>.zip, download one from ${rio_releases_url}"
      ;;
    *)
      die "unsupported operating system: $1. rio publishes linux and darwin builds at ${rio_releases_url}"
      ;;
  esac
}

detect_arch() { # uname -m output
  case "$1" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *)
      die "unsupported architecture: $1. rio publishes amd64 and arm64 builds at ${rio_releases_url}"
      ;;
  esac
}

# The release tag carries a leading v; the asset names carry the version
# without it (goreleaser's .Version strips it). Both directions are needed.
strip_v() { printf '%s\n' "${1#v}"; }
add_v() { printf 'v%s\n' "${1#v}"; }

asset_name() { # version os arch
  printf 'rio_%s_%s_%s.tar.gz\n' "$1" "$2" "$3"
}

# --- http --------------------------------------------------------------------

pick_http_client() {
  if have curl; then
    rio_http_client=curl
  elif have wget; then
    rio_http_client=wget
  else
    die "neither curl nor wget was found. Install one of them and re-run."
  fi
}

http_fetch() { # url -> body on stdout
  if [ "$rio_http_client" = curl ]; then
    curl -fsSL --retry 3 --retry-delay 1 "$1"
  else
    wget -q -O - "$1"
  fi
}

http_download() { # url dest
  if [ "$rio_http_client" = curl ]; then
    curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

# --- version resolution ------------------------------------------------------

# github.com/<repo>/releases/latest redirects to .../releases/tag/<tag>, so the
# tag can be read off the final url with no jq and no API rate limit.
tag_from_url() { # url -> tag, empty when the url is not a tag url
  printf '%s\n' "$1" | sed -n 's#^.*/releases/tag/\([^/[:space:]][^/[:space:]]*\)$#\1#p'
}

# Fallback for when the redirect cannot be observed (some wget builds do not
# report the effective url). A bare runner has no jq, hence sed.
tag_from_api_json() { # json on stdin -> tag
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_latest_tag() {
  rio_tag=""
  if [ "$rio_http_client" = curl ]; then
    # -I keeps it a HEAD request; -w prints where the redirects landed.
    rio_effective=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${rio_releases_url}/latest" 2>/dev/null || true)
    rio_tag=$(tag_from_url "$rio_effective")
  fi
  if [ -z "$rio_tag" ]; then
    rio_tag=$(http_fetch "$rio_api_latest_url" 2>/dev/null | tag_from_api_json || true)
  fi
  [ -n "$rio_tag" ] || die "could not determine the latest rio release. Set RIO_VERSION explicitly, e.g. RIO_VERSION=0.1.0, or check ${rio_releases_url}"
  printf '%s\n' "$rio_tag"
}

# --- checksums ---------------------------------------------------------------

sha256_tool() {
  if have sha256sum; then
    printf 'sha256sum\n'
  elif have shasum; then
    printf 'shasum\n'
  elif have openssl; then
    printf 'openssl\n'
  else
    return 1
  fi
}

sha256_file() { # file tool -> lowercase hex digest
  case "$2" in
    sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
    shasum) shasum -a 256 "$1" | cut -d' ' -f1 ;;
    openssl) openssl dgst -sha256 "$1" | sed 's/^.*[= ]//' ;;
    *) return 1 ;;
  esac
}

# awk rather than sed so the asset name is compared as a literal string: the
# name contains dots, which a regex would happily match against anything.
# goreleaser writes "<hash>  <name>"; the "*<name>" binary-mode form is
# accepted too because other tooling emits it.
expected_sha256() { # checksums-file asset-name
  awk -v want="$2" '$2 == want || $2 == "*" want { print $1; exit }' "$1"
}

verify_checksum() { # archive checksums-file asset-name
  rio_tool=$(sha256_tool) || die "no sha256 tool found (looked for sha256sum, shasum and openssl). Refusing to install an unverified download."
  rio_want=$(expected_sha256 "$2" "$3")
  [ -n "$rio_want" ] || die "checksums.txt has no entry for $3. Refusing to install an unverified download."
  rio_got=$(sha256_file "$1" "$rio_tool")
  rio_want=$(printf '%s' "$rio_want" | tr 'ABCDEF' 'abcdef')
  rio_got=$(printf '%s' "$rio_got" | tr 'ABCDEF' 'abcdef')
  if [ "$rio_want" != "$rio_got" ]; then
    die "checksum mismatch for $3: expected $rio_want, got $rio_got. Refusing to install."
  fi
  log "checksum ok for $3 (verified with $rio_tool)"
}

# --- install location --------------------------------------------------------

path_has_dir() { # dir
  case ":${PATH:-}:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

choose_install_dir() {
  if [ -n "${RIO_INSTALL_DIR:-}" ]; then
    printf '%s\n' "$RIO_INSTALL_DIR"
  elif [ -d "$rio_system_bin" ] && [ -w "$rio_system_bin" ]; then
    printf '%s\n' "$rio_system_bin"
  else
    printf '%s\n' "${HOME:-.}/.local/bin"
  fi
}

ensure_install_dir() { # dir
  if [ ! -d "$1" ]; then
    mkdir -p "$1" 2>/dev/null || die "cannot create $1. Set RIO_INSTALL_DIR to a directory you can write to. This installer will not use sudo on your behalf."
  fi
  [ -w "$1" ] || die "$1 is not writable. Set RIO_INSTALL_DIR to a directory you own, for example RIO_INSTALL_DIR=\$HOME/.local/bin. This installer will not use sudo on your behalf."
}

# --- main --------------------------------------------------------------------

cleanup() {
  if [ -n "$rio_tmp" ] && [ -d "$rio_tmp" ]; then
    rm -rf "$rio_tmp"
  fi
  # A failed rename would otherwise leave a stray dotfile in the user's bin
  # directory.
  if [ -n "$rio_staged" ] && [ -e "$rio_staged" ]; then
    rm -f "$rio_staged"
  fi
  return 0
}

main() {
  for rio_arg in "$@"; do
    case "$rio_arg" in
      -h | --help)
        usage
        exit 0
        ;;
      *)
        printf 'install.sh: unknown argument: %s\n\n' "$rio_arg" >&2
        usage
        exit 1
        ;;
    esac
  done

  pick_http_client
  have tar || die "tar was not found. Install it and re-run."

  rio_os=$(detect_os "$(uname -s)")
  rio_arch=$(detect_arch "$(uname -m)")

  if [ -n "${RIO_VERSION:-}" ]; then
    rio_tag=$(add_v "$RIO_VERSION")
  else
    log "resolving the latest rio release"
    rio_tag=$(resolve_latest_tag)
  fi
  rio_version=$(strip_v "$rio_tag")

  rio_asset=$(asset_name "$rio_version" "$rio_os" "$rio_arch")
  rio_base="${rio_releases_url}/download/${rio_tag}"

  # The trap covers failure too, so a botched download leaves nothing behind.
  trap cleanup EXIT INT TERM HUP
  rio_tmp=$(mktemp -d 2>/dev/null || mktemp -d -t rio-install) || die "could not create a temporary directory"

  log "downloading ${rio_base}/${rio_asset}"
  http_download "${rio_base}/${rio_asset}" "$rio_tmp/$rio_asset" ||
    die "download failed: ${rio_base}/${rio_asset}. Check that ${rio_tag} exists for ${rio_os}/${rio_arch} at ${rio_releases_url}"

  http_download "${rio_base}/checksums.txt" "$rio_tmp/checksums.txt" ||
    die "could not download ${rio_base}/checksums.txt. Refusing to install an unverified download."

  verify_checksum "$rio_tmp/$rio_asset" "$rio_tmp/checksums.txt" "$rio_asset"

  tar -xzf "$rio_tmp/$rio_asset" -C "$rio_tmp" || die "could not unpack $rio_asset"
  [ -f "$rio_tmp/rio" ] || die "$rio_asset did not contain a rio binary"

  rio_dir=$(choose_install_dir)
  ensure_install_dir "$rio_dir"
  rio_dir=$(cd -- "$rio_dir" && pwd)

  # Copy then rename, so an interrupted install cannot leave a half-written
  # binary at the destination, and so replacing a running rio works.
  chmod 0755 "$rio_tmp/rio"
  rio_staged="$rio_dir/.rio.install.$$"
  cp "$rio_tmp/rio" "$rio_staged" || die "could not write to $rio_dir"
  mv -f "$rio_staged" "$rio_dir/rio" || die "could not install into $rio_dir"
  rio_staged=""

  log "installed rio ${rio_version} (${rio_os}/${rio_arch}) to ${rio_dir}/rio"

  if ! path_has_dir "$rio_dir"; then
    log ""
    log "${rio_dir} is not on your PATH. Add it with:"
    log "  export PATH=\"${rio_dir}:\$PATH\""
  fi
}

[ "${RIO_SOURCE_ONLY:-0}" = "1" ] || main "$@"
