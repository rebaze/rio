#!/usr/bin/env sh
#
# install_test.sh - offline tests for install.sh.
#
#   sh install_test.sh
#   dash install_test.sh
#
# Makes no network calls. install.sh is sourced with RIO_SOURCE_ONLY=1 so the
# pure helpers can be exercised directly, and the end to end runs get a PATH
# shim whose `curl` and `wget` serve fixture files from a temp directory and
# record both the urls and the full argument lists they were asked for.
#
# Lint directives are scoped to the lines that need them rather than switched
# off for the whole file: a blanket disable hides the next real finding.

set -eu

unset CDPATH

here=$(cd -- "$(dirname -- "$0")" && pwd)
script="$here/install.sh"

# Absolute, because two cases below run install.sh with a PATH that has been
# stripped down to a shim directory.
sh_bin=$(command -v sh)

checks=0
failures=0

pass() { checks=$((checks + 1)); printf 'ok   %s\n' "$1"; }
flunk() { checks=$((checks + 1)); failures=$((failures + 1)); printf 'FAIL %s\n' "$1"; }

# A skip is counted and printed, never silently dropped: a check that stopped
# running has to be visible in the log.
skips=0
skip() { skips=$((skips + 1)); printf 'skip %s\n' "$1"; }

eq() { # want got label
  if [ "$1" = "$2" ]; then pass "$3"; else flunk "$3: want [$1], got [$2]"; fi
}

contains() { # haystack needle label
  case "$1" in
    *"$2"*) pass "$3" ;;
    *) flunk "$3: [$1] does not contain [$2]" ;;
  esac
}

t=$(mktemp -d 2>/dev/null || mktemp -d -t rio-install-test)
# Physical path: install.sh reports the install dir after cd, and on macOS
# /var is a symlink to /private/var. Compare like with like.
t=$(cd -- "$t" && pwd)
trap 'rm -rf "$t"' EXIT INT TERM HUP

[ -f "$script" ] || { printf 'FAIL install.sh not found at %s\n' "$script"; exit 1; }
[ -x "$script" ] || { printf 'FAIL install.sh is not executable\n'; exit 1; }

# Sourcing pulls in `set -eu`; the assertions below deliberately run commands
# that fail, so turn -e back off and check statuses by hand.
# shellcheck disable=SC2034  # read by install.sh below, which shellcheck does not follow
RIO_SOURCE_ONLY=1
# shellcheck source=install.sh
# shellcheck disable=SC1091  # sourced for its helpers; not analysed from here
. "$script"
set +e

# --- os detection ------------------------------------------------------------

eq linux "$(detect_os Linux)" "detect_os Linux"
eq darwin "$(detect_os Darwin)" "detect_os Darwin"

out=$( (detect_os FreeBSD) 2>&1 )
eq 1 "$?" "detect_os FreeBSD exits non-zero"
contains "$out" FreeBSD "detect_os FreeBSD names what it saw"
# shellcheck disable=SC2154  # rio_releases_url comes from the sourced install.sh
contains "$out" "$rio_releases_url" "detect_os FreeBSD points at the releases page"

out=$( (detect_os MINGW64_NT-10.0-22621) 2>&1 )
eq 1 "$?" "detect_os MINGW exits non-zero"
contains "$out" windows "detect_os MINGW mentions the windows asset"

# --- arch detection ----------------------------------------------------------

eq amd64 "$(detect_arch x86_64)" "detect_arch x86_64"
eq amd64 "$(detect_arch amd64)" "detect_arch amd64"
eq arm64 "$(detect_arch aarch64)" "detect_arch aarch64"
eq arm64 "$(detect_arch arm64)" "detect_arch arm64"

out=$( (detect_arch armv7l) 2>&1 )
eq 1 "$?" "detect_arch armv7l exits non-zero"
contains "$out" armv7l "detect_arch armv7l names what it saw"

# --- version handling --------------------------------------------------------

eq 0.1.0 "$(strip_v v0.1.0)" "strip_v strips a leading v"
eq 0.1.0 "$(strip_v 0.1.0)" "strip_v leaves a bare version alone"
eq v0.1.0 "$(add_v 0.1.0)" "add_v adds a leading v"
eq v0.1.0 "$(add_v v0.1.0)" "add_v does not double the v"

eq v1.2.3 "$(tag_from_url https://github.com/rebaze/rio/releases/tag/v1.2.3)" \
  "tag_from_url reads the tag out of a redirect target"
eq "" "$(tag_from_url https://github.com/rebaze/rio/releases/latest)" \
  "tag_from_url yields nothing when the redirect was not followed"
eq "" "$(tag_from_url '')" "tag_from_url tolerates an empty url"

eq v2.0.1 "$(printf '{\n  "url": "x",\n  "tag_name": "v2.0.1",\n  "name": "v2.0.1"\n}\n' | tag_from_api_json)" \
  "tag_from_api_json parses tag_name without jq"
eq v2.0.1 "$(printf '{"tag_name":"v2.0.1","draft":false}\n' | tag_from_api_json)" \
  "tag_from_api_json parses minified json"
eq "" "$(printf '{"message":"Not Found"}\n' | tag_from_api_json)" \
  "tag_from_api_json yields nothing for an error body"

eq rio_0.1.0_linux_amd64.tar.gz "$(asset_name 0.1.0 linux amd64)" "asset_name linux/amd64"
eq rio_1.2.3_darwin_arm64.tar.gz "$(asset_name 1.2.3 darwin arm64)" "asset_name darwin/arm64"

# The name that matters is the one goreleaser publishes, so pin asset_name to
# .goreleaser.yaml instead of to itself: every end to end run below serves its
# fixture under a name built the same way, so a wrong name would agree with
# itself and prove nothing.
goreleaser="$here/.goreleaser.yaml"
if [ -f "$goreleaser" ]; then
  tmpl=$(sed -n 's/^[[:space:]]*name_template:[[:space:]]*"\(.*ProjectName.*\)"[[:space:]]*$/\1/p' "$goreleaser" | head -n 1)
  rendered=$(printf '%s' "$tmpl" | sed \
    -e 's/{{[[:space:]]*\.ProjectName[[:space:]]*}}/rio/' \
    -e 's/{{[[:space:]]*\.Version[[:space:]]*}}/0.1.0/' \
    -e 's/{{[[:space:]]*\.Os[[:space:]]*}}/linux/' \
    -e 's/{{[[:space:]]*\.Arch[[:space:]]*}}/amd64/')
  eq rio_0.1.0_linux_amd64 "$rendered" "the archive name_template in .goreleaser.yaml renders as expected"
  eq "$rendered.tar.gz" "$(asset_name 0.1.0 linux amd64)" "asset_name matches .goreleaser.yaml's archive name_template"
  if grep -q '^[[:space:]]*- tar\.gz$' "$goreleaser"; then
    pass "goreleaser still publishes tar.gz archives"
  else
    flunk "goreleaser no longer declares a tar.gz archive format, so the .tar.gz in asset_name is wrong"
  fi
else
  flunk "no .goreleaser.yaml at $goreleaser to pin the asset name against"
fi

# --- version validation ------------------------------------------------------
#
# The version is interpolated into the asset name, which becomes a url and a
# path under the temp dir. RIO_VERSION=../../../../tmp/pwned used to produce
# rio_../../../../tmp/pwned_linux_amd64.tar.gz.
for v in 0.1.0 v0.1.0 1.2.3-rc.1 1.2.3+build.5 2024.06; do
  if valid_version "$v"; then pass "valid_version accepts $v"; else flunk "valid_version rejected $v"; fi
done
# shellcheck disable=SC2016  # the literal $(id) is the point: it must be rejected, not expanded
for v in '' '../../../../tmp/pwned' 'a/b' '1.0;id' '$(id)' 'a b' 'a*b'; do
  if valid_version "$v"; then flunk "valid_version accepted [$v]"; else pass "valid_version rejects [$v]"; fi
done

# --- checksums ---------------------------------------------------------------

sums="$t/checksums.txt"
cat > "$sums" <<'SUMS'
1111111111111111111111111111111111111111111111111111111111111111  rio_0.1.0_linux_amd64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222 *rio_0.1.0_darwin_arm64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  checksums-other.txt
SUMS

eq 1111111111111111111111111111111111111111111111111111111111111111 \
  "$(expected_sha256 "$sums" rio_0.1.0_linux_amd64.tar.gz)" "expected_sha256 exact match"
eq 2222222222222222222222222222222222222222222222222222222222222222 \
  "$(expected_sha256 "$sums" rio_0.1.0_darwin_arm64.tar.gz)" "expected_sha256 binary-mode (*name) match"
eq "" "$(expected_sha256 "$sums" rio_9.9.9_linux_arm64.tar.gz)" "expected_sha256 misses cleanly"

tool=$(sha256_tool) || tool=""
if [ -z "$tool" ]; then
  printf 'FAIL no sha256 tool on this machine, cannot run the rest\n'
  exit 1
fi
pass "sha256_tool found $tool"

printf 'abc' > "$t/abc"
eq ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  "$(sha256_file "$t/abc" "$tool")" "sha256_file hashes the known vector for 'abc'"

good="$t/good.txt"
printf 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc\n' > "$good"
out=$( (verify_checksum "$t/abc" "$good" abc) 2>&1 )
eq 0 "$?" "verify_checksum accepts a matching digest"
contains "$out" "$tool" "verify_checksum names the tool that verified it"

bad="$t/bad.txt"
printf 'deadbeef8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc\n' > "$bad"
out=$( (verify_checksum "$t/abc" "$bad" abc) 2>&1 )
eq 1 "$?" "verify_checksum refuses a mismatching digest"
contains "$out" checksum "verify_checksum says what went wrong"

out=$( (verify_checksum "$t/abc" "$sums" abc) 2>&1 )
eq 1 "$?" "verify_checksum refuses when the asset has no checksum entry"

# --- install directory selection --------------------------------------------

# PATH is set and restored around the call instead of being scoped to a
# subshell: a subshell assignment here would make every later `env PATH=...`
# look like a use of a change that got lost (SC2030/SC2031).
path_check() { # want-status path dir label
  path_saved="$PATH"
  PATH="$2"
  path_has_dir "$3"
  path_rc=$?
  PATH="$path_saved"
  eq "$1" "$path_rc" "$4"
}

path_check 0 "/bin:/usr/bin" /usr/bin "path_has_dir finds a dir on PATH"
path_check 1 "/bin:/usr/bin" /opt/nope "path_has_dir rejects a dir off PATH"
# A trailing slash names the same directory, and treating it as different is
# how the installer came to print "add this to your PATH" for a dir that was
# already on it.
path_check 0 "/opt/x/:/usr/bin" /opt/x "path_has_dir ignores a trailing slash on the PATH entry"
path_check 0 "/opt/x:/usr/bin" /opt/x/ "path_has_dir ignores a trailing slash on the install dir"
path_check 0 "/opt/x///:/usr/bin" /opt/x "path_has_dir ignores repeated trailing slashes"
path_check 0 "/:/usr/bin" / "path_has_dir still matches the root directory"
path_check 1 "/opt/xy:/usr/bin" /opt/x "path_has_dir does not match on a prefix"

mkdir -p "$t/sysbin"
# shellcheck disable=SC2034  # read by choose_install_dir, from the sourced install.sh
eq "$t/explicit" "$( RIO_INSTALL_DIR="$t/explicit"; choose_install_dir )" "RIO_INSTALL_DIR wins"
# shellcheck disable=SC2034  # ditto
eq "$t/sysbin" "$( rio_system_bin="$t/sysbin"; choose_install_dir )" "a writable system bin dir comes next"
# shellcheck disable=SC2034  # ditto
eq "$HOME/.local/bin" "$( rio_system_bin="$t/does-not-exist"; choose_install_dir )" "falls back to ~/.local/bin"

# With HOME unset the fallback used to expand to ./.local/bin, quietly
# installing into whatever directory the caller was standing in.
# shellcheck disable=SC2034  # ditto
out=$( unset HOME RIO_INSTALL_DIR; rio_system_bin="$t/does-not-exist"; choose_install_dir 2>&1 )
eq 1 "$?" "choose_install_dir fails when HOME is unset"
contains "$out" HOME "the no-HOME message names HOME"
contains "$out" RIO_INSTALL_DIR "the no-HOME message points at RIO_INSTALL_DIR"

# --- wget flag probe ---------------------------------------------------------
#
# busybox wget understands neither --tries nor --https-only, so the flags are
# probed against the local wget's help instead of assumed. Both shapes get a
# fake wget; PATH is moved at this level, never inside a subshell.
mkdir -p "$t/wgetgnu" "$t/wgetbb"
cat > "$t/wgetgnu/wget" <<'GNUWGET'
#!/usr/bin/env sh
cat <<'HELP'
GNU Wget 1.21.4, a non-interactive network retriever.
  -t,  --tries=NUMBER              set number of retries to NUMBER
       --waitretry=SECONDS         wait 1..SECONDS between retries of a retrieval
  -T,  --timeout=SECONDS           set all timeout values to SECONDS
       --https-only                only follow secure HTTPS links
HELP
GNUWGET
cat > "$t/wgetbb/wget" <<'BBWGET'
#!/usr/bin/env sh
echo "wget: unrecognized option: help" >&2
echo "Usage: wget [-cqS] [--spider] [-O FILE] [-T SEC] [-U AGENT] URL" >&2
exit 1
BBWGET
chmod +x "$t/wgetgnu/wget" "$t/wgetbb/wget"

path_saved="$PATH"
PATH="$t/wgetgnu:$path_saved"
gnu_flags=$(wget_flags)
PATH="$t/wgetbb:$path_saved"
bb_flags=$(wget_flags)
PATH="$path_saved"

contains "$gnu_flags" "-T 30" "wget_flags always sets a timeout"
contains "$gnu_flags" "--tries=3" "wget_flags retries when wget has --tries"
contains "$gnu_flags" "--https-only" "wget_flags pins https when wget has --https-only"
eq "-T 30" "$bb_flags" "wget_flags falls back to what busybox wget understands"

# --- end to end, with a stubbed http client ---------------------------------

os=$(detect_os "$(uname -s)")
arch=$(detect_arch "$(uname -m)")
version=9.9.9
# Spelled out rather than taken from asset_name: the fixture server is what
# tells the end to end runs whether the installer asked for the right file, so
# it must not be named by the function under test.
asset="rio_${version}_${os}_${arch}.tar.gz"

www="$t/www"
shim="$t/shim"
scratch="$t/scratch"
mkdir -p "$www" "$shim" "$scratch" "$t/build" "$t/home"

cat > "$t/build/rio" <<'FAKE'
#!/usr/bin/env sh
echo "rio version 9.9.9"
FAKE
chmod +x "$t/build/rio"
( cd "$t/build" && tar -czf "$www/$asset" rio )

sha=$(sha256_file "$www/$asset" "$tool")
printf '%s  %s\n' "$sha" "$asset" > "$www/checksums.txt"
printf 'https://github.com/rebaze/rio/releases/tag/v%s' "$version" > "$www/effective_url"

cat > "$shim/curl" <<'CURL'
#!/usr/bin/env sh
set -eu
if [ -n "${RIO_TEST_ARGS:-}" ]; then printf '%s\n' "$*" >> "$RIO_TEST_ARGS"; fi
# A download that accepts the connection and then stalls, for the signal case.
if [ -n "${RIO_TEST_SLOW:-}" ]; then : > "$RIO_TEST_SLOW"; sleep 2; fi
url=""; out=""; head=0; writeout=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) writeout=1; shift 2 ;;
    --retry|--retry-delay|--connect-timeout|-H) shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    -*I*) head=1; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$RIO_TEST_LOG"
if [ "$head" = 1 ] && [ "$writeout" = 1 ]; then
  cat "$RIO_TEST_WWW/effective_url"
  exit 0
fi
name=${url##*/}
[ -f "$RIO_TEST_WWW/$name" ] || exit 22
if [ -n "$out" ]; then cp "$RIO_TEST_WWW/$name" "$out"; else cat "$RIO_TEST_WWW/$name"; fi
CURL

cat > "$shim/wget" <<'WGET'
#!/usr/bin/env sh
set -eu
if [ -n "${RIO_TEST_ARGS:-}" ]; then printf '%s\n' "$*" >> "$RIO_TEST_ARGS"; fi
# GNU-wget-shaped help, so install.sh's flag probe has something to read.
case "${1:-}" in
  --help)
    printf '%s\n' '  -t,  --tries=NUMBER' '  -T,  --timeout=SECONDS' '       --https-only'
    exit 0
    ;;
esac
url=""; out="-"
while [ $# -gt 0 ]; do
  case "$1" in
    -O) out="$2"; shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$RIO_TEST_LOG"
name=${url##*/}
[ -f "$RIO_TEST_WWW/$name" ] || exit 8
if [ "$out" = "-" ]; then cat "$RIO_TEST_WWW/$name"; else cp "$RIO_TEST_WWW/$name" "$out"; fi
WGET

chmod +x "$shim/curl" "$shim/wget"

run_install() { # NAME=value ... ; runs install.sh with the shims in front
  env PATH="$shim:$PATH" \
    RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" RIO_TEST_ARGS="$t/args.log" \
    TMPDIR="$scratch" HOME="$t/home" "$@" sh "$script"
}

scratch_is_empty() {
  [ -z "$(ls -A "$scratch" 2>/dev/null)" ]
}

: > "$t/requests.log"
: > "$t/args.log"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin1" 2>&1)
eq 0 "$?" "end to end install with an explicit RIO_VERSION succeeds"
if [ -x "$t/bin1/rio" ]; then pass "the binary landed and is executable"; else flunk "no executable at $t/bin1/rio"; fi
contains "$out" "$t/bin1/rio" "the run prints the final absolute path"
contains "$out" "$tool" "the run names the tool that verified the checksum"
if grep -q 'api.github.com' "$t/requests.log"; then flunk "an explicit version still hit the release API"; else pass "an explicit version needs no release lookup"; fi
if scratch_is_empty; then pass "no temp dir left behind after a successful run"; else flunk "temp dir survived: $(ls -A "$scratch")"; fi
if grep -q 'releases/download/v9.9.9/checksums.txt' "$t/requests.log"; then pass "checksums.txt is fetched from the same tag"; else flunk "checksums.txt was not fetched"; fi

# An installer people pipe into sh must not be talked down to http by a
# redirect, and must not hang a CI job when a mirror accepts and then stalls.
args=$(cat "$t/args.log")
contains "$args" "--proto =https" "curl pins the scheme to https"
contains "$args" "--proto-redir =https" "curl pins redirected hops to https too"
contains "$args" "--connect-timeout " "curl bounds the connect time"
contains "$args" "--max-time " "curl bounds the whole transfer"
contains "$args" "--retry " "curl still retries"

: > "$t/requests.log"
out=$(run_install RIO_INSTALL_DIR="$t/bin2" 2>&1)
eq 0 "$?" "end to end install resolving the latest release succeeds"
if [ -x "$t/bin2/rio" ]; then pass "resolved-version install landed"; else flunk "no executable at $t/bin2/rio"; fi
contains "$out" 9.9.9 "the resolved version is reported"

# No releases published yet: the redirect does not land on a tag and the API
# has nothing either. The user must be told to set RIO_VERSION.
mv "$www/effective_url" "$www/effective_url.tag"
printf 'https://github.com/rebaze/rio/releases' > "$www/effective_url"
out=$(run_install RIO_INSTALL_DIR="$t/bin10" 2>&1)
eq 1 "$?" "an unresolvable latest release fails"
contains "$out" RIO_VERSION "the unresolvable-version message suggests RIO_VERSION"
mv "$www/effective_url.tag" "$www/effective_url"

# A tampered archive must never be installed.
cp "$www/$asset" "$t/pristine.tar.gz"
printf 'tampered' >> "$www/$asset"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin3" 2>&1)
eq 1 "$?" "a checksum mismatch fails the install"
if [ -e "$t/bin3/rio" ]; then flunk "a tampered archive was installed anyway"; else pass "nothing was installed from a tampered archive"; fi
contains "$out" checksum "the mismatch is reported as a checksum failure"
if scratch_is_empty; then pass "no temp dir left behind after a failed run"; else flunk "temp dir survived a failure: $(ls -A "$scratch")"; fi
cp "$t/pristine.tar.gz" "$www/$asset"

# A missing checksums.txt must fail rather than install unverified.
mv "$www/checksums.txt" "$www/checksums.hidden"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin4" 2>&1)
eq 1 "$?" "a missing checksums.txt fails the install"
if [ -e "$t/bin4/rio" ]; then flunk "installed without a checksum file"; else pass "nothing installed without checksums.txt"; fi
mv "$www/checksums.hidden" "$www/checksums.txt"

# A missing asset for this platform fails with a pointer at the releases page.
out=$(run_install RIO_VERSION=0.0.0 RIO_INSTALL_DIR="$t/bin6" 2>&1)
eq 1 "$?" "a version with no asset fails"
contains "$out" "$rio_releases_url" "the missing-asset message points at the releases page"

# An unwritable target is reported, never sudo'd around.
#
# Root ignores the mode bits, so the premise does not hold there and the check
# is skipped rather than failed. GitHub-hosted runners run as a normal user, so
# this does exercise on CI; a root container (docker, act) reports the skip.
if [ "$(id -u)" = "0" ]; then
  skip "an unwritable install dir fails (running as root)"
else
  mkdir -p "$t/ro"
  chmod 500 "$t/ro"
  out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/ro/bin" 2>&1)
  rc=$?
  chmod 700 "$t/ro"
  eq 1 "$rc" "an unwritable install dir fails"
  contains "$out" RIO_INSTALL_DIR "the unwritable-dir message suggests RIO_INSTALL_DIR"
  contains "$out" "will not use sudo" "the failure says it will not sudo"
fi

# The PATH hint fires only when the install dir is off PATH.
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin7" 2>&1)
contains "$out" "export PATH=\"$t/bin7:\$PATH\"" "an off-PATH install dir prints the exact export line"
out=$(env PATH="$t/bin8:$shim:$PATH" \
  RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" TMPDIR="$scratch" HOME="$t/home" \
  RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin8" sh "$script" 2>&1)
case "$out" in
  *"export PATH="*) flunk "PATH hint printed for a dir already on PATH" ;;
  *) pass "no PATH hint when the install dir is already on PATH" ;;
esac

# The installed mode must not depend on the caller's umask: chmod applies to
# the copy in the install dir, not to the file the copy was made from. Under
# umask 077 this used to install a 0700 binary into a shared bin directory.
mkdir -p "$t/bin12"
out=$( umask 077; run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin12" 2>&1 )
eq 0 "$?" "an install under umask 077 succeeds"
# shellcheck disable=SC2012  # a fixed path we created; ls is the portable way to read a mode
eq "-rwxr-xr-x" "$(ls -l "$t/bin12/rio" | cut -c1-10)" "the installed binary is 0755 even under umask 077"

# RIO_SYSTEM_BIN is the seam that makes the default install dir testable: with
# no RIO_INSTALL_DIR the installer takes the system bin dir when it is
# writable, and $HOME/.local/bin otherwise. Without the seam this case could
# only be exercised by writing to the real /usr/local/bin.
mkdir -p "$t/sysbin2"
out=$(run_install RIO_VERSION="$version" RIO_SYSTEM_BIN="$t/sysbin2" 2>&1)
eq 0 "$?" "a default install into a writable system bin dir succeeds"
if [ -x "$t/sysbin2/rio" ]; then pass "the default install used the system bin dir"; else flunk "nothing at $t/sysbin2/rio"; fi

out=$(run_install RIO_VERSION="$version" RIO_SYSTEM_BIN="$t/no-such-sysbin" 2>&1)
eq 0 "$?" "a default install with no system bin dir succeeds"
if [ -x "$t/home/.local/bin/rio" ]; then pass "the default install fell back to \$HOME/.local/bin"; else flunk "nothing at $t/home/.local/bin/rio"; fi

# A version that is not a version never reaches a path or a url.
: > "$t/requests.log"
out=$(run_install RIO_VERSION='../../../../tmp/pwned' RIO_INSTALL_DIR="$t/bin13" 2>&1)
eq 1 "$?" "a path-traversal RIO_VERSION fails"
contains "$out" '../../../../tmp/pwned' "the rejected version is named back"
if [ -s "$t/requests.log" ]; then flunk "a traversal version still reached the network: $(cat "$t/requests.log")"; else pass "nothing was requested for a traversal version"; fi

# A signal has to stop the run. The trap used to clean up and then resume, so
# the install carried on against a temp dir that had just been deleted.
#
# Spelled out instead of going through run_install: backgrounding a shell
# function gives you the pid of the subshell wrapping it, so the signal would
# land on the wrapper (which inherits this script's own EXIT trap) and never
# reach install.sh. A simple command is fork+exec, so $! is install.sh's shell.
rm -f "$t/slow.marker"
env PATH="$shim:$PATH" \
  RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" RIO_TEST_ARGS="$t/args.log" \
  RIO_TEST_SLOW="$t/slow.marker" TMPDIR="$scratch" HOME="$t/home" \
  RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin11" sh "$script" >/dev/null 2>&1 &
sig_pid=$!
sleep 1
kill -TERM "$sig_pid" 2>/dev/null
wait "$sig_pid"
sig_rc=$?
if [ -e "$t/slow.marker" ]; then pass "the signal arrived with a download in flight"; else flunk "the slow download never started, the signal case proves nothing"; fi
eq 143 "$sig_rc" "SIGTERM stops the run with 128+15 instead of resuming"
if [ -e "$t/bin11/rio" ]; then flunk "an interrupted install installed something anyway"; else pass "an interrupted install installs nothing"; fi
if scratch_is_empty; then pass "no temp dir left behind after a signal"; else flunk "temp dir survived a signal: $(ls -A "$scratch")"; fi

# wget-only boxes work too: hide curl by pointing PATH at a shim dir with only wget.
mkdir -p "$t/wgetonly"
cp "$shim/wget" "$t/wgetonly/wget"
# gzip matters: GNU tar shells out to it for -z, while the bsdtar on macOS
# decompresses in-process. Leaving it out passed locally and failed on Linux.
for b in sh tar gzip gunzip uname sed awk cut tr mktemp rm cp mv mkdir chmod ls \
         cat id printf shasum sha256sum openssl; do
  p=$(command -v "$b" 2>/dev/null) && ln -sf "$p" "$t/wgetonly/$b"
done
: > "$t/wget.args"
out=$(env PATH="$t/wgetonly" RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" \
  RIO_TEST_ARGS="$t/wget.args" \
  TMPDIR="$scratch" HOME="$t/home" RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin9" "$sh_bin" "$script" 2>&1)
eq 0 "$?" "install works with wget and no curl"
if [ -x "$t/bin9/rio" ]; then pass "wget-only install landed"; else flunk "wget-only install produced nothing: $out"; fi
wargs=$(grep -v -- '--help' "$t/wget.args")
contains "$wargs" "-T 30" "wget gets a timeout"
contains "$wargs" "--tries=3" "wget retries when its help advertises --tries"
contains "$wargs" "--https-only" "wget pins https when its help advertises --https-only"

# --- flags -------------------------------------------------------------------

out=$(env PATH="$shim:$PATH" sh "$script" --help 2>&1)
eq 0 "$?" "--help exits 0"
contains "$out" RIO_VERSION "--help documents RIO_VERSION"
contains "$out" RIO_INSTALL_DIR "--help documents RIO_INSTALL_DIR"
# checksums.txt travels with the archive, so matching it says the bytes arrived
# intact and nothing about where they came from. --help has to say so, and say
# what to run for the stronger check.
contains "$out" "transport-integrity" "--help calls the checksum a transport check"
contains "$out" "checksums.txt.sigstore.json" "--help names the cosign bundle the release publishes"
contains "$out" "cosign verify-blob" "--help gives the provenance check to run"
eq "" "$(env PATH="$shim:$PATH" sh "$script" --help 2>/dev/null)" "--help writes nothing to stdout"

out=$(env PATH="$shim:$PATH" sh "$script" --nonsense 2>&1)
eq 1 "$?" "an unknown flag exits non-zero"
contains "$out" "--nonsense" "the unknown flag is named back"

# --- no http client ----------------------------------------------------------

mkdir -p "$t/empty"
out=$(env PATH="$t/empty" RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin5" "$sh_bin" "$script" 2>&1)
eq 1 "$?" "no curl and no wget fails"
contains "$out" curl "the message names curl"
contains "$out" wget "the message names wget"

if [ "$skips" -gt 0 ]; then
  printf '\n%s checks, %s failures, %s skipped\n' "$checks" "$failures" "$skips"
else
  printf '\n%s checks, %s failures\n' "$checks" "$failures"
fi
[ "$failures" -eq 0 ]
