#!/usr/bin/env python3
"""Build the p2 bundle-symbolic-name -> Maven coordinate table rio consumes.

rio itself never touches the network: it repairs p2 purls from a table that is
embedded in the binary or merged in from the manifest. This script is how that
table is produced. It runs occasionally, on a workstation, and its output is
reviewed and committed like any other asset.

Run it from a repository root and it needs no arguments:

    python3 tools/build-p2-table.py

rio.yaml already says which SBOMs to read, which table to write and under which
scope filter, so nothing here asks you to say it again. The wiring arrives as
JSON from `rio plan --json`, which this script execs -- rio.yaml is YAML, and
YAML is not in the standard library, so a Python parser for it would be either
a dependency or a subset that drifts from rio's own loader. A tool that
disagreed with rio about which files it read would be worse than one that made
you type them.

The ordering of the resolution stages is the whole design. A bundle symbolic
name is NOT reliably groupId.artifactId -- com.google.inject is guice,
com.ibm.icu is icu4j, com.sun.jna.platform is net.java.dev.jna:jna-platform,
org.apache.commons.cli is commons-cli:commons-cli -- so splitting the name is
the last thing tried, never the first, and only when something else can
corroborate it.

  1. Eclipse's own p2 metadata. SimRel and Orbit publish content.xml documents
     in which installable units carry maven-groupId / maven-artifactId
     properties. That is Eclipse stating the coordinate. It is still checked
     against Maven Central before it is believed, because a p2 repository
     records the coordinate a bundle was BUILT under, and for Eclipse's own
     projects that is an unpublished Tycho reactor groupId.
  1b. The same claim, with the groupId looked up again. A rejected claim named
     the artifactId correctly; only its groupId was a build artifact. This is
     where the Eclipse Platform bundles come back, and no split of a symbolic
     name could reach them: org.eclipse.core.databinding is published under
     org.eclipse.platform, which appears nowhere in the name.
  2. Maven Central, proven against the jar. A coordinate is guessed by
     splitting the symbolic name, then the jar is fetched and its
     Bundle-SymbolicName header read back. A mismatch rejects the guess and the
     next candidate is tried. The guess is never trusted on its own.
  3. Maven Central by exact SHA-1, where the SBOM's hashes are usable at all;
     often they are not, see poisoned_hashes. Exact when it hits, and it only
     asks about what stages 1 and 2 could not settle, so it stays cheap.

Anything that survives none of those is reported rather than guessed at. So is
anything genuinely ambiguous: when several groupIds publish a jar declaring the
same symbolic name, one of them is a re-publisher and the manifest cannot say
which, so nothing is emitted.

Requires Python 3.9+ and nothing else.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import io
import json
import lzma
import os
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter
from typing import Iterable, Iterator, NamedTuple, Optional

SCHEMA_VERSION = 1
USER_AGENT = "rio-build-p2-table/1 (+https://github.com/rebaze/rio)"

REPO1 = "https://repo1.maven.org/maven2"
CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"

# The p2 repositories harvested when --p2-repo is not given. Ordered from
# lowest to highest precedence, so a later repository's answer wins.
#
# The Orbit aggregation repositories are last on purpose. Around 2022 Orbit
# switched from republishing third-party jars under its own groupId to
# recording the upstream coordinate, so where an old SimRel says
# org.eclipse.orbit.bundles:com.google.gson a recent Orbit says
# com.google.code.gson:gson. The upstream coordinate is the one vulnerability
# databases carry findings for, which is the entire reason rio repairs these
# purls, so the recent answer must be able to override the old one.
DEFAULT_P2_REPOS = (
    "https://download.eclipse.org/releases/2021-06/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.29.0/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.33.0/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.39.0/",
)

# The groupIds the Eclipse Foundation publishes its own bundles under, where
# the artifactId is the bundle symbolic name verbatim. Tried directly against
# repo1 before any search, because this is both the largest slice of a typical
# RCP product and the one a search cannot reach: no split of
# org.eclipse.core.databinding ever proposes org.eclipse.platform.
ECLIPSE_GROUPS = (
    "org.eclipse.platform",
    "org.eclipse.jdt",
    "org.eclipse.pde",
    "org.eclipse.emf",
    "org.eclipse.xtext",
    "org.eclipse.xtend",
    "org.eclipse.ecf",
    "org.eclipse.persistence",
    "org.eclipse.birt",
    "org.eclipse.orbit.bundles",
    "org.eclipse.jetty",
    "org.eclipse.equinox",
    "org.eclipse.core",
    "org.eclipse.ant",
    "org.eclipse.microprofile.config",
    "org.eclipse.microprofile.health",
)

# The plan contract this build understands. It is checked before anything else,
# so a plan from a newer rio is refused by number rather than misread key by
# key. rio calls the same number planVersion.
PLAN_VERSION = 1

# The transform and ecosystem this tool builds tables for. rio dispatches on
# the same two values, and an artifact declaring neither is not this tool's
# business.
REPAIR_PURL = "repair-purl"
ECOSYSTEM = "p2"

# Confidence tiers, strongest first. The value lands in the emitted entry so a
# reviewer can see how each coordinate was arrived at without rerunning this.
ECLIPSE_ASSERTED = "eclipse-asserted"
MANIFEST_PROVEN = "manifest-proven"
HASH_EXACT = "hash-exact"
INFERRED = "inferred"

# Not a confidence tier but an outcome: several groupIds publish a jar
# declaring this symbolic name, so the manifest cannot pick one. Never emitted.
AMBIGUOUS = "ambiguous"

CONFIDENCE_RANK = {
    ECLIPSE_ASSERTED: 0,
    MANIFEST_PROVEN: 1,
    HASH_EXACT: 2,
    INFERRED: 3,
}

# Two tiers, not four. The three proven kinds are different KINDS of evidence
# -- Eclipse said so, the jar's own manifest said so, a hash matched exactly --
# rather than different strengths of one, and ranking them against each other
# would invent a hierarchy nothing supports. What does need ranking is proof
# against no proof: a rerun must never let an inferred guess overwrite a
# coordinate something actually corroborated.
PROVEN = frozenset({ECLIPSE_ASSERTED, MANIFEST_PROVEN, HASH_EXACT})


class Transient(Exception):
    """The network could not answer, which is not the same as a negative answer.

    Keeping these apart is a correctness requirement, not a nicety. A timed-out
    maven-metadata.xml read as "Central does not publish this" would silently
    reject a coordinate that is perfectly good, and the resulting table would be
    quietly worse on a bad network day than on a good one. Every caller that
    turns an absence into a decision has to see this instead.
    """


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


class Fetcher:
    """HTTP GET with an on-disk cache, so a rerun costs nothing.

    The cache is keyed by URL and never expires. These are immutable release
    artifacts -- a published p2 repository and a released Maven jar do not
    change -- so re-fetching them would only burn Eclipse's and Sonatype's
    bandwidth. Delete the directory to force a refresh.
    """

    def __init__(self, cache_dir: str, offline: bool = False, retries: int = 3,
                 backoff: float = 2.0):
        self.cache_dir = cache_dir
        self.offline = offline
        self.retries = retries
        self.backoff = backoff
        self.hits = 0
        self.misses = 0
        os.makedirs(cache_dir, exist_ok=True)

    def _path(self, url: str) -> str:
        digest = hashlib.sha256(url.encode()).hexdigest()[:32]
        return os.path.join(self.cache_dir, digest)

    def _cached(self, path: str, marker: str):
        if os.path.exists(path):
            self.hits += 1
            with open(path, "rb") as fh:
                return True, fh.read()
        if os.path.exists(marker):
            self.hits += 1
            return True, None
        return False, None

    def _store(self, path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)

    def _fetch(self, req, path: str, marker: str, timeout: int) -> Optional[bytes]:
        """Fetch with bounded retries, raising Transient when it never answered.

        A 404 is cached: the artifact genuinely is not there and asking again
        tomorrow will not change that. A timeout is never cached, because doing
        so would freeze a network hiccup into a permanent wrong answer.
        """
        last = None
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff * (2 ** (attempt - 1)))
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = resp.read()
                self._store(path, data)
                return data
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 403, 410):
                    open(marker, "wb").close()
                    return None
                last = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
        raise Transient(f"{req.full_url}: {last}")

    def get(self, url: str, timeout: int = 30) -> Optional[bytes]:
        """Return the body, or None when the server said it is not there.

        Raises Transient when the server said nothing at all.
        """
        path = self._path(url)
        marker = path + ".404"
        cached, data = self._cached(path, marker)
        if cached:
            return data
        if self.offline:
            # A cache miss offline means nobody was asked, which is not the
            # same as being told no. Returning None here would let --offline
            # quietly demote good coordinates on a half-warm cache.
            raise Transient(f"{url}: not cached and running offline")
        self.misses += 1
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        return self._fetch(req, path, marker, timeout)

    def get_range(self, url: str, nbytes: int, timeout: int = 30) -> Optional[bytes]:
        """Fetch the first nbytes of url, cached under its own key.

        A server that ignores Range answers 200 with the whole body, which is
        still correct, only not the saving that was hoped for.
        """
        key = f"{url}#range0-{nbytes}"
        path = self._path(key)
        marker = path + ".404"
        cached, data = self._cached(path, marker)
        if cached:
            return data
        if self.offline:
            raise Transient(f"{url}: not cached and running offline")
        self.misses += 1
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{nbytes - 1}"},
        )
        return self._fetch(req, path, marker, timeout)


# --------------------------------------------------------------------------
# Reading the SBOM
# --------------------------------------------------------------------------


class Bundle(NamedTuple):
    bsn: str
    version: str
    sha1: Optional[str]


# The manifest keys the scope filter is spelled with, in Scope's field order.
# A message about a disagreement has to name the key the author wrote, not the
# identifier this module happens to use for it (§10).
SCOPE_KEYS = ("groupPrefix", "classifier", "syntheticNamespace")


class Scope(NamedTuple):
    """rio's scope filter, as rio has it.

    Every value comes from the plan, resolved, defaults already applied. This
    tool holds no copy of "p2." or "osgi.bundle": a manifest that overrides
    groupPrefix and a tool run that did not would harvest under one filter and
    have rio read the result back under another, silently.
    """

    group_prefix: str
    classifier: str
    synthetic_namespace: str


def parse_purl(purl: str) -> Optional[dict]:
    """Enough of a purl parser for the three shapes rio puts in scope."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    qualifiers: dict[str, str] = {}
    if "#" in body:
        body = body.split("#", 1)[0]
    if "?" in body:
        body, query = body.split("?", 1)
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k.lower()] = urllib.parse.unquote(v)
    version = ""
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = urllib.parse.unquote(version)
    parts = [urllib.parse.unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    return {
        "type": parts[0],
        "namespace": "/".join(parts[1:-1]),
        "name": parts[-1],
        "version": version,
        "qualifiers": qualifiers,
    }


def sha1_of(component: dict) -> Optional[str]:
    for h in component.get("hashes") or []:
        if h.get("alg") == "SHA-1":
            return (h.get("content") or "").lower() or None
    return None


def in_scope(component: dict, scope: Scope):
    """Mirror rio's scope filter, so this script and rio agree on the work-list.

    Diverging here would be worse than useless: the script would curate entries
    for components rio never looks up, and leave the ones it does unmapped.
    """
    purl = component.get("purl") or ""
    group = component.get("group") or ""
    name = component.get("name") or ""
    version = component.get("version") or ""

    if not purl:
        # A component with no purl beside an OSGi symbolic name.
        if group.startswith(scope.group_prefix) and name:
            return Bundle(name, version, sha1_of(component))
        return None

    parsed = parse_purl(purl)
    if not parsed:
        return None

    if parsed["type"] == "maven" and parsed["namespace"] == scope.synthetic_namespace:
        # A nested artefact repeats its bundle's name and version; resolving it
        # by name would put the bundle's coordinate on a jar shipped inside it.
        if parsed["qualifiers"].get("classifier"):
            return None
        return Bundle(parsed["name"], parsed["version"] or version, sha1_of(component))

    if parsed["type"] == "p2":
        if parsed["qualifiers"].get("classifier") != scope.classifier:
            return None
        if not group.startswith(scope.group_prefix):
            return None
        return Bundle(parsed["name"], parsed["version"] or version, sha1_of(component))

    return None


def infer_first_party_prefix(doc: dict) -> Optional[str]:
    """Guess the first-party prefix from the document's own subject.

    Tycho flattens every bundle under the same synthetic group, so nothing in a
    component distinguishes a first-party bundle from a third-party one. The
    subject is the one place the product's own coordinate survives: a
    metadata.component group of com.example.acme.product yields com.example,
    which excludes the reactor's own bundles from the work-list.

    Two labels is the useful depth. One would exclude every com.* bundle in the
    build; three would miss sibling reactors under the same organisation.
    """
    group = ((doc.get("metadata") or {}).get("component") or {}).get("group") or ""
    labels = [p for p in group.split(".") if p]
    if len(labels) >= 2:
        return ".".join(labels[:2])
    return None


def read_sbom(path: str, scope: Scope) -> tuple[list[Bundle], Optional[str]]:
    doc = read_json_document(path, "SBOM")
    bundles = []
    for component in doc.get("components") or []:
        b = in_scope(component, scope)
        if b:
            bundles.append(b)
    return bundles, infer_first_party_prefix(doc)


def poisoned_hashes(bundles: Iterable[Bundle], threshold: int = 2) -> set[str]:
    """SHA-1 values that appear on more than one component, and so identify none.

    Not a hypothetical. The document this was written against carries one
    identical SHA-1 on 504 of its 603 bundles: the generator emitted a
    placeholder rather than hashing each artifact. Feeding those to Central
    would be harmless but pointless, and trusting a collision would be worse,
    so any repeated value is dropped before the hash stage runs.
    """
    counts = Counter(b.sha1 for b in bundles if b.sha1)
    return {h for h, n in counts.items() if n >= threshold}


# --------------------------------------------------------------------------
# Stage 1: Eclipse p2 metadata
# --------------------------------------------------------------------------


def try_get(fetcher: Fetcher, url: str, timeout: int = 30) -> Optional[bytes]:
    """get() for speculative URLs, where a failure to answer is just a miss."""
    try:
        return fetcher.get(url, timeout=timeout)
    except Transient:
        return None


def read_p2_document(fetcher: Fetcher, base: str, stem: str) -> Optional[bytes]:
    """Fetch one p2 metadata document, trying the encodings p2 publishes.

    A repository serves exactly one of these three and 404s the others, so all
    three are tried rather than guessed at from the URL.
    """
    base = base if base.endswith("/") else base + "/"

    data = try_get(fetcher, base + stem + ".xml.xz", timeout=120)
    if data:
        try:
            return lzma.decompress(data)
        except lzma.LZMAError:
            pass

    data = try_get(fetcher, base + stem + ".jar", timeout=120)
    if data:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return zf.read(stem + ".xml")
        except (zipfile.BadZipFile, KeyError):
            pass

    return try_get(fetcher, base + stem + ".xml", timeout=120)


def walk_p2_repo(
    fetcher: Fetcher, url: str, depth: int = 0, seen: Optional[set] = None
) -> Iterator[bytes]:
    """Yield every content.xml reachable from url, following composites.

    Eclipse publishes releases as a composite pointing at timestamped children
    (/releases/2021-06/ -> /releases/2021-06/202106161001/), so the URL a human
    would quote is never the one holding the units. Recursing means the caller
    passes the memorable URL and this finds the real ones.
    """
    if seen is None:
        seen = set()
    url = url if url.endswith("/") else url + "/"
    if url in seen or depth > 4:
        return
    seen.add(url)

    content = read_p2_document(fetcher, url, "content")
    if content:
        yield content
        return

    composite = read_p2_document(fetcher, url, "compositeContent")
    if not composite:
        log(f"  ! no p2 metadata at {url}")
        return
    try:
        root = ET.fromstring(composite)
    except ET.ParseError:
        return
    for child in root.iterfind(".//child"):
        location = child.get("location")
        if location:
            yield from walk_p2_repo(
                fetcher, urllib.parse.urljoin(url, location), depth + 1, seen
            )


def harvest_p2(content: bytes) -> Iterator[tuple[str, str, str]]:
    """Yield (bsn, groupId, artifactId) for every unit that carries coordinates."""
    for _, unit in ET.iterparse(io.BytesIO(content), events=("end",)):
        if unit.tag != "unit":
            continue
        bsn = unit.get("id") or ""
        props = {
            p.get("name"): p.get("value") for p in unit.findall("./properties/property")
        }
        group = props.get("maven-groupId")
        artifact = props.get("maven-artifactId")
        if bsn and group and artifact:
            yield bsn, group, artifact
        unit.clear()


def stage_p2_metadata(fetcher: Fetcher, repos: Iterable[str]) -> dict[str, tuple]:
    """Build bsn -> (groupId, artifactId, evidence) from Eclipse's own metadata.

    Later repositories override earlier ones, and an upstream coordinate always
    beats an Orbit republication regardless of order: org.eclipse.orbit.bundles
    is a real place to download the bundle from, but almost no vulnerability
    database carries findings under it, so preferring it would repair the purl
    and still report nothing.
    """
    table: dict[str, tuple] = {}
    for repo in repos:
        log(f"  fetching {repo}")
        found = 0
        for content in walk_p2_repo(fetcher, repo):
            for bsn, group, artifact in harvest_p2(content):
                found += 1
                previous = table.get(bsn)
                if previous and is_orbit(group) and not is_orbit(previous[0]):
                    continue
                table[bsn] = (group, artifact, repo)
        log(f"    {found} units with Maven coordinates")
    return table


def bundle_version(work: dict, bsn: str) -> str:
    b = work.get(bsn)
    return b.version if b else ""


def is_orbit(group_id: str) -> bool:
    return group_id.startswith("org.eclipse.orbit")


# --------------------------------------------------------------------------
# Stage 2: Maven Central, proven against the jar manifest
# --------------------------------------------------------------------------


ECLIPSE_QUALIFIER = re.compile(r"\.(v\d{8}[-\d]*|[A-Za-z][\w-]*)$")
EMBEDDED_VERSION = re.compile(r"_\d+(\.\d+)*$")
BSN_HEADER = re.compile(r"^Bundle-SymbolicName:\s*([^;\s]+)", re.MULTILINE)


def strip_embedded_version(bsn: str) -> str:
    """com.fasterxml.jackson.core.jackson-annotations_2.10.2 -> ...jackson-annotations."""
    return EMBEDDED_VERSION.sub("", bsn)


def version_candidates(version: str) -> list[str]:
    """Maven versions an OSGi version could have come from.

    OSGi pads to three segments and Maven does not, so the bundle's 1.4.0 is
    Maven's 1.4 and 30.1.0 is 30.1. Both forms are tried, longest first.
    """
    version = ECLIPSE_QUALIFIER.sub("", version.strip())
    if not version:
        return []
    out = [version]
    parts = version.split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts = parts[:-1]
        out.append(".".join(parts))
    return out


def coordinate_candidates(bsn: str, limit: int = 12) -> list[tuple[str, str]]:
    """Every (groupId, artifactId) the symbolic name could decompose into.

    Longest groupId first, because org.glassfish.jersey.core:jersey-client is
    far more likely than org.glassfish:jersey.core.jersey-client. Both the
    dotted and the dashed artifactId are offered, since Eclipse writes
    org.apache.commons.lang3 for what Maven calls commons-lang3.

    Nothing here is trusted. These are hypotheses for the manifest check.
    """
    stem = strip_embedded_version(bsn)
    parts = stem.split(".")
    out: list[tuple[str, str]] = []
    if len(parts) == 1:
        out.append((stem, stem))
    for i in range(len(parts) - 1, 0, -1):
        group = ".".join(parts[:i])
        out.append((group, ".".join(parts[i:])))
        dashed = "-".join(parts[i:])
        if dashed != ".".join(parts[i:]):
            out.append((group, dashed))
    seen = set()
    unique = []
    for candidate in out:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique[:limit]


JAR_HEAD_BYTES = 32768


def manifest_from_jar_head(data: bytes) -> Optional[bytes]:
    """Pull META-INF/MANIFEST.MF out of the first bytes of a jar, if it is there.

    A jar is a zip, and the jar tool writes the manifest first, so the whole
    entry almost always sits within the first few kilobytes. Reading it from
    there turns a multi-megabyte download into a 32 KB range request, which for
    several hundred candidate coordinates is the difference between minutes and
    an hour. Returns None when the manifest is not in the fetched prefix, and
    the caller falls back to the whole file.
    """
    offset = 0
    while offset + 30 <= len(data) and data[offset : offset + 4] == b"PK\x03\x04":
        flags, method = struct.unpack_from("<HH", data, offset + 6)
        csize, = struct.unpack_from("<I", data, offset + 18)
        namelen, extralen = struct.unpack_from("<HH", data, offset + 26)
        name = data[offset + 30 : offset + 30 + namelen]
        body = offset + 30 + namelen + extralen
        if name.upper() == b"META-INF/MANIFEST.MF":
            if method == 8:
                # Bit 3 puts the sizes in a trailing descriptor, leaving csize
                # zero here -- which is how the jar tool writes a streamed jar,
                # so it is the common case rather than the exotic one. The
                # deflate stream is self-terminating, so it is decompressed
                # incrementally and eof tells us whether the whole entry was
                # inside the fetched prefix.
                decompressor = zlib.decompressobj(-15)
                try:
                    out = decompressor.decompress(data[body:])
                except zlib.error:
                    return None
                return out if decompressor.eof else None
            if method == 0 and not flags & 0x08:
                blob = data[body : body + csize]
                return blob if len(blob) == csize else None
            return None
        if flags & 0x08:
            return None
        offset = body + csize
    return None


def read_bsn(manifest: bytes) -> str:
    # MANIFEST.MF wraps at 72 columns and continues with a leading space.
    text = manifest.decode("utf-8", "replace").replace("\r\n", "\n").replace("\n ", "")
    match = BSN_HEADER.search(text)
    return match.group(1).strip() if match else ""


def jar_symbolic_name(fetcher: Fetcher, group: str, artifact: str, version: str):
    """Read Bundle-SymbolicName out of the published jar.

    Returns the header value, "" when the jar carries no such header, or None
    when there is no jar to read. The empty string is a distinct and important
    answer: it means the artifact exists but predates OSGi, so this coordinate
    can never be proven this way and must not be reported as if it had been.
    """
    url = f"{REPO1}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"

    try:
        head = fetcher.get_range(url, JAR_HEAD_BYTES)
        if head:
            manifest = manifest_from_jar_head(head)
            if manifest is not None:
                return read_bsn(manifest)
        data = fetcher.get(url, timeout=90)
    except Transient:
        # Unknown, not "no such header" -- returning "" would let an unproven
        # coordinate through as merely-inferred.
        return None
    if not data:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return read_bsn(zf.read("META-INF/MANIFEST.MF"))
    except (zipfile.BadZipFile, KeyError):
        return ""


METADATA_VERSION = re.compile(r"<version>([^<]+)</version>")


def published_versions(fetcher: Fetcher, group: str, artifact: str) -> Optional[list[str]]:
    """Versions Maven Central publishes for a groupId:artifactId, or None if absent.

    One request per coordinate answers both "does this exist" and "which
    versions", which is cheaper and far more reliable than probing a guessed
    version and reading 404 as "wrong coordinate" when it only meant "wrong
    version".
    """
    url = f"{REPO1}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    data = fetcher.get(url, timeout=45)
    if not data:
        return None
    return METADATA_VERSION.findall(data.decode("utf-8", "replace"))


# How well a claimed coordinate stood up to Central.
CONFIRMED = "confirmed"        # exists, and publishes this bundle's version
WRONG_VERSION = "wrong-version"  # exists, but not at this version
ABSENT = "absent"              # Central publishes no such coordinate
UNKNOWN = "unknown"            # Central did not answer


def confirm_on_central(fetcher: Fetcher, group: str, artifact: str, bundle: Bundle) -> str:
    """Check a claimed coordinate against Central, version included.

    Existence alone is too weak a test. org.eclipse.core.contenttype is claimed
    by two real coordinates: org.eclipse.core, last published in 2010 at
    3.4.100, and org.eclipse.platform, still maintained at 3.9.x. The bundle
    here is 3.8.100, so an existence check would happily pick the stale one and
    pin a decade-old artifact's identity onto a current bundle. Requiring the
    version narrows it to the coordinate that actually ships this build.
    """
    try:
        published = published_versions(fetcher, group, artifact)
    except Transient:
        return UNKNOWN
    if published is None:
        return ABSENT
    wanted = version_candidates(bundle.version)
    return CONFIRMED if any(v in published for v in wanted) else WRONG_VERSION


def resolve_by_name(fetcher: Fetcher, bundle: Bundle) -> Optional[tuple]:
    """Try each candidate coordinate until one is proven or plausibly exists.

    A candidate whose jar declares a DIFFERENT symbolic name is rejected
    outright and the search continues. That rejection is what separates this
    from guessing: the artifact that exists at a plausible coordinate is not
    necessarily the artifact the bundle was built from.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)

    fallback = None
    for group, artifact in coordinate_candidates(bundle.bsn):
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if published is None:
            continue
        # The table records only groupId and artifactId, so the version is
        # evidence rather than output: it is what lets the jar be fetched and
        # the symbolic name read back.
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        declared = jar_symbolic_name(fetcher, group, artifact, version)
        if declared in (bundle.bsn, stem):
            return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
        if declared:
            # The jar names a different bundle. Wrong artifact, keep going.
            continue
        # Exists at the right version, but the jar predates OSGi and carries no
        # symbolic name, so nothing can prove it. Hold it in case nothing
        # better turns up.
        if fallback is None:
            fallback = (
                group,
                artifact,
                INFERRED,
                f"{group}:{artifact}:{version} (jar has no Bundle-SymbolicName)",
            )
    return fallback


# --------------------------------------------------------------------------
# Stage 3: Maven Central by exact SHA-1
# --------------------------------------------------------------------------


MAX_PROOF_DOWNLOADS = 6


def shared_labels(group: str, bsn: str) -> int:
    """How many leading dot-labels a groupId shares with a symbolic name."""
    a, b = group.split("."), bsn.split(".")
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def resolve_in_known_groups(
    fetcher: Fetcher, groups: Iterable[str], artifact: str, bundle: Bundle
) -> Optional[tuple]:
    """Look for artifactId under a fixed set of groupIds, using repo1 alone.

    No search API and no throttle, so this is both fast and immune to the
    search endpoint being slow, rate-limited or down.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)
    for group in groups:
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if not published:
            continue
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        if jar_symbolic_name(fetcher, group, artifact, version) in (bundle.bsn, stem):
            return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
    return None


def groups_publishing(fetcher: Fetcher, throttle: "Throttle", artifact: str) -> list[str]:
    """Ask Central which groupIds publish this artifactId.

    This inverts the search. Splitting a symbolic name guesses the groupId and
    can only ever propose one that is a literal prefix of the name, which is
    hopeless for the Eclipse Platform: org.eclipse.core.databinding is
    published as org.eclipse.platform:org.eclipse.core.databinding, and no
    split of the name yields "org.eclipse.platform". Letting Central enumerate
    the real groupIds for a known artifactId reaches coordinates no amount of
    string surgery would.
    """
    query = urllib.parse.urlencode(
        {"q": f'a:"{artifact}"', "rows": "20", "wt": "json"}
    )
    url = f"{CENTRAL_SEARCH}?{query}"
    if not os.path.exists(fetcher._path(url)):
        throttle.wait()
    data = try_get(fetcher, url)
    if not data:
        return []
    try:
        docs = json.loads(data)["response"]["docs"]
    except (ValueError, KeyError):
        return []
    out = []
    for doc in docs:
        group = doc.get("g")
        if group and group not in out:
            out.append(group)
    return out


def resolve_by_artifact_id(
    fetcher: Fetcher, throttle: "Throttle", artifact: str, bundle: Bundle
) -> Optional[tuple]:
    """Find the groupId that publishes a known artifactId, and prove it.

    Used with an artifactId that came from Eclipse's own metadata, whose
    groupId turned out to be an unpublished reactor coordinate. The artifactId
    survives that rejection intact; only the groupId has to be found again.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)
    proven: list[tuple[str, str]] = []
    fallback = None
    groups = groups_publishing(fetcher, throttle, artifact)
    # Central returns up to 20 groupIds and each proof costs a jar download, so
    # the ones sharing leading labels with the symbolic name go first and the
    # tail is cut. A re-publisher rarely shares a prefix with what it repackages.
    groups.sort(key=lambda g: -shared_labels(g, stem))
    for group in groups[:MAX_PROOF_DOWNLOADS]:
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if not published:
            continue
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        declared = jar_symbolic_name(fetcher, group, artifact, version)
        if declared in (bundle.bsn, stem):
            proven.append((group, version))
        elif not declared and fallback is None:
            fallback = (
                group,
                artifact,
                INFERRED,
                f"{group}:{artifact}:{version} (jar has no Bundle-SymbolicName)",
            )

    # More than one groupId publishing a jar that declares this symbolic name
    # means a re-publisher is in the set, and the manifest cannot say which of
    # them the bundle came from -- both jars honestly carry the same header.
    # Re-publisher coordinates are the cardinal false positive here: they look
    # entirely plausible and carry no vulnerability data, so an ambiguous
    # answer is reported rather than guessed at.
    if len(proven) > 1:
        candidates = ", ".join(f"{g}:{artifact}" for g, _ in proven)
        return None, artifact, AMBIGUOUS, candidates
    if proven:
        group, version = proven[0]
        return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
    return fallback


class Throttle:
    """Central's search API throttles; repo1 does not. Only the former uses this."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self.last = 0.0

    def wait(self) -> None:
        delta = time.monotonic() - self.last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last = time.monotonic()


def resolve_by_sha1(fetcher: Fetcher, throttle: "Throttle", sha1: str) -> Optional[tuple]:
    query = urllib.parse.urlencode({"q": f'1:"{sha1}"', "rows": "5", "wt": "json"})
    url = f"{CENTRAL_SEARCH}?{query}"
    if not os.path.exists(fetcher._path(url)):
        throttle.wait()
    data = try_get(fetcher, url)
    if not data:
        return None
    try:
        docs = json.loads(data)["response"]["docs"]
    except (ValueError, KeyError):
        return None
    if len(docs) != 1:
        # Zero is a miss. More than one means the same bytes are published under
        # several coordinates and the hash does not pick one, so it proves nothing.
        return None
    doc = docs[0]
    return doc["g"], doc["a"], HASH_EXACT, f"sha1:{sha1}"

# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------


def fail(msg: str) -> "SystemExit":
    """Every refusal is a message a human can act on, not a traceback (§10)."""
    return SystemExit("error: " + msg)


def read_json_document(path: str, what: str) -> dict:
    """Read one JSON document, turning every way it can fail into a message.

    An unreadable file, a truncated write and a document that is not an object
    at all are each something a person can act on, and none of them is worth a
    traceback (§10). Everything downstream may then assume it has a mapping.
    """
    try:
        with open(path, "rb") as fh:
            doc = json.load(fh)
    except OSError as err:
        raise fail(f"reading the {what} {path}: {err.strerror or err}")
    except ValueError as err:
        raise fail(f"the {what} {path} is not JSON: {err}")
    if not isinstance(doc, dict):
        raise fail(f"the {what} {path} is not a JSON object")
    return doc


def load_plan(args) -> dict:
    """Get the wiring: rio.yaml as rio reads it, via `rio plan --json`.

    --plan takes a pre-computed plan instead, which is how the tests drive this
    with no rio binary in sight.
    """
    if args.plan:
        if args.plan == "-":
            raw, source = sys.stdin.read(), "standard input"
        else:
            try:
                with open(args.plan, encoding="utf-8") as fh:
                    raw, source = fh.read(), args.plan
            except OSError as err:
                raise fail(f"reading the plan {args.plan}: {err.strerror or err}")
    else:
        cmd = [args.rio, "plan", "--json", "--manifest", args.manifest]
        try:
            proc = subprocess.run(cmd, capture_output=True)
        except OSError as err:
            # A bare ENOENT here is the least helpful thing this tool could
            # say, because there are three ways out and none of them is
            # obvious from it.
            raise fail(
                f"could not run {args.rio!r}: {err.strerror}.\n"
                "  --rio PATH   point at the binary if it is not on PATH\n"
                "  --plan FILE  use a plan you already have (rio plan --json > plan.json)\n"
                "  or install rio: https://github.com/rebaze/rio"
            )
        if proc.returncode != 0:
            # rio's manifest diagnostics name the offending field and line.
            # Re-phrasing them here would lose the part that helps.
            sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
            raise fail(f"{' '.join(cmd)} exited {proc.returncode}")
        raw = proc.stdout.decode("utf-8")
        source = " ".join(cmd)

    try:
        plan = json.loads(raw)
    except ValueError as err:
        raise fail(f"{source}: not JSON: {err}")
    if not isinstance(plan, dict):
        raise fail(f"{source}: not a plan document")

    # Before anything else, so a document this build cannot read is refused by
    # number rather than misunderstood key by key.
    got = plan.get("planVersion")
    if got != PLAN_VERSION:
        if isinstance(got, int) and got > PLAN_VERSION:
            raise fail(
                f"{source}: planVersion is {got}, this tool understands {PLAN_VERSION}. "
                "Upgrade tools/build-p2-table.py; it ships with rio."
            )
        raise fail(
            f"{source}: planVersion is {got!r}, this tool understands {PLAN_VERSION}. "
            "Upgrade rio."
        )
    return plan


def plan_builtin(plan: dict) -> dict:
    """rio's own mapping table, as the plan publishes it.

    Checked here rather than trusted, because --plan takes a file a person can
    hand-edit, and a value that is not a coordinate pair would otherwise reach
    the merge and fail there with a traceback about a missing attribute.
    """
    builtin = plan.get("builtinTable") or {}
    if not isinstance(builtin, dict) or any(not isinstance(e, dict) for e in builtin.values()):
        raise fail(
            "the plan's builtinTable is not a map of coordinates. This plan is not one "
            "this tool can read; check that rio and tools/build-p2-table.py come from "
            "the same release."
        )
    return builtin


class Source(NamedTuple):
    """One artifact's SBOM, as a job reads it."""

    artifact: str
    path: str  # absolute
    rel: str  # as the plan names it, relative to the manifest directory


class Job(NamedTuple):
    """One mapping table and everything that feeds it.

    Artifacts are bucketed by the table their p2 transform names, because that
    is the file this run reads and rewrites. Two artifacts pointing at one
    table are one job over both their SBOMs.
    """

    path: str  # absolute path of the table
    rel: str  # the table exactly as the manifest wrote it
    scope: Scope
    sources: list


def plan_scope(artifact_id: str, transform: dict) -> Scope:
    """Read the resolved scope filter out of one transform.

    Missing keys are a refusal rather than a default. Defaulting here would put
    back exactly the second copy of "p2." that reading the plan exists to
    remove, and it would do it silently.
    """
    values = []
    for key in SCOPE_KEYS:
        value = transform.get(key)
        if not isinstance(value, str) or not value:
            raise fail(
                f"artifact {artifact_id!r}: the plan's repair-purl transform carries no {key}. "
                "This plan is not one this tool can read; check that rio and "
                "tools/build-p2-table.py come from the same release."
            )
        values.append(value)
    return Scope(*values)


def plan_jobs(plan: dict) -> list[Job]:
    """Bucket the plan's artifacts by the table each one's p2 transform names."""
    manifest = plan.get("manifest") or {}
    base = manifest.get("dir")
    if not base:
        raise fail("the plan carries no manifest.dir, so nothing can be resolved against it")

    jobs: dict[str, Job] = {}
    scoped_by: dict[str, str] = {}  # table -> the artifact that set its scope

    for artifact in plan.get("artifacts") or []:
        artifact_id = artifact.get("id") or "?"
        transforms = [
            t
            for t in (artifact.get("transforms") or [])
            if t.get("name") == REPAIR_PURL and t.get("ecosystem") == ECOSYSTEM
        ]
        if not transforms:
            log(f"  {artifact_id}: no {REPAIR_PURL} with ecosystem {ECOSYSTEM}; skipped")
            continue

        for transform in transforms:
            table = transform.get("table") or ""
            if not table:
                raise fail(
                    f"artifact {artifact_id!r} declares {REPAIR_PURL} with ecosystem "
                    f"{ECOSYSTEM} but names no table, so there is nothing to build "
                    "and nothing for rio to read back.\n"
                    "  Add one to the manifest:\n"
                    "      transforms:\n"
                    "        - repair-purl:\n"
                    "            ecosystem: p2\n"
                    "            table: p2-maven.json"
                )
            scope = plan_scope(artifact_id, transform)

            if table in jobs:
                job = jobs[table]
                # Two artifacts sharing a table but filtering differently would
                # be harvested under one filter and read back under the other.
                # First wins is exactly the silence this tool exists to remove.
                for key, mine, theirs in zip(SCOPE_KEYS, scope, job.scope):
                    if mine != theirs:
                        raise fail(
                            f"artifacts {scoped_by[table]!r} and {artifact_id!r} both write "
                            f"{table}, but disagree on {key}: {theirs!r} and {mine!r}.\n"
                            "  One table cannot be harvested under two filters. Give them "
                            "the same setting, or a table each."
                        )
            else:
                jobs[table] = Job(
                    path=os.path.join(base, table) if not os.path.isabs(table) else table,
                    rel=table,
                    scope=scope,
                    sources=[],
                )
                scoped_by[table] = artifact_id

            sbom = ((artifact.get("input") or {}).get("path")) or ""
            if not sbom:
                raise fail(f"artifact {artifact_id!r}: the plan names no input path")
            jobs[table].sources.append(
                Source(artifact=artifact_id, path=os.path.join(base, sbom), rel=sbom)
            )

    if not jobs:
        raise fail(
            f"{manifest.get('path', 'the manifest')} declares no {REPAIR_PURL} with "
            f"ecosystem {ECOSYSTEM}; nothing to build."
        )
    return list(jobs.values())


# --------------------------------------------------------------------------
# Reading and writing the table
# --------------------------------------------------------------------------


def load_table(path: str) -> dict:
    """Read the table this run owns. A missing file is the bootstrap, not an error.

    A table rio would refuse to load is refused here too, and refused BEFORE
    any of it is rewritten. The alternative is spending a whole run producing a
    file rio still will not load, having destroyed what was there in the
    process. It is also what lets everything downstream -- the merge rules, the
    built-in delta -- take an entry for a coordinate pair without re-checking.
    """
    if not os.path.exists(path):
        return {}
    doc = read_json_document(path, "mapping table")

    if doc.get("schemaVersion") != SCHEMA_VERSION:
        raise fail(
            f"{path}: schemaVersion is {doc.get('schemaVersion')}, want {SCHEMA_VERSION}. "
            "rio would refuse to load this table, so it will not be rewritten."
        )

    entries = doc.get("entries") or {}
    if not isinstance(entries, dict):
        raise fail(f"{path}: entries is not an object. rio would refuse this table.")
    for bsn, entry in entries.items():
        if not isinstance(entry, dict):
            raise fail(f"{path}: entry {bsn!r} is not an object. rio would refuse this table.")
        for key in ("groupId", "artifactId"):
            # Half an entry is worse than no entry: it produces a purl with an
            # empty segment that looks resolvable and is not, which is why rio
            # rejects it rather than reading around it.
            value = entry.get(key)
            if not isinstance(value, str) or not value:
                raise fail(
                    f"{path}: entry {bsn!r} has no usable {key}. rio would refuse this "
                    "table, so it will not be rewritten."
                )
    return entries


def write_table(path: str, entries: dict) -> None:
    """Emit the table sorted, so a rerun that changes nothing produces no diff."""
    doc = {
        "schemaVersion": SCHEMA_VERSION,
        "entries": {k: entries[k] for k in sorted(entries)},
    }
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def is_derived(entry: dict) -> bool:
    """An entry this run owns.

    The confidence key is the whole rule. A derived entry records how it was
    arrived at and may be corrected on the next run; an entry without one was
    written by a human and is never touched. You pin an entry by DELETING its
    confidence key.
    """
    return isinstance(entry, dict) and "confidence" in entry


def same_coordinates(a: dict, b: dict) -> bool:
    return a.get("groupId") == b.get("groupId") and a.get("artifactId") == b.get("artifactId")


def merge_entries(existing: dict, resolved: dict, builtin: dict, overwrite: bool, prune: bool):
    """Merge this run's answers into the table that is already there.

    Four rules, each of which exists because its absence has a failure mode:

    - **Pinned entries are untouchable.** A coordinate a human decided outranks
      anything derived, and the confidence key is how the two are told apart.
    - **Never delete.** An entry this run produced no answer for -- an offline
      run against a thin cache, Central having a bad day, a --no-hash pass --
      is carried over unchanged. Otherwise a flaky network quietly shrinks the
      table and rio starts emitting unrepaired purls, which is the failure this
      whole tool exists to prevent. --prune opts into the deliberate rebuild.
    - **Never downgrade.** `inferred` is not proof and must not overwrite an
      entry something actually corroborated.
    - **Stay a delta over the built-in table.** An override always wins inside
      rio, so an entry that redundantly repeats a built-in one silently shadows
      every later fix rio makes to it. A derived entry identical to the built-in
      is left out; one that contradicts it is kept, because that is a deliberate
      local override, and flagged for review.

    Every entry in `existing` is a coordinate pair, because load_table refused
    the table otherwise. That is held at the boundary rather than re-checked
    here, in redundant_pins and in contradicts_builtin.

    Returns the new entries, the bucket each name landed in, and the coordinate
    changes worth showing a human.
    """
    pinned = {} if overwrite else {b: e for b, e in existing.items() if not is_derived(e)}
    derived = {b: e for b, e in existing.items() if b not in pinned}

    entries: dict[str, dict] = {}
    bucket: dict[str, str] = {}
    changed: list[tuple[str, dict, dict]] = []

    for bsn, entry in pinned.items():
        entries[bsn] = entry
        bucket[bsn] = "pinned"

    for bsn in set(derived) | set(resolved):
        if bsn in pinned:
            # Decided by a human. A stage that answered for it anyway is
            # ignored rather than allowed to win by arriving later.
            continue
        old = derived.get(bsn)
        hit = resolved.get(bsn)

        if hit is None:
            if prune:
                bucket[bsn] = "pruned"
                continue
            entries[bsn] = old
            bucket[bsn] = "carried"
            continue

        group, artifact, confidence, evidence = hit
        new = {
            "groupId": group,
            "artifactId": artifact,
            "confidence": confidence,
            "evidence": evidence,
        }

        if old is None:
            entries[bsn] = new
            bucket[bsn] = "new"
        elif not overwrite and confidence == INFERRED and old.get("confidence") in PROVEN:
            entries[bsn] = old
            bucket[bsn] = "carried"
        elif same_coordinates(old, new):
            entries[bsn] = new
            bucket[bsn] = "same"
        else:
            entries[bsn] = new
            bucket[bsn] = "changed"
            changed.append((bsn, old, new))

    # The built-in delta, applied to every derived entry in the finished table
    # and not only to this run's new ones, so a table that already carries
    # redundant entries heals across runs.
    for bsn in list(entries):
        if bucket[bsn] == "pinned":
            continue
        shipped = builtin.get(bsn)
        if shipped and same_coordinates(shipped, entries[bsn]):
            del entries[bsn]
            bucket[bsn] = "builtin"

    changed = [c for c in changed if c[0] in entries]
    return entries, bucket, changed


def redundant_pins(entries: dict, bucket: dict, builtin: dict) -> list[str]:
    """Pinned entries that merely repeat what rio already ships.

    They are left alone -- a human wrote them, and this run does not decide
    otherwise -- but they are worth pointing at: an override wins, so a pin
    identical to a built-in entry shadows every later fix rio makes to it while
    looking like it changes nothing.
    """
    return [
        bsn
        for bsn in sorted(entries)
        if bucket.get(bsn) == "pinned"
        and bsn in builtin
        and same_coordinates(builtin[bsn], entries[bsn])
    ]


def contradicts_builtin(entries: dict, bucket: dict, builtin: dict) -> list[tuple]:
    """Table entries that disagree with the asset rio ships.

    A deliberate local override is legitimate -- it is why overrides win at all
    -- but a client table disagreeing with the shipped one is exactly what a
    human should look at before it goes in.
    """
    out = []
    for bsn in sorted(entries):
        shipped = builtin.get(bsn)
        if shipped and not same_coordinates(shipped, entries[bsn]):
            out.append((bsn, shipped, entries[bsn], bucket.get(bsn) == "pinned"))
    return out


# --------------------------------------------------------------------------
# The review report
# --------------------------------------------------------------------------


def write_review(path, provenance, changed, contradicting, redundant, unresolved, inferred,
                 ambiguous, skipped):
    lines = ["# p2 table build report", ""]
    lines += provenance
    lines += [
        "",
        f"changed: {len(changed)}   unresolved: {len(unresolved)}"
        f"   inferred (unproven): {len(inferred)}   ambiguous: {len(ambiguous)}",
        "",
    ]
    if changed:
        lines += [
            "## Changed since last run",
            "",
            "This run derived a different coordinate than the table recorded, and took it.",
            "A coordinate flipping is the one thing worth looking at here. It is also what",
            "surfaces an edit made to a derived entry in place: delete an entry's",
            "`confidence` key to pin it, or the next run will move it back.",
            "",
        ]
        for bsn, old, new in sorted(changed):
            lines.append(
                f"- `{bsn}`: `{old.get('groupId')}:{old.get('artifactId')}`"
                f" ({old.get('confidence')}) -> `{new['groupId']}:{new['artifactId']}`"
                f" ({new['confidence']})"
            )
        lines.append("")
    if contradicting:
        lines += [
            "## Disagrees with rio's built-in table",
            "",
            "An override wins over the table compiled into rio, so these entries change what",
            "rio does. That is what overrides are for; it is still worth a look.",
            "",
        ]
        for bsn, shipped, ours, pinned in contradicting:
            how = "pinned by hand" if pinned else ours.get("confidence")
            lines.append(
                f"- `{bsn}`: rio ships `{shipped['groupId']}:{shipped['artifactId']}`,"
                f" this table says `{ours['groupId']}:{ours['artifactId']}` ({how})"
            )
        lines.append("")
    if redundant:
        lines += [
            "## Already in rio's built-in table",
            "",
            "These entries are pinned -- they carry no `confidence` key, so nothing here",
            "touches them -- and they say exactly what rio already ships. An override wins,",
            "so each one quietly shadows any later fix rio makes to that entry. Deleting",
            "them changes nothing today and lets those fixes through tomorrow.",
            "",
        ]
        for bsn in redundant:
            lines.append(f"- `{bsn}`")
        lines.append("")
    if inferred:
        lines += [
            "## Emitted but only inferred",
            "",
            "The coordinate resolves to a real artifact on Maven Central, but that",
            "artifact predates OSGi and carries no Bundle-SymbolicName, so nothing",
            "could prove the bundle was built from it. Confirm each before relying on it.",
            "",
        ]
        for bsn, group, artifact, evidence in sorted(inferred):
            lines.append(f"- `{bsn}` -> `{group}:{artifact}`  ({evidence})")
        lines.append("")
    if ambiguous:
        lines += [
            "## Ambiguous",
            "",
            "Several groupIds publish a jar declaring this symbolic name, so the",
            "manifest cannot say which one the bundle came from. Usually one is the",
            "canonical project and the rest are re-publishers. Pick by hand.",
            "",
        ]
        for bsn in sorted(ambiguous):
            lines.append(f"- `{bsn}` -> {ambiguous[bsn]}")
        lines.append("")
    if unresolved:
        lines += ["## Unresolved", "", "No channel produced a candidate.", ""]
        for bsn, version in sorted(unresolved):
            lines.append(f"- `{bsn}` @ `{version}`")
        lines.append("")
    if skipped:
        lines += ["## Excluded from the work-list", ""]
        for reason, names in sorted(skipped.items()):
            lines.append(f"- {reason}: {len(names)}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def resolve_work(fetcher: Fetcher, args, work: dict[str, Bundle]):
    """Run the three stages over one work-list. Hardest evidence first."""
    resolved: dict[str, tuple] = {}

    # Coordinates Eclipse asserts but Maven Central does not publish. Kept only
    # as a last resort, after the stages that can do better have had their turn.
    deferred: dict[str, tuple] = {}
    # BSNs several groupIds could plausibly claim. Reported, never emitted.
    ambiguous: dict[str, str] = {}

    def accept(bsn: str, hit) -> None:
        """Route a resolver result: ambiguity is a report, not an answer."""
        if not hit:
            return
        if hit[2] == AMBIGUOUS:
            ambiguous[bsn] = hit[3]
            return
        resolved[bsn] = hit

    # ---- stage 1 ---------------------------------------------------------
    if not args.no_p2:
        repos = args.p2_repos or list(DEFAULT_P2_REPOS)
        log(f"stage 1: Eclipse p2 metadata ({len(repos)} repositories)")
        p2_table = stage_p2_metadata(fetcher, repos)
        log(f"  {len(p2_table)} coordinates known to Eclipse")

        claimed = {}
        for bsn in work:
            hit = p2_table.get(bsn) or p2_table.get(strip_embedded_version(bsn))
            if hit:
                claimed[bsn] = hit

        # Eclipse asserting a coordinate is not the same as that coordinate
        # existing. A SimRel content.xml records the coordinate the bundle was
        # BUILT under, which for Eclipse's own reactor projects is an internal
        # groupId that was never published: org.eclipse.e4.ui.css.swt claims
        # eclipse.platform.ui, a git repository name, and the artifact actually
        # lives under org.eclipse.platform. Emitting the claim unchecked would
        # be exactly the confident-but-wrong coordinate this table must not
        # contain, so every one is confirmed against Central before it is
        # accepted, and the rest fall through to the stages below.
        log(f"  {len(claimed)} claimed; confirming each is published on Central")
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            published = list(
                pool.map(
                    lambda item: confirm_on_central(
                        fetcher, item[1][0], item[1][1], work[item[0]]
                    ),
                    claimed.items(),
                )
            )
        unpublished: list[tuple[str, str]] = []
        unknown = 0
        stale = 0
        absent = 0
        for (bsn, hit), verdict in zip(claimed.items(), published):
            entry = (hit[0], hit[1], ECLIPSE_ASSERTED, hit[2])
            if verdict == UNKNOWN:
                # Central never answered. Rejecting on that would let a flaky
                # network quietly shrink the table, so the claim is kept and
                # the count is reported for a rerun to settle.
                unknown += 1
                resolved[bsn] = entry
            elif verdict == ABSENT:
                absent += 1
                unpublished.append((bsn, hit[1]))
            elif verdict == WRONG_VERSION:
                # A real coordinate, but not one that ships this build. The
                # later stages get first refusal; this is only the fallback.
                stale += 1
                unpublished.append((bsn, hit[1]))
                deferred.setdefault(
                    bsn,
                    (hit[0], hit[1], INFERRED,
                     f"{hit[0]}:{hit[1]} (Eclipse metadata; version {bundle_version(work, bsn)} not on Central)"),
                )
            elif is_orbit(hit[0]):
                # Real, but a republication almost no vulnerability database
                # carries findings under. Let stage 2 look for the upstream
                # coordinate first and fall back to this only if it finds none.
                deferred[bsn] = entry
            else:
                resolved[bsn] = entry
        if absent:
            log(f"  {absent} name a coordinate Central does not publish at all")
        if stale:
            log(f"  {stale} exist on Central but not at this bundle's version")
        if unknown:
            log(f"  {unknown} could not be confirmed (network); kept, rerun to settle")
        if deferred:
            log(f"  deferred {len(deferred)} Orbit republications pending an upstream match")
        log(f"  resolved {len(resolved)}/{len(work)}")

        # Stage 1b. A rejected claim is not a dead end: Eclipse named the
        # artifactId correctly and only the groupId was a reactor coordinate,
        # so the artifactId is carried forward and the real groupId is looked
        # up. This is where the Eclipse Platform bundles come back, since no
        # split of org.eclipse.core.databinding ever proposes the
        # org.eclipse.platform that actually publishes it.
        if unpublished:
            log(f"stage 1b: re-finding the groupId for {len(unpublished)} Eclipse artifactIds")
            with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
                fast = list(
                    pool.map(
                        lambda item: resolve_in_known_groups(
                            fetcher, ECLIPSE_GROUPS, item[1], work[item[0]]
                        ),
                        unpublished,
                    )
                )
            still_unpublished = []
            for (bsn, artifact), hit in zip(unpublished, fast):
                if hit:
                    resolved[bsn] = hit
                else:
                    still_unpublished.append((bsn, artifact))
            log(f"  {len(unpublished) - len(still_unpublished)} found in the known Eclipse groupIds")
            if still_unpublished and args.search:
                throttle = Throttle()
                for bsn, artifact in still_unpublished:
                    accept(bsn, resolve_by_artifact_id(fetcher, throttle, artifact, work[bsn]))
            log(f"  resolved {len(resolved)}/{len(work)}")

    # ---- stage 2 ---------------------------------------------------------
    if not args.no_name_split:
        pending = [b for bsn, b in work.items() if bsn not in resolved]
        log(f"stage 2: Maven Central, proven by jar manifest ({len(pending)} names)")
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            for bundle, hit in zip(
                pending, pool.map(lambda b: resolve_by_name(fetcher, b), pending)
            ):
                if hit:
                    resolved[bundle.bsn] = hit
        log(f"  resolved {len(resolved)}/{len(work)}")

        # Eclipse publishes its own bundles with the artifactId equal to the
        # symbolic name, so for anything still missing the name is worth trying
        # as an artifactId in its own right before giving up.
        still = [b for bsn, b in work.items() if bsn not in resolved]
        if still:
            log(f"stage 2b: trying the symbolic name as an artifactId ({len(still)} names)")
            with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
                fast = list(
                    pool.map(
                        lambda b: resolve_in_known_groups(
                            fetcher, ECLIPSE_GROUPS, strip_embedded_version(b.bsn), b
                        ),
                        still,
                    )
                )
            remaining = []
            for bundle, hit in zip(still, fast):
                if hit:
                    resolved[bundle.bsn] = hit
                else:
                    remaining.append(bundle)
            log(f"  {len(still) - len(remaining)} found in the known Eclipse groupIds")
            if args.search:
                throttle = Throttle()
                for bundle in remaining:
                    accept(
                        bundle.bsn,
                        resolve_by_artifact_id(
                            fetcher, throttle, strip_embedded_version(bundle.bsn), bundle
                        ),
                    )
            log(f"  resolved {len(resolved)}/{len(work)}")
            if ambiguous:
                log(f"  {len(ambiguous)} left ambiguous between several groupIds")

    # ---- stage 3 ---------------------------------------------------------
    if not args.no_hash:
        poisoned = poisoned_hashes(list(work.values()))
        if poisoned:
            log(f"stage 3: ignoring {len(poisoned)} SHA-1 values shared by several components")
        pending = [
            b for bsn, b in work.items()
            if bsn not in resolved and b.sha1 and b.sha1 not in poisoned
        ]
        log(f"stage 3: Maven Central by exact SHA-1 ({len(pending)} usable hashes)")
        throttle = Throttle()
        for bundle in pending:
            hit = resolve_by_sha1(fetcher, throttle, bundle.sha1)
            if hit:
                resolved[bundle.bsn] = hit
        log(f"  resolved {len(resolved)}/{len(work)}")

    # Nothing better was found for these, so Eclipse's republication stands.
    for bsn, entry in deferred.items():
        resolved.setdefault(bsn, entry)

    return resolved, ambiguous


# --------------------------------------------------------------------------


def run_job(fetcher: Fetcher, args, plan: dict, job: Job, review_override: Optional[str]) -> None:
    """Build one table from the SBOMs the manifest points at it."""
    builtin = plan_builtin(plan)

    # ---- work-list -------------------------------------------------------
    bundles: dict[str, Bundle] = {}
    inferred_prefixes: list[str] = []
    for source in job.sources:
        found, prefix = read_sbom(source.path, job.scope)
        log(f"  {source.artifact}  {source.rel}   {len(found)} in-scope bundles")
        if prefix and not args.no_infer_first_party:
            inferred_prefixes.append(prefix)
        for b in found:
            bundles.setdefault(b.bsn, b)

    first_party = list(args.first_party)
    for prefix in inferred_prefixes:
        if prefix not in first_party:
            log(f"inferred first-party prefix from metadata.component: {prefix}")
            first_party.append(prefix)

    existing = load_table(job.path)
    if existing:
        log(f"{len(existing)} entries already in {job.rel}")

    # A pinned name costs no network: it is decided, and this run may not
    # touch it whatever it finds.
    pinned_names = set() if args.overwrite else {b for b, e in existing.items() if not is_derived(e)}

    skipped: dict[str, list] = {}
    work: dict[str, Bundle] = {}
    for bsn, bundle in bundles.items():
        if bsn in pinned_names:
            skipped.setdefault("pinned by hand", []).append(bsn)
        elif any(bsn == fp or bsn.startswith(fp + ".") for fp in first_party):
            skipped.setdefault("first-party", []).append(bsn)
        elif bsn.endswith(".source") and not args.include_source_bundles:
            skipped.setdefault("source bundle", []).append(bsn)
        else:
            work[bsn] = bundle

    log(f"{len(bundles)} distinct bundles, {len(work)} to resolve")
    for reason, names in sorted(skipped.items()):
        log(f"  excluded {len(names)} ({reason})")

    resolved, ambiguous = resolve_work(fetcher, args, work)

    # ---- merge and emit --------------------------------------------------
    entries, bucket, changed = merge_entries(
        existing, resolved, builtin, args.overwrite, args.prune
    )
    contradicting = contradicts_builtin(entries, bucket, builtin)
    redundant = redundant_pins(entries, bucket, builtin)
    write_table(job.path, entries)

    review_path = review_override or job.path + ".review.md"
    manifest = plan.get("manifest") or {}
    tool = plan.get("tool") or {}
    provenance = [
        f"Built by `tools/build-p2-table.py` from `{manifest.get('path', '?')}`",
        f"(sha256 `{manifest.get('sha256', '?')}`), as read by "
        f"{tool.get('name', 'rio')} {tool.get('version', '?')}.",
        "",
        "SBOMs read:",
        "",
    ] + [f"- `{s.artifact}` — `{s.rel}`" for s in job.sources]
    write_review(
        review_path,
        provenance,
        changed,
        contradicting,
        redundant,
        [
            (bsn, b.version)
            for bsn, b in sorted(work.items())
            if bsn not in resolved and bsn not in entries and bsn not in ambiguous
        ],
        [(bsn, v[0], v[1], v[3]) for bsn, v in resolved.items() if v[2] == INFERRED],
        ambiguous,
        skipped,
    )

    counts = Counter(bucket.values())
    log("")
    log(
        f"wrote {job.rel}: {len(entries)} entries: "
        f"{counts['new']} new, {counts['same']} re-derived unchanged, "
        f"{counts['carried']} carried over, {counts['changed']} changed, "
        f"{counts['pinned']} pinned"
    )
    if counts["builtin"]:
        log(f"  {counts['builtin']} left out as identical to rio's built-in table")
    if counts["pruned"]:
        log(f"  {counts['pruned']} dropped (--prune)")
    if contradicting:
        log(f"  {len(contradicting)} disagree with rio's built-in table")
    if redundant:
        log(f"  {len(redundant)} pinned entries repeat rio's built-in table; see the report")
    log(f"unresolved: {len(work) - len(resolved)}")
    log(f"review report: {review_path}")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Build the p2 bundle-symbolic-name to Maven coordinate table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--manifest", default="rio.yaml", help="rio manifest to read the wiring from")
    p.add_argument("--rio", default="rio", help="rio binary, if it is not on PATH")
    p.add_argument(
        "--plan",
        help="read a pre-computed `rio plan --json` from this file, or - for standard "
        "input, instead of running rio",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="let this run replace hand-written entries too, and let an inferred "
        "coordinate replace a proven one. Both rules exist for a reason; this lifts them",
    )
    p.add_argument(
        "--prune",
        action="store_true",
        help="drop derived entries this run found no answer for, instead of carrying "
        "them over. A deliberate rebuild, not something to run on a thin cache",
    )
    p.add_argument("--review", default=None, help="write the review report here (default: <table>.review.md)")
    p.add_argument("--cache", default=".p2cache", help="HTTP cache directory")
    p.add_argument("--offline", action="store_true", help="use only what is already cached")
    p.add_argument("--p2-repo", action="append", dest="p2_repos", metavar="URL",
                   help="p2 repository to harvest; repeatable, later wins. Defaults to SimRel + Orbit")
    p.add_argument("--no-p2", action="store_true", help="skip the Eclipse metadata stage")
    p.add_argument("--no-name-split", action="store_true", help="skip the name-split stage")
    p.add_argument(
        "--no-hash",
        action="store_true",
        help="skip the SHA-1 stage. It runs by default: it only asks about bundles "
        "the earlier stages left unresolved, and only those whose hash is not shared "
        "with another component, so it is usually a handful of requests",
    )
    p.add_argument(
        "--search",
        action="store_true",
        help="also ask search.maven.org which groupIds publish an artifactId, for names "
        "the repo1 stages could not settle. Off by default: on the estate this was built "
        "for it added nothing they had not already found, and it is slow because each "
        "answer costs a jar to verify. Unrelated to --no-hash, which has its own stage",
    )
    p.add_argument("--first-party-prefix", action="append", dest="first_party", default=[],
                   metavar="PREFIX", help="never map bundles under this prefix; repeatable")
    p.add_argument("--no-infer-first-party", action="store_true",
                   help="do not guess the first-party prefix from metadata.component")
    p.add_argument("--include-source-bundles", action="store_true",
                   help="also try to map .source bundles")
    p.add_argument("-j", "--jobs", type=int, default=6, help="concurrent Maven Central requests")
    args = p.parse_args()

    plan = load_plan(args)
    manifest = plan.get("manifest") or {}
    tool = plan.get("tool") or {}
    log(
        f"{manifest.get('path', '?')} (sha256 {str(manifest.get('sha256', ''))[:12]}...), "
        f"{tool.get('name', 'rio')} {tool.get('version', '?')}"
    )

    jobs = plan_jobs(plan)
    if args.review and len(jobs) > 1:
        # --review names one file and the run writes several reports.
        raise fail(
            f"--review names one file, but this manifest builds {len(jobs)} tables "
            f"({', '.join(sorted(j.rel for j in jobs))}). Drop --review and each table "
            "gets its own <table>.review.md."
        )

    fetcher = Fetcher(args.cache, offline=args.offline)
    for job in jobs:
        if len(jobs) > 1:
            log("")
            log(f"--- {job.rel} ---")
        run_job(fetcher, args, plan, job, args.review)

    log(f"cache: {fetcher.hits} hits, {fetcher.misses} fetches in {args.cache}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
