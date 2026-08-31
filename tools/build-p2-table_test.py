#!/usr/bin/env python3
"""Tests for build-p2-table.py. Standard library only, no network, no rio binary.

Every test drives the tool through --plan, with a plan built here rather than
produced by rio, and with the resolution stages replaced by a stub. That is
deliberate: what needs covering is the wiring and the merge rules, and neither
should need Maven Central to be up to be tested. The one test that does run the
stages runs them --offline against an empty cache, because "a colder cache
never shrinks the table" is an acceptance criterion rather than a nicety.

    python3 tools/build-p2-table_test.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile


def _load_tool():
    """Import build-p2-table.py, whose name is not an identifier."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "build-p2-table.py")
    spec = importlib.util.spec_from_file_location("build_p2_table", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def sbom(*components, subject_group="org.acme.product") -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "group": subject_group,
                "name": "product",
                "version": "1.0.0",
            }
        },
        "components": list(components),
    }


def p2_bundle(bsn, version="1.0.0", sha1=None, group="p2.eclipse.plugin"):
    component = {
        "type": "library",
        "group": group,
        "name": bsn,
        "version": version,
        "purl": f"pkg:p2/{bsn}@{version}?classifier=osgi.bundle",
    }
    if sha1:
        component["hashes"] = [{"alg": "SHA-1", "content": sha1}]
    return component


def transform(table="p2-maven.json", group_prefix="p2.", classifier="osgi.bundle",
              synthetic="p2.eclipse.plugin"):
    return {
        "name": "repair-purl",
        "ecosystem": "p2",
        "table": table,
        "groupPrefix": group_prefix,
        "classifier": classifier,
        "syntheticNamespace": synthetic,
    }


def entry(group, artifact, confidence=None, evidence="test"):
    """A table entry. No confidence key means a human wrote it."""
    out = {"groupId": group, "artifactId": artifact}
    if confidence:
        out["confidence"] = confidence
        out["evidence"] = evidence
    return out


def hit(group, artifact, confidence, evidence="test"):
    """What a resolver stage returns."""
    return (group, artifact, confidence, evidence)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def write_json(self, name, doc):
        path = self.path(name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def read_json(self, name):
        with open(self.path(name), encoding="utf-8") as fh:
            return json.load(fh)

    def read_text(self, name):
        with open(self.path(name), encoding="utf-8") as fh:
            return fh.read()

    def plan(self, artifacts, builtin=None, plan_version=1):
        return {
            "planVersion": plan_version,
            "tool": {"name": "rio", "version": "0.0.0-test"},
            "manifest": {"path": "rio.yaml", "dir": self.dir, "sha256": "abc123"},
            "out": "target/rio",
            "builtinTable": builtin or {},
            "artifacts": artifacts,
            "gate": {"require": ["name", "version", "purl"]},
        }

    def artifact(self, artifact_id, sbom_name, transforms=None):
        return {
            "id": artifact_id,
            "input": {"path": sbom_name},
            "output": {"path": artifact_id + ".cdx.json"},
            "transforms": [transform()] if transforms is None else transforms,
        }

    def run_tool(self, plan, *extra, resolved=None, ambiguous=None):
        """Run the tool over a plan, with the resolution stages stubbed out."""
        self.write_json("plan.json", plan)

        calls = []

        def stub(fetcher, args, work):
            calls.append(dict(work))
            answers = {} if resolved is None else {k: v for k, v in resolved.items() if k in work}
            return answers, dict(ambiguous or {})

        original = tool.resolve_work
        tool.resolve_work = stub
        self.addCleanup(setattr, tool, "resolve_work", original)

        ok, out = self.invoke("--plan", self.path("plan.json"), *extra)
        self.assertTrue(ok, "the run failed:\n" + out)
        return out, calls

    def invoke(self, *argv):
        """Call main() with argv.

        Returns whether it succeeded and everything it said, the refusal
        message included: a message a human can act on is the whole value of a
        refusal, so it is the thing worth asserting on.
        """
        err = io.StringIO()
        argv = ["build-p2-table.py", "--cache", self.path(".cache")] + list(argv)
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stderr(err):
                tool.main()
        except SystemExit as exc:
            return False, err.getvalue() + str(exc)
        finally:
            sys.argv = old
        return True, err.getvalue()

    def expect_failure(self, *argv):
        ok, out = self.invoke(*argv)
        self.assertFalse(ok, "the run was expected to fail:\n" + out)
        return out

    def expect_plan_failure(self, plan, *extra):
        self.write_json("plan.json", plan)
        return self.expect_failure("--plan", self.path("plan.json"), *extra)


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------


class PlanVersionTest(Base):
    def test_a_newer_plan_is_refused_by_number(self):
        message = self.expect_plan_failure(self.plan([], plan_version=2))
        self.assertIn("planVersion is 2", message)
        self.assertIn("Upgrade tools/build-p2-table.py", message)

    def test_an_older_or_missing_plan_version_says_to_upgrade_rio(self):
        for value in (None, 0, "1"):
            with self.subTest(value=value):
                doc = self.plan([])
                if value is None:
                    del doc["planVersion"]
                else:
                    doc["planVersion"] = value
                message = self.expect_plan_failure(doc)
                self.assertIn("planVersion", message)
                self.assertIn("Upgrade rio", message)

    def test_the_version_is_checked_before_the_content(self):
        # A plan this build cannot read must not be half-interpreted first.
        doc = self.plan([{"id": "broken"}], plan_version=99)
        self.assertIn("planVersion is 99", self.expect_plan_failure(doc))


class PlanSourceTest(Base):
    def test_rio_not_on_path_names_all_three_ways_out(self):
        message = self.expect_failure("--rio", self.path("no-such-rio"))
        self.assertIn("--rio", message)
        self.assertIn("--plan", message)
        self.assertIn("install rio", message)

    def test_a_failing_rio_plan_is_relayed_verbatim(self):
        fake = self.path("fake-rio")
        with open(fake, "w", encoding="utf-8") as fh:
            fh.write(
                "#!/bin/sh\n"
                'echo "rio: rio.yaml: artifacts[0].sbom: is required" >&2\n'
                "exit 2\n"
            )
        os.chmod(fake, 0o755)

        message = self.expect_failure("--rio", fake)
        # rio's own diagnostic names the offending field; re-phrasing it here
        # would lose exactly the part that helps.
        self.assertIn("artifacts[0].sbom: is required", message)
        self.assertIn("exited 2", message)

    def test_a_plan_can_come_from_standard_input(self):
        self.write_json("bom.json", sbom(p2_bundle("com.example.thing")))
        doc = self.plan([self.artifact("a", "bom.json")])

        original = tool.resolve_work
        tool.resolve_work = lambda fetcher, args, work: ({}, {})
        self.addCleanup(setattr, tool, "resolve_work", original)

        stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(doc))
        try:
            ok, out = self.invoke("--plan", "-")
        finally:
            sys.stdin = stdin
        self.assertTrue(ok, out)
        self.assertEqual(self.read_json("p2-maven.json")["schemaVersion"], 1)


class GroupingTest(Base):
    def test_artifacts_sharing_a_table_are_one_job(self):
        self.write_json("one.json", sbom(p2_bundle("com.example.one")))
        self.write_json("two.json", sbom(p2_bundle("com.example.two")))
        doc = self.plan([self.artifact("a", "one.json"), self.artifact("b", "two.json")])

        _, calls = self.run_tool(doc)
        self.assertEqual(len(calls), 1, "one table, one pass over both SBOMs")
        self.assertEqual(set(calls[0]), {"com.example.one", "com.example.two"})

    def test_two_tables_are_two_jobs_each_with_its_own_report(self):
        self.write_json("one.json", sbom(p2_bundle("com.example.one")))
        self.write_json("two.json", sbom(p2_bundle("com.example.two")))
        doc = self.plan([
            self.artifact("a", "one.json", [transform(table="first.json")]),
            self.artifact("b", "two.json", [transform(table="second.json")]),
        ])

        out, calls = self.run_tool(
            doc, resolved={"com.example.one": hit("g", "one", tool.MANIFEST_PROVEN),
                           "com.example.two": hit("g", "two", tool.MANIFEST_PROVEN)}
        )
        self.assertEqual(len(calls), 2)
        self.assertIn("com.example.one", self.read_json("first.json")["entries"])
        self.assertIn("com.example.two", self.read_json("second.json")["entries"])
        self.read_text("first.json.review.md")
        self.read_text("second.json.review.md")
        self.assertIn("first.json", out)
        self.assertIn("second.json", out)

    def test_an_artifact_with_no_p2_transform_is_skipped_out_loud(self):
        self.write_json("one.json", sbom(p2_bundle("com.example.one")))
        self.write_json("two.json", sbom(p2_bundle("com.example.two")))
        doc = self.plan([
            self.artifact("mapped", "one.json"),
            self.artifact("plain", "two.json", []),
        ])

        out, calls = self.run_tool(doc)
        self.assertIn("plain: no repair-purl with ecosystem p2; skipped", out)
        self.assertEqual(set(calls[0]), {"com.example.one"})

    def test_no_p2_transform_anywhere_is_an_error(self):
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        doc = self.plan([self.artifact("plain", "bom.json", [])])
        message = self.expect_plan_failure(doc)
        self.assertIn("no repair-purl with ecosystem p2", message)
        self.assertIn("nothing to build", message)

    def test_a_p2_transform_with_no_table_names_the_fix(self):
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        doc = self.plan([self.artifact("a", "bom.json", [transform(table="")])])
        message = self.expect_plan_failure(doc)
        self.assertIn("names no table", message)
        self.assertIn("table: p2-maven.json", message)

    def test_scope_keys_disagreeing_inside_one_table_is_an_error(self):
        for key, override in (
            ("groupPrefix", {"group_prefix": "acme."}),
            ("classifier", {"classifier": "osgi.fragment"}),
            ("syntheticNamespace", {"synthetic": "acme.plugin"}),
        ):
            with self.subTest(key=key):
                self.write_json("one.json", sbom(p2_bundle("com.example.one")))
                self.write_json("two.json", sbom(p2_bundle("com.example.two")))
                doc = self.plan([
                    self.artifact("first", "one.json"),
                    self.artifact("second", "two.json", [transform(**override)]),
                ])
                message = self.expect_plan_failure(doc)
                self.assertIn(key, message)
                self.assertIn("'first'", message)
                self.assertIn("'second'", message)

    def test_the_scope_filter_comes_from_the_plan(self):
        # The whole point: a manifest that overrides groupPrefix must produce a
        # table built under that same filter, with no default reasserted here.
        self.write_json("bom.json", sbom(
            p2_bundle("acme.in.scope", group="acme.plugin"),
            p2_bundle("p2.out.of.scope", group="p2.eclipse.plugin"),
        ))
        doc = self.plan([self.artifact("a", "bom.json", [transform(group_prefix="acme.")])])

        _, calls = self.run_tool(doc)
        self.assertEqual(set(calls[0]), {"acme.in.scope"})

    def test_a_plan_missing_a_scope_key_is_refused_rather_than_defaulted(self):
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        broken = transform()
        del broken["groupPrefix"]
        doc = self.plan([self.artifact("a", "bom.json", [broken])])
        self.assertIn("groupPrefix", self.expect_plan_failure(doc))

    def test_review_names_one_file_so_it_is_refused_for_several_tables(self):
        self.write_json("one.json", sbom(p2_bundle("com.example.one")))
        self.write_json("two.json", sbom(p2_bundle("com.example.two")))
        doc = self.plan([
            self.artifact("a", "one.json", [transform(table="first.json")]),
            self.artifact("b", "two.json", [transform(table="second.json")]),
        ])
        message = self.expect_plan_failure(doc, "--review", self.path("one.md"))
        self.assertIn("--review names one file", message)
        self.assertIn("first.json", message)
        self.assertIn("second.json", message)


# --------------------------------------------------------------------------
# The table
# --------------------------------------------------------------------------


class SchemaVersionTest(Base):
    def test_a_table_rio_would_refuse_is_never_rewritten(self):
        self.write_json("p2-maven.json", {"schemaVersion": 2, "entries": {"a.b": entry("g", "a")}})
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        doc = self.plan([self.artifact("a", "bom.json")])

        message = self.expect_plan_failure(doc)
        self.assertIn("schemaVersion is 2", message)
        # And the file is exactly as it was.
        self.assertEqual(self.read_json("p2-maven.json")["schemaVersion"], 2)


class CandidateTest(unittest.TestCase):
    """Which coordinates the name-split stage is even willing to consider.

    Nothing here is trusted -- every candidate still has to survive the jar
    check -- but a coordinate that is never proposed can never be found, and
    that is a silent miss rather than a reported one.
    """

    def test_the_group_can_be_the_whole_symbolic_name(self):
        # The commonest Java convention there is: the groupId is the package
        # root and the artifactId repeats its last label. Splitting only
        # BETWEEN labels can never reach it, so com.thoughtworks.xstream and
        # com.google.guava came back unresolved while sitting on Central under
        # a coordinate nobody had asked about.
        for bsn, want in (
            ("com.thoughtworks.xstream", ("com.thoughtworks.xstream", "xstream")),
            ("com.google.guava", ("com.google.guava", "guava")),
        ):
            with self.subTest(bsn=bsn):
                self.assertIn(want, tool.coordinate_candidates(bsn))

    def test_the_longest_group_is_still_offered_first(self):
        self.assertEqual(
            tool.coordinate_candidates("com.thoughtworks.xstream")[0],
            ("com.thoughtworks.xstream", "xstream"),
        )

    def test_the_splits_that_already_worked_still_come(self):
        candidates = tool.coordinate_candidates("org.glassfish.jersey.core.jersey-client")
        self.assertIn(("org.glassfish.jersey.core", "jersey-client"), candidates)
        # Note this one is the split's honest limit rather than the answer:
        # org.apache.commons.lang3 really is org.apache.commons:commons-lang3,
        # which no split proposes. That is what the curated table is for.
        self.assertIn(("org.apache.commons", "lang3"),
                      tool.coordinate_candidates("org.apache.commons.lang3"))

    def test_an_embedded_version_is_stripped_before_splitting(self):
        candidates = tool.coordinate_candidates(
            "com.fasterxml.jackson.core.jackson-annotations_2.10.2")
        self.assertIn(
            ("com.fasterxml.jackson.core.jackson-annotations", "jackson-annotations"),
            candidates)
        self.assertIn(("com.fasterxml.jackson.core", "jackson-annotations"), candidates)

    def test_a_one_label_name_still_yields_one_candidate(self):
        self.assertEqual(tool.coordinate_candidates("javassist"), [("javassist", "javassist")])

    def test_no_candidate_is_offered_twice(self):
        for bsn in ("com.thoughtworks.xstream", "javassist", "org.apache.commons.lang3"):
            with self.subTest(bsn=bsn):
                candidates = tool.coordinate_candidates(bsn)
                self.assertEqual(len(candidates), len(set(candidates)))


class FakeCentral:
    """Just enough of repo1 to drive the name-split stage with no network.

    artifacts maps (groupId, artifactId) to {version: Bundle-SymbolicName},
    where None means the jar carries no such header at all -- the distinction
    the whole inferred tier rests on.
    """

    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.fetched = []

    def _jar(self, bsn):
        buf = io.BytesIO()
        lines = "Manifest-Version: 1.0\r\n"
        if bsn:
            lines += f"Bundle-SymbolicName: {bsn}\r\n"
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("META-INF/MANIFEST.MF", lines)
        return buf.getvalue()

    def get(self, url, timeout=30):
        self.fetched.append(url)
        for (group, artifact), versions in self.artifacts.items():
            base = f"{tool.REPO1}/{group.replace('.', '/')}/{artifact}"
            if url == f"{base}/maven-metadata.xml":
                body = "".join(f"<version>{v}</version>" for v in versions)
                return f"<metadata><versioning><versions>{body}</versions></versioning></metadata>".encode()
            for version, bsn in versions.items():
                if url == f"{base}/{version}/{artifact}-{version}.jar":
                    return self._jar(bsn)
        return None

    def get_range(self, url, nbytes, timeout=30):
        data = self.get(url, timeout=timeout)
        return data[:nbytes] if data else None


class QualifiedVersionTest(unittest.TestCase):
    """An OSGi version cannot express a Maven qualifier.

    guava's 30.1-jre and 30.1-android are both the bundle's 30.1.0, and
    neither is spelled that way anywhere in the SBOM. Refusing to look at them
    leaves a coordinate that could be proven sitting at inferred.
    """

    def test_a_hyphen_qualifier_is_the_same_release(self):
        self.assertEqual(
            tool.qualified_versions(["30.1.0", "30.1"], ["30.1-jre", "30.1-android", "29.0"]),
            ["30.1-android", "30.1-jre"],
        )

    def test_a_dot_qualifier_is_the_same_release(self):
        self.assertEqual(
            tool.qualified_versions(["4.1.65"], ["4.1.65.Final", "4.1.64.Final"]),
            ["4.1.65.Final"],
        )

    def test_a_further_numeric_segment_is_a_different_release(self):
        # 30.1.1 is not 30.1. A Maven qualifier never begins with a digit,
        # which is exactly the distinction.
        self.assertEqual(tool.qualified_versions(["30.1"], ["30.1.1", "30.1.0"]), [])

    def test_an_exact_match_is_not_a_qualified_one(self):
        self.assertEqual(tool.qualified_versions(["30.1"], ["30.1"]), [])

    def test_an_unrelated_version_never_matches(self):
        self.assertEqual(tool.qualified_versions(["1.2"], ["1.20-jre", "11.2-jre"]), [])


class ResolveByNameTest(unittest.TestCase):
    """The name-split stage end to end, against a fake Central."""

    def resolve(self, artifacts, bsn, version):
        central = FakeCentral(artifacts)
        return central, tool.resolve_by_name(central, tool.Bundle(bsn, version, None))

    def test_a_qualified_version_can_prove_a_coordinate(self):
        # The guava shape: the bundle says 30.1.0, Central publishes 30.1-jre,
        # and the jar's own header settles it.
        _, hit = self.resolve(
            {("com.google.guava", "guava"): {"30.1-jre": "com.google.guava"}},
            "com.google.guava", "30.1.0.v20210127-2300")
        self.assertIsNotNone(hit)
        group, artifact, confidence, evidence = hit
        self.assertEqual((group, artifact), ("com.google.guava", "guava"))
        self.assertEqual(confidence, tool.MANIFEST_PROVEN)
        # The evidence says which variant was read, and why it is not the
        # version the bundle states.
        self.assertIn("30.1-jre", evidence)
        self.assertIn("30.1.0.v20210127-2300", evidence)

    def test_a_qualified_version_alone_never_stands_as_inferred(self):
        # No header means nothing proved it, and the variant was a guess on
        # top of that. Two guesses stacked is not an entry.
        _, hit = self.resolve(
            {("com.google.guava", "guava"): {"30.1-jre": None}},
            "com.google.guava", "30.1.0.v20210127-2300")
        self.assertIsNone(hit)

    def test_the_stated_version_with_no_header_still_stands_as_inferred(self):
        # The xstream shape, unchanged: Central publishes exactly this
        # version, and the jar predates OSGi.
        _, hit = self.resolve(
            {("com.thoughtworks.xstream", "xstream"): {"1.4.3": None}},
            "com.thoughtworks.xstream", "1.4.3")
        self.assertEqual(hit[:3], ("com.thoughtworks.xstream", "xstream", tool.INFERRED))

    def test_the_stated_version_is_preferred_over_a_qualified_one(self):
        central, hit = self.resolve(
            {("com.google.guava", "guava"): {"30.1": "com.google.guava", "30.1-jre": "com.google.guava"}},
            "com.google.guava", "30.1.0")
        self.assertIn("30.1", hit[3])
        self.assertNotIn("30.1-jre", hit[3])
        self.assertFalse([u for u in central.fetched if "30.1-jre" in u],
                         "a qualified variant was fetched although the stated version exists")

    def test_a_jar_declaring_another_bundle_is_still_rejected(self):
        _, hit = self.resolve(
            {("com.example.thing", "thing"): {"1.0-final": "com.example.somethingelse"}},
            "com.example.thing", "1.0.0")
        self.assertIsNone(hit)

    def test_a_different_release_is_not_reached_through_a_qualifier(self):
        _, hit = self.resolve(
            {("com.google.guava", "guava"): {"30.1.1": "com.google.guava"}},
            "com.google.guava", "30.1.0")
        self.assertIsNone(hit)


class MalformedInputTest(Base):
    """Nothing a person can mistype should reach a traceback.

    A refusal is a message that says what to fix; a stack trace is neither.
    These are the inputs that arrive from outside the tool -- a table, an
    SBOM, a plan -- and every way each of them can be wrong.
    """

    def setUp(self):
        super().setUp()
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        self.doc = self.plan([self.artifact("a", "bom.json")])

    def write_raw(self, name, text):
        with open(self.path(name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_a_table_that_is_not_json_is_refused(self):
        self.write_raw("p2-maven.json", "{ this is not json")
        message = self.expect_plan_failure(self.doc)
        self.assertIn("p2-maven.json", message)
        self.assertIn("not JSON", message)

    def test_a_table_that_is_not_an_object_is_refused(self):
        self.write_raw("p2-maven.json", "[]")
        message = self.expect_plan_failure(self.doc)
        self.assertIn("p2-maven.json", message)
        self.assertIn("not a JSON object", message)

    @unittest.skipIf(getattr(os, "geteuid", lambda: -1)() == 0,
                     "root ignores the mode bits this relies on")
    def test_an_unreadable_table_is_refused_by_name(self):
        self.write_json("p2-maven.json", {"schemaVersion": 1, "entries": {}})
        os.chmod(self.path("p2-maven.json"), 0o000)
        self.addCleanup(os.chmod, self.path("p2-maven.json"), 0o644)
        message = self.expect_plan_failure(self.doc)
        self.assertIn("p2-maven.json", message)
        self.assertNotIn("Traceback", message)

    def test_a_table_rio_could_not_decode_is_refused_rather_than_rewritten(self):
        # rio decodes each entry into a groupId/artifactId pair. Half an entry
        # makes a purl with an empty segment that looks resolvable and is not,
        # so rio refuses the file -- and a run that rewrote it in place would
        # have spent itself producing a table rio still will not load.
        for name, entries in (
            ("entries is not an object", "nope"),
            ("an entry is not an object", {"a.b": "nope"}),
            ("an entry has no groupId", {"a.b": {"artifactId": "a"}}),
            ("an entry has an empty artifactId", {"a.b": {"groupId": "g", "artifactId": ""}}),
            ("an entry has a non-string groupId", {"a.b": {"groupId": 7, "artifactId": "a"}}),
        ):
            with self.subTest(name):
                before = {"schemaVersion": 1, "entries": entries}
                self.write_json("p2-maven.json", before)
                message = self.expect_plan_failure(self.doc)
                self.assertIn("rio would refuse", message)
                self.assertNotIn("Traceback", message)
                self.assertEqual(self.read_json("p2-maven.json"), before,
                                 "a table rio refuses must not be rewritten")

    def test_a_malformed_sbom_is_refused_by_artifact(self):
        self.write_raw("bom.json", "{ truncated")
        message = self.expect_plan_failure(self.doc)
        self.assertIn("bom.json", message)
        self.assertIn("not JSON", message)
        self.assertNotIn("Traceback", message)

    def test_a_missing_plan_file_is_refused_by_name(self):
        message = self.expect_failure("--plan", self.path("no-such-plan.json"))
        self.assertIn("no-such-plan.json", message)
        self.assertNotIn("Traceback", message)

    def test_a_plan_whose_builtin_table_is_junk_is_refused(self):
        doc = self.plan([self.artifact("a", "bom.json")], builtin={"a.b": "not coordinates"})
        message = self.expect_plan_failure(doc)
        self.assertIn("builtinTable", message)
        self.assertNotIn("Traceback", message)

    def test_a_malformed_pin_cannot_reach_the_merge(self):
        # merge_entries and redundant_pins assume every entry is a coordinate
        # pair. That invariant is held at the boundary rather than re-checked
        # in each of them, so this asserts the boundary actually holds it --
        # including under --overwrite, which is the path that treats a pinned
        # entry as this run's to replace.
        self.write_json("p2-maven.json", {"schemaVersion": 1, "entries": {"a.b": "junk"}})
        for extra in ([], ["--overwrite"]):
            with self.subTest(extra=extra):
                message = self.expect_plan_failure(self.doc, *extra)
                self.assertIn("rio would refuse", message)
                self.assertNotIn("Traceback", message)


class MergeRulesTest(unittest.TestCase):
    """The merge rules on their own, where each one is a single assertion."""

    def merge(self, existing, resolved, builtin=None, overwrite=False, prune=False):
        return tool.merge_entries(existing, resolved, builtin or {}, overwrite, prune)

    def test_a_new_coordinate_is_added(self):
        entries, bucket, changed = self.merge({}, {"a.b": hit("g", "a", tool.MANIFEST_PROVEN)})
        self.assertEqual(entries["a.b"]["groupId"], "g")
        self.assertEqual(bucket["a.b"], "new")
        self.assertEqual(changed, [])

    def test_a_hand_written_entry_is_never_touched(self):
        existing = {"a.b": entry("human", "choice")}
        entries, bucket, _ = self.merge(existing, {"a.b": hit("robot", "guess", tool.HASH_EXACT)})
        self.assertEqual(entries["a.b"], {"groupId": "human", "artifactId": "choice"})
        self.assertEqual(bucket["a.b"], "pinned")

    def test_a_derived_entry_with_no_answer_is_carried_over(self):
        existing = {"a.b": entry("g", "a", tool.HASH_EXACT)}
        entries, bucket, _ = self.merge(existing, {})
        self.assertEqual(entries["a.b"], existing["a.b"])
        self.assertEqual(bucket["a.b"], "carried")

    def test_prune_drops_what_no_longer_resolves(self):
        existing = {"a.b": entry("g", "a", tool.HASH_EXACT), "c.d": entry("h", "c")}
        entries, bucket, _ = self.merge(existing, {}, prune=True)
        self.assertNotIn("a.b", entries)
        self.assertEqual(bucket["a.b"], "pruned")
        # A pin survives a prune: it was never this run's to drop.
        self.assertIn("c.d", entries)

    def test_inferred_never_overwrites_proven(self):
        for proven in (tool.ECLIPSE_ASSERTED, tool.MANIFEST_PROVEN, tool.HASH_EXACT):
            with self.subTest(proven=proven):
                existing = {"a.b": entry("right", "one", proven)}
                entries, bucket, changed = self.merge(
                    existing, {"a.b": hit("wrong", "guess", tool.INFERRED)}
                )
                self.assertEqual(entries["a.b"]["groupId"], "right")
                self.assertEqual(bucket["a.b"], "carried")
                self.assertEqual(changed, [])

    def test_proven_does_overwrite_inferred(self):
        existing = {"a.b": entry("guess", "one", tool.INFERRED)}
        entries, bucket, changed = self.merge(
            existing, {"a.b": hit("proven", "one", tool.MANIFEST_PROVEN)}
        )
        self.assertEqual(entries["a.b"]["groupId"], "proven")
        self.assertEqual(bucket["a.b"], "changed")
        self.assertEqual(len(changed), 1)

    def test_the_three_proven_kinds_are_not_ranked_against_each_other(self):
        existing = {"a.b": entry("old", "one", tool.ECLIPSE_ASSERTED)}
        entries, bucket, _ = self.merge(existing, {"a.b": hit("new", "one", tool.HASH_EXACT)})
        self.assertEqual(entries["a.b"]["groupId"], "new")
        self.assertEqual(bucket["a.b"], "changed")

    def test_a_re_derived_identical_coordinate_is_not_a_change(self):
        existing = {"a.b": entry("g", "a", tool.HASH_EXACT)}
        entries, bucket, changed = self.merge(
            existing, {"a.b": hit("g", "a", tool.MANIFEST_PROVEN)}
        )
        self.assertEqual(bucket["a.b"], "same")
        self.assertEqual(changed, [])
        # The evidence is refreshed even so, because it is this run's.
        self.assertEqual(entries["a.b"]["confidence"], tool.MANIFEST_PROVEN)

    def test_a_changed_coordinate_is_taken_and_reported(self):
        existing = {"a.b": entry("was", "a", tool.HASH_EXACT)}
        entries, bucket, changed = self.merge(
            existing, {"a.b": hit("now", "a", tool.HASH_EXACT)}
        )
        self.assertEqual(entries["a.b"]["groupId"], "now")
        self.assertEqual(bucket["a.b"], "changed")
        self.assertEqual(changed[0][0], "a.b")
        self.assertEqual(changed[0][1]["groupId"], "was")
        self.assertEqual(changed[0][2]["groupId"], "now")

    def test_a_derived_entry_identical_to_the_builtin_is_left_out(self):
        builtin = {"a.b": {"groupId": "g", "artifactId": "a"}}
        entries, bucket, _ = self.merge({}, {"a.b": hit("g", "a", tool.HASH_EXACT)}, builtin)
        self.assertNotIn("a.b", entries)
        self.assertEqual(bucket["a.b"], "builtin")

    def test_an_existing_redundant_entry_heals_away(self):
        builtin = {"a.b": {"groupId": "g", "artifactId": "a"}}
        existing = {"a.b": entry("g", "a", tool.HASH_EXACT)}
        entries, bucket, _ = self.merge(existing, {}, builtin)
        self.assertNotIn("a.b", entries)
        self.assertEqual(bucket["a.b"], "builtin")

    def test_an_entry_contradicting_the_builtin_is_kept(self):
        builtin = {"a.b": {"groupId": "shipped", "artifactId": "a"}}
        entries, bucket, _ = self.merge({}, {"a.b": hit("ours", "a", tool.HASH_EXACT)}, builtin)
        self.assertEqual(entries["a.b"]["groupId"], "ours")
        self.assertEqual(bucket["a.b"], "new")
        flagged = tool.contradicts_builtin(entries, bucket, builtin)
        self.assertEqual(flagged[0][0], "a.b")

    def test_a_redundant_pin_is_reported_rather_than_removed(self):
        builtin = {"a.b": {"groupId": "g", "artifactId": "a"}}
        entries, bucket, _ = self.merge({"a.b": entry("g", "a")}, {}, builtin)
        self.assertEqual(tool.redundant_pins(entries, bucket, builtin), ["a.b"])
        # A pin that says something different is an override, not a repetition.
        entries, bucket, _ = self.merge({"a.b": entry("other", "a")}, {}, builtin)
        self.assertEqual(tool.redundant_pins(entries, bucket, builtin), [])

    def test_a_pinned_entry_identical_to_the_builtin_stays(self):
        # It is redundant, but a human wrote it, and this run does not decide
        # that for them.
        builtin = {"a.b": {"groupId": "g", "artifactId": "a"}}
        entries, bucket, _ = self.merge({"a.b": entry("g", "a")}, {}, builtin)
        self.assertIn("a.b", entries)
        self.assertEqual(bucket["a.b"], "pinned")

    def test_overwrite_lifts_both_rules(self):
        existing = {
            "pinned.one": entry("human", "choice"),
            "proven.one": entry("right", "one", tool.HASH_EXACT),
        }
        resolved = {
            "pinned.one": hit("robot", "guess", tool.HASH_EXACT),
            "proven.one": hit("wrong", "guess", tool.INFERRED),
        }
        entries, bucket, _ = self.merge(existing, resolved, overwrite=True)
        self.assertEqual(entries["pinned.one"]["groupId"], "robot")
        self.assertEqual(entries["proven.one"]["groupId"], "wrong")
        self.assertNotIn("pinned", bucket.values())


class MergeThroughTheToolTest(Base):
    """The same rules, reached the way a user reaches them."""

    def setUp(self):
        super().setUp()
        self.write_json("bom.json", sbom(
            p2_bundle("com.example.pinned"),
            p2_bundle("com.example.derived"),
            p2_bundle("com.example.fresh"),
        ))

    def test_a_pinned_name_costs_no_network(self):
        self.write_json("p2-maven.json", {
            "schemaVersion": 1,
            "entries": {"com.example.pinned": entry("human", "choice")},
        })
        doc = self.plan([self.artifact("a", "bom.json")])

        out, calls = self.run_tool(doc)
        self.assertNotIn("com.example.pinned", calls[0])
        self.assertIn("pinned by hand", out)
        self.assertEqual(
            self.read_json("p2-maven.json")["entries"]["com.example.pinned"],
            {"groupId": "human", "artifactId": "choice"},
        )

    def test_the_summary_reports_what_happened(self):
        self.write_json("p2-maven.json", {
            "schemaVersion": 1,
            "entries": {
                "com.example.pinned": entry("human", "choice"),
                "com.example.derived": entry("was", "d", tool.HASH_EXACT),
                "com.example.gone": entry("g", "gone", tool.HASH_EXACT),
            },
        })
        doc = self.plan([self.artifact("a", "bom.json")])

        out, _ = self.run_tool(doc, resolved={
            "com.example.derived": hit("now", "d", tool.HASH_EXACT),
            "com.example.fresh": hit("g", "f", tool.MANIFEST_PROVEN),
        })
        self.assertIn(
            "wrote p2-maven.json: 4 entries: 1 new, 0 re-derived unchanged, "
            "1 carried over, 1 changed, 1 pinned",
            out,
        )

    def test_the_review_report_says_what_it_was_built_from(self):
        doc = self.plan([self.artifact("sample.product", "bom.json")])
        self.run_tool(doc, resolved={"com.example.fresh": hit("g", "f", tool.INFERRED)})

        report = self.read_text("p2-maven.json.review.md")
        self.assertIn("rio.yaml", report)
        self.assertIn("abc123", report)
        self.assertIn("rio 0.0.0-test", report)
        self.assertIn("`sample.product`", report)
        self.assertIn("`bom.json`", report)

    def test_the_review_report_shows_a_changed_coordinate(self):
        self.write_json("p2-maven.json", {
            "schemaVersion": 1,
            "entries": {"com.example.derived": entry("was", "d", tool.HASH_EXACT)},
        })
        doc = self.plan([self.artifact("a", "bom.json")])
        self.run_tool(doc, resolved={"com.example.derived": hit("now", "d", tool.HASH_EXACT)})

        report = self.read_text("p2-maven.json.review.md")
        self.assertIn("## Changed since last run", report)
        self.assertIn("`was:d`", report)
        self.assertIn("`now:d`", report)
        # The reader is told how to stop it happening again.
        self.assertIn("`confidence`", report)

    def test_the_review_report_flags_a_disagreement_with_the_builtin(self):
        doc = self.plan(
            [self.artifact("a", "bom.json")],
            builtin={"com.example.fresh": {"groupId": "shipped", "artifactId": "f"}},
        )
        out, _ = self.run_tool(doc, resolved={"com.example.fresh": hit("ours", "f", tool.HASH_EXACT)})

        report = self.read_text("p2-maven.json.review.md")
        self.assertIn("## Disagrees with rio's built-in table", report)
        self.assertIn("shipped:f", report)
        self.assertIn("ours:f", report)
        self.assertIn("disagree with rio's built-in table", out)

    def test_an_entry_the_binary_already_ships_is_not_repeated(self):
        doc = self.plan(
            [self.artifact("a", "bom.json")],
            builtin={"com.example.fresh": {"groupId": "g", "artifactId": "f"}},
        )
        out, _ = self.run_tool(doc, resolved={"com.example.fresh": hit("g", "f", tool.HASH_EXACT)})

        self.assertNotIn("com.example.fresh", self.read_json("p2-maven.json")["entries"])
        self.assertIn("left out as identical to rio's built-in table", out)

    def test_the_table_is_written_where_the_manifest_says(self):
        doc = self.plan([self.artifact("a", "bom.json", [transform(table="mappings/p2.json")])])
        self.run_tool(doc, resolved={"com.example.fresh": hit("g", "f", tool.HASH_EXACT)})
        self.assertIn("com.example.fresh", self.read_json("mappings/p2.json")["entries"])

    def test_a_rerun_that_changes_nothing_produces_no_diff(self):
        doc = self.plan([self.artifact("a", "bom.json")])
        answers = {"com.example.fresh": hit("g", "f", tool.HASH_EXACT)}
        self.run_tool(doc, resolved=answers)
        first = self.read_text("p2-maven.json")
        self.run_tool(doc, resolved=answers)
        self.assertEqual(first, self.read_text("p2-maven.json"))

    def test_first_party_bundles_are_excluded(self):
        self.write_json("bom.json", sbom(
            p2_bundle("com.example.acme.internal"),
            p2_bundle("org.third.party"),
            subject_group="com.example.acme.product",
        ))
        doc = self.plan([self.artifact("a", "bom.json")])
        out, calls = self.run_tool(doc)
        self.assertEqual(set(calls[0]), {"org.third.party"})
        self.assertIn("first-party", out)


class OfflineTest(Base):
    """A colder cache must never shrink the table.

    This is the one test that runs the real stages. --offline against an empty
    cache is the worst case they can be in: nothing can be answered, so nothing
    may be concluded, and every entry already in the table has to survive.
    """

    def test_an_offline_run_with_an_empty_cache_keeps_every_entry(self):
        self.write_json("bom.json", sbom(p2_bundle("com.example.one")))
        self.write_json("p2-maven.json", {
            "schemaVersion": 1,
            "entries": {
                "com.example.one": entry("g", "one", tool.HASH_EXACT),
                "com.example.gone": entry("g", "gone", tool.ECLIPSE_ASSERTED),
                "com.example.human": entry("human", "choice"),
            },
        })
        self.write_json("plan.json", self.plan([self.artifact("a", "bom.json")]))

        ok, out = self.invoke("--plan", self.path("plan.json"), "--offline")
        self.assertTrue(ok, out)

        entries = self.read_json("p2-maven.json")["entries"]
        self.assertEqual(len(entries), 3, "an offline run dropped an entry")
        self.assertEqual(entries["com.example.human"], {"groupId": "human", "artifactId": "choice"})
        self.assertIn("0 new", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
