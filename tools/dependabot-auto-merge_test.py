"""Exercise the real auto-merge workflow shell offline with fake GitHub API responses.

Only gh and sleep are stubbed. The production jq policy and merge command run
unchanged, and every attempted mutation must match the scenario's expectation.
Requires Python 3.9+, bash and jq. Never contacts GitHub or merges a real PR.
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap

workflow = (
    Path(__file__).resolve().parents[1] / ".github/workflows/dependabot-auto-merge.yaml"
).read_text()
script = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
head = "a" * 40
merge_request = [
    "api",
    "--method",
    "PUT",
    "repos/rebaze/rio/pulls/99/merge",
    "-f",
    "sha=" + head,
    "-f",
    "merge_method=merge",
    "--jq",
    ".merged",
]
base_metadata = [
    dict(
        targetBranch="main",
        maintainerChanges=False,
        packageEcosystem="go_modules",
        dependencyGroup="security-go",
        updateType="version-update:semver-patch",
    )
]
base_commits = [
    dict(
        sha=head,
        author=dict(login="dependabot[bot]"),
        commit=dict(verification=dict(verified=True)),
    )
]
base_current = dict(
    head=dict(sha=head),
    auto_merge=None,
    state="open",
    base=dict(ref="main"),
    draft=False,
)
cases = []


def add(name, metadata=None, commits=None, current=None, expected="none"):
    cases.append(
        (
            name,
            base_metadata if metadata is None else metadata,
            base_commits if commits is None else commits,
            base_current if current is None else current,
            expected,
        )
    )


add("security patch", expected="enable")
add(
    "security minor",
    metadata=[dict(base_metadata[0], updateType="version-update:semver-minor")],
    expected="enable",
)
add(
    "actions security group",
    metadata=[
        dict(
            base_metadata[0],
            packageEcosystem="github_actions",
            dependencyGroup="security-actions",
        )
    ],
    expected="enable",
)
add(
    "upstream maintainer changes",
    metadata=[dict(base_metadata[0], maintainerChanges=True)],
)
add(
    "unknown maintainer status",
    metadata=[dict(base_metadata[0], maintainerChanges=None)],
)
add(
    "configuration ecosystem is not branch metadata",
    metadata=[dict(base_metadata[0], packageEcosystem="gomod")],
)
add("routine version update", metadata=[dict(base_metadata[0], dependencyGroup="")])
add(
    "major security update",
    metadata=[dict(base_metadata[0], updateType="version-update:semver-major")],
)
add(
    "mixed patch and unknown",
    metadata=base_metadata + [dict(base_metadata[0], updateType="")],
)
add(
    "mixed patch and major",
    metadata=base_metadata
    + [dict(base_metadata[0], updateType="version-update:semver-major")],
)
add("empty metadata", metadata=[])
add("malformed metadata", metadata="invalid json")
add(
    "wrong ecosystem group",
    metadata=[dict(base_metadata[0], packageEcosystem="github_actions")],
)
add("wrong target branch", metadata=[dict(base_metadata[0], targetBranch="release")])
add("multiple commits", commits=base_commits + base_commits)
unsigned = copy.deepcopy(base_commits)
unsigned[0]["commit"]["verification"]["verified"] = False
add("unverified commit", commits=unsigned)
human = copy.deepcopy(base_commits)
human[0]["author"]["login"] = "maintainer"
add("human commit", commits=human)
add("retargeted PR", current=dict(base_current, base=dict(ref="other")))
add("converted to draft", current=dict(base_current, draft=True))
add("closed PR", current=dict(base_current, state="closed"))
add("stale event", current=dict(base_current, head=dict(sha="b" * 40)))
wrong_head = copy.deepcopy(base_commits)
wrong_head[0]["sha"] = "b" * 40
add("commit head mismatch", commits=wrong_head)
add(
    "manually edited PR",
    commits=human,
    current=dict(base_current, auto_merge={}),
    expected="none",
)
add(
    "missing metadata cannot merge",
    metadata=[],
    current=dict(base_current, auto_merge={}),
    expected="none",
)
with tempfile.TemporaryDirectory(prefix="rio-auto-merge-test-") as tmp:
    p = Path(tmp)
    (p / "gh").write_text("""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if args[:3] == ['api', '--method', 'PUT']:
    with Path(os.environ['TEST_CALLS']).open('a') as f:
        f.write(json.dumps(args) + '\\n')
    print(os.environ.get('TEST_MERGE_REPLY', 'true'))
    sys.exit(int(os.environ.get('TEST_MERGE_EXIT', '0')))
elif args[:2] == ['pr', 'checks']:
    print(os.environ.get('TEST_CHECKS', '[{"name":"build","bucket":"pass"},{"name":"Analyze Go","bucket":"pass"}]'))
elif args[:2] == ['api', 'graphql']:
    states = json.loads(os.environ.get('TEST_BODY_STATES', '[{"body":"Dependabot update","lastEditedAt":null,"editor":null,"author":"bot-id"}]'))
    counter = Path(os.environ['TEST_CALLS'] + '.body-count')
    index = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(index + 1))
    print(json.dumps(states[min(index, len(states) - 1)]))
elif args[0] == 'api':
    print(os.environ['TEST_COMMITS'] if '/commits?' in args[1] else os.environ['TEST_CURRENT'])
else:
    with Path(os.environ['TEST_CALLS']).open('a') as f:
        f.write(json.dumps(args) + '\\n')
""")
    (p / "gh").chmod(0o755)
    (p / "sleep").write_text("#!/bin/sh\nexit 0\n")
    (p / "sleep").chmod(0o755)
    for name, metadata, commits, current, expected in cases:
        calls = p / "calls"
        calls.write_text("")
        env = dict(
            os.environ,
            PATH=str(p) + os.pathsep + os.environ["PATH"],
            PR_NUMBER="99",
            PR_HEAD=head,
            PR_BODY="Dependabot update",
            GH_REPO="rebaze/rio",
            GH_TOKEN="test",
            TEST_CHECKS='[{"name":"build","bucket":"pass"},{"name":"Analyze Go","bucket":"pass"}]',
            METADATA=metadata if isinstance(metadata, str) else json.dumps(metadata),
            TEST_COMMITS=json.dumps(commits),
            TEST_CURRENT=json.dumps(current),
            TEST_CALLS=str(calls),
        )
        result = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, (name, result.stderr)
        invoked = [json.loads(line) for line in calls.read_text().splitlines()]
        want = (
            []
            if expected == "none"
            else [
                merge_request,
                ["workflow", "run", "scorecard.yaml", "--ref", "main"],
            ]
        )
        assert invoked == want, (name, invoked, want)
        print("PASS", name)
    (p / "sleep").write_text("#!/bin/sh\nexit 0\n")
    (p / "sleep").chmod(0o755)
    baseline_body = dict(
        body="Dependabot update", lastEditedAt=None, editor=None, author="bot-id"
    )
    bot_edit = dict(baseline_body, lastEditedAt="2026-09-12T15:00:00Z", editor="bot-id")
    body_cases = [
        ("unchanged bot-edited body", [bot_edit], True),
        ("human removed marker before run", [dict(bot_edit, editor="human-id")], False),
        ("unknown body editor", [dict(bot_edit, editor=None)], False),
        ("body differs from event", [dict(baseline_body, body="changed")], False),
        (
            "marker added while waiting",
            [baseline_body, dict(bot_edit, body="Maintainer changes")],
            False,
        ),
        ("body reverted after edit", [baseline_body, bot_edit], False),
        (
            "body changed during check query",
            [baseline_body, baseline_body, bot_edit],
            False,
        ),
    ]
    for name, states, allowed in body_cases:
        calls.write_text("")
        Path(str(calls) + ".body-count").unlink(missing_ok=True)
        env.update(
            METADATA=json.dumps(base_metadata),
            TEST_COMMITS=json.dumps(base_commits),
            TEST_CURRENT=json.dumps(base_current),
            TEST_BODY_STATES=json.dumps(states),
        )
        result = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, (name, result.stderr)
        invoked = [json.loads(line) for line in calls.read_text().splitlines()]
        want = (
            [
                merge_request,
                ["workflow", "run", "scorecard.yaml", "--ref", "main"],
            ]
            if allowed
            else []
        )
        assert invoked == want, (name, invoked, want)
        print("PASS", name)
    env.pop("TEST_BODY_STATES", None)
    merge_cases = [("merge refused", "false", "0"), ("merge API failure", "", "1")]
    for name, reply, status in merge_cases:
        calls.write_text("")
        env.update(
            METADATA=json.dumps(base_metadata),
            TEST_COMMITS=json.dumps(base_commits),
            TEST_CURRENT=json.dumps(base_current),
            TEST_MERGE_REPLY=reply,
            TEST_MERGE_EXIT=status,
        )
        result = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        assert result.returncode != 0, name
        invoked = [json.loads(line) for line in calls.read_text().splitlines()]
        assert invoked == [merge_request], (name, invoked)
        print("PASS", name, "does not dispatch post-merge verification")
    env.pop("TEST_MERGE_REPLY", None)
    env.pop("TEST_MERGE_EXIT", None)
    for name, checks in [
        ("failed", '[{"name":"build","bucket":"fail"}]'),
        ("cancelled", '[{"name":"build","bucket":"cancel"}]'),
        ("pending", '[{"name":"build","bucket":"pending"}]'),
        ("missing", "[]"),
        (
            "skipped",
            '[{"name":"build","bucket":"skipping"},{"name":"Analyze Go","bucket":"pass"}]',
        ),
        ("malformed", "error"),
    ]:
        calls.write_text("")
        env.update(
            METADATA=json.dumps(base_metadata),
            TEST_COMMITS=json.dumps(base_commits),
            TEST_CURRENT=json.dumps(base_current),
            TEST_CHECKS=checks,
        )
        result = subprocess.run(
            ["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        assert not calls.read_text(), (name, calls.read_text())
        assert result.returncode == (0 if name in ("failed", "cancelled") else 1), (
            name,
            result.stderr,
        )
        print("PASS", name, "checks do not merge")
print(len(cases) + len(body_cases) + len(merge_cases) + 6, "policy scenarios passed")
