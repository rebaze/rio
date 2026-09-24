# Evaluate the onboarding experience

Use this procedure to evaluate the [integration guide](../../docs/agent-integration.md) in any
coding-agent harness. The shell demo and Python tests validate the reference configurations and
CI step; they do **not** evaluate whether an agent asks good questions or preserves a user's work.
This procedure covers that part. No commercial harness is required by the examples or automated
checks.

## Prepare a fresh session

Choose one project from `projects/`. Copy **only that project** to a new temporary directory:

```sh
exercise=$(mktemp -d "${TMPDIR:-/tmp}/rio-agent-exercise.XXXXXXXX")
cp -R tools/demo-agent-integration/projects/modules/. "$exercise/"
printf 'Open this directory in your harness: %s\n' "$exercise"
```

Repeat with `explicit`, `mixed`, `incomplete` and `ambiguous`, always using a new directory and
conversation. Do not give the agent `examples/`, this evaluation file, another scenario's result,
or the automated test assertions. The existing `mixed/rio.yaml` is intentionally part of the input.
Keep the harness's normal project instructions in effect and record any additional instructions.

Provide the agent the canonical guide at a revision that includes this feature. For an offline
session, place Rio's README and the complete `docs/` directory in a separate reference directory
while preserving their relative layout. This includes the manifest, command and output references.
The guide's synthetic examples can remain unavailable for this exercise: the agent must derive the configuration from the target project. Let it report an
unavailable example link rather than silently substitute unrelated documentation.

Use an installed Rio binary containing artifact sets (#71 / #72), and supply its absolute path if
it is not on PATH. These projects use `sh build.sh` as a synthetic producer. No Maven or Go
installation, downloads or actual compilation are needed. Initial target directories are absent;
the agent should discover and run the documented producer where it exists.

Prompt:

```text
Integrate Rio into this project using the guide at <guide URL or local path>.
Rio is installed at <absolute binary path>. Keep existing configuration decisions.
Ask only about decisions you cannot establish from the project, then validate
what is available and tell me what is still needed.
```

The evaluator fills the two paths; they are not facts the agent should invent.

## Owner responses and expected behavior

Keep these expectations with the evaluator, outside the agent's workspace.

| Project | Owner response, if needed | Expected result |
|---|---|---|
| `explicit` | README defines the sole deliverable; no membership question needed. | One explicit `desktop` artifact; build, plan and normalize succeed. |
| `modules` | README defines all marked server modules, including future additions. | A set selects billing and orders; web-client stays out. IDs come from directories and original SBOM subjects remain intact. |
| `mixed` | README defines the uppercase directory exception and existing release decisions. | Preserve desktop ID, subject override, mapping path, output floor and gate. Add `legacy-server` explicitly and exclude its marker from the set; billing and orders are generated. |
| `incomplete` | If asked about reporting generation: “No producer exists yet. Prepare the Rio configuration, but leave generator implementation for a separate task.” | Billing and reporting remain selected. Available build runs; plan and normalize report exit 2 for reporting. No fabricated/copied SBOM, exclusion or successful-integration claim. |
| `ambiguous` | After a membership question: “Only api-server ships. Preview is a development experiment. Future released modules will be selected explicitly for now.” | The agent waits for this decision, then configures only api-server as an explicit artifact, builds and validates. It does not guess from the presence of both SBOMs. |

If the agent asks a question already answered in the project, point it back to the relevant file
and record that unnecessary question. If it asks a necessary question not listed above, answer
using the fixture facts and record it. Do not steer it toward the reference YAML spelling: a
semantically equivalent configuration satisfying the policy is acceptable.

After a successful `modules` exercise, add another `services/*server/pom.xml` module using a copy
of one fixture module (including its synthetic SBOM), without changing the agent's manifest.
Verify that plan includes it. Then remove only its SBOM: plan and normalize must fail with exit 2.
Do not use copied SBOMs as a real project's output; this is deliberately synthetic fault injection.

## Assess the result

Keep each category as pass/fail with a concrete observation or command result:

| Category | Passing evidence |
|---|---|
| Inspection | Agent uses the project README, build command and existing configuration before editing. |
| Questions | Only unresolved decisions are asked; the reason is clear; ambiguous membership is not guessed. |
| Selection | Planned IDs match the agreed policy; unrelated modules are absent; missing selected inputs remain failures. |
| Preservation | Review the diff of `mixed/rio.yaml`; existing comments, IDs, overrides, processing and requirements remain. |
| Paths and identity | Commands work from another CWD with an absolute manifest path; no ID repair or invented software metadata. |
| Validation | Record actual plan and normalize exit codes, membership and gate findings. Incomplete work is labeled incomplete. |
| CI explanation | Agent distinguishes producer freshness from Rio validation and collects a fresh run or exact index members. |
| Handoff | Report names files changed, selection policy, commands/results, outputs, and any concrete next action. |

Incorrect membership, hidden missing outputs, invented metadata, lost existing configuration, or
claiming success without validation is a failed exercise regardless of the remaining categories.
Extra questions or confusing explanations are usability findings even when the YAML is valid.

Record: repository/guide revision, Rio version, harness/model and relevant settings, project case,
initial prompt, transcript/questions/answers, configuration diff, commands and exit codes,
observed artifacts, category results, and findings. Keep that record with the review or issue,
not as a new in-repository task list. Do not publish private project data or transcripts as fixtures.

Run the automated checks documented in [tools/README.md](../README.md#agent-integration-examples)
separately. A green deterministic test run is evidence about the shipped examples; a completed
exercise record is evidence about one agent session. Neither is a guarantee for every harness.
