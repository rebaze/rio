#!/usr/bin/env python3
"""The walkthrough itself: what is run, what to look for, and what is said.

Everything specific to this video lives here. `capture.py` executes the commands and
records their real output; `render.py` draws them. Neither holds an opinion about the
content, so a re-recording against a later Rio release only changes this file.

Python 3.9+, standard library only.
"""

VIDEO_ID = "rio-context-demo"
TITLE = "Rio — source and build context"
SUBTITLE = "Source and build context"
FEATURE = "PR #66"
FEATURE_URL = "https://github.com/rebaze/rio/pull/66"
ISSUE_URL = "https://github.com/rebaze/rio/issues/62"

# The approved narration direction. It is part of the TTS cache key: changing a word
# here invalidates every clip, which is the intended behaviour.
VOICE_PROVIDER = "google"
VOICE_MODEL = "gemini-3.1-flash-tts-preview"
VOICE_NAME = "Charon"
VOICE_DIRECTION = (
    "Speak as a calm, experienced software developer walking a colleague through a terminal demo. "
    "Natural conversational American English, warm but matter-of-fact. Moderate, unhurried pace, "
    "about 150 words per minute. Use natural phrasing and brief pauses between ideas. "
    "No announcer voice, advertising enthusiasm, dramatic emphasis, or robotic word-by-word delivery. "
    "Pronounce Rio as REE-oh. Read the transcript exactly, without introductions or added words."
)

# Spoken-form substitutions. The written transcript, subtitles and captions keep natural
# prose; only the bytes handed to the synthesizer change, so "SBOM" is read as letters
# instead of rhyming with "bomb". Applied in order, on word boundaries.
PRONUNCIATION = (
    (r"\bRio\b", "Ree oh"),
    (r"\bSBOMs\b", "S B O Ms"),
    (r"\bSBOM\b", "S B O M"),
    (r"\bCI\b", "C I"),
    (r"\bjq\b", "jay cue"),
    (r"\bJSON\b", "jay son"),
)

# One line per chapter, shown on every frame of it. The command answers "what happens";
# this answers "why would I want it".
WHY = {
    "01": "A repeatable local workspace makes the result easy to inspect and reproduce.",
    "02": "The manifest declares policy. The producer supplies facts. The original SBOM is the inventory.",
    "03": "An earlier CI step can learn what to prepare before the context file has been generated.",
    "04": "A recipient can inspect which inputs and claims accompanied this SBOM.",
    "05": "The same inputs and tool version should produce the same handoff bytes.",
    "06": "A familiar artifact name cannot rescue a context file bound to different SBOM bytes.",
    "07": "Missing information is a visible input failure, not an invitation to guess.",
    "08": "A new snapshot must not inherit stale revision, workspace or build-ID claims.",
    "09": "Generation is outside Rio. Context enters through a small, explicit local contract.",
}

INTRO_VOICE = (
    "An ecosystem build has finished, and it has produced an SBOM: a software bill of materials. "
    "That inventory may not tell a recipient which source revision and CI run it came from. "
    "Pull request sixty six lets Rio combine existing SBOMs with an explicit local context file. "
    "We will inspect the inputs, normalize two fictional products, read the records, and watch the refusal cases. "
    "The commands and outputs are real; this replay adds typing and reading time. Nothing is published."
)
OUTRO_VOICE = (
    "We now have an inspectable handoff: which SBOM bytes, which source and build claims, "
    "where they came from, and what changed. "
    "Stale bindings, missing required fields, and unapproved updates stop before outputs. "
    "These are producer assertions, not authenticated build provenance or proof about compiled artifact bytes. "
    "The same examples ship with the pull request. Use the demo runner with a Rio release containing this feature."
)

STEPS = []


def add(chapter, title, command, meaning, voice="", expect=0, hold=3.0):
    STEPS.append(
        dict(
            chapter=chapter,
            title=title,
            command=command,
            meaning=meaning,
            voice=voice,
            expectedExit=expect,
            hold=hold,
        )
    )


C1 = "01 · Prepare the workspace"
add(C1, "Pin the feature being shown", "git rev-parse --short HEAD",
    "This is the PR #66 feature branch.\nThe examples use synthetic data.",
    "We are in a checkout of pull request sixty six. This commit pins the feature we are demonstrating.")
add(C1, "Build the PR binary", "mkdir -p target/feature-video/bin",
    "Create a local destination for this recording's binary.", hold=1.5)
add(C1, "Build the PR binary",
    "CGO_ENABLED=0 go build -trimpath -o target/feature-video/bin/rio ./cmd/rio",
    "A static-style build of this PR.\nOnce released, use the installed Rio binary.",
    "For this recording, we build the pull request. After release, an installed Rio binary replaces this step. The normal demo does not require Go.")
add(C1, "Make the binary available", 'export PATH="$PWD/target/feature-video/bin:$PATH"',
    "The shell will now use the binary we just built.", hold=1.5)
add(C1, "Keep the repository location", 'REPO="$PWD"',
    "We will use this path later for the optional CI helper.", hold=1.3)
add(C1, "Use a fresh scratch directory", "WORK=$(mktemp -d /tmp/rio-context-demo.XXXXXX)",
    "Every result starts fresh.\nOld output cannot masquerade as a new success.", hold=2)
add(C1, "Copy the committed examples", 'git archive HEAD tools/demo-context | tar -x -C "$WORK"',
    "Export only committed example data, manifests and scripts.",
    "We copy the committed examples into a fresh directory. These are fictional products and repositories. No production data or network access is needed.")
add(C1, "Enter the example directory", 'cd "$WORK/tools/demo-context"',
    "This folder now contains everything needed for the fixture walkthrough.", hold=1.5)
add(C1, "Confirm the binary", "rio version",
    '"dev" is expected for this local build.\nThe checkout commit was shown above.', hold=2.5)

C2 = "02 · Read the inputs"
add(C2, "Inspect the first artifact binding", "sed -n '1,9p' rio.yaml",
    'The manifest selects an SBOM and a context file.\n"require" names facts that must be supplied.',
    "The manifest identifies the console SBOM and its context file. This artifact requires a repository, a full revision, and a build URL. Requirements are explicit.")
add(C2, "Read the second binding and gate", "sed -n '10,20p' rio.yaml",
    "Both products share context.json.\nExisting enrichment supplies version and purl.\nThe gate requires name, version and purl.",
    "The second product uses the same context file. Existing manifest enrichment supplies the version and package URL. The gate checks name, version, and package URL; context requirements are separate input checks.")
add(C2, "What the generator already supplied",
    "jq '.metadata | {timestamp, component, tools: .tools.components}' inputs/console.cdx.json",
    "Start with the ecosystem's SBOM.\nRio will preserve its inventory and original metadata.",
    "Here is the existing SBOM. We will preserve its inventory and original metadata. I am using jq only to inspect JSON; it is not a Rio runtime dependency.")
add(C2, "Read the console context", "jq '.artifacts[0] | {id, sbom, source}' context.json",
    "Exact artifact ID + original SBOM digest.\nRepository, revision and workspace are producer claims.",
    "The context names the artifact and the hash of the original SBOM bytes. The producer supplies the source repository, full revision, and clean workspace claim. Rio checks the binding, not whether that claim is true.")
add(C2, "Separate build and generator claims",
    "jq '.artifacts[0] | {build, generator, lifecycle}' context.json",
    "Build system and SBOM generator have different roles.\nLifecycle describes inventory capture, not when Rio runs.",
    "Build details and generator attribution are separate claims. The lifecycle describes when the inventory was captured. Running Rio after a build does not turn a build inventory into a post-build inventory.")
add(C2, "A second product, a different source", "jq '.artifacts[1] | {id, source}' context.json",
    "One file can describe several artifacts.\nThis entry intentionally omits workspace state.",
    "The agent artifact comes from a different repository. Its workspace state is omitted. Rio will make that uncertainty visible as unknown, rather than assuming clean.")

C3 = "03 · Plan before CI produces context"
add(C3, "Temporarily remove the context file", "mv context.json context.saved.json",
    "Simulate the stage before CI has produced the context file.", hold=2)
add(C3, "Describe the future run", "rio plan --manifest rio.yaml --out normalized --json > plan.json",
    "Plan describes the bindings.\nIt does not open the context file.", hold=3)
add(C3, "Inspect the declared binding", "jq '.artifacts[0] | {id, context}' plan.json",
    "The plan succeeds without context.json.\nNormalization will require and validate it.",
    "Planning works before the context exists. It reports which file and fields normalization will need. That lets an earlier pipeline step prepare the inputs without pretending they have already been checked.")
add(C3, "Restore the producer's input", "mv context.saved.json context.json",
    "The context is now available for normalization.", hold=1.5)

C4 = "04 · Normalize and inspect"
add(C4, "Run the real normalizer",
    "rio normalize --manifest rio.yaml --out normalized --gate fail --attest",
    "Two artifacts should pass.\n--attest writes unsigned normalization statements.",
    "Now we run normalization for both artifacts. The gate must pass. The attest flag also writes unsigned statements about the normalized SBOMs; it does not sign or authenticate them.")
add(C4, "Look at native SBOM references",
    "jq '.metadata.component.externalReferences' normalized/console.cdx.json",
    "VCS and build-system links belong to the subject.\nThird-party dependencies do not inherit them.",
    "The source and build links are now on the product being described. Rio does not copy this repository or build identity onto all of the third-party dependencies.")
add(C4, "See clean versus unknown",
    "jq '.artifacts[] | {id, workspace: .context.effective.source.workspace, defaulted: .context.defaulted}' normalized/index.json",
    "Console: explicitly supplied clean.\nAgent: unknown, with the default recorded.",
    "The distinction is explicit in the record. Console has a supplied clean claim. Agent is unknown, and the defaulted list explains why. Missing information has not become an invented fact.")
add(C4, "Inspect the source of the assertions",
    "jq '.artifacts[0].context | {file, selector, assertion}' normalized/index.json",
    'Raw context digest + entry selector.\n"producer" means supplied, not independently verified.',
    "The record identifies the exact context file bytes and the selected entry. The assertion label is producer. This is traceability and consistency, not proof that a binary was built from that source.")
add(C4, "Preserve original metadata",
    "jq '.metadata | {timestamp, tools: .tools.components}' normalized/console.cdx.json",
    "Original timestamp and tool remain.\nRio adds its own normalizer entry.",
    "The original timestamp and tool remain. Rio adds its normalizer entry. Supplied generator claims stay separately labelled in context.")
add(C4, "Extract the index context",
    "jq -S '.artifacts[0].context' normalized/index.json > index-context.json",
    "Sort JSON keys for a direct comparison.", hold=1.5)
add(C4, "Extract the statement context",
    "jq -S '.predicate.artifact.context' normalized/console.intoto.json > statement-context.json",
    "The statement should carry the same context record.", hold=1.5)
add(C4, "Check that the records agree",
    'cmp index-context.json statement-context.json && echo "Context records match"',
    "The index and unsigned statement carry the same record.",
    "The comparison succeeds. The statement and index tell the same story about this normalization run.")

C5 = "05 · Check repeatability"
add(C5, "Repeat with the same inputs",
    "rio normalize --manifest rio.yaml --out repeated --gate fail --attest",
    "A new output directory; the same input bytes and policy.", hold=3)
add(C5, "Compare all three output files",
    'cmp normalized/index.json repeated/index.json && \\\n  cmp normalized/console.cdx.json repeated/console.cdx.json && \\\n  cmp normalized/agent.cdx.json repeated/agent.cdx.json && \\\n  echo "Index and both SBOMs are byte-identical"',
    "The index and both SBOMs match byte for byte.",
    "We compare the index and both normalized SBOMs. These three files are byte-identical. Rio did not insert the current clock or discover new environment facts.")

C6 = "06 · Refuse stale context"
add(C6, "Select the stale-digest fixture", "cat stale.yaml",
    "This manifest points to context-stale.json.\nIts SBOM digest is deliberately wrong.", hold=3)
add(C6, "Try to normalize with stale context", "rio normalize --manifest stale.yaml --out stale-refused",
    "Expected: refusal before output.\nA matching artifact name is not enough.",
    "This context contains the wrong SBOM digest. Rio refuses it. The artifact name alone cannot establish that the supplied context belongs to these bytes.",
    expect=2)
add(C6, "Read the actual exit status", "echo $?",
    "Exit 2 means invalid input or configuration.\nThis is not a completed gate failure.", hold=2)
add(C6, "Confirm that output was not written",
    'test ! -e stale-refused && echo "No output directory was written"',
    "The failed input did not produce a new run record.", hold=3)

C7 = "07 · Require the fields you need"
add(C7, "Inspect the required-field policy", "cat missing.yaml",
    "build.url is required.\nThe selected fixture omits it.", hold=3)
add(C7, "Refuse the missing build URL", "rio normalize --manifest missing.yaml --out missing-refused",
    "Expected: a field-specific error.\nNo guessed build URL is supplied.",
    "This producer omitted a required build URL. Rio names the missing field and stops. It does not read unrelated environment variables or guess which pipeline run to use.",
    expect=2)
add(C7, "Confirm the refusal", "echo $?",
    "Again, exit 2.\nThe producer must supply the required fact.", hold=2)

C8 = "08 · Resolve prior claims explicitly"
add(C8, "Try to change an owned source revision",
    "rio normalize --manifest conflict.yaml --out conflict-refused",
    "This input already carries a prior context snapshot.\nChanging its revision needs explicit permission.",
    "The next input already contains a prior context record. A new source revision conflicts with it. The manifest has not authorized that revision change, so Rio refuses.",
    expect=2)
add(C8, "Inspect the policy difference", "diff -u conflict.yaml replace.yaml",
    "The replacement manifest adds source.revision.\nThe other two permissions handle workspace and old build ID.",
    "The diff shows the authorization. We add source dot revision to the replacement list. Workspace change and build ID removal are also explicit. This is a scoped decision, not an overwrite-everything switch.",
    expect=1)
add(C8, "Apply the authorized snapshot", "rio normalize --manifest replace.yaml --out replaced",
    "Expected: success with an inspectable change history.", hold=3)
add(C8, "Inspect the new source state",
    "jq '.artifacts[0].context | {source: .effective.source, defaulted}' replaced/index.json",
    "The revision changed.\nOmitted workspace is unknown, not inherited clean.",
    "The revision is updated. Because the new producer input omitted workspace state, it is unknown. The old clean claim does not silently carry forward.")
add(C8, "Inspect removal of the old build ID",
    "jq '.artifacts[0].context.changes[] | select(.field == \"build.id\") | {field, before, after, override}' replaced/index.json",
    "before: old-run\nafter: null\noverride: true",
    "The old build ID is removed. The audit keeps its previous value, the null replacement, and the explicit override flag. Missing new data is not filled from stale old context.")
add(C8, "Run the shipped replacement check", "sh ./check-replacement.sh replaced/index.json",
    "Exit 0 verifies the specific effective revision, workspace and removal.", hold=3)

C9 = "09 · Produce context in a real CI job"
add(C9, "Use the optional explicit-input helper",
    'python3 "$REPO/tools/rio-context.py" \\\n  --artifact-id console --sbom inputs/console.cdx.json \\\n  --source-repository https://code.example.org/widgets/console \\\n  --source-revision 1111111111111111111111111111111111111111 \\\n  --source-workspace clean \\\n  --build-url https://ci.example.org/widgets/runs/42 \\\n  > generated-context.json',
    "Optional helper: Python standard library.\nEvery assertion is passed explicitly.\nThe original SBOM bytes are hashed locally.",
    "In a real pipeline, the optional Python helper can produce this JSON from explicit arguments. It hashes the original SBOM. It does not discover Git, environment variables, or the current time. Pass only facts your job actually established.")
add(C9, "Inspect the generated binding",
    "jq '.artifacts[0] | {id, sbom, source}' generated-context.json",
    "This is a one-artifact producer file.\nRio remains the final binding validator.", hold=4)


def narration_clips():
    """Every distinct piece of speech in playback order: (key, text)."""
    clips = [("intro", INTRO_VOICE)]
    for index, step in enumerate(STEPS, 1):
        if step["voice"]:
            clips.append(("step-%02d" % index, step["voice"]))
    clips.append(("outro", OUTRO_VOICE))
    return clips
