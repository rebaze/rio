# feature-video

Builds the narrated walkthrough of rio's source and build context feature: a 1080p MP4 in
which the left half is a terminal running the real commands and the right half explains what
to look for and why it matters.

Nothing here ships in the binary and rio never calls any of it. It is authoring equipment,
kept in the repository because the video has to be reproducible by someone who was not there
when it was first made.

## What it produces

| file | what it is |
|---|---|
| `rio-context-demo.mp4` | H.264/yuv420p, AAC, faststart, chapter markers, embedded captions |
| `rio-context-demo.srt`, `.vtt` | English captions, same cues in both dialects |
| `poster.png` | the opening frame, for a thumbnail or a `poster=` attribute |
| `transcript.json` | every command, its real output, its exit code and how long it took |
| `commands.sh`, `command-output.txt` | the same thing as flat files, to diff or replay by hand |
| `narration.txt` | the spoken script |
| `narration.json` | clip identities, timing and recorded voice metadata |
| `chapters.txt`, `chapters.json` | chapter names and boundaries |
| `timeline.json` | every shot, when it starts and when its narration does |
| `usage.json` | what the narration pass requested and what it is estimated to have cost |
| `SHA256SUMS` | checksums of everything above |
| `bundle/` | those files plus `index.html`: a self-contained page that plays the video |

They land in `target/feature-video/`, which is not tracked. The video is tens of megabytes
and regenerable; what is committed is the thing that regenerates it.

## The five steps

```sh
python3 tools/feature-video/capture.py     # run the commands, record what they printed
python3 tools/feature-video/narrate.py     # synthesize the narration (paid; see below)
python3 tools/feature-video/render.py      # draw the frames and encode
python3 tools/feature-video/verify.py      # check the result is worth publishing
python3 tools/feature-video/bundle.py      # assemble the portable viewing folder
```

They are separate because they fail for unrelated reasons and cost unrelated amounts.
Re-rendering is free and takes minutes; re-narrating costs money. Keeping them apart means
a font change never re-buys the soundtrack.

### capture.py

Runs [`storyboard.py`](storyboard.py)'s commands in **one persistent bash process**, so `cd`,
shell variables and `$?` are real rather than re-created per command. Each command's exit
status is compared against the storyboard's expectation, and a mismatch fails the capture.
That is the part that matters: three of these commands are supposed to fail, and an
"expected exit 2" that silently returns 0 would otherwise produce a video demonstrating a
refusal that no longer happens.

Run it from a checkout containing the feature, with Go available. It writes no video.

### narrate.py

Synthesizes each line with **Google Gemini `gemini-3.1-flash-tts-preview`, voice `Charon`**,
under the director instructions in `storyboard.py`. That combination was auditioned and
approved; it is recorded in one place and the tool refuses to substitute another model
rather than quietly producing a video in the wrong voice.

The API key is read at runtime from 1Password (`op://Employee/Gemini_TTS_gf/API_KEY`), kept
in memory and sent as a header. It is never an argument, never printed, and never written to
the cache, `usage.json` or an error message — HTTP failures report the status and the API's
own short error code and discard the rest.

Clips are cached under `target/feature-video/narration-cache/`, keyed by a digest of
**provider, model, voice, director instructions and the line itself**. Change one sentence
and one clip is regenerated; change the direction and all of them are. Nothing else causes a
retake, so the cost of an edit is the cost of what was edited.

```sh
python3 tools/feature-video/narrate.py --dry-run          # what would be generated, and for how much
python3 tools/feature-video/narrate.py --only step-07     # retake one line
python3 tools/feature-video/narrate.py --only step-07 --force
```

**Cost.** Paid-tier rates are $1.00 per million input text tokens and $20.00 per million
output audio tokens, billed at 25 audio tokens per second
([pricing](https://ai.google.dev/gemini-api/docs/pricing), checked 2026-09-16). Speech
dominates: a complete pass is about five and a half minutes of audio, roughly **$0.16**.
`--dry-run` prints an estimate before anything is spent and `usage.json` records what was
actually requested. Reading pauses are silence on the timeline and cost nothing.

### render.py

Draws every frame with Pillow and encodes with ffmpeg. All pacing comes from
[`timeline.py`](timeline.py), which derives it from the measured length of each audio clip —
not the other way around. The rule it enforces is that **narration never describes something
before it is on screen**: a clip starts after its command has been typed, run and revealed,
and the shot lasts as long as the longest of the storyboard's minimum hold, the time needed
to read the output, and the clip itself. Audio is never trimmed or sped up to fit.

Two things it refuses rather than renders: output taller than the 24 visible terminal rows,
and a step that has narration but no measured audio.

Fonts default to macOS system fonts. On another machine, point `RIO_VIDEO_FONT_MONO`,
`RIO_VIDEO_FONT_SANS` and `RIO_VIDEO_FONT_BOLD` at a monospace and a sans family.

`--preview-only` writes one frame per shot and all the text outputs, and skips the encode.
It is the fast way to check a wording or layout change.

### verify.py

Decodes the finished file and checks it against what the timeline promised: that it decodes
without errors at all, that the codecs and pixel format are the portable ones, that playback
can start before the file has downloaded, that the chapters match the timeline and none of
them collapsed to zero length, that captions are ordered and end inside the video, that the
narration is audible, on target and does not clip, and that the captions read as prose rather
than as the letters the synthesizer was handed.

It compares every chapter start/end and both caption tracks' starts, ends and text. Each
narration entry must match its scripted clip and the approved provider/model/voice metadata;
older manifests obtain those settings from their matching cache sidecars. This checks recorded
metadata, not the identity of the audible speaker. The 90–200 words-per-minute guard catches
implausible durations; the original recording's measured 111.94–155.17 range is an observation,
not an acceptance band. Neither check proves that every word was spoken correctly; that needs
listening to the recording.

Every one of these failed in a draft at least once. The chapter check exists because ffmpeg
picks a movie timescale that rounds chapter boundaries into each other unless
`-movie_timescale 1000` is passed, and the result looks fine until a player shows the wrong
chapter name.

### bundle.py

Copies the assets next to a generated `index.html` — a single page with the video, a chapter
list that seeks it, the transcript and download links. No build step, no framework, no
external request, so it can be opened from disk or served by any static host.

```sh
python3 -m http.server --directory target/feature-video/bundle
```

Serving it matters for captions: a browser opening the page straight from `file://` may
refuse to load the separate `.vtt`.

Two things about that command specifically. It is single-threaded, so one stalled request
blocks the rest of the page; and it does not implement `Range`, answering a range request
with `200` and the whole file. A browser can still play the video that way, but it cannot
seek until the download finishes, so **scrubbing and the chapter links will feel broken
under `http.server` and work on any real static host**. It is fine for checking the page;
it is not a fair test of playback.

`bundle.py` also writes a `SHA256SUMS` covering exactly the files it shipped, so
`shasum -a 256 -c SHA256SUMS` works inside the folder someone was handed.
It assembles a fresh directory before replacing the previous generated bundle, so stale files
are not carried into delivery. A custom `--out` must be empty or an existing generated bundle;
the rendered source directory cannot be used as the output. Bundling copies the existing MP4
and never renders video or generates narration. It consolidates legacy voice metadata from
validated cache sidecars into the bundle's `narration.json`, so checking that metadata does
not depend on the author's workstation. The original manifest and audio remain unchanged.

### endscreen.py

Renders `endscreen.png`, the 1920x1080 card for the last seconds of the video on YouTube.

This is the one asset here that is not in rio's palette. The video is rio's terminal styling;
an end card is rebaze speaking, so it uses the brand's own colours, mark and typography as
they are on rebaze.de — near-black green `#20251f`, warm cream `#f4f1e8`, sage `#b7ccaa`, and
a medium-weight grotesque with -3% tracking. The two brand SVGs are vendored in `brand/` so
the card renders offline.

The right-hand third is deliberately empty: YouTube draws its own end-screen elements over
the frame, and anything placed there would be covered. The mark bleeds off that edge so the
crop reads as deliberate.

```sh
python3 tools/feature-video/endscreen.py
python3 tools/feature-video/endscreen.py --headline "Find out more" --url rebaze.de
python3 tools/feature-video/endscreen.py --no-watermark
```

Needs Pillow and `rsvg-convert`. YouTube shows end screens only over the last 5-20 seconds,
so the card is uploaded as an end-screen background or appended to the cut; it is not part of
the encoded walkthrough.

## Dependencies

| step | needs |
|---|---|
| `capture.py` | Python 3.9+, bash, git, a Go toolchain, `jq` (the commands being demonstrated use it) |
| `narrate.py` | Python 3.9+, the 1Password CLI, network access, a paid Gemini API key |
| `render.py` | Python 3.9+, [Pillow](https://pypi.org/project/pillow/), ffmpeg |
| `verify.py` | Python 3.9+, ffmpeg and ffprobe |
| `bundle.py` | Python 3.9+ |
| `feature_video_test.py` | Python 3.9+ only |
| `tooling_test.py` | Python 3.9+, bash and `ps` |

None of these is a rio runtime dependency, and none is needed to *watch* the video or to run
the [demo the video walks through](../demo-context/README.md), which needs rio and a POSIX
shell.

## Tests

```sh
python3 tools/feature-video/feature_video_test.py
python3 tools/feature-video/tooling_test.py
```

They cover the pacing rules, the cache, the audio decoding and the failure paths, and they
run in CI. They make no network calls and read no credentials: the synthesizer is replaced
with a local stub, so a test run never spends anything. What they cannot check is whether the
result sounds right — that needs someone to watch it.

## Existing recording and publication

The existing recording was captured from `b8395098615ea2aaae35dfa8ad111ec7f077c415`.
Its MP4 and narration are retained unchanged at the owner's request. The renderer's progress
cache correction applies to future renders; it does not change the already encoded progress
indicator. The portable bundle can be rebuilt from the existing assets without re-rendering.
Public hosting and a README viewing link remain pending by the owner's decision; a fresh
checkout contains authoring sources, not the video assets.

## Re-recording against a release

The video says which build it was captured from, and the storyboard builds rio from source
because the feature was not released when it was first recorded. Once it ships:

1. Check out the released tag.
2. In `storyboard.py`, replace the `go build` and `export PATH` steps with the installed
   binary, and adjust the narration that explains the local build.
3. `capture.py`, then `narrate.py` (only the changed lines are re-synthesized), then
   `render.py`, `verify.py` and `bundle.py`.

Everything else — the pacing, the panel text, the chapter structure — follows from the
storyboard and needs no further edit.
