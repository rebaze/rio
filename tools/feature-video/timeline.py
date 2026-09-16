#!/usr/bin/env python3
"""Turn a capture plus measured narration into a timeline, captions and chapters.

This is where pacing is decided, and it is deliberately free of drawing and network code
so it can be tested on its own. The ordering rule it exists to enforce:

    narration of a result never starts before that result is on screen.

Every clip is placed at `output_end`, after the command has been typed, run and revealed.
The shot then lasts as long as the slowest of three things: the storyboard's minimum hold,
time to read the output, and the clip's own measured duration. Audio is never trimmed,
sped up or faded to fit a predetermined length; the picture waits for the voice.

Python 3.9+, standard library only.
"""
import math

FPS = 15
RATE = 24000  # narration sample rate, mono 16-bit

# Terminal geometry, in characters. render.py draws to these and nothing else decides them.
COLS = 85
ROWS = 24

TYPING_CPS = 36.0          # characters per second while "typing" a command
TYPING_LEAD = 0.35         # beat before the first character appears
MIN_TYPING = 0.7
MIN_RUN = 0.25             # shortest visible "running" beat
MAX_RUN = 1.2
REVEAL_PER_LINE = 0.16
MAX_REVEAL = 3.5
READ_PER_LINE = 0.27
READ_BASE = 1.5
MAX_READ = 8.0
AUDIO_LEAD = 0.25          # gap between the output settling and the voice starting
AUDIO_TAIL = 0.7           # breath after a clip before the next command types
CARD_LEAD = 0.8            # silence before narration on the intro and outro cards
CARD_TAIL = 2.2


def quantize(seconds):
    """Round a duration up to a whole frame so audio and video never drift apart."""
    return math.ceil(seconds * FPS) / FPS


def wrap_chars(text, prefix="", cols=COLS):
    """Hard-wrap to the terminal width, the way a terminal does it."""
    out = []
    for index, line in enumerate(text.split("\n")):
        line = (prefix if index == 0 else "") + line.expandtabs(4)
        out.extend([line[n:n + cols] for n in range(0, len(line), cols)] or [""])
    return out


def command_rows(command, where, cols=COLS):
    """Rendered rows for a prompt line and its continuations."""
    rows = []
    for number, line in enumerate(command.split("\n")):
        prefix = (where + " $ ") if number == 0 else "> "
        for index, row in enumerate(wrap_chars(prefix + line, cols=cols)):
            rows.append((row, "ink", len(prefix) if index == 0 else 0))
    return rows


def output_rows(step, cols=COLS):
    """Rendered rows for captured output, coloured by what the command was."""
    rows = []
    for line in step["output"].splitlines():
        if step["command"].startswith("diff "):
            color = "mint" if line.startswith("+") else "red" if line.startswith("-") else "muted"
        elif step["exitCode"] == 2:
            # A refusal is the point of the shot; nothing else may recolour it.
            color = "red"
        elif step["command"] == "echo $?":
            color = "mint" if step["output"].strip() == "0" else "red"
        elif "echo " in step["command"]:
            color = "mint"
        else:
            color = "ink"
        for wrapped in wrap_chars(line, cols=cols):
            rows.append((wrapped, color, 0))
    return rows


def shot_durations(step, clip_seconds, rows_of_output):
    """The four beats of one command, derived from its own content."""
    typing = max(MIN_TYPING, len(step["command"]) / TYPING_CPS)
    typing_end = TYPING_LEAD + typing
    output_start = typing_end + max(MIN_RUN, min(MAX_RUN, step.get("elapsed", 0.0)))
    reveal = min(MAX_REVEAL, rows_of_output * REVEAL_PER_LINE) if rows_of_output else 0.0
    output_end = output_start + reveal
    read = max(
        step.get("hold", 3.0),
        min(MAX_READ, READ_BASE + rows_of_output * READ_PER_LINE),
        (clip_seconds + AUDIO_TAIL) if clip_seconds else 0.0,
    )
    return dict(
        typing=typing,
        typing_end=typing_end,
        output_start=output_start,
        reveal=reveal,
        output_end=output_end,
        read=read,
        audio_start=output_end + AUDIO_LEAD,
        duration=output_end + AUDIO_LEAD + read,
    )


def build(transcript, clip_seconds, intro_voice, outro_voice, history_limit=120):
    """The whole video as a list of shots, plus its total duration.

    `clip_seconds` maps a clip name ("intro", "step-07", "outro") to measured seconds.
    A step with narration but no measured clip is an error: silently dropping it would
    publish a video missing part of its own script.
    """
    shots = []
    elapsed = 0.0
    history = []
    where = "repo"

    def append(shot):
        nonlocal elapsed
        shot["start"] = elapsed
        shot["duration"] = quantize(shot["duration"])
        elapsed += shot["duration"]
        shots.append(shot)

    intro = clip_seconds.get("intro", 0.0)
    append(dict(kind="intro", title="Introduction", voice=intro_voice,
                clip="intro", audio_start=CARD_LEAD, duration=CARD_LEAD + intro + CARD_TAIL))

    for index, step in enumerate(transcript["steps"], 1):
        name = "step-%02d" % index
        seconds = clip_seconds.get(name, 0.0)
        if step["voice"] and not seconds:
            raise ValueError("%s has narration but no measured audio" % name)
        rows = output_rows(step)
        used = len(command_rows(step["command"], where)) + len(rows) + 2
        if used > ROWS:
            raise ValueError(
                "step %d needs %d terminal rows but only %d are visible: %s"
                % (index, used, ROWS, step["command"])
            )
        timing = shot_durations(step, seconds, len(rows))
        next_where = "demo" if "/rio-context-demo." in step["cwd"] else "repo"
        shot = dict(
            kind="step", index=index, title=step["title"], step=step, where=where,
            next_where=next_where, history=history[-history_limit:], out=rows,
            voice=step["voice"], clip=name if step["voice"] else None, **timing
        )
        append(shot)
        history = history + command_rows(step["command"], where) + rows + [("", "ink", 0)]
        where = next_where

    outro = clip_seconds.get("outro", 0.0)
    append(dict(kind="outro", title="Summary and boundaries", voice=outro_voice,
                clip="outro", audio_start=CARD_LEAD, duration=CARD_LEAD + outro + CARD_TAIL))
    return shots, elapsed


def check_ordering(shots, clip_seconds):
    """Every spoken clip must start after its result is visible and end inside its shot."""
    problems = []
    for shot in shots:
        if not shot.get("voice"):
            continue
        seconds = clip_seconds.get(shot.get("clip"), 0.0)
        if shot["kind"] == "step" and shot["audio_start"] < shot["output_end"]:
            problems.append(
                "%s speaks at %.2fs, before its output is complete at %.2fs"
                % (shot["title"], shot["audio_start"], shot["output_end"])
            )
        if shot["audio_start"] + seconds > shot["duration"] + 1e-6:
            problems.append(
                "%s narration runs %.2fs past the end of its shot"
                % (shot["title"], shot["audio_start"] + seconds - shot["duration"])
            )
    return problems


def timestamp(value):
    return "%02d:%02d" % (int(value) // 60, int(value) % 60)


def caption_time(seconds, comma=True):
    ms = int(round(seconds * 1000))
    hours, ms = divmod(ms, 3600000)
    minutes, ms = divmod(ms, 60000)
    secs, ms = divmod(ms, 1000)
    return "%02d:%02d:%02d%s%03d" % (hours, minutes, secs, "," if comma else ".", ms)


def caption_chunks(text, limit=118):
    parts = []
    chunk = ""
    for word in text.split():
        if len(chunk) + len(word) + 1 > limit and chunk:
            parts.append(chunk)
            chunk = ""
        chunk = (chunk + " " + word).strip()
    if chunk:
        parts.append(chunk)
    return parts


def captions(shots, clip_seconds):
    """Subtitle cues, apportioned across a clip by word count.

    Cue text is the written transcript, never the spoken form: a viewer reading along
    should see "SBOM", not the letters the synthesizer was handed.
    """
    cues = []
    for shot in shots:
        if not shot.get("voice"):
            continue
        duration = clip_seconds.get(shot.get("clip"), 0.0)
        parts = caption_chunks(shot["voice"])
        words = sum(len(part.split()) for part in parts) or 1
        at = shot["start"] + shot["audio_start"]
        for part in parts:
            end = at + duration * len(part.split()) / words
            cues.append((at, end, part))
            at = end
    return cues


def wrap_text(text, width=62):
    lines = []
    line = ""
    for word in text.split():
        if len(line) + len(word) + 1 > width and line:
            lines.append(line)
            line = ""
        line = (line + " " + word).strip()
    if line:
        lines.append(line)
    return lines


def srt(cues):
    blocks = []
    for number, (start, end, text) in enumerate(cues, 1):
        blocks.append(
            "%d\n%s --> %s\n%s"
            % (number, caption_time(start), caption_time(end), "\n".join(wrap_text(text)))
        )
    return "\n\n".join(blocks) + "\n"


def vtt(cues):
    blocks = ["WEBVTT", ""]
    for number, (start, end, text) in enumerate(cues, 1):
        blocks.append(
            "%d\n%s --> %s\n%s\n"
            % (number, caption_time(start, comma=False), caption_time(end, comma=False),
               "\n".join(wrap_text(text)))
        )
    return "\n".join(blocks)


def chapters(shots, total):
    marks = []
    for shot in shots:
        label = shot["step"]["chapter"] if shot["kind"] == "step" else shot["title"]
        if not marks or marks[-1]["title"] != label:
            marks.append(dict(title=label, start=shot["start"]))
    for index, mark in enumerate(marks):
        mark["end"] = marks[index + 1]["start"] if index + 1 < len(marks) else total
    return marks


def ffmetadata(marks, title, comment):
    """ffmpeg chapter metadata. TIMEBASE is milliseconds, matching -movie_timescale 1000."""
    lines = [";FFMETADATA1", "title=" + title, "comment=" + comment]
    for mark in marks:
        lines += [
            "[CHAPTER]",
            "TIMEBASE=1/1000",
            "START=%d" % round(mark["start"] * 1000),
            "END=%d" % round(mark["end"] * 1000),
            "title=" + mark["title"],
        ]
    return "\n".join(lines) + "\n"


def chapter_list(marks):
    return "\n".join(timestamp(m["start"]) + "  " + m["title"] for m in marks) + "\n"
