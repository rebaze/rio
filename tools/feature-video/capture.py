#!/usr/bin/env python3
"""Run the storyboard's commands for real and record what they printed.

One persistent bash process runs every command in order, so `cd`, shell variables and
`$?` are real rather than re-created per command. The exit status of each command is
compared against the storyboard's expectation, which is how an intentional refusal stays
distinguishable from a broken demo: an unexpected zero fails the capture just as loudly
as an unexpected two.

Nothing here paces, pauses or renders. The output is a transcript of real bytes, and
`render.py` is the only thing that adds time to it.

Python 3.9+, standard library only.
"""
import argparse
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402

# Long enough for a cold `go build`, short enough that a command waiting on input fails
# the capture instead of hanging the session.
DEFAULT_TIMEOUT = 300.0
MARKER = "__RIO_FEATURE_VIDEO_%d_END__"


class CaptureError(RuntimeError):
    pass


def repo_root():
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if result.returncode:
        raise CaptureError("not inside a git checkout; pass --repo")
    return Path(result.stdout.strip())


def parse_marked(text, marker):
    """Split a command's merged output from the trailing status marker line.

    The marker carries the real exit status and working directory back out of the
    persistent shell. It is transport bookkeeping and never appears on screen.
    """
    needle = "\n" + marker + ":"
    if needle not in text:
        raise CaptureError("marker %s not found in output" % marker)
    output, ending = text.split(needle, 1)
    rc, _, cwd = ending.rstrip("\n").partition(":")
    return output.rstrip("\n"), int(rc), cwd


def payload_for(command, marker):
    return (
        command
        + '\n__rio_video_rc=$?; printf "\\n%s:%%s:%%s\\n" "$__rio_video_rc" "$PWD"; '
        '(exit "$__rio_video_rc")\n' % marker
    )


def run_steps(steps, root, timeout=DEFAULT_TIMEOUT, log=print):
    """Execute every step in one bash process and return the captured records."""
    env = dict(os.environ, TERM="dumb", LC_ALL="en_US.UTF-8")
    shell = subprocess.Popen(
        ["/bin/bash", "--noprofile", "--norc"],
        cwd=str(root),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    records = []
    try:
        for index, step in enumerate(steps):
            marker = MARKER % index
            start = time.monotonic()
            shell.stdin.write(payload_for(step["command"], marker).encode())
            shell.stdin.flush()
            data = b""
            while marker.encode() not in data:
                ready, _, _ = select.select([shell.stdout], [], [], 1)
                if ready:
                    chunk = os.read(shell.stdout.fileno(), 65536)
                    if not chunk:
                        raise CaptureError(
                            "shell exited early: " + data.decode(errors="replace")
                        )
                    data += chunk
                if time.monotonic() - start > timeout:
                    raise CaptureError("timed out after %gs: %s" % (timeout, step["command"]))
            output, rc, cwd = parse_marked(data.decode("utf-8", errors="replace"), marker)
            if rc != step["expectedExit"]:
                raise CaptureError(
                    "step %d expected exit %d, got %d: %s\n%s"
                    % (index + 1, step["expectedExit"], rc, step["command"], output)
                )
            records.append(
                dict(
                    step,
                    output=output,
                    exitCode=rc,
                    cwd=cwd,
                    elapsed=round(time.monotonic() - start, 3),
                )
            )
            log("%02d exit=%d %s" % (index + 1, rc, step["title"]))
    finally:
        # Ask bash to leave, then close both pipes: closing stdin is the EOF that ends it
        # even when the write above could not be delivered. Leaving them to the garbage
        # collector leaks two descriptors per run and warns under -W error.
        try:
            shell.stdin.write(b"exit\n")
            shell.stdin.flush()
        except (OSError, ValueError):
            pass
        for stream in (shell.stdin, shell.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            shell.wait(timeout=20)
        except subprocess.TimeoutExpired:
            shell.kill()
            shell.wait(timeout=5)
    return records


def documents(records, commit):
    """The transcript plus the two flat files a reader can diff or replay by hand."""
    transcript = {
        "version": 1,
        "title": storyboard.TITLE,
        "feature": storyboard.FEATURE,
        "featureUrl": storyboard.FEATURE_URL,
        "commit": commit,
        "capture": (
            "Actual persistent bash commands and merged stdout/stderr. "
            "Playback typing and pauses are paced for readability."
        ),
        "steps": records,
    }
    commands = (
        "#!/bin/bash\n"
        "# Recorded commands, including intentional refusals. Run from the PR checkout.\n"
        "# Do not enable errexit: refusal examples intentionally return exit 2.\n\n"
        + "\n\n".join("# " + r["title"] + "\n" + r["command"] for r in records)
        + "\n"
    )
    outputs = (
        "\n\n".join(
            "$ " + r["command"] + "\n" + r["output"] + "\n[exit " + str(r["exitCode"]) + "]"
            for r in records
        )
        + "\n"
    )
    return transcript, commands, outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=None, help="checkout to run in")
    parser.add_argument("--out", type=Path, default=None, help="directory for the transcript")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    root = args.repo.resolve() if args.repo else repo_root()
    out = (args.out or root / "target" / "feature-video").resolve()
    out.mkdir(parents=True, exist_ok=True)

    records = run_steps(storyboard.STEPS, root, timeout=args.timeout)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True, check=True
    ).stdout.strip()
    transcript, commands, outputs = documents(records, commit)
    (out / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n")
    (out / "commands.sh").write_text(commands)
    (out / "command-output.txt").write_text(outputs)
    print("Captured %d commands to %s" % (len(records), out / "transcript.json"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CaptureError as error:
        print("capture failed: %s" % error, file=sys.stderr)
        sys.exit(1)
