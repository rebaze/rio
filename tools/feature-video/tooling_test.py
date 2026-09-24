"""Regression checks for bundle replacement, capture cleanup and frame caching."""
import contextlib
import io
import json
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

import bundle
import capture
import narrate
import render
import storyboard
import verify


class Bundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        for name in bundle.ASSETS:
            (self.work / name.format(base=storyboard.VIDEO_ID)).write_text("asset")
        (self.work / "transcript.json").write_text(json.dumps({"commit": "abc123", "steps": []}))
        (self.work / "chapters.json").write_text(json.dumps([{"start": 0, "end": 10, "title": "Intro"}]))
        clips = [dict(clip=name, text=text, seconds=10, provider=storyboard.VOICE_PROVIDER,
                      model=storyboard.VOICE_MODEL, voice=storyboard.VOICE_NAME)
                 for name, text in storyboard.narration_clips()]
        (self.work / "narration.json").write_text(json.dumps(clips))

    def assemble(self, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return bundle.main(["--dir", str(self.work), *args])

    def test_rebuilding_excludes_stale_files_and_directories(self):
        self.assemble()
        out = self.work / "bundle"
        (out / "obsolete.txt").write_text("stale")
        (out / "old").mkdir()
        (out / "old" / "private.txt").write_text("stale")
        self.assemble()
        self.assertFalse((out / "obsolete.txt").exists())
        self.assertFalse((out / "old").exists())
        shipped = {line.split("  ", 1)[1] for line in (out / "SHA256SUMS").read_text().splitlines()}
        self.assertEqual(shipped, {p.name for p in out.iterdir()} - {"SHA256SUMS"})

    def test_missing_input_preserves_previous_bundle(self):
        self.assemble()
        before = (self.work / "bundle" / "SHA256SUMS").read_bytes()
        (self.work / "poster.png").unlink()
        with self.assertRaises(SystemExit):
            self.assemble()
        self.assertEqual(before, (self.work / "bundle" / "SHA256SUMS").read_bytes())

    def test_output_cannot_replace_source_directory(self):
        with self.assertRaises(SystemExit):
            self.assemble("--out", str(self.work))
        self.assertTrue((self.work / "transcript.json").exists())

    def test_legacy_voice_metadata_is_portable_without_changing_source(self):
        source = self.work / "narration.json"
        clips = json.loads(source.read_text())
        for clip in clips:
            clip["spoken"] = narrate.spoken_form(clip["text"])
            clip["key"] = narrate.cache_key(clip["spoken"])
            cache = self.work / (clip["key"] + ".wav")
            cache.with_suffix(".json").write_text(json.dumps(clip))
            clip["path"] = str(cache)
            for field in ("provider", "model", "voice"):
                del clip[field]
        source.write_text(json.dumps(clips))
        before = source.read_bytes()
        self.assemble()
        shipped = json.loads((self.work / "bundle" / "narration.json").read_text())
        self.assertEqual(before, source.read_bytes())
        for clip in shipped:
            self.assertEqual(clip["voice"], "Charon")
            self.assertEqual(clip["provider"], "google")
            self.assertEqual(clip["model"], "gemini-3.1-flash-tts-preview")
            self.assertNotIn("path", clip)

    def test_unrelated_output_directory_is_preserved(self):
        out = self.work / "other"
        out.mkdir()
        (out / "important.txt").write_text("keep")
        with self.assertRaises(SystemExit):
            self.assemble("--out", str(out))
        self.assertEqual((out / "important.txt").read_text(), "keep")

    def test_verifying_bundle_keeps_viewer_in_checksums(self):
        (self.work / "timeline.json").write_text('[{"start":0,"duration":10}]')
        self.assemble()
        out = self.work / "bundle"
        before = (out / "SHA256SUMS").read_text()
        probe = {"format": {"duration": "10"}, "chapters": [], "streams": [
            {"codec_type": "video", "width": 1920, "height": 1080, "avg_frame_rate": "15/1"}]}
        with mock.patch.object(verify, "probe", return_value=probe), \
             mock.patch.object(verify, "decodes", return_value=(True, "")), \
             mock.patch.object(verify, "loudness", return_value={"lufs": -18, "peak": -2}):
            verify.verify(out, log=lambda _: None)
        self.assertEqual(before, (out / "SHA256SUMS").read_text())


class CaptureCleanup(unittest.TestCase):
    def test_timeout_terminates_shell_and_foreground_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = (
                "import os, signal, time; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "Path('child.pid').write_text(str(os.getpid())); time.sleep(8)"
            )
            command = "printf '%s' $$ > shell.pid; " + shlex.quote(sys.executable) + " -c " + shlex.quote(child)
            started = time.monotonic()
            with self.assertRaisesRegex(capture.CaptureError, "timed out"):
                capture.run_steps([{"command": command, "expectedExit": 0, "title": "timeout"}],
                                  root, timeout=0.2, log=lambda _: None)
            self.assertLess(time.monotonic() - started, 5, "cleanup waited for the stuck command")
            for name in ("shell.pid", "child.pid"):
                pid = (root / name).read_text()
                result = subprocess.run(["ps", "-p", pid, "-o", "stat="], capture_output=True, text=True)
                self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith("Z"),
                                "%s is still running: %s" % (name, result.stdout))


class FrameCaching(unittest.TestCase):
    def test_static_card_progress_changes_within_one_second(self):
        shot = {"kind": "intro", "start": 0}
        self.assertNotEqual(render.frame_key(shot, 0.1, 600), render.frame_key(shot, 0.4, 600))

    def test_static_terminal_progress_changes_between_blinks(self):
        shot = {"kind": "step", "start": 0, "step": {"command": "echo hi"},
                "typing": 0.7, "typing_end": 1.05, "out": [], "reveal": 0,
                "output_start": 1.3, "output_end": 1.3}
        self.assertNotEqual(render.frame_key(shot, 3.1, 600), render.frame_key(shot, 3.4, 600))


if __name__ == "__main__":
    unittest.main()
