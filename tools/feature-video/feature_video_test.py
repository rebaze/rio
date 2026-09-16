#!/usr/bin/env python3
"""Checks for the feature-video tooling. No network, no credentials, no paid API calls.

The interesting properties are the ones a viewer would notice and a reviewer cannot see
in a diff: that narration never describes something before it is on screen, that a clip
is never cut off to fit, that the cache regenerates exactly when the audio would differ,
and that a failure says what went wrong without printing the key.

    python3 tools/feature-video/feature_video_test.py
"""
import io
import json
import subprocess
import sys
import unittest
import wave
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capture  # noqa: E402
import narrate  # noqa: E402
import storyboard  # noqa: E402
import timeline  # noqa: E402
import verify  # noqa: E402


def step(command="echo hi", output="hi", exit_code=0, voice="", hold=3.0, elapsed=0.1,
         chapter="01 · Prepare the workspace", title="A step", cwd="/repo"):
    return dict(chapter=chapter, title=title, command=command, meaning="m", voice=voice,
                expectedExit=exit_code, output=output, exitCode=exit_code, cwd=cwd,
                elapsed=elapsed, hold=hold)


def transcript(steps):
    return {"version": 1, "title": "t", "commit": "c", "steps": steps}


def broken_key():
    raise AssertionError("a cached pass must not read the credential")


class stubbed_api(object):
    """Replace the HTTP layer with a local synthesizer. No test may reach the network."""

    def __enter__(self):
        import base64
        self.calls = []
        self.original = narrate._request

        def fake(url, key, body=None, timeout=None):
            self.calls.append(url)
            if url.endswith("/models"):
                return json.dumps({"models": [{"name": "models/" + storyboard.VOICE_MODEL}]}).encode()
            seconds = max(1, len(body["input"]) // 100)
            pcm = b"\x00\x01" * (24000 * seconds)
            return json.dumps({"output": [{"content": [{
                "type": "audio", "data": base64.b64encode(pcm).decode(),
                "mime_type": "audio/l16; rate=24000; channels=1"}]}]}).encode()

        narrate._request = fake
        return self.calls

    def __exit__(self, *exc):
        narrate._request = self.original


class TimelineOrdering(unittest.TestCase):
    def test_narration_starts_only_after_the_output_is_visible(self):
        steps = [step(command="rio normalize", output="a\nb\nc", voice="It passed.")]
        shots, total = timeline.build(transcript(steps), {"step-01": 4.0}, "in", "out")
        shot = shots[1]
        self.assertGreaterEqual(shot["audio_start"], shot["output_end"])
        self.assertEqual([], timeline.check_ordering(shots, {"step-01": 4.0, "intro": 0, "outro": 0}))

    def test_ordering_check_reports_a_clip_that_would_be_cut_off(self):
        shots = [dict(kind="step", title="s", voice="v", clip="step-01", audio_start=1.0,
                      output_end=1.0, duration=2.0, start=0.0)]
        problems = timeline.check_ordering(shots, {"step-01": 5.0})
        self.assertEqual(1, len(problems))
        self.assertIn("past the end of its shot", problems[0])

    def test_ordering_check_reports_speaking_before_the_result(self):
        shots = [dict(kind="step", title="s", voice="v", clip="step-01", audio_start=0.5,
                      output_end=2.0, duration=20.0, start=0.0)]
        problems = timeline.check_ordering(shots, {"step-01": 1.0})
        self.assertIn("before its output is complete", problems[0])

    def test_a_long_clip_lengthens_its_shot_rather_than_being_trimmed(self):
        steps = [step(voice="A very long explanation.", hold=1.0)]
        short, _ = timeline.build(transcript(steps), {"step-01": 2.0}, "i", "o")
        long, _ = timeline.build(transcript(steps), {"step-01": 30.0}, "i", "o")
        self.assertGreater(long[1]["duration"], short[1]["duration"] + 25)
        self.assertLessEqual(long[1]["audio_start"] + 30.0, long[1]["duration"])

    def test_the_whole_storyboard_holds_its_narration(self):
        steps = [step(voice=s["voice"], hold=s["hold"], command=s["command"],
                      chapter=s["chapter"], title=s["title"])
                 for s in storyboard.STEPS]
        clips = {"intro": 30.0, "outro": 28.0}
        for index, s in enumerate(storyboard.STEPS, 1):
            if s["voice"]:
                clips["step-%02d" % index] = len(s["voice"].split()) / 150.0 * 60.0
        shots, total = timeline.build(transcript(steps), clips, storyboard.INTRO_VOICE,
                                      storyboard.OUTRO_VOICE)
        self.assertEqual([], timeline.check_ordering(shots, clips))
        self.assertGreater(total, 240)

    def test_durations_land_on_whole_frames(self):
        shots, total = timeline.build(transcript([step()]), {}, "i", "o")
        for shot in shots:
            self.assertAlmostEqual(shot["duration"] * timeline.FPS,
                                   round(shot["duration"] * timeline.FPS), places=6)


class TimelineLimits(unittest.TestCase):
    def test_output_taller_than_the_terminal_is_refused(self):
        tall = step(output="\n".join("line %d" % n for n in range(40)))
        with self.assertRaises(ValueError) as caught:
            timeline.build(transcript([tall]), {}, "i", "o")
        self.assertIn("terminal rows", str(caught.exception))

    def test_narration_without_measured_audio_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            timeline.build(transcript([step(voice="spoken")]), {}, "i", "o")
        self.assertIn("no measured audio", str(caught.exception))

    def test_long_lines_wrap_to_the_terminal_width(self):
        rows = timeline.wrap_chars("x" * 200)
        self.assertTrue(all(len(r) <= timeline.COLS for r in rows))
        self.assertEqual("x" * 200, "".join(rows))

    def test_a_refusal_is_coloured_as_one(self):
        rows = timeline.output_rows(
            step(command="rio normalize", output="rio: refused", exit_code=2))
        self.assertEqual("red", rows[0][1])

    def test_a_refusal_keeps_its_colour_even_when_the_command_echoes(self):
        rows = timeline.output_rows(step(command="echo hi", output="refused", exit_code=2))
        self.assertEqual("red", rows[0][1])

    def test_a_reported_nonzero_status_is_coloured_as_a_failure(self):
        self.assertEqual("red", timeline.output_rows(step(command="echo $?", output="2"))[0][1])
        self.assertEqual("mint", timeline.output_rows(step(command="echo $?", output="0"))[0][1])


class Captions(unittest.TestCase):
    def setUp(self):
        steps = [step(command="rio normalize", output="ok", voice="Rio checked the SBOM.")]
        self.clips = {"intro": 3.0, "step-01": 6.0, "outro": 2.0}
        self.shots, self.total = timeline.build(transcript(steps), self.clips, "Intro.", "Outro.")
        self.cues = timeline.captions(self.shots, self.clips)

    def test_cues_are_ordered_and_inside_the_video(self):
        for start, end, _ in self.cues:
            self.assertLess(start, end)
            self.assertLessEqual(end, self.total + 0.001)
        self.assertEqual(sorted(self.cues, key=lambda c: c[0]), self.cues)

    def test_cues_use_the_written_prose_not_the_spoken_form(self):
        text = " ".join(c[2] for c in self.cues)
        self.assertIn("SBOM", text)
        self.assertNotIn("S B O M", text)

    def test_srt_and_vtt_agree_on_timing(self):
        self.assertTrue(timeline.vtt(self.cues).startswith("WEBVTT"))
        self.assertIn("-->", timeline.srt(self.cues))
        self.assertIn(",", timeline.srt(self.cues).splitlines()[1])
        self.assertIn(".", timeline.vtt(self.cues).splitlines()[3])

    def test_caption_time_formats_hours(self):
        self.assertEqual("01:01:01,500", timeline.caption_time(3661.5))
        self.assertEqual("01:01:01.500", timeline.caption_time(3661.5, comma=False))


class Chapters(unittest.TestCase):
    def test_chapters_are_contiguous_and_cover_the_video(self):
        steps = [step(chapter="01 · One"), step(chapter="01 · One"), step(chapter="02 · Two")]
        shots, total = timeline.build(transcript(steps), {}, "i", "o")
        marks = timeline.chapters(shots, total)
        self.assertEqual(["Introduction", "01 · One", "02 · Two", "Summary and boundaries"],
                         [m["title"] for m in marks])
        for index, mark in enumerate(marks[:-1]):
            self.assertEqual(mark["end"], marks[index + 1]["start"])
        self.assertEqual(total, marks[-1]["end"])

    def test_ffmetadata_uses_a_millisecond_timebase(self):
        marks = [dict(title="One", start=0.0, end=1.5)]
        text = timeline.ffmetadata(marks, "T", "C")
        self.assertIn("TIMEBASE=1/1000", text)
        self.assertIn("START=0", text)
        self.assertIn("END=1500", text)


class NarrationCache(unittest.TestCase):
    def test_the_key_covers_everything_that_changes_the_sound(self):
        base = narrate.cache_key("hello")
        self.assertEqual(base, narrate.cache_key("hello"))
        self.assertNotEqual(base, narrate.cache_key("hello there"))
        self.assertNotEqual(base, narrate.cache_key("hello", voice="Kore"))
        self.assertNotEqual(base, narrate.cache_key("hello", model="other"))
        self.assertNotEqual(base, narrate.cache_key("hello", direction="Read it fast."))
        self.assertNotEqual(base, narrate.cache_key("hello", provider="openai"))

    def test_a_cached_clip_is_reused_and_force_retakes_it(self):
        with TempCache() as cache:
            clips = [("intro", "one"), ("outro", "two")]
            planned = narrate.plan_clips(clips, cache)
            self.assertEqual([True, True], [p["generate"] for p in planned])
            cache.write(planned[0]["key"], b"RIFFfake", {"clip": "intro"})
            planned = narrate.plan_clips(clips, cache)
            self.assertEqual([False, True], [p["generate"] for p in planned])
            forced = narrate.plan_clips(clips, cache, force=True)
            self.assertEqual([True, True], [p["generate"] for p in forced])

    def test_only_restricts_generation_to_the_named_clips(self):
        with TempCache() as cache:
            planned = narrate.plan_clips([("intro", "a"), ("outro", "b")], cache, only=["outro"])
            self.assertEqual({"intro": False, "outro": True},
                             {p["clip"]: p["generate"] for p in planned})

    def test_changing_one_clip_leaves_the_others_cached(self):
        with TempCache() as cache:
            for item in narrate.plan_clips([("intro", "a"), ("outro", "b")], cache):
                cache.write(item["key"], b"RIFFfake", {})
            planned = narrate.plan_clips([("intro", "a"), ("outro", "b changed")], cache)
            self.assertEqual({"intro": False, "outro": True},
                             {p["clip"]: p["generate"] for p in planned})

    def test_a_partial_pass_writes_no_narration_manifest(self):
        with TempCache() as cache, stubbed_api() as calls:
            clips, usage = narrate.narrate(
                [("intro", "a"), ("outro", "b")], cache, only=["intro"],
                key_reader=lambda: "key", log=lambda *a: None)
            self.assertIsNone(clips)
            self.assertEqual(1, usage["requestsThisRun"])
            self.assertEqual(1, len([c for c in calls if "interactions" in c]))

    def test_a_complete_pass_reuses_the_cache_on_a_second_run(self):
        with TempCache() as cache, stubbed_api() as calls:
            clips = [("intro", "a"), ("outro", "b")]
            first, usage = narrate.narrate(clips, cache, key_reader=lambda: "key",
                                           log=lambda *a: None)
            self.assertEqual(2, len(first))
            self.assertEqual(2, usage["requestsThisRun"])
            del calls[:]
            second, usage = narrate.narrate(clips, cache, key_reader=broken_key,
                                            log=lambda *a: None)
            # Nothing was generated, so no credential was read and nothing was called.
            self.assertEqual([], calls)
            self.assertEqual(0, usage["requestsThisRun"])
            self.assertEqual(2, usage["clipsReused"])
            self.assertEqual([c["seconds"] for c in first], [c["seconds"] for c in second])


class TempCache(narrate.Cache):
    def __init__(self):
        import tempfile
        self._dir = tempfile.TemporaryDirectory()
        narrate.Cache.__init__(self, self._dir.name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._dir.cleanup()


class AudioDecoding(unittest.TestCase):
    def test_the_documented_mime_is_parsed(self):
        self.assertEqual((24000, 1), narrate.parse_audio_mime("audio/l16; rate=24000; channels=1"))

    def test_mime_spelling_and_spacing_do_not_matter(self):
        for mime in ("audio/L16;rate=24000;channels=1", "AUDIO/L16; RATE=24000",
                     "audio/L16 ; rate = 24000 ; channels = 1"):
            self.assertEqual(24000, narrate.parse_audio_mime(mime)[0], mime)

    def test_an_unstated_rate_falls_back_to_the_documented_default(self):
        self.assertEqual((24000, 1), narrate.parse_audio_mime("audio/pcm"))

    def test_a_nonpositive_rate_is_refused(self):
        with self.assertRaises(narrate.NarrationError):
            narrate.parse_audio_mime("audio/l16; rate=0")

    def test_raw_pcm_is_wrapped_as_a_readable_wav(self):
        pcm = b"\x00\x01" * 24000
        data = narrate.to_wav(pcm, "audio/l16; rate=24000; channels=1")
        self.assertEqual(b"RIFF", data[:4])
        with wave.open(io.BytesIO(data), "rb") as handle:
            self.assertEqual(24000, handle.getframerate())
            self.assertEqual(1, handle.getnchannels())
            self.assertEqual(2, handle.getsampwidth())
        self.assertAlmostEqual(1.0, narrate.wav_duration(data), places=6)

    def test_an_existing_riff_header_is_not_wrapped_again(self):
        pcm = b"\x00\x01" * 100
        wav = narrate.to_wav(pcm, "audio/l16")
        self.assertEqual(wav, narrate.to_wav(wav, "audio/wav"))

    def test_a_truncated_frame_is_refused(self):
        with self.assertRaises(narrate.NarrationError):
            narrate.to_wav(b"\x00\x01\x02", "audio/l16; rate=24000; channels=1")

    def test_an_unknown_format_names_itself(self):
        with self.assertRaises(narrate.NarrationError) as caught:
            narrate.to_wav(b"OggS....", "audio/ogg")
        self.assertIn("audio/ogg", str(caught.exception))

    def test_audio_is_found_in_either_response_shape(self):
        import base64
        encoded = base64.b64encode(b"\x00\x01").decode()
        typed = {"output": [{"content": [{"type": "audio", "data": encoded,
                                          "mime_type": "audio/l16; rate=24000"}]}]}
        inline = {"candidates": [{"content": {"parts": [
            {"inlineData": {"data": encoded, "mimeType": "audio/L16;rate=24000"}}]}}]}
        for payload in (typed, inline):
            wav, mime = narrate.decode_response(payload)
            self.assertEqual(b"RIFF", wav[:4])
            self.assertIn("24000", mime)

    def test_a_response_without_audio_says_so(self):
        with self.assertRaises(narrate.NarrationError) as caught:
            narrate.decode_response({"candidates": [{"finishReason": "SAFETY"}]})
        self.assertIn("no audio", str(caught.exception))

    def test_an_empty_audio_block_says_so(self):
        with self.assertRaises(narrate.NarrationError) as caught:
            narrate.decode_response({"type": "audio", "data": ""})
        self.assertIn("empty", str(caught.exception))


class ErrorHandling(unittest.TestCase):
    def test_a_missing_model_refuses_instead_of_substituting_a_voice(self):
        original = narrate._request
        narrate._request = lambda *a, **k: json.dumps(
            {"models": [{"name": "models/gemini-2.5-pro-preview-tts"}]}).encode()
        try:
            with self.assertRaises(narrate.NarrationError) as caught:
                narrate.check_model("key")
        finally:
            narrate._request = original
        message = str(caught.exception)
        self.assertIn(storyboard.VOICE_MODEL, message)
        self.assertIn("do not substitute", message)

    def test_the_approved_model_is_accepted(self):
        original = narrate._request
        narrate._request = lambda *a, **k: json.dumps(
            {"models": [{"name": "models/" + storyboard.VOICE_MODEL}]}).encode()
        try:
            narrate.check_model("key")
        finally:
            narrate._request = original

    def test_a_locked_password_manager_says_how_to_fix_it(self):
        original = subprocess.run
        subprocess.run = lambda *a, **k: subprocess.CompletedProcess(
            a[0], 1, "", "[ERROR] account is not signed in")
        try:
            with self.assertRaises(narrate.NarrationError) as caught:
                narrate.read_credential()
        finally:
            subprocess.run = original
        self.assertIn("op signin", str(caught.exception))

    def test_a_credential_read_never_puts_the_secret_in_the_command(self):
        seen = {}
        original = subprocess.run

        def record(args, **kwargs):
            seen["args"] = args
            return subprocess.CompletedProcess(args, 0, "sekrit\n", "")

        subprocess.run = record
        try:
            self.assertEqual("sekrit", narrate.read_credential("op://v/i/f"))
        finally:
            subprocess.run = original
        self.assertEqual(["op", "read", "op://v/i/f"], seen["args"])
        self.assertNotIn("sekrit", " ".join(seen["args"]))

    def test_an_http_failure_reports_status_without_the_key(self):
        import urllib.error
        original = narrate.urllib.request.urlopen

        def fail(*a, **k):
            raise urllib.error.HTTPError(
                "https://example.invalid", 403, "Forbidden", {},
                io.BytesIO(json.dumps({"error": {"status": "PERMISSION_DENIED",
                                                 "message": "key sekrit-123 invalid"}}).encode()))

        narrate.urllib.request.urlopen = fail
        try:
            with self.assertRaises(narrate.NarrationError) as caught:
                narrate._request("https://example.invalid", "sekrit-123", {"a": 1})
        finally:
            narrate.urllib.request.urlopen = original
        message = str(caught.exception)
        self.assertIn("403", message)
        self.assertIn("PERMISSION_DENIED", message)
        self.assertNotIn("sekrit-123", message)

    def test_a_hostile_error_code_cannot_smuggle_text_into_the_message(self):
        import urllib.error
        original = narrate.urllib.request.urlopen

        def fail(*a, **k):
            raise urllib.error.HTTPError(
                "https://example.invalid", 500, "Server Error", {},
                io.BytesIO(json.dumps({"error": {"status": "x" * 200 + " key leaked"}}).encode()))

        narrate.urllib.request.urlopen = fail
        try:
            with self.assertRaises(narrate.NarrationError) as caught:
                narrate._request("https://example.invalid", "k", {"a": 1})
        finally:
            narrate.urllib.request.urlopen = original
        self.assertEqual("HTTP 500", str(caught.exception))


class Pronunciation(unittest.TestCase):
    def test_only_the_synthesizer_sees_the_spoken_form(self):
        written = "Rio reads the SBOM and the CI context as JSON."
        spoken = narrate.spoken_form(written)
        self.assertEqual("Ree oh reads the S B O M and the C I context as jay son.", spoken)
        self.assertIn("Rio", written)

    def test_substitutions_respect_word_boundaries(self):
        self.assertEqual("Priority riot", narrate.spoken_form("Priority riot"))


class Cost(unittest.TestCase):
    def test_the_estimate_follows_the_published_rates(self):
        # 60 s of audio is 1500 audio tokens at $20/M; 1000 input tokens is $1/M.
        self.assertAlmostEqual(0.001 + 0.03, narrate.estimate_cost(1000, 60.0), places=6)

    def test_a_full_pass_lands_in_the_planned_range(self):
        words = sum(len(text.split()) for _, text in storyboard.narration_clips())
        seconds = words / 150.0 * 60.0
        characters = sum(len(narrate.spoken_form(t)) for _, t in storyboard.narration_clips())
        cost = narrate.estimate_cost(characters / 4.0, seconds)
        self.assertTrue(0.10 <= cost <= 0.30, "a full pass now estimates $%.3f" % cost)

    def test_reported_tokens_are_preferred_over_an_estimate(self):
        self.assertEqual(41, narrate.reported_tokens({"usageMetadata": {"promptTokenCount": 41}}))
        self.assertIsNone(narrate.reported_tokens({"usageMetadata": {}}))
        self.assertIsNone(narrate.reported_tokens(None))


class Capture(unittest.TestCase):
    def test_the_status_marker_is_read_back_off_the_shell(self):
        text = "hello\nworld\n__M__:2:/tmp/work\n"
        output, code, cwd = capture.parse_marked(text, "__M__")
        self.assertEqual("hello\nworld", output)
        self.assertEqual(2, code)
        self.assertEqual("/tmp/work", cwd)

    def test_a_working_directory_containing_a_colon_survives(self):
        output, code, cwd = capture.parse_marked("x\n__M__:0:/tmp/a:b\n", "__M__")
        self.assertEqual("/tmp/a:b", cwd)

    def test_a_missing_marker_is_an_error_not_a_silent_zero(self):
        with self.assertRaises(capture.CaptureError):
            capture.parse_marked("output with no marker", "__M__")

    def test_the_payload_restores_the_real_exit_status(self):
        payload = capture.payload_for("false", "__M__")
        self.assertIn("false\n", payload)
        self.assertIn('(exit "$__rio_video_rc")', payload)

    def test_an_unexpected_exit_status_fails_the_capture(self):
        steps = [dict(command="true", expectedExit=2, title="t", chapter="01 · c",
                      meaning="m", voice="", hold=1)]
        with self.assertRaises(capture.CaptureError) as caught:
            capture.run_steps(steps, Path("/tmp"), log=lambda *a: None)
        self.assertIn("expected exit 2", str(caught.exception))

    def test_a_real_refusal_is_captured_with_its_exit_code(self):
        steps = [dict(command="sh -c 'echo refused >&2; exit 2'", expectedExit=2, title="t",
                      chapter="01 · c", meaning="m", voice="", hold=1)]
        records = capture.run_steps(steps, Path("/tmp"), log=lambda *a: None)
        self.assertEqual(2, records[0]["exitCode"])
        self.assertEqual("refused", records[0]["output"])


class Storyboard(unittest.TestCase):
    def test_every_chapter_explains_why_it_matters(self):
        for step_ in storyboard.STEPS:
            self.assertIn(step_["chapter"][:2], storyboard.WHY)

    def test_the_refusals_are_declared_as_refusals(self):
        refusals = [s for s in storyboard.STEPS if s["expectedExit"] == 2]
        self.assertEqual(3, len(refusals))
        for step_ in refusals:
            self.assertIn("rio normalize", step_["command"])

    def test_the_voice_decision_is_the_approved_one(self):
        self.assertEqual("google", storyboard.VOICE_PROVIDER)
        self.assertEqual("gemini-3.1-flash-tts-preview", storyboard.VOICE_MODEL)
        self.assertEqual("Charon", storyboard.VOICE_NAME)
        self.assertIn("REE-oh", storyboard.VOICE_DIRECTION)

    def test_clip_names_line_up_with_the_steps_that_speak(self):
        names = [name for name, _ in storyboard.narration_clips()]
        self.assertEqual("intro", names[0])
        self.assertEqual("outro", names[-1])
        for index, step_ in enumerate(storyboard.STEPS, 1):
            self.assertEqual(bool(step_["voice"]), ("step-%02d" % index) in names)

    def test_the_closing_narration_states_the_limitation(self):
        self.assertIn("not authenticated build provenance", storyboard.OUTRO_VOICE)


class Verification(unittest.TestCase):
    def test_caption_timestamps_are_read_in_both_dialects(self):
        self.assertAlmostEqual(3661.5, verify.parse_caption_time("01:01:01,500"))
        self.assertAlmostEqual(3661.5, verify.parse_caption_time("01:01:01.500"))

    def test_generated_captions_parse_back_to_the_times_they_were_written_with(self):
        cues = [(1.0, 2.5, "one"), (2.5, 4.0, "two")]
        for text in (timeline.srt(cues), timeline.vtt(cues)):
            parsed = verify.parse_cues(text)
            self.assertEqual(2, len(parsed))
            self.assertAlmostEqual(1.0, parsed[0][0], places=3)
            self.assertAlmostEqual(4.0, parsed[1][1], places=3)

    def test_well_formed_captions_pass(self):
        self.assertEqual([], verify.check_cues([(1.0, 2.0), (2.0, 3.0)], 10.0))

    def test_captions_running_past_the_end_are_caught(self):
        problems = verify.check_cues([(1.0, 2.0), (2.0, 30.0)], 10.0)
        self.assertIn("after the video does", problems[0])

    def test_overlapping_and_inverted_cues_are_caught(self):
        self.assertIn("overlaps", " ".join(verify.check_cues([(1.0, 5.0), (2.0, 6.0)], 10.0)))
        self.assertIn("ends before it starts", " ".join(verify.check_cues([(5.0, 1.0)], 10.0)))

    def test_chapters_that_match_the_timeline_pass(self):
        expected = [{"start": 0.0, "title": "One", "end": 5.0},
                    {"start": 5.0, "title": "Two", "end": 9.0}]
        found = [{"start_time": "0.000", "end_time": "5.000", "tags": {"title": "One"}},
                 {"start_time": "5.000", "end_time": "9.000", "tags": {"title": "Two"}}]
        self.assertEqual([], verify.check_chapters(found, expected, 9.0))

    def test_a_collapsed_chapter_is_caught(self):
        # This is what a missing -movie_timescale produced in the draft.
        expected = [{"start": 0.0, "title": "One", "end": 5.0},
                    {"start": 5.0, "title": "Two", "end": 9.0}]
        found = [{"start_time": "0.000", "end_time": "5.000", "tags": {"title": "One"}},
                 {"start_time": "5.000", "end_time": "5.000", "tags": {"title": "Two"}}]
        problems = verify.check_chapters(found, expected, 9.0)
        self.assertIn("no duration", " ".join(problems))

    def test_a_wrong_chapter_title_or_start_is_caught(self):
        expected = [{"start": 0.0, "title": "One", "end": 9.0}]
        drifted = [{"start_time": "3.000", "end_time": "9.000", "tags": {"title": "One"}}]
        renamed = [{"start_time": "0.000", "end_time": "9.000", "tags": {"title": "Other"}}]
        self.assertIn("expected 0.00s", " ".join(verify.check_chapters(drifted, expected, 9.0)))
        self.assertIn("is titled", " ".join(verify.check_chapters(renamed, expected, 9.0)))

    def test_clips_paced_like_their_script_pass(self):
        clips = [{"clip": "intro", "text": "one two three four five", "seconds": 2.0}]
        self.assertEqual([], verify.check_speaking_rates(verify.speaking_rates(clips)))

    def test_a_clip_with_an_added_preamble_is_caught(self):
        # Five words that took twenty seconds: the synthesizer said more than it was given.
        clips = [{"clip": "intro", "text": "one two three four five", "seconds": 20.0}]
        problems = verify.check_speaking_rates(verify.speaking_rates(clips))
        self.assertIn("may have gained words", problems[0])

    def test_a_clip_missing_a_sentence_is_caught(self):
        clips = [{"clip": "intro", "text": " ".join(["word"] * 100), "seconds": 5.0}]
        problems = verify.check_speaking_rates(verify.speaking_rates(clips))
        self.assertIn("may have lost words", problems[0])

    def test_a_clip_with_no_measured_audio_is_not_rated(self):
        self.assertEqual({}, verify.speaking_rates([{"clip": "a", "text": "x", "seconds": 0}]))

    def test_a_missing_chapter_is_caught(self):
        expected = [{"start": 0.0, "title": "One", "end": 5.0},
                    {"start": 5.0, "title": "Two", "end": 9.0}]
        problems = verify.check_chapters(expected[:1] and [
            {"start_time": "0.000", "end_time": "9.000", "tags": {"title": "One"}}], expected, 9.0)
        self.assertIn("1 chapters in the file, 2 in the timeline", " ".join(problems))


if __name__ == "__main__":
    unittest.main(verbosity=2)
