"""Terminal helpers: colour detection, labels, progress and spinner all degrade to plain text."""
import io
import os
import unittest
import unittest.mock as mock

from aiit.common import term


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class ColorDetectionTests(unittest.TestCase):
    def setUp(self):
        term.set_color(None)
        self.addCleanup(term.set_color, None)

    def test_no_color_wins_over_force_color_and_tty(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1", "FORCE_COLOR": "1"}):
            self.assertFalse(term.supports_color(_Tty()))

    def test_force_color_enables_on_a_pipe(self):
        with mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=False):
            os.environ.pop("NO_COLOR", None)
            self.assertTrue(term.supports_color(io.StringIO()))

    def test_pipe_and_dumb_terminal_are_plain(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("NO_COLOR", "FORCE_COLOR"):
                os.environ.pop(k, None)
            self.assertFalse(term.supports_color(io.StringIO()))
            os.environ["TERM"] = "dumb"
            self.assertFalse(term.supports_color(_Tty()))

    def test_explicit_override_beats_detection(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            term.set_color(True)
            self.assertTrue(term.use_color(io.StringIO()))
            self.assertIn("\x1b[", term.paint("x", "red"))
            term.set_color(False)
            self.assertEqual(term.paint("x", "red", "bold"), "x")

    def test_windows_vt_failure_means_no_color(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("NO_COLOR", "FORCE_COLOR", "TERM"):
                os.environ.pop(k, None)
            with mock.patch.object(term, "_enable_windows_vt", return_value=False):
                self.assertFalse(term.supports_color(_Tty()))
            with mock.patch.object(term, "_enable_windows_vt", return_value=True):
                self.assertTrue(term.supports_color(_Tty()))


class LabelTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(term.set_color, None)

    def test_labels_are_fixed_width_and_plain_without_color(self):
        term.set_color(False)
        self.assertEqual(term.risk_label("low"), "low      ")
        self.assertEqual(term.status_label("failed"), "failed      ")
        self.assertEqual(term.risk_label("weird"), "weird    ")

    def test_labels_are_coloured_with_color(self):
        term.set_color(True)
        self.assertTrue(term.risk_label("high").startswith("\x1b[31;1m"))
        self.assertTrue(term.status_label("success").startswith("\x1b[32m"))
        self.assertTrue(term.risk_label("high").endswith("\x1b[0m"))

    def test_report_error_prints_one_line_and_hint(self):
        term.set_color(False)
        out = io.StringIO()
        term.report_error("boom\nsecond line ignored", "try --debug", stream=out)
        self.assertEqual(out.getvalue(), "error: boom\n  hint: try --debug\n")


class ProgressAndSpinnerTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(term.set_color, None)

    def test_progress_on_a_pipe_is_one_plain_line_per_item(self):
        term.set_color(False)
        out = io.StringIO()
        p = term.Progress(stream=out)
        p.start("sys/echo")
        p.done("sys/echo", ok=True, duration_ms=12)
        p.start("logs/missing")
        p.done("logs/missing", ok=False, note="command not found", duration_ms=3)
        self.assertEqual(out.getvalue(), "  - sys/echo ... ok (12 ms)\n  - logs/missing ... FAIL (3 ms)  command not found\n")

    def test_progress_on_a_tty_writes_the_status_on_the_same_line(self):
        term.set_color(True)
        out = _Tty()
        p = term.Progress(stream=out)
        p.start("sys/echo")
        self.assertEqual(out.getvalue(), "  - sys/echo ... ")
        p.done("sys/echo", ok=True, duration_ms=5)
        self.assertIn("\x1b[32mok\x1b[0m (5 ms)\n", out.getvalue())

    def test_spinner_on_a_pipe_prints_once_and_never_an_escape(self):
        term.set_color(False)
        out = io.StringIO()
        with term.Spinner("Waiting for the model", stream=out):
            pass
        self.assertEqual(out.getvalue(), "Waiting for the model ...\n")

    def test_spinner_on_a_tty_animates_and_clears(self):
        term.set_color(True)
        out = _Tty()
        with term.Spinner("Thinking", stream=out, interval=0.01) as sp:
            sp._stop.wait(0.05)
        text = out.getvalue()
        self.assertIn("\rThinking ", text)
        self.assertTrue(text.endswith("\r" + " " * len("Thinking  ") + "\r"))
