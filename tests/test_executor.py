import codecs
import ctypes
import glob
import ntpath
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from datetime import timedelta
from pathlib import Path

from . import helpers
from aiit.common.audit import AuditLog
from aiit.common.crypto import Identity, sign_object
from aiit.common.policy import Policy
from aiit.common.schema import Enrollment, FixPlan, PlanStep, SignedPlan
from aiit.common.util import current_os, in_hours, iso, utcnow
from aiit.agent import executor as executor_mod
from aiit.agent import procs
from aiit.agent.collectors import WINDOWS, resolve_windows_argv, windows_system32_argv
from aiit.agent.executor import OUTPUT_CAP, apply_plan, run_step, shell_argv, verify_signed_plan
from aiit.agent.procs import (
    _KEEP_ENV, _POSIX_PATH, ProcResult, _is_sensitive, child_locale, console_codec, powershell_exe,
    run_capped, scrubbed_env, windows_path, windows_system32,
)


def make_plan(agent_id: str, steps: list[PlanStep], hours: float = 1.0) -> FixPlan:
    return FixPlan(
        issue_summary="i", diagnosis="d", confidence=0.5, steps=steps, plan_id="plan-000000000001", case_id="case-000000000001",
        target_agent_id=agent_id, target_os=current_os(), created_at=iso(), expires_at=in_hours(hours), provider="dryrun", model="none",
    )


def sign(console: Identity, plan: FixPlan) -> SignedPlan:
    return SignedPlan(plan=plan, signer_id=console.id, signer_pub=console.sign_pub_hex, approved_by="tester", approved_at=iso(),
                      signature=sign_object(console, plan.model_dump()))


def _sleeper_alive(token: str):
    """True when a ``sleep <token>`` process exists, None when that cannot be checked.

    On Linux every /proc cmdline is split into its argv elements and compared
    exactly (``sleep`` + the token), never as a substring, so an unrelated
    process whose command line merely contains the digits cannot trip the
    check. Elsewhere on POSIX ``pgrep -x -f`` matches the whole command line.
    """
    if os.path.isdir("/proc"):
        want = token.encode("ascii")
        for cmdline in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                with open(cmdline, "rb") as f:
                    parts = [p for p in f.read().split(b"\0") if p]
            except OSError:
                continue
            if len(parts) == 2 and parts[0].rsplit(b"/", 1)[-1] == b"sleep" and parts[1] == want:
                return True
        return False
    pgrep = shutil.which("pgrep")
    if pgrep is None:
        return None
    r = subprocess.run([pgrep, "-x", "-f", f"sleep {token}"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
    return r.returncode == 0


def _windows_sleeper_alive(token: str) -> bool:
    """True when a powershell.exe whose command line runs ``Start-Sleep -Seconds <token>`` exists.

    The query script travels on stdin, so the querying PowerShell's own
    command line never contains the token.
    """
    script = ("Get-CimInstance Win32_Process -Filter \"Name = 'powershell.exe'\" | "
              "ForEach-Object { $_.CommandLine }\n")
    pr = run_capped([powershell_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"],
                    90, stdin_bytes=script.encode(console_codec()))
    return re.search(r"Start-Sleep -Seconds " + re.escape(token) + r"(?!\d)", pr.stdout) is not None


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-aaaaaaaaaaaa", with_box=True)
        self.enr = Enrollment(console_id="console-aaaaaaaaaaaa", console_sign_pub=self.console.sign_pub_hex, console_box_pub=self.console.box_pub_hex, created_at=iso())
        self.step = PlanStep(id="s1", title="t", rationale="r", action="command", command="echo hi", risk="read_only")

    def test_good_plan_passes(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step]))
        self.assertEqual(verify_signed_plan(sp, self.enr, "agent-000000000001", []), [])

    def test_refusals(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step]))
        self.assertTrue(any("targets agent" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000002", [])))
        self.assertTrue(any("already applied" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", ["plan-000000000001"])))
        other = Identity.generate("console-bbbbbbbbbbbb", with_box=True)
        sp2 = sign(other, make_plan("agent-000000000001", [self.step]))
        self.assertTrue(any("not signed by the enrolled console" in p for p in verify_signed_plan(sp2, self.enr, "agent-000000000001", [])))
        tampered = sp.model_copy(deep=True)
        tampered.plan.steps[0].command = "echo evil"
        self.assertTrue(any("signature is invalid" in p for p in verify_signed_plan(tampered, self.enr, "agent-000000000001", [])))
        expired = make_plan("agent-000000000001", [self.step])
        expired.expires_at = (utcnow() - timedelta(hours=1)).isoformat(timespec="seconds")
        self.assertTrue(any("expired" in p for p in verify_signed_plan(sign(self.console, expired), self.enr, "agent-000000000001", [])))

    def test_plan_lifetime_too_long_refused(self):
        sp = sign(self.console, make_plan("agent-000000000001", [self.step], hours=100))
        self.assertTrue(any("lifetime too long" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", [])))
        # A shorter lifetime still passes, and the ceiling is configurable.
        self.assertEqual(verify_signed_plan(sp, self.enr, "agent-000000000001", [], max_plan_hours=200), [])

    def test_created_at_in_the_future_refused(self):
        plan = make_plan("agent-000000000001", [self.step])
        plan.created_at = (utcnow() + timedelta(hours=1)).isoformat(timespec="seconds")
        plan.expires_at = (utcnow() + timedelta(hours=1, minutes=30)).isoformat(timespec="seconds")
        sp = sign(self.console, plan)
        self.assertTrue(any("created_at is in the future" in p for p in verify_signed_plan(sp, self.enr, "agent-000000000001", [])))


class ScrubbedEnvTests(unittest.TestCase):
    def test_scrubbed_env_is_an_allow_list_with_fixed_path_and_locale(self):
        evil_path = r"C:\evil;C:\Windows\System32" if os.name == "nt" else "/evil/bin:/usr/bin"
        with mock.patch.dict(os.environ, {
            "PATH": evil_path, "USER": "bob", "HOSTNAME": "h", "LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8",
            "AIIT_KEY_PASSPHRASE": "x", "AIIT_SERVER_TOKEN": "y", "MY_API_KEY": "z", "SOME_SECRET": "s", "DB_PASSWORD": "p",
        }):
            env = scrubbed_env()
        # secrets and arbitrary variables never cross; only the allow list does
        for name in ("AIIT_KEY_PASSPHRASE", "AIIT_SERVER_TOKEN", "MY_API_KEY", "SOME_SECRET", "DB_PASSWORD", "USER", "HOSTNAME"):
            self.assertNotIn(name, env)
        self.assertLessEqual(set(env), set(_KEEP_ENV) | {"NoDefaultCurrentDirectoryInExePath"}, sorted(env))
        # PATH is replaced with the fixed system PATH, never inherited
        self.assertEqual(env["PATH"], windows_path() if os.name == "nt" else _POSIX_PATH)
        self.assertNotIn("evil", env["PATH"])
        self.assertNotIn("%", env["PATH"])
        self.assertEqual(env["NoDefaultCurrentDirectoryInExePath"], "1")
        # the locale is pinned to one that exists on this platform, not inherited
        self.assertEqual(env["LC_ALL"], child_locale())
        self.assertNotEqual(env["LC_ALL"], "de_DE.UTF-8")

    def test_is_sensitive_on_representative_names(self):
        for name in ("AIIT_KEY_PASSPHRASE", "aiit_server_token", "CI_DEPLOY_TOKEN", "STORAGE_ACCOUNT_KEY", "MY_API_KEY",
                     "APP_SECRET", "DB_PASSWORD", "PassPhrase", "CLOUD_CREDENTIAL_FILE"):
            self.assertTrue(_is_sensitive(name), name)
        for name in _KEEP_ENV + ("USER", "HOSTNAME", "SHELL", "PWD"):
            self.assertFalse(_is_sensitive(name), name)

    def test_sensitive_name_is_dropped_even_when_allow_listed(self):
        # Defence in depth: adding a secret-bearing name to the keep list must not leak it.
        with mock.patch.object(procs, "_KEEP_ENV", procs._KEEP_ENV + ("SOME_API_KEY",)), \
             mock.patch.dict(os.environ, {"SOME_API_KEY": "k"}):
            env = scrubbed_env()
        self.assertNotIn("SOME_API_KEY", env)

    def test_child_locale_only_pins_locales_that_exist(self):
        self.assertEqual(child_locale("linux"), "C.UTF-8")
        self.assertEqual(child_locale("linux2"), "C.UTF-8")
        self.assertEqual(child_locale("darwin"), "en_US.UTF-8")
        self.assertEqual(child_locale("win32"), "C")
        self.assertEqual(child_locale("freebsd14"), "C")
        self.assertEqual(child_locale(), child_locale(sys.platform))

    @unittest.skipUnless(os.name == "posix", "POSIX shells and locales")
    def test_posix_children_start_without_locale_warnings(self):
        pr = run_capped(["/bin/sh", "-c", "true"], 30)
        self.assertEqual(pr.exit_code, 0)
        self.assertEqual(pr.stderr, "")
        perl = shutil.which("perl")
        if perl:   # perl is the loudest setlocale() user: "Setting locale failed" on a missing locale
            pr = run_capped([perl, "-e", "1"], 30)
            self.assertEqual(pr.exit_code, 0)
            self.assertEqual(pr.stderr, "")


class ConsoleCodecTests(unittest.TestCase):
    def test_non_windows_is_utf8(self):
        self.assertEqual(console_codec("posix"), "utf-8")
        self.assertEqual(console_codec("java"), "utf-8")

    def test_windows_uses_the_oem_code_page(self):
        fake = mock.Mock()
        fake.kernel32.GetOEMCP.return_value = 850
        with mock.patch.object(ctypes, "windll", fake, create=True):
            self.assertEqual(console_codec("nt"), "cp850")
        fake.kernel32.GetOEMCP.return_value = 437
        with mock.patch.object(ctypes, "windll", fake, create=True):
            self.assertEqual(console_codec("nt"), "cp437")

    def test_windows_falls_back_to_mbcs(self):
        fake = mock.Mock()
        fake.kernel32.GetOEMCP.side_effect = OSError("no kernel32")
        with mock.patch.object(ctypes, "windll", fake, create=True):
            self.assertEqual(console_codec("nt"), "mbcs")
        fake.kernel32.GetOEMCP.side_effect = None
        fake.kernel32.GetOEMCP.return_value = 99999      # no such Python codec
        with mock.patch.object(ctypes, "windll", fake, create=True):
            self.assertEqual(console_codec("nt"), "mbcs")

    def test_default_is_a_real_codec_on_this_host(self):
        name = console_codec()
        self.assertEqual(name, console_codec(os.name))
        codecs.lookup(name)
        if os.name != "nt":
            self.assertEqual(name, "utf-8")


class RunStepEncodingTests(unittest.TestCase):
    def setUp(self):
        self.pr = ProcResult(exit_code=0, stdout="out", stderr="", timed_out=False, duration_ms=1)

    def test_unencodable_command_is_refused_before_running(self):
        euro = "\u20ac"   # not representable in cp437
        step = PlanStep(id="s1", title="t", rationale="r", action="command", command="Write-Output '" + euro + "'", risk="read_only")
        with mock.patch.object(executor_mod, "console_codec", return_value="cp437"), \
             mock.patch.object(executor_mod, "run_capped") as rc:
            result = run_step(step, "windows")
        rc.assert_not_called()
        self.assertEqual(result.status, "failed")
        self.assertIn("cp437", result.reason)
        self.assertIn("not run", result.reason)
        self.assertEqual(result.command, step.command)
        self.assertEqual(result.exit_code, None)

    def test_windows_command_is_fed_to_powershell_on_stdin_in_the_console_codec(self):
        e_acute = "\u00e9"   # 0x82 in cp850
        step = PlanStep(id="s1", title="t", rationale="r", action="command", command="Write-Output 'caf" + e_acute + "'", risk="read_only")
        with mock.patch.object(executor_mod, "console_codec", return_value="cp850"), \
             mock.patch.object(executor_mod, "run_capped", return_value=self.pr) as rc, \
             mock.patch.dict(os.environ, {"SystemRoot": r"C:\WinTest"}):
            result = run_step(step, "windows")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.stdout, "out")
        argv = rc.call_args.args[0]
        self.assertEqual(argv[0], r"C:\WinTest\System32\WindowsPowerShell\v1.0\powershell.exe")
        self.assertEqual(argv[-2:], ["-Command", "-"])
        self.assertNotIn(step.command, argv)   # the command never travels on the command line
        self.assertEqual(rc.call_args.args[1], step.timeout_seconds)
        self.assertEqual(rc.call_args.kwargs["stdin_bytes"], step.command.encode("cp850") + b"\n")
        self.assertEqual(rc.call_args.kwargs["cap"], OUTPUT_CAP)

    def test_posix_command_runs_under_sh_without_stdin(self):
        step = PlanStep(id="s1", title="t", rationale="r", action="command", command="echo hi", risk="read_only")
        with mock.patch.object(executor_mod, "run_capped", return_value=self.pr) as rc:
            result = run_step(step, "linux")
        self.assertEqual(result.status, "success")
        self.assertEqual(rc.call_args.args[0], ["/bin/sh", "-c", "echo hi"])
        self.assertIsNone(rc.call_args.kwargs["stdin_bytes"])


class WindowsArgvTests(unittest.TestCase):
    ROOT = r"C:\WinTest"
    PS = ROOT + r"\System32\WindowsPowerShell\v1.0\powershell.exe"

    def test_system32_paths_are_absolute_under_systemroot(self):
        with mock.patch.dict(os.environ, {"SystemRoot": self.ROOT}):
            ps, tk = powershell_exe(), windows_system32("taskkill.exe")
            ipc, path = windows_system32_argv("ipconfig.exe", "/all"), windows_path()
        self.assertEqual(ps, self.PS)
        self.assertEqual(tk, self.ROOT + r"\System32\taskkill.exe")
        self.assertEqual(ipc, [self.ROOT + r"\System32\ipconfig.exe", "/all"])
        for p in (ps, tk, ipc[0]):
            self.assertTrue(ntpath.isabs(p), p)
        self.assertEqual(path, ";".join([self.ROOT + r"\System32", self.ROOT,
                                         self.ROOT + r"\System32\WindowsPowerShell\v1.0", self.ROOT + r"\System32\Wbem"]))
        self.assertNotIn("%", path)

    def test_systemroot_falls_back_to_c_windows(self):
        env = {k: v for k, v in os.environ.items() if k.lower() != "systemroot"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(powershell_exe(), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
            self.assertTrue(windows_path().startswith(r"C:\Windows\System32;C:\Windows;"))

    def test_static_windows_collectors_use_absolute_programs(self):
        for c in WINDOWS:
            self.assertTrue(ntpath.isabs(c.argv[0]), c.name)
            self.assertIn("\\System32\\", c.argv[0], c.name)
            if c.argv[0].lower().endswith("powershell.exe"):
                self.assertEqual(c.argv[1:5], ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"], c.name)

    def test_shell_argv_windows_reads_the_command_from_stdin(self):
        with mock.patch.dict(os.environ, {"SystemRoot": self.ROOT}):
            argv = shell_argv("Write-Output 'hi'", "windows")
        self.assertEqual(argv[0], self.PS)
        self.assertEqual(argv[-2:], ["-Command", "-"])
        self.assertNotIn("Write-Output 'hi'", argv)
        self.assertIn("-NoProfile", argv)
        self.assertIn("-NonInteractive", argv)
        self.assertEqual(shell_argv("echo hi", "linux"), ["/bin/sh", "-c", "echo hi"])

    def test_bare_powershell_collector_is_resolved_with_hardened_switches(self):
        with mock.patch.dict(os.environ, {"SystemRoot": self.ROOT}):
            plain = resolve_windows_argv(["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"])
            dupes = resolve_windows_argv(["PowerShell", "-ExecutionPolicy", "Unrestricted", "-NoProfile", "-File", "x.ps1", "-NoProfile"])
            native = resolve_windows_argv(["ipconfig", "/all"], exists=lambda p: True)
            native_exe = resolve_windows_argv(["netsh.exe", "winhttp", "show", "proxy"], exists=lambda p: p.endswith("netsh.exe"))
            unknown = resolve_windows_argv(["definitely-not-a-real-command-xyz"], exists=lambda p: False)
            explicit = resolve_windows_argv([r"C:\Tools\x.exe", "a"], exists=lambda p: True)
        flags = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
        self.assertEqual(plain, [self.PS, *flags, "-Command", "Write-Output ok"])
        self.assertEqual(dupes, [self.PS, *flags, "-File", "x.ps1", "-NoProfile"])
        self.assertEqual(native, [self.ROOT + r"\System32\ipconfig.exe", "/all"])
        self.assertEqual(native_exe, [self.ROOT + r"\System32\netsh.exe", "winhttp", "show", "proxy"])
        self.assertEqual(unknown, ["definitely-not-a-real-command-xyz"])
        self.assertEqual(explicit, [r"C:\Tools\x.exe", "a"])
        self.assertEqual(resolve_windows_argv([]), [])


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.console = Identity.generate("console-aaaaaaaaaaaa", with_box=True)
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl", actor_id="agent-000000000001")

    def tearDown(self):
        self.tmp.cleanup()

    def _enforce(self) -> Policy:
        pol = Policy()
        pol.mode = "enforce"
        return pol

    def test_dry_run_default_runs_nothing(self):
        steps = [PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hi"), risk="read_only"),
                 PlanStep(id="s2", title="manual", rationale="r", action="manual", risk="high")]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, Policy(), "agent-000000000001", self.audit)
        self.assertEqual(report.mode, "dry_run")
        self.assertEqual([r.status for r in report.results], ["dry_run", "manual"])
        self.assertTrue(self.audit.verify()[0])

    def test_enforce_halts_on_failure(self):
        steps = [
            PlanStep(id="s1", title="echo", rationale="r", action="command", command=helpers.echo_cmd("hello-world"), risk="read_only"),
            PlanStep(id="s2", title="fails", rationale="r", action="command", command=helpers.fail_cmd(3), risk="low"),
            PlanStep(id="s3", title="skipped", rationale="r", action="command", command=helpers.echo_cmd("never"), risk="low"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.mode, "enforce")
        self.assertEqual([r.status for r in report.results], ["success", "failed", "skipped"])
        self.assertIn("hello-world", report.results[0].stdout)
        self.assertEqual(report.results[1].exit_code, 3)
        # explicit dry_run flag wins even in enforce mode
        report2 = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit, dry_run=True)
        self.assertEqual(report2.mode, "dry_run")
        self.assertEqual([r.status for r in report2.results], ["dry_run", "dry_run", "dry_run"])
        self.assertTrue(self.audit.verify()[0])

    def test_timeout(self):
        steps = [PlanStep(id="s1", title="slow", rationale="r", action="command", command=helpers.sleep_cmd(20), risk="read_only", timeout_seconds=5)]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "timeout")

    def test_env_step_scrubs_secrets(self):
        cmd = "Get-ChildItem Env: | ForEach-Object { $_.Name }" if os.name == "nt" else "env"
        step = PlanStep(id="s1", title="env", rationale="r", action="command", command=cmd, risk="read_only")
        sp = sign(self.console, make_plan("agent-000000000001", [step]))
        with mock.patch.dict(os.environ, {"AIIT_KEY_PASSPHRASE": "x", "AIIT_SERVER_TOKEN": "y", "MY_API_KEY": "z"}):
            report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "success")
        out = report.results[0].stdout
        for name in ("AIIT_KEY_PASSPHRASE", "AIIT_SERVER_TOKEN", "MY_API_KEY"):
            self.assertNotIn(name, out)

    def test_timeout_kills_grandchild(self):
        # A per-run sleep length so two suites on one host cannot see each other's sleeper.
        token = str(30000 + os.getpid() % 20000)
        if os.name == "nt":
            # The call operator blocks on the child, so the step really does outlive its timeout
            # (Start-Process without -Wait would return at once); the child is started by
            # absolute path because the scrubbed PATH is deliberately minimal.
            cmd = '& "$PSHOME\\powershell.exe" -NoProfile -Command "Start-Sleep -Seconds ' + token + '"'
        else:
            cmd = f"sleep {token} & wait"
        step = PlanStep(id="s1", title="grandchild", rationale="r", action="command", command=cmd, risk="read_only", timeout_seconds=5)
        sp = sign(self.console, make_plan("agent-000000000001", [step]))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        self.assertEqual(report.results[0].status, "timeout")
        time.sleep(0.5)
        alive = _windows_sleeper_alive(token) if os.name == "nt" else _sleeper_alive(token)
        if alive is not None:
            self.assertFalse(alive, "a sleeping grandchild survived the timeout kill")

    def test_preflight_blocks_whole_plan(self):
        steps = [
            PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
            PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only"),
            PlanStep(id="s3", title="denied", rationale="r", action="command", command="rm -rf /", risk="low"),
            PlanStep(id="s4", title="four", rationale="r", action="command", command=helpers.echo_cmd("four"), risk="read_only"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit)
        statuses = [r.status for r in report.results]
        self.assertEqual(statuses, ["skipped", "skipped", "blocked_by_policy", "skipped"])
        self.assertTrue(all(s in ("skipped", "blocked_by_policy") for s in statuses))
        # no command actually ran: nothing produced any stdout
        self.assertTrue(all(r.stdout == "" for r in report.results))
        self.assertEqual(report.results[0].reason, "preflight: step s3 blocked")
        text = self.audit.path.read_text(encoding="utf-8")
        self.assertIn("apply_preflight_failed", text)
        self.assertNotIn("apply_start", text)
        self.assertTrue(self.audit.verify()[0])

    def test_skip_step_ids_and_on_step_callback(self):
        steps = [
            PlanStep(id="s1", title="one", rationale="r", action="command", command=helpers.echo_cmd("one"), risk="read_only"),
            PlanStep(id="s2", title="two", rationale="r", action="command", command=helpers.echo_cmd("two"), risk="read_only"),
            PlanStep(id="s3", title="three", rationale="r", action="command", command=helpers.echo_cmd("three"), risk="read_only"),
        ]
        sp = sign(self.console, make_plan("agent-000000000001", steps))
        calls: list[tuple[int, str, bool]] = []

        def on_step(index, step, result):
            calls.append((index, step.id, result is None))

        report = apply_plan(sp, self._enforce(), "agent-000000000001", self.audit,
                            skip_step_ids={"s1"}, on_step=on_step)
        statuses = [r.status for r in report.results]
        self.assertEqual(statuses, ["skipped", "success", "success"])
        self.assertEqual(report.results[0].reason, "completed in an earlier run")
        # on_step fires before (result None) and after for the two executed steps only
        self.assertEqual(calls, [(1, "s2", True), (1, "s2", False), (2, "s3", True), (2, "s3", False)])


class RunCappedTests(unittest.TestCase):
    def test_output_cap_honoured(self):
        code = "import sys; sys.stdout.write('a' * (1024 * 1024))"
        pr = run_capped([sys.executable, "-c", code], 30, cap=20_000)
        self.assertEqual(pr.exit_code, 0)
        self.assertFalse(pr.timed_out)
        self.assertIn("truncated", pr.stdout)
        self.assertLess(len(pr.stdout), 20_000 + 100)
        self.assertGreaterEqual(len(pr.stdout), 20_000)

    def test_output_is_decoded_with_the_console_codec(self):
        # 0x82 is e-acute in cp850 (and cp437); under UTF-8 it would be a lone continuation byte.
        code = "import sys; sys.stdout.buffer.write(b'caf\\x82'); sys.stderr.buffer.write(b'\\x82!')"
        with mock.patch.object(procs, "console_codec", return_value="cp850"):
            pr = run_capped([sys.executable, "-c", code], 30)
        self.assertEqual(pr.stdout, "caf\u00e9")
        self.assertEqual(pr.stderr, "\u00e9!")
        with mock.patch.object(procs, "console_codec", return_value="utf-8"):
            pr = run_capped([sys.executable, "-c", code], 30)
        self.assertEqual(pr.stdout, "caf\ufffd")


class WindowsShellTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "PowerShell stdin round-trip is Windows only")
    def test_windows_quote_roundtrip(self):
        q_single = "'"
        q_double = '"'
        expected = "a" + q_single + "b" + q_double + "c"
        # Write-Output "a'b`"c" prints  a'b"c  . The backtick escapes the inner
        # double quote; the single quote is literal inside a double-quoted string.
        cmd = "Write-Output " + q_double + "a" + q_single + "b`" + q_double + "c" + q_double
        step = PlanStep(id="s1", title="quotes", rationale="r", action="command", command=cmd, risk="read_only")
        result = run_step(step, "windows")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.stdout.strip(), expected)

    @unittest.skipUnless(os.name == "nt", "PowerShell console code page is Windows only")
    def test_windows_non_ascii_roundtrip_uses_the_console_code_page(self):
        # e-acute exists in every Western OEM code page; it would be mojibake under UTF-8 either way.
        text = "caf\u00e9"
        try:
            text.encode(console_codec())
        except UnicodeEncodeError:
            self.skipTest("this host's OEM code page cannot represent the probe")
        step = PlanStep(id="s1", title="accent", rationale="r", action="command", command="Write-Output '" + text + "'", risk="read_only")
        result = run_step(step, "windows")
        self.assertEqual(result.status, "success", result.reason or result.stderr)
        self.assertEqual(result.stdout.strip(), text)

    @unittest.skipUnless(os.name == "nt", "System32 PATH is Windows only")
    def test_windows_child_path_finds_system32_tools_by_bare_name(self):
        # A step naming a native tool (as the policy's own dry run plan does with sfc) must resolve it.
        # A plain native command, no pipeline: `ipconfig | Select-Object -First 1`
        # made Windows PowerShell exit non-zero when it stopped the pipeline early.
        step = PlanStep(id="s1", title="where", rationale="r", action="command", command="hostname", risk="read_only")
        result = run_step(step, "windows")
        self.assertEqual(result.status, "success", (result.stdout, result.stderr))
        self.assertNotIn("not recognized", result.stderr)
        self.assertTrue(result.stdout.strip(), "hostname printed nothing")


if __name__ == "__main__":
    unittest.main()
