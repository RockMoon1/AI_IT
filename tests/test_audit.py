"""Tests for the hash-chained audit log: chain, torn lines, concurrency, checkpoints, export, alerts."""
import csv
import io
import json
import multiprocessing
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from . import helpers
from aiit.common.audit import AuditLog, Break
from aiit.common.crypto import Identity
from aiit.common.util import read_json, sha256_hex, write_json


def _mp_writer(args):
    """Top-level so multiprocessing's spawn start method can import it."""
    path, actor, n = args
    from aiit.common.audit import AuditLog as _Log
    log = _Log(Path(path), actor_id=actor)
    for i in range(n):
        log.record("mp_write", i=i)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tamper_line(path: Path, index: int, mutate) -> None:
    lines = path.read_bytes().split(b"\n")
    e = json.loads(lines[index])
    mutate(e)
    lines[index] = json.dumps(e, sort_keys=True).encode("utf-8")
    path.write_bytes(b"\n".join(lines))


class AuditTests(unittest.TestCase):
    def test_chain_verify_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")
            self.assertEqual(log.verify(), (True, "0 entries verified"))
            log.record("init")
            log.record("ingest", case_id="c1", files=3)
            log.record("plan_approved", plan_id="p1")
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual(msg, "3 entries verified")
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            e = json.loads(lines[1])
            e["details"]["files"] = 99
            lines[1] = json.dumps(e, sort_keys=True)
            (Path(d) / "audit.jsonl").write_text("\n".join(lines) + "\n")
            ok, msg = log.verify()
            self.assertFalse(ok)
            self.assertIn("entry 2", msg)
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            del lines[1]
            (Path(d) / "audit.jsonl").write_text("\n".join(lines) + "\n")
            self.assertFalse(log.verify()[0])

    def test_head_and_entries(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")
            self.assertIsNone(log.head())
            self.assertEqual(log.entries(), [])
            e1 = log.record("init")
            e2 = log.record("ingest", case_id="case-000000000001")
            self.assertEqual(log.head(), {"seq": 2, "hash": e2["hash"]})
            self.assertEqual(e2["prev_hash"], e1["hash"])
            self.assertEqual([e["seq"] for e in log.entries()], [1, 2])

    def test_torn_tail_then_record_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            for i in range(3):
                log.record("step", i=i)
            with open(path, "ab") as f:
                f.write(b'{"seq": 4, "ts": "2026-10-14T00:00:00+00:00", "actor_id": "console-1", "det')
            e = log.record("after_torn")
            self.assertEqual(e["seq"], 4)
            self.assertEqual(e["prev_hash"], log.entries()[2]["hash"])
            self.assertEqual(len(log.entries()), 4)
            ok, msg = log.verify()
            self.assertFalse(ok)
            self.assertIn("line 4", msg)
            self.assertIn("unparseable", msg)
            breaks = log.verify_detailed()
            self.assertEqual(len(breaks), 1)
            self.assertIsInstance(breaks[0], Break)
            self.assertEqual((breaks[0].line_no, breaks[0].seq), (4, 0))
            # the fragment stayed on its own line and the new entry is on line 5
            lines = path.read_bytes().split(b"\n")
            self.assertEqual(json.loads(lines[4])["seq"], 4)
            self.assertTrue(lines[3].startswith(b'{"seq": 4, "ts"'))

    def test_repair_tail_moves_fragment(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            self.assertFalse(log.repair_tail()["repaired"])
            for i in range(3):
                log.record("step", i=i)
            fragment = b'{"seq": 4, "ts": "2026-10-14T00:00:00+00:00", "act'
            with open(path, "ab") as f:
                f.write(fragment)
            self.assertFalse(log.verify()[0])
            result = log.repair_tail()
            self.assertTrue(result["repaired"])
            self.assertEqual(result["method"], "truncated")
            self.assertEqual(result["bytes"], len(fragment))
            self.assertEqual(result["fragment_sha256"], sha256_hex(fragment))
            self.assertEqual(result["line_no"], 4)
            corrupt = Path(d) / "audit.jsonl.corrupt"
            self.assertEqual(corrupt.read_bytes(), fragment + b"\n")
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual(msg, "4 entries verified")
            last = log.entries()[-1]
            self.assertEqual(last["action"], "audit_tail_repaired")
            self.assertEqual(last["details"]["fragment_sha256"], sha256_hex(fragment))
            self.assertNotIn("act", json.dumps(last["details"]))  # hash and size only, never the bytes
            self.assertFalse(log.repair_tail()["repaired"])

    def test_repair_tail_after_entries_were_recorded_past_the_fragment(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            log.record("a")
            log.record("b")
            with open(path, "ab") as f:
                f.write(b'{"seq": 3, "ts": ')
            log.record("c")
            log.record("d")
            self.assertEqual(len(log.verify_detailed()), 1)
            result = log.repair_tail()
            self.assertTrue(result["repaired"])
            self.assertEqual(result["method"], "spliced")
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual([e["action"] for e in log.entries()], ["a", "b", "c", "d", "audit_tail_repaired"])

    def test_four_threads_times_fifty(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")

            def work(t):
                for i in range(50):
                    log.record("thread_write", t=t, i=i)

            threads = [threading.Thread(target=work, args=(t,)) for t in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual(msg, "200 entries verified")
            self.assertEqual([e["seq"] for e in log.entries()], list(range(1, 201)))

    def test_spawned_processes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            ctx = multiprocessing.get_context("spawn")
            with ctx.Pool(3) as pool:
                pool.map(_mp_writer, [(str(path), f"agent-00000000000{i}", 15) for i in range(3)])
            log = AuditLog(path, actor_id="console-1")
            ok, msg = log.verify()
            self.assertTrue(ok, msg)
            self.assertEqual([e["seq"] for e in log.entries()], list(range(1, 46)))

    def test_checkpoint_detects_truncation_tamper_and_wrong_key(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-aaaaaaaaaaaa")
            ident = Identity.generate("console-aaaaaaaaaaaa", with_box=False)
            self.assertIsNone(log.checkpoint(ident))
            for i in range(5):
                log.record("step", i=i)
            cp = log.checkpoint(ident)
            self.assertEqual(cp["seq"], 5)
            self.assertEqual(cp["offset"], path.stat().st_size)
            head = read_json(Path(d) / "audit.jsonl.head.json")
            self.assertEqual(set(head), {"seq", "hash", "offset", "ts", "signer_id", "signer_pub", "signature"})
            self.assertTrue(log.verify()[0])
            self.assertTrue(log.verify(expected_pub=ident.sign_pub_hex)[0])
            # appending after the checkpoint is fine
            log.record("later")
            self.assertTrue(log.verify(expected_pub=ident.sign_pub_hex)[0])
            # wrong expected key
            other = Identity.generate("console-bbbbbbbbbbbb", with_box=False)
            ok, msg = log.verify(expected_pub=other.sign_pub_hex)
            self.assertFalse(ok)
            self.assertIn("expected key", msg)
            # truncate below the checkpoint: every remaining line still chains, only the checkpoint catches it
            lines = path.read_bytes().split(b"\n")
            path.write_bytes(b"\n".join(lines[:3]) + b"\n")
            ok, msg = log.verify(expected_pub=ident.sign_pub_hex)
            self.assertFalse(ok)
            self.assertIn("shorter than checkpoint", msg)
            self.assertIn("shorter than checkpoint", str(log.check_and_alert(expected_pub=ident.sign_pub_hex, sinks_from_env=False,
                                                                              stream=io.StringIO())))
            # a different entry at the checkpoint seq
            for i in range(3):
                log.record("replaced", i=i)
            ok, msg = log.verify(expected_pub=ident.sign_pub_hex)
            self.assertFalse(ok)
            self.assertIn("checkpoint hash mismatch", msg)
            # altered checkpoint file: signature no longer matches
            head["seq"] = 2
            write_json(Path(d) / "audit.jsonl.head.json", head)
            ok, msg = log.verify()
            self.assertFalse(ok)
            self.assertIn("signature invalid", msg)
            (Path(d) / "audit.jsonl.head.json").write_text("not json")
            self.assertIn("checkpoint unreadable", log.verify()[1])

    def test_check_and_alert_incremental_after_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-aaaaaaaaaaaa")
            ident = Identity.generate("console-aaaaaaaaaaaa", with_box=False)
            for i in range(4):
                log.record("step", i=i)
            log.checkpoint(ident)
            for i in range(3):
                log.record("more", i=i)
            out = io.StringIO()
            self.assertIsNone(log.check_and_alert(expected_pub=ident.sign_pub_hex, sinks_from_env=False, stream=out))
            self.assertEqual(out.getvalue(), "")
            _tamper_line(path, 5, lambda e: e["details"].__setitem__("i", 42))
            b = log.check_and_alert(expected_pub=ident.sign_pub_hex, sinks_from_env=False, stream=out)
            self.assertIsNotNone(b)
            self.assertEqual((b.line_no, b.seq), (6, 6))
            self.assertIn("hash mismatch at entry 6", out.getvalue())

    def test_verify_detailed_lists_every_break(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            for i in range(6):
                log.record("step", i=i)
            _tamper_line(path, 1, lambda e: e["details"].__setitem__("i", 99))
            _tamper_line(path, 3, lambda e: e.__setitem__("action", "forged"))
            breaks = log.verify_detailed()
            self.assertEqual([(b.line_no, b.seq) for b in breaks], [(2, 2), (4, 4)])
            self.assertTrue(all("hash mismatch" in b.reason for b in breaks))
            ok, msg = log.verify()
            self.assertFalse(ok)
            self.assertIn("entry 2", msg)
            # blank lines are tolerated, binary garbage is reported with its line number
            with open(path, "ab") as f:
                f.write(b"\n\xff\xfe garbage\n")
            breaks = log.verify_detailed()
            self.assertEqual(len(breaks), 3)
            self.assertEqual(breaks[-1].line_no, 8)
            self.assertIn("corrupt", breaks[-1].reason)

    def test_csv_export_guards_formulas_and_adds_summary(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")
            log.record("init")
            log.record("ingest", case_id="=cmd|' /C calc'!A0", note="-1 and +2")
            log.record("plan_created", case_id="case-000000000001", plan_id="plan-000000000001")
            out = Path(d) / "export.csv"
            n = log.export("csv", out)
            self.assertEqual(n, 3)
            rows = list(csv.reader(io.StringIO(out.read_text(encoding="utf-8"))))
            self.assertEqual(rows[0], ["seq", "ts", "actor_id", "os_user", "action", "case_id", "plan_id", "details_json", "hash"])
            self.assertEqual(rows[2][5], "'=cmd|' /C calc'!A0")
            self.assertTrue(rows[2][7].startswith("{"))
            self.assertEqual(len(rows), 5)
            summary = rows[4]
            self.assertEqual(summary[4], "export_summary")
            info = json.loads(summary[7])
            self.assertTrue(info["verified"])
            self.assertEqual(info["rows"], 3)
            self.assertEqual(info["message"], "3 entries verified")
            # filtered export only counts matching rows
            n = log.export("csv", out, case_id="case-000000000001")
            self.assertEqual(n, 1)
            n = log.export("jsonl", Path(d) / "export.jsonl", actions=["init", "ingest"])
            self.assertEqual(n, 2)
            lines = (Path(d) / "export.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual([json.loads(x)["action"] for x in lines], ["init", "ingest"])
            with self.assertRaises(ValueError):
                log.export("xlsx", out)

    def test_html_export_escapes_values(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-aaaaaaaaaaaa")
            ident = Identity.generate("console-aaaaaaaaaaaa", with_box=False)
            log.record("ingest", case_id="case-000000000001", note="<script>alert(1)</script>")
            log.checkpoint(ident)
            out = Path(d) / "export.html"
            n = log.export("html", out, case_id="case-000000000001")
            self.assertEqual(n, 1)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn("<script>", text)
            self.assertIn("&lt;script&gt;", text)
            self.assertIn("VERIFIED", text)
            self.assertIn(log.head()["hash"], text)
            self.assertIn("case-000000000001", text)
            self.assertIn("@media print", text)
            self.assertTrue(text.startswith("<!DOCTYPE html>"))

    def test_iter_filtered(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            log.record("init")
            log.record("ingest", case_id="case-000000000001")
            log.record("ingest", case_id="case-000000000002")
            log.record("plan_created", case_id="case-000000000001", plan_id="plan-000000000001")
            other = AuditLog(path, actor_id="console-2")
            other.record("report", case_id="case-000000000001", plan_id="plan-000000000001")
            self.assertEqual([e["seq"] for e in log.iter_filtered(actions=["ingest"])], [2, 3])
            self.assertEqual([e["seq"] for e in log.iter_filtered(case_id="case-000000000001")], [2, 4, 5])
            self.assertEqual([e["seq"] for e in log.iter_filtered(case_id="case-000000000001", actions={"ingest"})], [2])
            self.assertEqual([e["seq"] for e in log.iter_filtered(plan_id="plan-000000000001")], [4, 5])
            self.assertEqual([e["seq"] for e in log.iter_filtered(actor_id="console-2")], [5])
            self.assertEqual(len(list(log.iter_filtered(since="2000-01-01T00:00:00+00:00"))), 5)
            self.assertEqual(len(list(log.iter_filtered(until="2000-01-01T00:00:00+00:00"))), 0)
            self.assertEqual(len(list(log.iter_filtered(since="2999-01-01"))), 0)

    def test_timeline_labels(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl", actor_id="console-1")
            c = "case-000000000001"
            log.record("init")
            for action in ("ingest", "llm_request", "llm_response", "llm_invalid_plan", "llm_error", "plan_created",
                           "plan_approved", "report", "apply_start", "apply_end", "something_new"):
                log.record(action, case_id=c)
            log.record("ingest", case_id="case-000000000002")
            tl = log.timeline(c)
            self.assertEqual(len(tl), 11)
            self.assertEqual([e["label"] for e in tl], [
                "Bundle ingested", "LLM request", "LLM response", "LLM plan rejected", "LLM error", "Plan created",
                "Plan approved", "Report received", "Apply start", "Apply end", "something new",
            ])
            self.assertEqual([e["seq"] for e in tl], list(range(2, 13)))
            self.assertNotIn("label", log.entries()[1])  # the log itself is untouched

    def test_check_and_alert_clean_and_broken_with_sinks(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            for i in range(4):
                log.record("step", i=i)
            out = io.StringIO()
            with mock.patch.dict(os.environ, {"AIIT_ALERT_CMD": "this-should-not-run", "AIIT_ALERT_WEBHOOK": "http://127.0.0.1:1/"}):
                self.assertIsNone(log.check_and_alert(stream=out))
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(len(log.entries()), 4)

            _tamper_line(path, 2, lambda e: e["details"].__setitem__("i", "x"))
            captured = Path(d) / "alert.json"
            script = "import sys;open(sys.argv[1],'w').write(sys.stdin.read())"
            cmd = f'"{sys.executable}" -c "{script}" "{captured}"'
            http = helpers.FakeHTTP().start()
            try:
                env = {"AIIT_ALERT_CMD": cmd, "AIIT_ALERT_WEBHOOK": http.url + "/hook", "AIIT_ALERT_SYSLOG": "127.0.0.1:%d" % _free_port()}
                with mock.patch.dict(os.environ, env):
                    b = log.check_and_alert(stream=out)
            finally:
                http.stop()
            self.assertIsInstance(b, Break)
            self.assertEqual((b.line_no, b.seq), (3, 3))
            self.assertIn("hash mismatch at entry 3", b.reason)
            banner = out.getvalue()
            self.assertIn("AUDIT CHAIN BROKEN", banner)
            self.assertNotIn("\x1b[", banner)  # StringIO is not a TTY
            entries = log.entries()
            self.assertEqual(entries[-1]["action"], "audit_chain_broken")
            self.assertEqual(entries[-1]["seq"], 5)
            self.assertEqual(entries[-1]["prev_hash"], entries[-2]["hash"])
            self.assertEqual(entries[-1]["details"]["line_no"], 3)
            self.assertIn("hash mismatch", entries[-1]["details"]["reason"])
            sent = json.loads(captured.read_text(encoding="utf-8"))
            self.assertEqual(sent["line_no"], 3)
            self.assertEqual(sent["actor_id"], "console-1")
            self.assertEqual(sent["log_path"], str(path))
            self.assertIn("hash mismatch", sent["reason"])
            self.assertEqual(len(http.requests), 1)
            self.assertEqual(http.requests[0]["method"], "POST")
            self.assertEqual(http.requests[0]["path"], "/hook")
            body = json.loads(http.requests[0]["body"])
            self.assertIn("hash mismatch", body["reason"])
            self.assertEqual(body["seq"], 3)

            # a second check does not pile up duplicate audit_chain_broken entries
            with mock.patch.dict(os.environ, {"AIIT_ALERT_CMD": "", "AIIT_ALERT_WEBHOOK": "", "AIIT_ALERT_SYSLOG": ""}):
                b2 = log.check_and_alert(stream=io.StringIO())
            self.assertEqual(b2.line_no, 3)
            self.assertEqual(len(log.entries()), 5)

    def test_check_and_alert_failing_sinks_do_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "audit.jsonl"
            log = AuditLog(path, actor_id="console-1")
            log.record("a")
            log.record("b")
            with open(path, "ab") as f:
                f.write(b"{torn")
            env = {
                "AIIT_ALERT_CMD": str(Path(d) / "no-such-program") + " --flag",
                "AIIT_ALERT_WEBHOOK": "http://127.0.0.1:%d/hook" % _free_port(),
                "AIIT_ALERT_SYSLOG": "not a host port",
            }
            out = io.StringIO()
            with mock.patch.dict(os.environ, env):
                b = log.check_and_alert(stream=out)
            self.assertIsInstance(b, Break)
            self.assertEqual(b.line_no, 3)
            self.assertIn("torn", b.reason)
            self.assertIn("AUDIT CHAIN BROKEN", out.getvalue())
            self.assertEqual(log.entries()[-1]["action"], "audit_chain_broken")
            # the banner is red on a TTY
            class Tty(io.StringIO):
                def isatty(self):
                    return True
            tty = Tty()
            with mock.patch.dict(os.environ, {"AIIT_ALERT_CMD": "", "AIIT_ALERT_WEBHOOK": "", "AIIT_ALERT_SYSLOG": ""}):
                log.check_and_alert(stream=tty)
            self.assertTrue(tty.getvalue().startswith("\x1b[1;31m"))


if __name__ == "__main__":
    unittest.main()
