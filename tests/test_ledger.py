"""The protection log: every change to what the guard allows, hash-chained so an edit, a deletion or a cut tail shows.
Standard library only: python -m unittest discover -s tests"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

from pah import guard, ledger  # noqa: E402


class TempHome(unittest.TestCase):
    """Each test gets its own guard state folder."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="pah-test-home-"))
        patcher = mock.patch.object(guard, "HOME", self.home)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.home, True)

    def lines(self) -> list[str]:
        return ledger.path().read_text(encoding="utf-8").splitlines()

    def write_lines(self, lines: list[str]) -> None:
        ledger.path().write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


class LedgerTest(TempHome):
    def test_entries_chain_to_each_other_and_verify(self):
        a = ledger.record("trust-add", path="/work/a")
        b = ledger.record("shield-add", id="S-1", mode="monitor")
        c = ledger.record("shield-enforce", id="S-1")
        self.assertEqual(a["prev"], "0" * 64)
        self.assertEqual(b["prev"], a["hash"])
        self.assertEqual(c["prev"], b["hash"])
        self.assertEqual([e["n"] for e in ledger.entries()], [1, 2, 3])
        result = ledger.verify()
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["count"], 3)
        self.assertEqual(result["head"], c["hash"])

    def test_an_empty_log_verifies(self):
        result = ledger.verify()
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 0)

    def test_an_edited_entry_is_reported(self):
        for i in range(3):
            ledger.record("trust-add", path=f"/work/{i}")
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["detail"]["path"] = "/work/somewhere-else"
        lines[1] = json.dumps(entry)
        self.write_lines(lines)
        result = ledger.verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("entry 2" in p for p in result["problems"]), result["problems"])

    def test_a_deleted_entry_is_reported(self):
        for i in range(3):
            ledger.record("trust-add", path=f"/work/{i}")
        lines = self.lines()
        del lines[1]
        self.write_lines(lines)
        self.assertFalse(ledger.verify()["ok"])

    def test_a_cut_tail_is_reported_through_the_head(self):
        for i in range(3):
            ledger.record("trust-add", path=f"/work/{i}")
        self.write_lines(self.lines()[:-1])
        result = ledger.verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("head" in p for p in result["problems"]), result["problems"])

    def test_a_deleted_log_is_reported_through_the_head(self):
        ledger.record("trust-add", path="/work/a")
        ledger.path().unlink()
        self.assertFalse(ledger.verify()["ok"])

    def test_a_head_noted_earlier_must_still_be_in_the_chain(self):
        ledger.record("trust-add", path="/work/a")
        noted = ledger.verify()["head"]
        ledger.record("trust-add", path="/work/b")  # later, legitimate entries keep the anchor valid
        self.assertTrue(ledger.verify(anchor=noted)["ok"])
        self.assertTrue(ledger.verify(anchor=noted[:16])["ok"])
        self.assertFalse(ledger.verify(anchor="ab" * 32)["ok"])

    def test_a_consistently_rewritten_history_fails_an_outside_anchor(self):
        ledger.record("trust-add", path="/work/a")
        noted = ledger.verify()["head"]
        # Someone who knows the format rewrites the whole log and its head: the log alone looks fine, the anchor does not.
        ledger.path().unlink()
        ledger.head_path().unlink()
        ledger.record("trust-add", path="/work/evil")
        self.assertTrue(ledger.verify()["ok"])
        self.assertFalse(ledger.verify(anchor=noted)["ok"])

    def test_garbage_lines_are_reported_not_raised(self):
        ledger.record("trust-add", path="/work/a")
        self.write_lines(self.lines() + ["not json"])
        result = ledger.verify()
        self.assertFalse(result["ok"])

    def test_details_are_clipped_and_cleaned(self):
        entry = ledger.record("shield-add", reason="x\x1b[31m" + "y" * 5000)
        self.assertNotIn("\x1b", entry["detail"]["reason"])
        self.assertLessEqual(len(entry["detail"]["reason"]), 600)


if __name__ == "__main__":
    unittest.main()
