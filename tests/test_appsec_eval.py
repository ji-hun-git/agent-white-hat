"""The scoring of bench/appsec_eval.py: labels joined to findings, precision with Wilson intervals, recall."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))

import appsec_eval  # noqa: E402


def finding(rule, severity, path, line):
    return {"rule": rule, "severity": severity, "path": path, "line": line, "message": "m"}


RESULTS = {"apps": [
    {"repo": "a/vuln", "stratum": "vulnerable", "seconds": 1.0, "files": 10, "findings": [
        finding("PAH-W012", "high", "db.py", 4), finding("PAH-W001", "medium", "t.html", 2),
        finding("PAH-W002", "low", "x.py", 9)]},
    {"repo": "b/good", "stratum": "well_built", "seconds": 2.0, "files": 20, "findings": [
        finding("PAH-W002", "medium", "api.ts", 7), finding("PAH-W013", "high", ".env", 1)]},
]}
LABELS = {"labels": [
    {"app": "a/vuln", "rule": "PAH-W012", "path": "db.py", "line": 4, "label": "true", "why": "f-string SQL"},
    {"app": "a/vuln", "rule": "PAH-W001", "path": "t.html", "line": 2, "label": "uncertain", "why": "?"},
    {"app": "b/good", "rule": "PAH-W002", "path": "api.ts", "line": 7, "label": "false", "why": "owner checked"},
],
    "caught": {"a/vuln": ["sqli"]}}
FIXTURE = {"expected": {"a/vuln": [{"id": "sqli", "class": "PAH-W012"}, {"id": "idor", "class": "PAH-W002"}]}}


class ScoreTest(unittest.TestCase):
    def setUp(self):
        self.out = appsec_eval.score(RESULTS, LABELS, FIXTURE)

    def test_low_findings_are_not_scored(self):
        self.assertEqual(self.out["precision"]["all"]["true"] + self.out["precision"]["all"]["false"] +
                         self.out["precision"]["all"]["uncertain"] + self.out["precision"]["all"]["unlabeled"], 4)

    def test_precision_ignores_uncertain_but_bounds_it(self):
        row = self.out["precision"]["all"]
        self.assertEqual((row["true"], row["false"], row["uncertain"]), (1, 1, 1))
        self.assertEqual(row["precision"], 0.5)
        self.assertEqual(row["bounds"], [round(1 / 3, 3), round(2 / 3, 3)])

    def test_unlabeled_findings_are_listed(self):
        self.assertEqual(self.out["unlabeled"], [("b/good", "PAH-W013", ".env", 1)])

    def test_recall_per_class(self):
        r = self.out["recall"]
        self.assertEqual((r["caught"], r["documented"]), (1, 2))
        self.assertEqual(r["per_class"]["PAH-W002"], {"caught": 0, "documented": 1})
        self.assertEqual(r["per_app"]["a/vuln"]["missed"], ["idor"])

    def test_wilson_interval(self):
        lo, hi = appsec_eval.wilson(9, 10)
        self.assertAlmostEqual(lo, 0.596, places=3)
        self.assertAlmostEqual(hi, 0.982, places=3)
        self.assertEqual(appsec_eval.wilson(0, 0), (0.0, 1.0))

    def test_wilson_never_goes_below_zero(self):
        lo, hi = appsec_eval.wilson(0, 5)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.4)

    def test_publish_hides_where_real_apps_are_vulnerable(self):
        results = {"apps": RESULTS["apps"] + [
            {"repo": "someone/their-app", "stratum": "ai_built", "commit": "c", "seconds": 1, "files": 3,
             "verdict": "block", "incomplete": [], "findings": [finding("PAH-W012", "high", "supabase/m.sql", 17)]}]}
        labels = {"labels": LABELS["labels"] + [
            {"app": "someone/their-app", "rule": "PAH-W012", "path": "supabase/m.sql", "line": 17, "label": "true",
             "why": "anyone can overwrite every row"}], "caught": LABELS["caught"]}
        pub_results, pub_labels = appsec_eval.publish(results, labels)
        text = json.dumps([pub_results, pub_labels])
        for secret in ("someone/their-app", "supabase/m.sql", "overwrite every row"):
            self.assertNotIn(secret, text)
        self.assertIn("a/vuln", text)  # apps built to be attacked stay named
        # and the published files score exactly like the private ones
        self.assertEqual(appsec_eval.score(pub_results, pub_labels, FIXTURE)["precision"],
                         appsec_eval.score(results, labels, FIXTURE)["precision"])

    def test_publish_masks_keys_quoted_in_notes(self):
        import random
        import string
        rnd = random.Random(3)
        key = "sk_" + "test_" + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(40))
        labels = {"labels": [dict(LABELS["labels"][2], why=f"the sample file holds {key}, Stripe's documented key")],
                  "caught": {}}
        _, pub_labels = appsec_eval.publish(RESULTS, labels)
        self.assertNotIn(key[8:], json.dumps(pub_labels))
        self.assertIn("documented key", json.dumps(pub_labels))

    def test_seeded_draw_is_reproducible_and_skips_the_development_set(self):
        frame = [f"u{i}/app" for i in range(40)]
        order1 = sorted(frame)
        order2 = sorted(frame)
        import random
        random.Random(appsec_eval.SEED).shuffle(order1)
        random.Random(appsec_eval.SEED).shuffle(order2)
        self.assertEqual(order1, order2)
        self.assertNotIn("juice-shop/juice-shop", set(appsec_eval.VULNERABLE + appsec_eval.WELL_BUILT))
        self.assertFalse(set(appsec_eval.DEVELOPMENT) & set(appsec_eval.VULNERABLE + appsec_eval.WELL_BUILT))

    def test_round_two_draws_nothing_round_one_saw(self):
        first = json.loads(appsec_eval.FIXTURE.read_text(encoding="utf-8"))
        seen = set(appsec_eval.DEVELOPMENT) | {a["repo"] for apps in first["strata"].values() for a in apps}
        self.assertFalse(seen & set(appsec_eval.VULNERABLE_2 + appsec_eval.WELL_BUILT_2))
        self.assertNotEqual(appsec_eval.ROUNDS[1]["seed"], appsec_eval.ROUNDS[2]["seed"])
        self.assertNotEqual(appsec_eval.ROUNDS[1]["results"], appsec_eval.ROUNDS[2]["results"])

    def test_round_two_fixture_when_drawn(self):
        fixture = appsec_eval._paths(2)[0]
        if not fixture.exists():
            self.skipTest("round two not drawn")
        doc = json.loads(fixture.read_text(encoding="utf-8"))
        drawn = {a["repo"] for apps in doc["strata"].values() for a in apps}
        self.assertFalse(drawn & set(doc["development_set"]))
        first = json.loads(appsec_eval.FIXTURE.read_text(encoding="utf-8"))
        examined = {s["repo"] for s in first["frame"]["ai_built"]["skipped_in_order"]}
        self.assertFalse(drawn & examined)


if __name__ == "__main__":
    unittest.main()
