import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import playbook  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIX_RUN = FIXTURES / "run"
CSV_HEADER = ["asset", "ip", "fqdn", "source", "plugin_id", "plugin_name",
              "php_version", "port", "last_seen", "status", "fixed_version"]


def run_cli(argv):
    """Run playbook.main, capturing its output. Returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = playbook.main(argv)
    return code, out.getvalue(), err.getvalue()


def write_report(run, rows):
    """Write a report.csv the way render.py does: UTF-8 with a BOM."""
    with open(run / "report.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_HEADER})


class RunDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run = Path(self._tmp.name) / "2026-10-23-1500"
        shutil.copytree(FIX_RUN, self.run)

    def tearDown(self):
        self._tmp.cleanup()


class FindHandoffTest(RunDirTest):
    def test_reads_bom_csv_with_en_dash_statuses(self):
        rows = playbook.load_rows(FIX_RUN)
        self.assertEqual(rows[0]["asset"], "web01")
        self.assertIn("Vulnerable – EOL", {r["status"] for r in rows})

    def test_same_hostname_different_ip_are_separate(self):
        hosts, _ = playbook.rollup(playbook.load_rows(FIX_RUN))
        web01 = {h["ip"]: h for h in hosts if h["asset"] == "web01"}
        self.assertEqual(web01["10.0.0.1"]["status"], "Vulnerable – patch available")
        self.assertEqual(web01["10.0.0.1"]["last_seen"], "2026-10-22")
        self.assertEqual(web01["10.0.0.2"]["status"], "Patched")

    def test_fix_and_hunt_lists(self):
        h = playbook.build_find_handoff(self.run)
        fix = {(x["asset"], x["ip"]) for x in h["fix_list"]}
        self.assertEqual(fix, {("web01", "10.0.0.1"), ("old01", "10.0.0.3"),
                               ("mystery01", "10.0.0.4"), ("future01", "10.0.0.5")})
        self.assertEqual(len(h["hunt_list"]), 6)
        self.assertEqual(h["fix_list"][0]["asset"], "old01")
        self.assertEqual(h["status_counts"]["Patched"], 1)

    def test_unknown_status_goes_on_fix_list_with_warning(self):
        h = playbook.build_find_handoff(self.run)
        self.assertIn("future01", [x["asset"] for x in h["fix_list"]])
        self.assertTrue(any("Vulnerable – something new" in w for w in h["warnings"]))

    def test_empty_fix_list_keeps_hunt_list(self):
        write_report(self.run, [
            {"asset": "a1", "ip": "10.9.0.1", "status": "Patched"},
            {"asset": "a2", "ip": "10.9.0.2", "status": "Patched"},
        ])
        h = playbook.build_find_handoff(self.run)
        self.assertEqual(h["fix_list"], [])
        self.assertEqual(len(h["hunt_list"]), 2)

    def test_faq_values_carried_from_faq_json(self):
        h = playbook.build_find_handoff(self.run)
        self.assertEqual(h["faq"]["cves"], ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertIn("fatal_error_backtraces=0", playbook.find_markdown(h))

    def test_missing_faq_is_null_and_markdown_links_faq(self):
        (self.run / "faq.json").unlink()
        h = playbook.build_find_handoff(self.run)
        self.assertIsNone(h["faq"])
        self.assertIn(playbook.FAQ_URL, playbook.find_markdown(h))

    def test_reports_missing_files_are_null(self):
        h = playbook.build_find_handoff(self.run)
        self.assertTrue(h["reports"]["csv"].endswith("report.csv"))
        self.assertIsNone(h["reports"]["pdf"])

    def test_cli_find_writes_both_files(self):
        self.assertEqual(run_cli(["find", str(self.run)])[0], 0)
        data = json.loads((self.run / "handoff-1-find.json").read_text(encoding="utf-8"))
        self.assertEqual(data["step"], "find")
        md = (self.run / "handoff-1-find.md").read_text(encoding="utf-8")
        self.assertIn("/php2shell-playbook fix", md)

    def test_cli_find_without_report_csv_fails_cleanly(self):
        (self.run / "report.csv").unlink()
        self.assertNotEqual(run_cli(["find", str(self.run)])[0], 0)


ITEMS = FIXTURES / "fix-items.json"


class FixHandoffTest(RunDirTest):
    def setUp(self):
        super().setUp()
        self.find = playbook.build_find_handoff(self.run)
        self.items = json.loads(ITEMS.read_text(encoding="utf-8"))

    def test_items_sorted_by_priority(self):
        h = playbook.build_fix_handoff(self.find, self.items)
        self.assertEqual([i["priority"] for i in h["items"]], ["FIRST", "SOON"])
        self.assertEqual(h["fix_list_size"], 4)

    def test_out_of_scope_items_are_reported_not_kept(self):
        h = playbook.build_fix_handoff(self.find, self.items)
        self.assertEqual([i["asset"] for i in h["out_of_scope"]], ["dbserver9"])

    def test_unranked_fix_hosts_are_listed(self):
        h = playbook.build_fix_handoff(self.find, self.items)
        self.assertEqual({x["asset"] for x in h["not_ranked"]}, {"mystery01", "future01"})

    def test_bad_priority_is_rejected(self):
        with self.assertRaises(ValueError):
            playbook.build_fix_handoff(
                self.find, [{"priority": "LATER", "asset": "old01", "ip": "10.0.0.3"}])

    def test_blank_ip_matches_unique_asset_only(self):
        self.find["fix_list"].append({"asset": "old01", "ip": "10.0.0.33", "status": "Vulnerable – EOL"})
        h = playbook.build_fix_handoff(self.find, [
            {"priority": "FIRST", "asset": "mystery01", "ip": "", "fix": "x"},
            {"priority": "NEXT", "asset": "old01", "ip": "", "fix": "y"},
        ])
        self.assertEqual([i["asset"] for i in h["items"]], ["mystery01"])
        self.assertEqual(h["items"][0]["ip"], "10.0.0.4")
        self.assertEqual([i["asset"] for i in h["out_of_scope"]], ["old01"])

    def test_markdown_has_sections_and_next_step(self):
        md = playbook.fix_markdown(playbook.build_fix_handoff(self.find, self.items))
        for s in ["FIRST", "NEXT", "SOON", "Out of scope", "Not ranked",
                  "Upgrade to a supported PHP branch", "/php2shell-playbook hunt"]:
            self.assertIn(s, md)

    def test_cli_fix_requires_handoff_1(self):
        self.assertNotEqual(run_cli(["fix", str(self.run), str(ITEMS)])[0], 0)

    def test_cli_fix_writes_handoff_2(self):
        run_cli(["find", str(self.run)])
        self.assertEqual(run_cli(["fix", str(self.run), str(ITEMS)])[0], 0)
        data = json.loads((self.run / "handoff-2-fix.json").read_text(encoding="utf-8"))
        self.assertEqual(data["step"], "fix")
        self.assertTrue((self.run / "handoff-2-fix.md").exists())


if __name__ == "__main__":
    unittest.main()
