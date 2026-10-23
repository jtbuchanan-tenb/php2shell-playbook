import contextlib
import csv
import io
import json
import re
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

    def test_markdown_lists_the_hunt_list(self):
        md = playbook.find_markdown(playbook.build_find_handoff(self.run))
        hunt = md.split("## Hunt list")[1].split("## Step 1 reports")[0]
        self.assertIn("ancient01", hunt)
        self.assertIn("Patched", hunt)

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
                self.find, [{"priority": "LATER", "asset": "old01", "ip": "10.0.0.3",
                             "cves": ["CVE-2026-109618"]}])

    def test_blank_ip_matches_unique_asset_only(self):
        self.find["fix_list"].append({"asset": "old01", "ip": "10.0.0.33", "status": "Vulnerable – EOL"})
        h = playbook.build_fix_handoff(self.find, [
            {"priority": "FIRST", "asset": "mystery01", "ip": "", "fix": "x", "cves": ["CVE-2026-109618"]},
            {"priority": "NEXT", "asset": "old01", "ip": "", "fix": "y", "cves": ["CVE-2026-109618"]},
        ])
        self.assertEqual([i["asset"] for i in h["items"]], ["mystery01"])
        self.assertEqual(h["items"][0]["ip"], "10.0.0.4")
        self.assertEqual([i["asset"] for i in h["out_of_scope"]], ["old01"])

    def test_non_php2shell_items_are_out_of_scope(self):
        h = playbook.build_fix_handoff(self.find, [
            {"priority": "FIRST", "asset": "web01", "ip": "10.0.0.1",
             "fix": "Apply KB5046612", "cves": ["CVE-2025-1234"]}])
        self.assertEqual(h["items"], [])
        self.assertEqual(h["out_of_scope"][0]["fix"], "Apply KB5046612")

    def test_items_without_cves_are_rejected(self):
        with self.assertRaises(ValueError):
            playbook.build_fix_handoff(self.find, [
                {"priority": "FIRST", "asset": "old01", "ip": "10.0.0.3", "fix": "x"}])

    def test_matching_ignores_case_and_uses_fqdn_or_ip(self):
        h = playbook.build_fix_handoff(self.find, [
            {"priority": "FIRST", "asset": "WEB01.EXAMPLE.COM", "ip": "", "fix": "a",
             "cves": ["CVE-2026-109618"]},
            {"priority": "NEXT", "asset": "old01.corp.example", "ip": "10.0.0.3", "fix": "b",
             "cves": ["CVE-2026-109619"]}])
        self.assertEqual([(i["asset"], i["ip"]) for i in h["items"]],
                         [("WEB01.EXAMPLE.COM", "10.0.0.1"), ("old01.corp.example", "10.0.0.3")])
        self.assertEqual(h["out_of_scope"], [])

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


KIT_DIR = ROOT / "hunt-kit"
PLACEHOLDERS = r"\$\{?(start|start_spl|start_us|proc_filter|file_filter|net_filter|kql_filter|esql_filter)\b"


def many_hosts(n):
    return [{"asset": f"h{i}", "fqdn": "", "ip": f"10.1.{i // 250}.{i % 250}",
             "status": "Patched"} for i in range(n)]


class HuntTest(RunDirTest):
    def setUp(self):
        super().setUp()
        run_cli(["find", str(self.run)])
        self.find = playbook.load_handoff(self.run, "handoff-1-find", "find")

    def test_hypothesis_names_hosts_date_and_behaviors(self):
        t = playbook.hunt_hypothesis(self.find)
        for s in ["2026-10-17", "web01.example.com", "ancient01", "php-fpm", "shell",
                  ".php", "outbound", "CVE-2026-109618", "patched"]:
            self.assertIn(s, t)

    def test_host_names_prefer_fqdn_and_dedupe(self):
        names = playbook.host_names(self.find["hunt_list"])
        self.assertIn("web01.example.com", names)
        self.assertEqual(names.count("web01"), 1)   # 10.0.0.2 has no fqdn
        self.assertEqual(names, sorted(names))

    def test_hunt_kit_has_every_platform_and_no_unfilled_placeholders(self):
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        for s in ["Splunk", "Sentinel", "Elastic", "checklist", "2026-10-17",
                  "10/17/2026:00:00:00", "web01.example.com", "fleet-wide"]:
            self.assertIn(s, md)
        self.assertNotRegex(md, PLACEHOLDERS)
        self.assertIn('Processes.dest IN ("ancient01"', md)
        self.assertIn('| where DeviceName in~ ("ancient01"', md)
        self.assertIn('AND host.name IN ("ancient01"', md)
        self.assertIn('InitiatingProcessFileName startswith "php"', md)
        self.assertNotIn('has_any ("php-fpm"', md)    # misses Debian's php-fpm8.2

    def test_moved_run_folder_uses_the_new_folder(self):
        moved = Path(self._tmp.name) / "copied-from-share"
        shutil.copytree(self.run, moved)
        shutil.rmtree(self.run)
        code, _, err = run_cli(["hunt-kit", str(moved)])
        self.assertEqual((code, err), (0, ""))
        self.assertTrue((moved / "hunt-hosts.csv").exists())
        find = playbook.load_handoff(moved, "handoff-1-find", "find")
        self.assertEqual(find["run_dir"], str(moved))
        self.find["hunt_list"] = many_hosts(201)
        self.find["run_dir"] = str(moved)
        self.assertIn(str(moved), playbook.hunt_hypothesis(self.find))

    def test_host_names_include_short_name_and_asset(self):
        names = playbook.host_names([{"asset": "WEB01", "fqdn": "web01.example.com", "ip": "10.0.0.1"}])
        self.assertEqual(names, ["WEB01", "web01", "web01.example.com"])

    def test_ip_only_hosts_stay_in_scope(self):
        self.find["hunt_list"] = [{"asset": "", "fqdn": "", "ip": "10.7.0.1", "status": "Patched"}]
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        self.assertIn('Processes.dest IN ("10.7.0.1")', md)
        self.assertNotIn("IN ()", md)
        self.assertNotRegex(md, PLACEHOLDERS)
        self.assertIn("10.7.0.1", playbook.hunt_hypothesis(self.find))

    def test_kit_warns_about_name_formats_and_time_pickers(self):
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        self.assertIn("short names", md.split("## Splunk")[0])
        self.assertIn("time picker", md.split("## Microsoft Defender")[1].split("## Elastic")[0])
        self.assertIn("time picker", md.split("## Elastic")[1])
        self.assertIn('index=* sourcetype="sysmon:linux"', md)

    def test_fleet_kql_has_no_blank_lines_inside_queries(self):
        self.find["hunt_list"] = []
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        for block in re.findall(r"```kql\n(.*?)```", md, re.S):
            self.assertNotIn("\n\n", block)

    def test_hostnames_are_escaped_per_language(self):
        self.assertEqual(playbook.quote_list(['a"b', 'c\\d'], "spl"), '"a\\"b", "c\\\\d"')
        self.assertEqual(playbook.quote_list(['a"b'], "kql"), '"a\\"b"')
        self.assertEqual(playbook.quote_list(['a"b'], "esql"), '"a\\"b"')

    def test_large_hunt_list_uses_lookup_file(self):
        self.find["hunt_list"] = many_hosts(201)
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        self.assertIn("hunt-hosts.csv", md)
        self.assertIn("inputlookup hunt-hosts.csv", md)
        self.assertIn("_GetWatchlist", md)
        self.assertNotIn("h200", md)
        self.assertNotRegex(md, PLACEHOLDERS)
        self.assertIn("hunt-hosts.csv", playbook.hunt_hypothesis(self.find))
        self.assertNotIn("h200", playbook.hunt_hypothesis(self.find))

    def test_inline_limit_is_200(self):
        self.find["hunt_list"] = many_hosts(200)
        self.assertIn("h199", playbook.render_hunt_kit(self.find, KIT_DIR))

    def test_hunt_kit_with_no_hosts_is_fleet_wide(self):
        self.find["hunt_list"] = []
        md = playbook.render_hunt_kit(self.find, KIT_DIR)
        self.assertIn("fleet-wide", md)
        self.assertNotIn("Processes.dest IN", md)
        self.assertNotRegex(md, PLACEHOLDERS)
        self.assertIn("fleet-wide", playbook.hunt_hypothesis(self.find))

    def test_cli_hunt_kit_writes_kit_and_hosts_csv(self):
        self.assertEqual(run_cli(["hunt-kit", str(self.run)])[0], 0)
        self.assertTrue((self.run / "hunt-kit.md").exists())
        with open(self.run / "hunt-hosts.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows[0], ["host", "ip"])
        self.assertEqual(len(rows), 7)

    def test_cli_hypothesis_prints_text(self):
        code, out, _ = run_cli(["hypothesis", str(self.run)])
        self.assertEqual(code, 0)
        self.assertIn("2026-10-17", out)

    def test_hunt_handoff_soc_hunter_mode(self):
        h = playbook.build_hunt_handoff(self.run, {
            "mode": "soc-hunter", "hunt_file": "hunts/H-0001.md",
            "verdict": "no evidence of exploitation", "findings": []})
        self.assertEqual(h["start_date"], "2026-10-17")
        self.assertEqual(h["hunt_list_size"], 6)
        self.assertIsNone(h["kit"])
        self.assertIn("H-0001", playbook.hunt_markdown(h))

    def test_hunt_handoff_kit_mode_needs_the_kit(self):
        with self.assertRaises(ValueError):
            playbook.build_hunt_handoff(self.run, {"mode": "hunt-kit"})
        run_cli(["hunt-kit", str(self.run)])
        h = playbook.build_hunt_handoff(self.run, {"mode": "hunt-kit"})
        self.assertTrue(h["kit"].endswith("hunt-kit.md"))

    def test_hunt_handoff_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            playbook.build_hunt_handoff(self.run, {"mode": "vibes"})

    def test_cli_hunt_writes_handoff_3(self):
        result = self.run / "hunt-result.json"
        result.write_text(json.dumps({"mode": "soc-hunter", "hunt_file": "hunts/H-0002.md",
                                      "verdict": "1 suspicious", "findings": ["web01: bash under php-fpm"]}))
        self.assertEqual(run_cli(["hunt", str(self.run), str(result)])[0], 0)
        data = json.loads((self.run / "handoff-3-hunt.json").read_text(encoding="utf-8"))
        self.assertEqual(data["step"], "hunt")
        self.assertTrue((self.run / "handoff-3-hunt.md").exists())


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def touch(self, rel):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")

    def test_nothing_installed(self):
        self.assertEqual(playbook.preflight(self.home), {
            "php2shell_tenable": False, "fix_today": False,
            "soc_hunter": False, "soc_hunter_configured": False})

    def test_all_installed_and_configured(self):
        for rel in [".claude/skills/php2shell-tenable/SKILL.md", ".claude/commands/fix-today.md",
                    ".claude/skills/soc-hunter/SKILL.md", ".claude/skills/soc-hunter/CONFIG.local.md"]:
            self.touch(rel)
        self.assertTrue(all(playbook.preflight(self.home).values()))

    def test_soc_hunter_installed_not_configured(self):
        self.touch(".claude/skills/soc-hunter/SKILL.md")
        r = playbook.preflight(self.home)
        self.assertTrue(r["soc_hunter"])
        self.assertFalse(r["soc_hunter_configured"])

    def test_cli_preflight_prints_json(self):
        code, out, _ = run_cli(["preflight", "--home", str(self.home)])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["fix_today"])


class LatestRunTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_picks_newest_folder_with_report(self):
        for name in ["2026-10-22-0900", "2026-10-23-1100"]:
            (self.root / name).mkdir()
            (self.root / name / "report.csv").write_text("x")
        (self.root / "2026-10-23-1200").mkdir()          # newer but empty
        self.assertEqual(playbook.latest_run(self.root), self.root / "2026-10-23-1100")

    def test_none_when_empty_or_missing(self):
        self.assertIsNone(playbook.latest_run(self.root))
        self.assertIsNone(playbook.latest_run(self.root / "nope"))

    def test_cli_latest_run_exit_codes(self):
        self.assertEqual(run_cli(["latest-run", "--root", str(self.root)])[0], 1)
        (self.root / "2026-10-23-1100").mkdir()
        (self.root / "2026-10-23-1100" / "report.csv").write_text("x")
        code, out, _ = run_cli(["latest-run", "--root", str(self.root)])
        self.assertEqual((code, out.strip()), (0, str(self.root / "2026-10-23-1100")))


class SummaryTest(RunDirTest):
    def test_summary_after_find_only(self):
        run_cli(["find", str(self.run)])
        md = playbook.write_summary(self.run).read_text(encoding="utf-8")
        self.assertIn("report.csv", md)
        self.assertIn("handoff-1-find.md", md)
        self.assertIn("Fix it: not run", md)
        self.assertIn("Hunt for it: not run", md)

    def test_summary_after_all_three(self):
        run_cli(["find", str(self.run)])
        run_cli(["fix", str(self.run), str(ITEMS)])
        run_cli(["hunt-kit", str(self.run)])
        result = self.run / "hunt-result.json"
        result.write_text('{"mode": "hunt-kit"}')
        run_cli(["hunt", str(self.run), str(result)])
        md = playbook.write_summary(self.run).read_text(encoding="utf-8")
        for s in ["handoff-1-find.md", "handoff-2-fix.md", "handoff-3-hunt.md",
                  "hunt-kit.md", "hunt-hosts.csv", "](report.csv)"]:
            self.assertIn(s, md)
        self.assertNotIn(str(self.run), md.split("Run folder")[1].split("\n", 1)[1])
        self.assertNotIn(": not run.", md)

    def test_summary_without_handoff_1_fails(self):
        self.assertNotEqual(run_cli(["summary", str(self.run)])[0], 0)


VETTING_DISCLAIMER = (
    "Exchange Inspector vetting covers the reviewed commit, not later changes. "
    "Remediation Priority & Impact Agent was vetted on Sep 23, 2026 at `536616f` and "
    "SOC-Hunter on Oct 7, 2026 at `5eea59b`; this installs the latest version.")
HEXA_DOCS = ("https://docs.tenable.com/vulnerability-management/Content/"
             "getting-started/hexa-AI-MCP.htm")


class SkillMdTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "SKILL.md").read_text(encoding="utf-8")

    def test_frontmatter(self):
        m = re.match(r"---\n(.*?)\n---\n", self.text, re.S)
        self.assertIsNotNone(m)
        self.assertIn("name: php2shell-playbook", m.group(1))
        desc = re.search(r"^description: (.+)$", m.group(1), re.M)
        self.assertIsNotNone(desc)
        self.assertIn("PHP2Shell", desc.group(1))

    def test_cli_commands_match_playbook_py(self):
        defined = set(playbook.parser()._subparsers._group_actions[0].choices)
        used = set(re.findall(r"playbook\.py ([a-z][a-z-]*)", self.text))
        self.assertEqual(used, defined)

    def test_required_text(self):
        for s in [HEXA_DOCS, playbook.FAQ_URL, VETTING_DISCLAIMER, "2026-10-17",
                  "separate terminal", "fatal_error_backtraces=0", "revoke", "cves",
                  "only the PHP2Shell part"]:
            self.assertIn(s, self.text)


if __name__ == "__main__":
    unittest.main()
