#!/usr/bin/env python3
"""Helper for the /php2shell-playbook skill.

Does the deterministic work between the three skills: reads the PHP2Shell
Tenable Skill's report, builds the fix and hunt lists, and writes a handoff
file (Markdown and JSON) after each step. Standard library only.

    python3 playbook.py find RUN_DIR
"""
import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

FAQ_URL = ("https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-"
           "frequently-asked-questions-about-critical-php-remote")

# Status strings from the PHP2Shell Tenable Skill's render.py, worst first.
VULN_EOL = "Vulnerable – EOL"
VULN_BACKPORT = "Vulnerable – backport only"
VULN_PATCH = "Vulnerable – patch available"
UNKNOWN = "Unknown – verify"
PATCHED = "Patched"
NOT_AFFECTED = "Not affected"
STATUS_ORDER = [VULN_EOL, VULN_BACKPORT, VULN_PATCH, UNKNOWN, PATCHED, NOT_AFFECTED]

# First exploitation attempt seen, per the Tenable Research FAQ.
HUNT_START = "2026-10-17"

HOST_FIELDS = ["asset", "ip", "fqdn", "source", "php_version", "status",
               "fixed_version", "last_seen"]


class PlaybookError(Exception):
    """Bad input the user can fix; reported as one line."""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rank(status):
    """Position in STATUS_ORDER. An unrecognized status ranks just above
    Unknown – verify, so it lands on the fix list rather than being hidden."""
    if status in STATUS_ORDER:
        return STATUS_ORDER.index(status)
    return STATUS_ORDER.index(UNKNOWN) - 0.5


def load_rows(run_dir):
    path = Path(run_dir) / "report.csv"
    if not path.is_file():
        raise PlaybookError(f"{path} not found. Run /php2shell-tenable first.")
    # render.py writes the CSV with a BOM.
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def asset_key(row):
    # Hostnames repeat across distinct assets, so the IP is part of the key
    # (the same key render.py uses).
    return (row.get("asset") or row.get("fqdn") or "", row.get("ip") or "")


def rollup(rows):
    """One host per asset: fields from its worst-status row, latest last_seen.
    Returns (hosts sorted worst first then by asset, warnings)."""
    worst, latest = {}, {}
    warnings = []
    for r in rows:
        status = r.get("status", "")
        if status not in STATUS_ORDER:
            msg = (f"Unrecognized status '{status}' on {r.get('asset') or r.get('ip')}; "
                   "kept on the fix list.")
            if msg not in warnings:
                warnings.append(msg)
        key = asset_key(r)
        if key not in worst or rank(status) < rank(worst[key]["status"]):
            worst[key] = r
        latest[key] = max(latest.get(key, ""), r.get("last_seen") or "")
    hosts = []
    for key, r in worst.items():
        h = {f: r.get(f, "") for f in HOST_FIELDS}
        h["last_seen"] = latest[key]
        hosts.append(h)
    hosts.sort(key=lambda h: (rank(h["status"]), h["asset"], h["ip"]))
    return hosts, warnings


def needs_fix(status):
    return status not in (PATCHED, NOT_AFFECTED)


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise PlaybookError(f"{path} is not valid JSON: {e}")


def build_find_handoff(run_dir):
    run_dir = Path(run_dir)
    hosts, warnings = rollup(load_rows(run_dir))
    counts = {}
    for h in hosts:
        counts[h["status"]] = counts.get(h["status"], 0) + 1
    faq_path = run_dir / "faq.json"
    faq = read_json(faq_path) if faq_path.is_file() else None
    reports = {}
    for name, fname in (("csv", "report.csv"), ("html", "report.html"),
                        ("pdf", "report.pdf"), ("findings", "findings.json")):
        p = run_dir / fname
        reports[name] = str(p) if p.is_file() else None
    return {
        "step": "find",
        "version": 1,
        "created": now_iso(),
        "run_dir": str(run_dir),
        "faq": faq,
        "status_counts": counts,
        "fix_list": [h for h in hosts if needs_fix(h["status"])],
        "hunt_list": hosts,
        "warnings": warnings,
        "reports": reports,
    }


def md_table(headers, rows):
    def cell(v):
        return str(v if v not in (None, "") else "–").replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def host_table(hosts):
    return md_table(["Asset", "IP", "FQDN", "Source", "PHP", "Status", "Fixed in", "Last seen"],
                    [[h.get(f) for f in HOST_FIELDS] for h in hosts])


def faq_section(faq):
    if not faq:
        return ("## Tenable Research FAQ\n\nThe FAQ values were not recorded for this run. "
                f"Check the FAQ for the current CVEs, fixed releases and mitigations: {FAQ_URL}\n")
    lines = ["## Tenable Research FAQ", "",
             f"Read {faq.get('read_at', 'during this run')} from {faq.get('url') or FAQ_URL}. "
             "The FAQ is updated continuously; check it for current guidance.", ""]
    if faq.get("cves"):
        lines.append("**CVEs:** " + ", ".join(faq["cves"]))
    if faq.get("fixed_releases"):
        lines.append("**Fixed releases:** " + " · ".join(
            f"{v}" for _, v in sorted(faq["fixed_releases"].items(), reverse=True)))
    if faq.get("mitigations"):
        lines += ["", "**Interim mitigations, until you can patch** "
                  "(then restart every PHP worker):", ""]
        lines += [f"- {m}" for m in faq["mitigations"]]
    return "\n".join(lines) + "\n"


def find_markdown(h):
    run = h["run_dir"]
    counts = [[s, h["status_counts"][s]] for s in sorted(h["status_counts"], key=rank)]
    parts = [
        "# PHP2Shell playbook: step 1 handoff (Find it)", "",
        f"Run folder: `{run}`  ",
        f"Written: {h['created']}", "",
        "## Assets by status", "", md_table(["Status", "Assets"], counts), "",
        faq_section(h["faq"]),
        f"## Fix list ({len(h['fix_list'])} hosts)", "",
        "Every host that is not patched. Step 2 ranks these.", "",
        host_table(h["fix_list"]) if h["fix_list"] else "No unpatched hosts.", "",
        f"## Hunt list ({len(h['hunt_list'])} hosts)", "",
        "Every host step 1 saw running PHP, patched or not. Hosts that patched after "
        f"{HUNT_START} are in scope for step 3.", "",
        "## Step 1 reports", "",
    ]
    parts += [f"- {k.upper()}: `{v}`" for k, v in h["reports"].items() if v]
    if h["warnings"]:
        parts += ["", "## Warnings", ""] + [f"- {w}" for w in h["warnings"]]
    parts += ["", "## Next step", "",
              f"`/php2shell-playbook fix {run}`", ""]
    return "\n".join(parts)


def write_handoff(run_dir, name, data, markdown):
    run_dir = Path(run_dir)
    jpath, mpath = run_dir / f"{name}.json", run_dir / f"{name}.md"
    jpath.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    mpath.write_text(markdown, encoding="utf-8")
    return jpath, mpath


def cmd_find(args):
    h = build_find_handoff(args.run_dir)
    for p in write_handoff(args.run_dir, "handoff-1-find", h, find_markdown(h)):
        print(p)
    print(f"fix_list={len(h['fix_list'])} hunt_list={len(h['hunt_list'])}")


def parser():
    p = argparse.ArgumentParser(prog="playbook.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("find", help="write handoff 1 from the step 1 run folder")
    s.add_argument("run_dir")
    s.set_defaults(func=cmd_find)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.func(args)
    except PlaybookError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
