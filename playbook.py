#!/usr/bin/env python3
"""Helper for the /php2shell-playbook skill.

Does the deterministic work between the three skills: reads the PHP2Shell
Tenable Skill's report, builds the fix and hunt lists, and writes a handoff
file (Markdown and JSON) after each step. Standard library only.

    python3 playbook.py find RUN_DIR
    python3 playbook.py fix RUN_DIR ITEMS_JSON
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

PRIORITIES = ["FIRST", "NEXT", "SOON"]

HOST_FIELDS = ["asset", "ip", "fqdn", "source", "php_version", "status",
               "fixed_version", "last_seen"]


class PlaybookError(ValueError):
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


def load_handoff(run_dir, name, step_cmd):
    path = Path(run_dir) / f"{name}.json"
    if not path.is_file():
        raise PlaybookError(f"{path} not found. Run `playbook.py {step_cmd} {run_dir}` first.")
    return read_json(path)


def build_fix_handoff(find, items):
    """Match /fix-today's ranked items to the fix list. Items for hosts outside
    the fix list are reported, not kept; fix-list hosts it didn't rank are listed."""
    by_key = {(h["asset"], h["ip"]): h for h in find["fix_list"]}
    by_name = {}
    for h in find["fix_list"]:
        by_name.setdefault(h["asset"], []).append(h)
    kept, out_of_scope, ranked = [], [], set()
    for item in items:
        priority = str(item.get("priority", "")).upper()
        if priority not in PRIORITIES:
            raise PlaybookError(f"priority must be one of {', '.join(PRIORITIES)}, "
                                f"got {item.get('priority')!r} for {item.get('asset')!r}")
        item = dict(item, priority=priority)
        host = by_key.get((item.get("asset", ""), item.get("ip", "")))
        if host is None and not item.get("ip"):
            # A blank IP matches by name only when the name is unambiguous.
            matches = by_name.get(item.get("asset", ""), [])
            host = matches[0] if len(matches) == 1 else None
        if host is None:
            out_of_scope.append(item)
            continue
        item["ip"] = host["ip"]
        ranked.add((host["asset"], host["ip"]))
        kept.append(item)
    kept.sort(key=lambda i: PRIORITIES.index(i["priority"]))  # stable within a priority
    return {
        "step": "fix",
        "version": 1,
        "created": now_iso(),
        "run_dir": find["run_dir"],
        "items": kept,
        "out_of_scope": out_of_scope,
        "not_ranked": [h for h in find["fix_list"] if (h["asset"], h["ip"]) not in ranked],
        "fix_list_size": len(find["fix_list"]),
    }


def fix_markdown(h):
    run = h["run_dir"]
    parts = [
        "# PHP2Shell playbook: step 2 handoff (Fix it)", "",
        f"Run folder: `{run}`  ",
        f"Written: {h['created']}", "",
        f"Ranked {len(h['items'])} of {h['fix_list_size']} hosts on the fix list "
        "with /fix-today (Remediation Priority & Impact Agent).", "",
    ]
    for p in PRIORITIES:
        group = [i for i in h["items"] if i["priority"] == p]
        parts += [f"## {p} ({len(group)})", ""]
        if not group:
            parts += ["None.", ""]
        for i in group:
            parts += [f"### {i.get('asset')} ({i.get('ip') or 'no IP'})", "",
                      f"- **Fix:** {i.get('fix') or '–'}",
                      f"- **Interim mitigation:** {i.get('mitigation') or '–'}",
                      f"- **Why:** {i.get('why') or '–'}", ""]
    parts += ["## Out of scope (dropped)", "",
              "Items /fix-today ranked that are not on the PHP2Shell fix list. "
              "They are not part of this response.", ""]
    parts += ([f"- {i.get('priority')}: {i.get('asset')} ({i.get('ip') or 'no IP'}): "
               f"{i.get('fix') or '–'}" for i in h["out_of_scope"]] or ["None."])
    parts += ["", "## Not ranked by /fix-today", "",
              "Hosts on the fix list that /fix-today did not rank. They still need a fix.", ""]
    parts += [host_table(h["not_ranked"]) if h["not_ranked"] else "None."]
    parts += ["", "## Next step", "", f"`/php2shell-playbook hunt {run}`", ""]
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


def cmd_fix(args):
    find = load_handoff(args.run_dir, "handoff-1-find", "find")
    items = read_json(args.items_json)
    if not isinstance(items, list):
        raise PlaybookError(f"{args.items_json} must hold a JSON list of items")
    h = build_fix_handoff(find, items)
    for p in write_handoff(args.run_dir, "handoff-2-fix", h, fix_markdown(h)):
        print(p)
    print(f"ranked={len(h['items'])} out_of_scope={len(h['out_of_scope'])} "
          f"not_ranked={len(h['not_ranked'])}")


def parser():
    p = argparse.ArgumentParser(prog="playbook.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("find", help="write handoff 1 from the step 1 run folder")
    s.add_argument("run_dir")
    s.set_defaults(func=cmd_find)
    s = sub.add_parser("fix", help="write handoff 2 from /fix-today's ranked items")
    s.add_argument("run_dir")
    s.add_argument("items_json")
    s.set_defaults(func=cmd_fix)
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
