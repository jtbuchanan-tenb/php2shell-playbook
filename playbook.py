#!/usr/bin/env python3
"""Helper for the /php2shell-playbook skill.

Does the deterministic work between the three skills: reads the PHP2Shell
Tenable Skill's report, builds the fix and hunt lists, and writes a handoff
file (Markdown and JSON) after each step. Standard library only.

    python3 playbook.py find RUN_DIR
    python3 playbook.py fix RUN_DIR ITEMS_JSON
    python3 playbook.py hypothesis RUN_DIR
    python3 playbook.py hunt-kit RUN_DIR
    python3 playbook.py hunt RUN_DIR RESULT_JSON
    python3 playbook.py summary RUN_DIR
    python3 playbook.py preflight [--home DIR]
    python3 playbook.py latest-run [--root DIR]
"""
import argparse
import csv
import json
import sys
from string import Template
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

# Above this many hosts, the hunt kit points at hunt-hosts.csv instead of
# writing every hostname into the queries.
INLINE_HOST_LIMIT = 200
KIT_DIR = Path(__file__).resolve().parent / "hunt-kit"
KIT_FILES = ["splunk.md", "defender-sentinel.md", "elastic.md", "checklist.md"]
REPORTS_ROOT = Path.home() / "Dev" / "php2shell-reports"
DEFAULT_CVES = ["CVE-2026-109618", "CVE-2026-109619"]

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
        host_table(h["hunt_list"]) if h["hunt_list"] else "No PHP hosts reported.", "",
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
    data = read_json(path)
    # The folder may have been moved or copied since the handoff was written
    # (a SOC lead picking it up from a share), so trust where it is now.
    data["run_dir"] = str(Path(run_dir))
    return data


def name_forms(host):
    """Lower-cased names a host may go by: asset, FQDN and the FQDN's short form."""
    names = {host.get("asset") or "", host.get("fqdn") or ""}
    if host.get("fqdn"):
        names.add(host["fqdn"].split(".")[0])
    return {n.lower() for n in names if n}


def match_host(item, hosts):
    """The fix-list host an item refers to, or None. An IP narrows first; a name
    (any case, asset, FQDN or short name) settles it. Ambiguous means no match."""
    names = name_forms({"asset": item.get("asset"), "fqdn": item.get("asset")})
    by_name = [h for h in hosts if names & name_forms(h)]
    if item.get("ip"):
        by_ip = [h for h in hosts if h["ip"] == item["ip"]]
        if len(by_ip) > 1:
            by_ip = [h for h in by_ip if h in by_name]
        if len(by_ip) == 1:
            return by_ip[0]
    return by_name[0] if len(by_name) == 1 else None


def build_fix_handoff(find, items):
    """Match /fix-today's ranked items to the fix list. Items for hosts outside
    the fix list, or for CVEs other than PHP2Shell's, are reported, not kept;
    fix-list hosts it didn't rank are listed."""
    scope_cves = set(cves(find))
    kept, out_of_scope, ranked = [], [], set()
    for item in items:
        priority = str(item.get("priority", "")).upper()
        if priority not in PRIORITIES:
            raise PlaybookError(f"priority must be one of {', '.join(PRIORITIES)}, "
                                f"got {item.get('priority')!r} for {item.get('asset')!r}")
        if not isinstance(item.get("cves"), list) or not item["cves"]:
            raise PlaybookError(f"item for {item.get('asset')!r} needs a 'cves' list: the CVEs "
                                "/fix-today gave for that fix")
        item = dict(item, priority=priority)
        host = match_host(item, find["fix_list"])
        if host is None or not scope_cves & set(item["cves"]):
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
              "Items /fix-today ranked for hosts not on the PHP2Shell fix list, or for "
              "other CVEs. They are not part of this response. If a host here is one of "
              "yours under another name, check it against the fix list.", ""]
    parts += ([f"- {i.get('priority')}: {i.get('asset')} ({i.get('ip') or 'no IP'}), "
               f"{', '.join(i.get('cves') or [])}: {i.get('fix') or '–'}"
               for i in h["out_of_scope"]] or ["None."])
    parts += ["", "## Not ranked by /fix-today", "",
              "Hosts on the fix list that /fix-today did not rank. They still need a fix.", ""]
    parts += [host_table(h["not_ranked"]) if h["not_ranked"] else "None."]
    parts += ["", "## Next step", "", f"`/php2shell-playbook hunt {run}`", ""]
    return "\n".join(parts)


def host_names(hosts):
    """Every name a host may go by in a SIEM or EDR: asset name, FQDN and the
    FQDN's short form, as Tenable spelled them."""
    names = set()
    for h in hosts:
        for n in (h.get("asset"), h.get("fqdn")):
            if n:
                names.add(n)
        if h.get("fqdn"):
            names.add(h["fqdn"].split(".")[0])
    return sorted(names)


def host_ips(hosts):
    return sorted({h["ip"] for h in hosts if h.get("ip")})


def unnamed_ips(hosts):
    """IPs of hosts Tenable gave no name for."""
    return sorted({h["ip"] for h in hosts
                   if h.get("ip") and not (h.get("asset") or h.get("fqdn"))})


def quote_list(names, lang):
    """Double-quoted, comma-separated string literals. SPL, KQL and ES|QL all
    escape a backslash and a double quote with a backslash."""
    if lang not in ("spl", "kql", "esql"):
        raise PlaybookError(f"unknown query language {lang!r}")
    return ", ".join('"' + n.replace("\\", "\\\\").replace('"', '\\"') + '"' for n in names)


def hunt_scope(find):
    """'inline' (hosts written into queries), 'lookup' (too many: use
    hunt-hosts.csv) or 'fleet' (no hosts known: hunt everything)."""
    hosts = find["hunt_list"]
    if not (host_names(hosts) or host_ips(hosts)):
        return "fleet"
    return "inline" if len(hosts) <= INLINE_HOST_LIMIT else "lookup"


def hunt_hosts_path(find):
    return Path(find["run_dir"]) / "hunt-hosts.csv"


def write_hunt_hosts(find):
    path = hunt_hosts_path(find)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "ip"])
        for h in find["hunt_list"]:
            w.writerow([h.get("fqdn") or h.get("asset") or "", h.get("ip") or ""])
    return path


def cves(find):
    return (find.get("faq") or {}).get("cves") or DEFAULT_CVES


def hunt_hypothesis(find):
    scope = hunt_scope(find)
    if scope == "inline":
        targets = host_names(find["hunt_list"]) + unnamed_ips(find["hunt_list"])
        where = "on these hosts: " + ", ".join(targets)
    elif scope == "lookup":
        where = (f"fleet-wide: all PHP web servers. The {len(find['hunt_list'])} hosts "
                 f"Tenable saw running PHP are listed in {hunt_hosts_path(find)}; start with those")
    else:
        where = "fleet-wide: all PHP web servers (Tenable reported no PHP hosts)"
    return (f"Hunt for PHP2Shell ({', '.join(cves(find))}) exploitation since {HUNT_START} "
            f"{where}. No IOCs are published, so hunt on behavior: PHP worker processes "
            "(php-fpm, php-cgi, httpd, apache2) spawning a shell, curl or wget; new .php files "
            "written under web roots; outbound connections initiated by PHP workers. Hosts that "
            "have since patched are in scope, because the question is whether they were hit "
            "before patching.")


def kit_values(find):
    scope = hunt_scope(find)
    names = host_names(find["hunt_list"])
    # Splunk's dest and host fields hold a name or an IP, so it gets both.
    spl_targets = names + host_ips(find["hunt_list"])
    y, m, d = HUNT_START.split("-")
    values = {"start": HUNT_START, "start_spl": f"{m}/{d}/{y}:00:00:00", "start_us": f"{m}/{d}/{y}"}
    spl_fields = {"proc_filter": "Processes.dest", "file_filter": "Filesystem.dest", "net_filter": "host"}
    for key, field in spl_fields.items():
        if scope == "inline":
            values[key] = f"{field} IN ({quote_list(spl_targets, 'spl')})"
        elif scope == "lookup":
            values[key] = f"[| inputlookup hunt-hosts.csv | rename host AS {field} | fields {field}]"
        else:
            values[key] = ""
    # A comment, not an empty line: a blank line ends a KQL query in Log Analytics.
    fleet = "// no host filter: runs fleet-wide"
    if scope == "inline" and names:
        values["kql_filter"] = f"| where DeviceName in~ ({quote_list(names, 'kql')})"
        values["esql_filter"] = f"AND host.name IN ({quote_list(names, 'esql')})"
    elif scope == "lookup":
        values["kql_filter"] = '| where DeviceName in~ ((_GetWatchlist("php2shell-hunt-hosts") | project SearchKey))'
        values["esql_filter"] = fleet
    else:
        values["kql_filter"] = values["esql_filter"] = fleet
    return values


def render_hunt_kit(find, kit_dir=KIT_DIR):
    scope = hunt_scope(find)
    n = len(find["hunt_list"])
    if scope == "inline":
        scope_text = (f"The searches are limited to the {n} hosts Tenable saw running PHP "
                      "(patched or not); the same hosts are in `hunt-hosts.csv`. Each host is "
                      "listed under every name Tenable has for it (asset name, FQDN and short "
                      "name), and Splunk also matches IPs.")
    elif scope == "lookup":
        scope_text = (
            f"Tenable saw {n} hosts running PHP, too many to write into each search. "
            "The host list is in `hunt-hosts.csv` (columns `host`, `ip`):\n\n"
            "- **Splunk:** upload it as a lookup file named `hunt-hosts.csv`.\n"
            "- **Sentinel:** create a watchlist named `php2shell-hunt-hosts` from it with "
            "`host` as the search key. Defender XDR advanced hunting has no watchlists; "
            "run the searches fleet-wide there.\n"
            "- **Elastic:** the searches run fleet-wide; check hits against the file.")
    else:
        scope_text = ("Tenable reported no PHP hosts, so every search runs fleet-wide. "
                      "That also catches PHP servers Tenable never scanned.")
    parts = [
        "# PHP2Shell hunt kit", "",
        f"Hunt for PHP2Shell ({', '.join(cves(find))}) exploitation since {HUNT_START}. "
        "Behavior-based: no PHP2Shell IOCs have been published, so these searches look for "
        "what exploitation does, not for known indicators.", "",
        "## Scope", "", scope_text, "",
        "**Check how your tools name hosts.** A SIEM or EDR may record short names, FQDNs, "
        "IPs or a different case than Tenable does. If a host filter matches nothing, the "
        "search returns nothing, which looks the same as \"not hit\". Run one search without "
        "the filter first to see the names your data uses.", "",
        "Every search can also be run fleet-wide by removing its host filter, which catches "
        "PHP servers Tenable never scanned.", "",
        "Contents: Splunk, Microsoft Defender XDR and Sentinel (KQL), Elastic (ES|QL), "
        "and a manual checklist for one Linux host.", "",
    ]
    values = kit_values(find)
    for name in KIT_FILES:
        text = (Path(kit_dir) / name).read_text(encoding="utf-8")
        parts += [Template(text).substitute(values).rstrip(), ""]
    return "\n".join(parts)


def build_hunt_handoff(run_dir, result):
    find = load_handoff(run_dir, "handoff-1-find", "find")
    mode = result.get("mode")
    if mode not in ("soc-hunter", "hunt-kit"):
        raise PlaybookError(f"mode must be 'soc-hunter' or 'hunt-kit', got {mode!r}")
    kit = None
    if mode == "hunt-kit":
        kit_path = Path(run_dir) / "hunt-kit.md"
        if not kit_path.is_file():
            raise PlaybookError(f"{kit_path} not found. Run `playbook.py hunt-kit {run_dir}` first.")
        kit = str(kit_path)
    h = {
        "step": "hunt",
        "version": 1,
        "created": now_iso(),
        "run_dir": str(run_dir),
        "start_date": HUNT_START,
        "hunt_list_size": len(find["hunt_list"]),
    }
    h.update(result)
    h["kit"] = kit
    if mode == "soc-hunter":
        h.setdefault("hunt_file", None)
        h.setdefault("verdict", None)
        h.setdefault("findings", [])
    return h


def hunt_markdown(h):
    parts = [
        "# PHP2Shell playbook: step 3 handoff (Hunt for it)", "",
        f"Run folder: `{h['run_dir']}`  ",
        f"Written: {h['created']}", "",
        f"Hunt window: since {h['start_date']}. Hosts in scope: {h['hunt_list_size']} "
        "(every host Tenable saw running PHP, patched or not).", "",
    ]
    if h["mode"] == "soc-hunter":
        parts += ["## SOC-Hunter result", "",
                  f"- **Hunt file:** `{h.get('hunt_file') or 'not recorded'}`",
                  f"- **Verdict:** {h.get('verdict') or 'not recorded'}", "",
                  "### Findings", ""]
        parts += [f"- {f}" for f in h.get("findings") or []] or ["None reported."]
    else:
        parts += ["## Hunt kit", "",
                  "SOC-Hunter was not run. The hunt kit has ready-to-paste searches for "
                  f"Splunk, Defender XDR / Sentinel and Elastic, plus a manual checklist: `{h['kit']}`"]
    parts += ["", "## Next step", "",
              f"`python3 playbook.py summary {h['run_dir']}` writes the summary of all three steps.", ""]
    return "\n".join(parts)


def preflight(home):
    """Which of the three skills are installed under HOME/.claude, and whether
    SOC-Hunter has its local config."""
    claude = Path(home) / ".claude"
    soc = claude / "skills" / "soc-hunter"
    return {
        "php2shell_tenable": (claude / "skills" / "php2shell-tenable" / "SKILL.md").is_file(),
        "fix_today": (claude / "commands" / "fix-today.md").is_file(),
        "soc_hunter": (soc / "SKILL.md").is_file(),
        "soc_hunter_configured": (soc / "CONFIG.local.md").is_file(),
    }


def latest_run(root):
    """Newest run folder that has a report.csv. Folder names are
    YYYY-MM-DD-HHMM, so name order is time order."""
    root = Path(root)
    if not root.is_dir():
        return None
    runs = sorted(p for p in root.iterdir() if (p / "report.csv").is_file())
    return runs[-1] if runs else None


def write_summary(run_dir):
    run_dir = Path(run_dir)
    find = load_handoff(run_dir, "handoff-1-find", "find")

    def link(name):
        return f"[{name}]({name})" if (run_dir / name).is_file() else None

    counts = ", ".join(f"{find['status_counts'][k]} {k}"
                       for k in sorted(find["status_counts"], key=rank))
    parts = [
        "# PHP2Shell playbook: summary", "",
        f"Run folder: `{run_dir}`", "",
        "## Find it", "",
        f"{len(find['hunt_list'])} hosts running PHP: {counts}. "
        f"{len(find['fix_list'])} need a fix.", "",
    ]
    parts += [f"- {x}" for x in (link("handoff-1-find.md"), link("report.html"), link("report.pdf"),
                                 link("report.csv"), link("findings.json")) if x]
    fix_path = run_dir / "handoff-2-fix.json"
    parts += ["", "## Fix it", ""]
    if fix_path.is_file():
        fix = read_json(fix_path)
        by_p = ", ".join(f"{sum(1 for i in fix['items'] if i['priority'] == p)} {p}" for p in PRIORITIES)
        parts += [f"/fix-today ranked {len(fix['items'])} of {fix['fix_list_size']} hosts: {by_p}. "
                  f"{len(fix['not_ranked'])} not ranked, {len(fix['out_of_scope'])} out of scope.", "",
                  f"- {link('handoff-2-fix.md')}"]
    else:
        parts += ["Fix it: not run."]
    hunt_path = run_dir / "handoff-3-hunt.json"
    parts += ["", "## Hunt for it", ""]
    if hunt_path.is_file():
        hunt = read_json(hunt_path)
        if hunt["mode"] == "soc-hunter":
            parts += [f"SOC-Hunter hunted {hunt['hunt_list_size']} hosts since {hunt['start_date']}. "
                      f"Verdict: {hunt.get('verdict') or 'not recorded'}. "
                      f"Hunt file: `{hunt.get('hunt_file') or 'not recorded'}`.", ""]
        else:
            parts += [f"SOC-Hunter was not run; the hunt kit covers {hunt['hunt_list_size']} hosts "
                      f"since {hunt['start_date']}.", ""]
        parts += [f"- {x}" for x in (link("handoff-3-hunt.md"), link("hunt-kit.md"),
                                     link("hunt-hosts.csv")) if x]
    else:
        parts += ["Hunt for it: not run."]
        if (run_dir / "hunt-kit.md").is_file():
            parts += ["", f"- {link('hunt-kit.md')}"]
    path = run_dir / "summary.md"
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")
    return path


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


def cmd_hypothesis(args):
    find = load_handoff(args.run_dir, "handoff-1-find", "find")
    write_hunt_hosts(find)
    print(hunt_hypothesis(find))


def cmd_hunt_kit(args):
    find = load_handoff(args.run_dir, "handoff-1-find", "find")
    hosts = write_hunt_hosts(find)
    kit = Path(args.run_dir) / "hunt-kit.md"
    kit.write_text(render_hunt_kit(find), encoding="utf-8")
    print(kit)
    print(hosts)


def cmd_hunt(args):
    result = read_json(args.result_json)
    if not isinstance(result, dict):
        raise PlaybookError(f"{args.result_json} must hold a JSON object")
    h = build_hunt_handoff(args.run_dir, result)
    for p in write_handoff(args.run_dir, "handoff-3-hunt", h, hunt_markdown(h)):
        print(p)


def cmd_summary(args):
    print(write_summary(args.run_dir))


def cmd_preflight(args):
    print(json.dumps(preflight(args.home), indent=2))


def cmd_latest_run(args):
    run = latest_run(args.root)
    if run is None:
        raise PlaybookError(f"no run folder with a report.csv under {args.root}")
    print(run)


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
    s = sub.add_parser("hypothesis", help="print the SOC-Hunter hunt hypothesis")
    s.add_argument("run_dir")
    s.set_defaults(func=cmd_hypothesis)
    s = sub.add_parser("hunt-kit", help="write hunt-kit.md and hunt-hosts.csv")
    s.add_argument("run_dir")
    s.set_defaults(func=cmd_hunt_kit)
    s = sub.add_parser("hunt", help="write handoff 3 from the hunt result")
    s.add_argument("run_dir")
    s.add_argument("result_json")
    s.set_defaults(func=cmd_hunt)
    s = sub.add_parser("summary", help="write summary.md from the handoffs so far")
    s.add_argument("run_dir")
    s.set_defaults(func=cmd_summary)
    s = sub.add_parser("preflight", help="report which of the three skills are installed")
    s.add_argument("--home", default=str(Path.home()))
    s.set_defaults(func=cmd_preflight)
    s = sub.add_parser("latest-run", help="print the newest step 1 run folder")
    s.add_argument("--root", default=str(REPORTS_ROOT))
    s.set_defaults(func=cmd_latest_run)
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
