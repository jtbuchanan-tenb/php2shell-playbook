---
name: php2shell-playbook
description: PHP2Shell (CVE-2026-109618, CVE-2026-109619) response playbook that runs three CyberAgents Exchange skills in order (find exposed hosts with /php2shell-tenable, rank fixes with /fix-today, hunt for exploitation with /soc-hunter or a hunt kit) and writes a handoff file after each step. Use when someone wants to respond to PHP2Shell end to end, run the PHP2Shell playbook, pick up a PHP2Shell response from a handoff, or hunt for PHP2Shell exploitation.
---

# PHP2Shell Response Playbook

Runs Tenable's three-step PHP2Shell response, one skill per step:

1. **Find it.** `/php2shell-tenable` (PHP2Shell Tenable Skill): "Where are we exposed?"
2. **Fix it.** `/fix-today` (Remediation Priority & Impact Agent): "What do we fix first?"
3. **Hunt for it.** `/soc-hunter` (SOC-Hunter), or the PHP2Shell hunt kit: "Were we hit before we patched?"

After each step, write a handoff file and ask before going on. The person can stop after any step; someone else picks up from the handoff later. Step 1 and 2 usually belong to the vulnerability manager and step 3 to the SOC lead.

`playbook.py` in this skill's directory does the deterministic work. Run it as `python3 <this skill's directory>/playbook.py <command>`. Below, `<run>` is the step 1 run folder.

Source of truth for CVEs, fixed releases and mitigations: the [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote). It is updated continuously, so never use values from memory or from this file; use what step 1 reads from the FAQ during this run.

## Rules

- **Read only.** Never patch, scan, tag, open tickets or change anything in Tenable, a SIEM, an EDR or a host. The three skills only read data, and so does this one.
- **Nothing invented.** Every host, version, fix and finding comes from a tool result in this run. No PHP2Shell IOCs have been published; never make up IP addresses, domains or hashes.
- **No keys in the chat.** Never ask for, accept or repeat Tenable API keys. Setup commands that carry keys are run by the person in a separate terminal. If someone pastes keys into the chat anyway, don't use or repeat them; tell them the keys are now in this conversation's history and to revoke them and generate new ones in Tenable (Settings > My Account > API Keys).

## Arguments

`/php2shell-playbook [find|fix|hunt] [RUN_DIR]`

- No step: start at **Find it**.
- `fix` or `hunt` with no `RUN_DIR`: run `playbook.py latest-run`, show the folder it prints, and confirm it with the person before using it. If it exits non-zero, there is no step 1 run yet; start at **Find it**.
- `fix` needs `handoff-1-find.json` in the run folder. `hunt` needs it too. If it's missing, run `playbook.py find <run>` first (it only needs step 1's `report.csv`).

## Preflight

Do all three checks before the first step that runs.

1. **Tenable Hexa AI MCP.** Steps 1 and 2 read Tenable through it. Check whether tools named `mcp__tenable__*` are available.
   - If Tenable tools exist under a different server name (for example `mcp__tenable-vm__*`), say that `/fix-today` expects the server to be named `tenable`, and that re-adding it under that name is the simplest fix.
   - If there are none, stop and walk the person through setup, one step at a time:
     1. **Requirements:** Tenable One Foundation or Advanced; Hexa AI MCP turned on under Settings > Hexa AI; a role of Standard User or higher. The Hexa MCP is not available in FedRAMP Moderate environments.
     2. **API keys:** in Tenable, Settings > My Account > API Keys. Tell them to keep the keys to themselves; you don't need them.
     3. **Add the server**, named `tenable`, by running this in a **separate terminal**, not in this chat, with their own keys in place of the placeholders:

        ```bash
        claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
          --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
        ```

        In most shells, starting the command with a space keeps it, and the keys, out of shell history.

     4. **Restart Claude Code**, then run `/php2shell-playbook` again.
     5. **Docs:** https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm

   Only the step that's about to run needs Tenable: a `hunt` resume with an existing handoff does not.

2. **The three skills.** Run `playbook.py preflight`. It prints which are installed:

   | Key | Skill | Install (latest version) |
   |---|---|---|
   | `php2shell_tenable` | `/php2shell-tenable` | `git clone https://github.com/securibee/php2shell-tenable-skill ~/.claude/skills/php2shell-tenable` |
   | `fix_today` | `/fix-today` | `git clone https://github.com/smjennings/Remediation_Priority-Impact_Agent /tmp/rpia && mkdir -p ~/.claude/commands && cp /tmp/rpia/commands/fix-today.md ~/.claude/commands/fix-today.md` |
   | `soc_hunter` | `/soc-hunter` | `git clone https://github.com/sherlon1/soc-hunter ~/.claude/skills/soc-hunter` |

   For each one that's missing, show its install command and ask whether to run it. For `/fix-today` and `/soc-hunter`, say this with the offer:

   > Exchange Inspector vetting covers the reviewed commit, not later changes. Remediation Priority & Impact Agent was vetted on Sep 23, 2026 at `536616f` and SOC-Hunter on Oct 7, 2026 at `5eea59b`; this installs the latest version.

   A newly installed skill loads after Claude Code restarts.
   - **Step 1 is required.** Every later step works from its host list. If they won't install it, stop.
   - **Step 2 can be skipped.** The run goes from Find straight to Hunt.
   - **Step 3 can be skipped.** It is replaced by the hunt kit.

3. **SOC-Hunter setup.** SOC-Hunter needs `~/.claude/skills/soc-hunter/CONFIG.local.md`, mapping its placeholders to real SIEM and EDR MCP servers (`soc_hunter_configured` in the preflight output), and at least one SIEM or EDR MCP connected. If either is missing, step 3 uses the hunt kit. Mention that SOC-Hunter's `CONFIG.md` explains its setup, for next time.

## Step 1: Find it

1. Invoke `/php2shell-tenable`. It re-reads the FAQ, pulls PHP2Shell findings and PHP inventory from Tenable, and writes `report.csv`, `report.html`, `report.pdf` and `findings.json` to `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/`. That folder is `<run>`.
2. Write `<run>/faq.json` from what the FAQ said **during this run**:

   ```json
   {"url": "<FAQ URL>", "read_at": "<ISO time>", "cves": ["CVE-…"],
    "fixed_releases": {"8.5": "…", "8.4": "…", "8.3": "…", "8.2": "…"},
    "mitigations": ["…"]}
   ```

   Copy every interim mitigation the FAQ lists, including the PHP 8.5 one (`fatal_error_backtraces=0`) when the FAQ has it. If step 1 couldn't read the FAQ, don't write the file; the handoff will say the values weren't recorded.
3. Run `playbook.py find <run>`. It writes `handoff-1-find.md` and `handoff-1-find.json` with:
   - the **fix list**: every host that isn't patched;
   - the **hunt list**: every host running PHP, patched or not, because a host that patched after 2026-10-17 may have been hit before it did.
4. Tell the person the counts by status and the size of both lists, and show the path to `handoff-1-find.md`. Show any warnings the handoff has.
5. Ask: **"Continue to Fix it?"** If not, tell them how to pick up later: `/php2shell-playbook fix <run>`.

*Done when `handoff-1-find.json` exists and the person has answered.*

## Step 2: Fix it

1. If the fix list is empty, say there is nothing to fix and offer to go on to Hunt.
2. If `/fix-today` isn't installed and they chose to skip it, go to Hunt.
3. Invoke `/fix-today` with this scope, filling in the hosts and CVEs from `handoff-1-find.json`:

   > Scope this run to PHP2Shell only. Rank only these hosts: <asset (IP) for each fix-list host>. Only the findings for <CVEs from faq.json> matter. Ignore other assets and other vulnerabilities. If the dashboard widget isn't available, the FIRST / NEXT / SOON text summary is enough.

   `/fix-today` is general-purpose: it ranks by exposure across all findings and often merges several CVEs into one action per host ("one reboot closes …"). Keep only what it says about the fix-list hosts, and of each fix keep only the PHP2Shell part.
4. Write `<run>/fix-items.json`, transcribing its FIRST / NEXT / SOON result exactly. Use one object per host:

   ```json
   [{"priority": "FIRST", "asset": "…", "ip": "…", "cves": ["CVE-…"], "fix": "…", "mitigation": "…", "why": "…"}]
   ```

   - `cves` is the list of CVEs `/fix-today` gave for that action. It is required.
   - `fix` is Tenable's remediation as `/fix-today` gave it, cut down to only the PHP2Shell part when it bundled other fixes. Don't write fixes of your own.
   - `asset` and `ip` are as `/fix-today` named the host. The helper matches either one against the fix list, in any case.
5. Run `playbook.py fix <run> <run>/fix-items.json`. It writes `handoff-2-fix.md` and `handoff-2-fix.json`. It drops anything for a host outside the fix list, or with none of the PHP2Shell CVEs (listed under "Out of scope"), and lists fix-list hosts `/fix-today` didn't rank.
6. Tell the person the FIRST / NEXT / SOON counts, and anything out of scope or not ranked, and show the path to `handoff-2-fix.md`.
7. Ask: **"Continue to Hunt for it?"** If not: `/php2shell-playbook hunt <run>`.

*Done when `handoff-2-fix.json` exists, or the step was skipped, and the person has answered.*

## Step 3: Hunt for it

The hunt covers activity since **2026-10-17**, the first exploitation attempt the FAQ reports, on the hunt list.

**With SOC-Hunter** (installed, configured, and a SIEM or EDR MCP connected):

1. Run `playbook.py hypothesis <run>`. It prints the hunt hypothesis: the hosts, the date and the three behaviors.
2. Invoke `/soc-hunter hunt <the printed hypothesis>`. Keep its approval gates; don't approve its phases on the person's behalf.
3. When it has written its hunt file (`hunts/H-XXXX.md`), write `<run>/hunt-result.json`:

   ```json
   {"mode": "soc-hunter", "hunt_file": "<path>", "verdict": "<its conclusion>", "findings": ["…"]}
   ```

**Without SOC-Hunter:**

1. Run `playbook.py hunt-kit <run>`. It writes `hunt-kit.md` and `hunt-hosts.csv`. The kit has ready-to-paste searches for Splunk, Microsoft Defender XDR / Sentinel (KQL) and Elastic (ES|QL), plus a manual checklist, filled in with the hunt list and the date.
2. Write `<run>/hunt-result.json` as `{"mode": "hunt-kit"}`.
3. Tell the person the searches are behavior-based, may need their field names, and can be run fleet-wide to catch PHP servers Tenable never scanned.

Then run `playbook.py hunt <run> <run>/hunt-result.json`. It writes `handoff-3-hunt.md` and `handoff-3-hunt.json`.

*Done when `handoff-3-hunt.json` exists, or the step was skipped.*

## Finish

Run `playbook.py summary <run>`. It writes `summary.md`, linking every report and handoff with a line on what each step found. Show its path, plus the interim mitigations from `faq.json` for hosts that can't patch yet, and remind the person that patching is still required.
