# PHP2Shell Response Playbook

A Claude Code playbook that runs Tenable's three-step response to PHP2Shell (CVE-2026-109618 and CVE-2026-109619, pre-authentication remote code execution in PHP). One command, `/php2shell-playbook`, chains three CyberAgents Exchange skills. It writes a handoff file after each step, so the person who finds and fixes can hand off to the person who hunts.

| Step | Question | Skill |
|---|---|---|
| 1. Find it | Where are we exposed? | [PHP2Shell Tenable Skill](https://exchange.tenable.com/skills/php2shell-tenable-skill) (`/php2shell-tenable`) |
| 2. Fix it | What do we fix first? | [Remediation Priority & Impact Agent](https://exchange.tenable.com/skills/remediation-priority-impact-agent) (`/fix-today`) |
| 3. Hunt for it | Were we hit before we patched? | [SOC-Hunter](https://exchange.tenable.com/skills/soc-hunter) (`/soc-hunter`), or the bundled hunt kit |

**Read the briefing:** [php2shell-response-briefing.pdf](php2shell-response-briefing.pdf) (7 slides). It's the same response, ready to share with your team.

## PHP2Shell at a glance

Two critical CVEs let an unauthenticated attacker run code on any PHP that serves web requests, from PHP-FPM to mod_php.

| | |
|---|---|
| **9.2** | CVSS v4.0, both CVEs, no login needed |
| **1.3M+** | Internet-facing hosts that may be vulnerable |
| **Oct 17** | First attempt seen, four days before disclosure |
| **8.1** | No official fix for 8.1 and older: upgrade |

**Fixed releases:** 8.5.12 · 8.4.27 · 8.3.36 · 8.2.35

**Interim only, until you can patch:** `memory_limit=-1` and `session.upload_progress.enabled=0`, then restart every PHP worker. On PHP 8.5, also set `fatal_error_backtraces=0`.

Source: the [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote), Oct 21, 2026. The FAQ is updated continuously, so check it for current guidance. The playbook re-reads it on every run and carries what it finds into the handoffs.

## What it does

1. **Preflight.**
   - Checks that the Tenable Hexa AI MCP is connected. If it isn't, it walks you through setup.
   - Checks that the three skills are installed. For any that are missing, it offers to install them.
   - Checks whether SOC-Hunter is configured.
2. **Find it.** Runs `/php2shell-tenable`, then writes `handoff-1-find.md` and `.json` with two lists:
   - The **fix list:** every host that isn't patched.
   - The **hunt list:** every host running PHP, patched or not. A host that patched after Oct 17 may have been hit before it did.

   Then it asks whether to continue.
3. **Fix it.** Runs `/fix-today` scoped to the fix list and the PHP2Shell CVEs. It writes `handoff-2-fix.md` and `.json`: a FIRST / NEXT / SOON plan with Tenable's fix for each host. Anything `/fix-today` ranked for another host, or for CVEs other than PHP2Shell's, is listed as out of scope, not mixed in. Then it asks whether to continue.
4. **Hunt for it.**
   - With SOC-Hunter set up, it runs `/soc-hunter hunt`. The hypothesis covers the hunt list, activity since Oct 17, and three behaviors: PHP workers starting shells, `curl` or `wget`; new `.php` files under web roots; outbound connections from PHP workers.
   - Without SOC-Hunter, it writes the **hunt kit** (below).

   Either way, it writes `handoff-3-hunt.md` and `.json`.
5. **Summary.** Writes `summary.md`, linking every report and handoff.

The playbook only reads data. It never patches, scans, tags or changes anything in Tenable, a SIEM, an EDR or a host.

## Prerequisites

- **Claude Code.**
- **Tenable One Foundation or Advanced**, with Hexa AI MCP turned on under Settings > Hexa AI, and a role of Standard User or higher. The Hexa MCP is not available in FedRAMP Moderate environments.
- **Python 3.9 or later.** `playbook.py` uses only the standard library.
- What the three skills need, which is listed in their READMEs: Python 3 and Chrome for step 1's PDF, and for SOC-Hunter, its Python packages and a SIEM or EDR MCP server.

## Set up the Tenable Hexa AI MCP

1. Generate API keys in Tenable under Settings > My Account > API Keys.
2. In a **separate terminal**, not in a Claude Code chat, add the server. Name it `tenable`, because `/fix-today` expects that name:

   ```bash
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```

   In most shells, starting the command with a space keeps it, and your keys, out of shell history. Never paste the keys into a chat. If you do, revoke them and generate new ones.

3. Restart Claude Code.

Tenable's documentation: [Hexa AI MCP](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm).

## Install

Install the playbook:

```bash
git clone https://github.com/jtbuchanan-tenb/php2shell-playbook ~/.claude/skills/php2shell-playbook
```

Install the three skills. The playbook offers to do this for any that are missing:

```bash
# Step 1: PHP2Shell Tenable Skill
git clone https://github.com/securibee/php2shell-tenable-skill ~/.claude/skills/php2shell-tenable

# Step 2: Remediation Priority & Impact Agent
git clone https://github.com/smjennings/Remediation_Priority-Impact_Agent /tmp/rpia
mkdir -p ~/.claude/commands && cp /tmp/rpia/commands/fix-today.md ~/.claude/commands/fix-today.md

# Step 3: SOC-Hunter (then follow its CONFIG.md to map your SIEM and EDR)
git clone https://github.com/sherlon1/soc-hunter ~/.claude/skills/soc-hunter
```

> Exchange Inspector vetting covers the reviewed commit, not later changes. Remediation Priority & Impact Agent was vetted on Sep 23, 2026 at `536616f` and SOC-Hunter on Oct 7, 2026 at `5eea59b`; this installs the latest version.

Restart Claude Code so it loads the skills.

## Usage

```
/php2shell-playbook
```

Or ask Claude to "run the PHP2Shell playbook". Each step ends by asking whether to continue. If you stop, pick up later, or hand the run to someone else:

```
/php2shell-playbook fix  ~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>
/php2shell-playbook hunt ~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>
```

Leave out the folder to use the most recent run. The playbook shows it and asks you to confirm.

## Output

Everything goes in the step 1 run folder, `~/Dev/php2shell-reports/<YYYY-MM-DD-HHMM>/`, next to step 1's own reports:

| File | Written by | Contents |
|---|---|---|
| `report.html`, `report.pdf`, `report.csv`, `findings.json` | step 1 | The PHP2Shell exposure report |
| `faq.json` | playbook | CVEs, fixed releases and mitigations as the FAQ gave them during this run |
| `handoff-1-find.md` / `.json` | playbook | Status counts, fix list, hunt list, FAQ values |
| `handoff-2-fix.md` / `.json` | playbook | FIRST / NEXT / SOON with the fix per host, plus out-of-scope and unranked hosts |
| `hunt-kit.md`, `hunt-hosts.csv` | playbook | The hunt kit and its host list |
| `handoff-3-hunt.md` / `.json` | playbook | The SOC-Hunter result, or a pointer to the hunt kit |
| `summary.md` | playbook | Links to everything, with a line per step |

## No SIEM or EDR set up? The hunt kit

If SOC-Hunter isn't installed or configured, step 3 writes `hunt-kit.md`. It has ready-to-paste searches for:

- **Splunk:** the CIM Endpoint data model, plus Sysmon for Linux network events.
- **Microsoft Defender XDR and Microsoft Sentinel:** KQL over the `Device*` tables.
- **Elastic:** ES|QL over Elastic Defend events.

There's also a **manual checklist** for one Linux host.

The searches look for the same three behaviors as the hunt hypothesis, since Oct 17. They are behavior-based because no PHP2Shell IOCs have been published. They are filled in with the hunt list; above 200 hosts they point at `hunt-hosts.csv` (a Splunk lookup or a Sentinel watchlist) instead of listing every host. Every search can also run fleet-wide, which catches PHP servers Tenable never scanned. The templates are in [`hunt-kit/`](hunt-kit/).

## Data flows

- **Tenable Hexa AI MCP** (`https://cloud.tenable.com/mcp`). Steps 1 and 2 send read-only queries with your API keys.
- **Your SIEM and EDR MCP servers.** SOC-Hunter queries them, if you've set it up.
- **tenable.com.** Step 1 fetches the FAQ once per run. `/fix-today` also searches the web for exploitation reports on the CVEs it ranks.
- **Your LLM provider.** As with any MCP server, the asset data those tools return passes through Claude Code to the model you use.
- **No network access from `playbook.py`.** It reads and writes files in the run folder only.

## Known limitations

- **Status comes from the PHP version.** This is inherited from step 1. Distribution packages often backport fixes without changing the version number, so they can show as vulnerable when they're patched.
- **Step 2's scope relies on the model.** `/fix-today` is general-purpose and has no built-in scope setting. The playbook asks it to rank only the fix-list hosts for the PHP2Shell CVEs. It then drops any item for another host or other CVEs, and reports what it dropped and which hosts it left unranked. Trimming a bundled fix down to its PHP2Shell part is still up to the model.
- **The hunt-kit searches need your field names.** Index names, data models, process names and web root paths vary. Check them against your data before you trust an empty result. The outbound-connection searches will show PHP applications that call outside APIs.
- **Host names must match.** The searches list each host under every name Tenable has for it (asset name, FQDN and short name). Splunk also matches IPs. If your SIEM or EDR names hosts differently, a filter that matches nothing returns nothing, which looks the same as "not hit". Run one search without the filter first to see the names your data uses.
- **Time pickers.** In Sentinel and Kibana Discover, set the time picker to cover Oct 17 to now. The kit says so in each section.

## Repository layout

```
SKILL.md                         the /php2shell-playbook skill Claude Code loads
playbook.py                      handoffs, hunt kit, summary, preflight (standard library only)
hunt-kit/                        Splunk, KQL and ES|QL templates, and the manual checklist
tests/                           unit tests and sample step 1 output
php2shell-response-briefing.pdf  the briefing deck
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT, copyright Tenable, Inc. See [LICENSE](LICENSE).
