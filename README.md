# DetectLedger

[![detections](https://github.com/AdrielU2605/DetectLedger/actions/workflows/detections.yml/badge.svg)](https://github.com/AdrielU2605/DetectLedger/actions/workflows/detections.yml)

**Detection-as-code for Windows attacks.** 10 Sigma detection rules, version-controlled and
tested in CI against **~33,700 real Windows events** recorded during lab attacks (Mimikatz,
DCSync, PsExec, WMI lateral movement, and more). Every rule must fire on the attack it targets
and stay silent everywhere else. An **MCP server** lets an AI assistant investigate the alerts
and write incident reports.

```
logs (OTRF recordings) ─► ingest + UTC clock alignment ─► SQLite ─► Sigma engine ─► alerts
                                                                         │              │
                                              CI: expected counts per rule/dataset    timeline, context,
                                              (true positives + zero false positives)  MCP triage server
```

## Highlights

- **Catches attacks by behavior, not names.** The LSASS rule flags any process requesting
  memory-read access to `lsass.exe`, so it caught Mimikatz running **in-memory inside PowerShell**
  with no `mimikatz.exe` on disk.
- **Rules are tested like code.** [`tests/expectations.yml`](tests/expectations.yml) pins the exact
  alert count each rule must produce on each recording. Loosening a rule (e.g. allowing access mask
  `0x1000`) fails CI immediately: 3 alerts instead of 1.
- **Real log-pipeline problems, found and fixed:**
  - A collector wrote `security` instead of `Security`, making **481 events invisible** to every
    rule. Fixed with case-insensitive matching plus a regression test.
  - Timestamp labels lie. One field ending in `Z` (claiming UTC) was really 5 hours off, another 16.
    DetectLedger **learns each recording's clock offsets** from Sysmon's trusted `UtcTime`, so
    cross-source timelines line up to the millisecond.
- **AI-assisted triage, built with prompt injection in mind.** Attackers control their own command
  lines, so every MCP tool result is labeled untrusted, the database is opened read-only, and output
  is bounded. See the [sample triage report](docs/sample-triage-report.md).
- **The triage → detection loop works.** Triage found that nothing alerted on the encoded Empire
  PowerShell stager. The new rule written for it also caught attacker `whoami /user` recon that no
  other rule saw.

## Detection matrix

Alerts per rule (rows) per attack recording (columns). `-` = silent. CI fails if any cell changes.

| Rule | ATT&CK | dcsync | lsass_comsvcs | mimikatz | psexec | run_key | sam_reg_dump | schtask | wmic_add_user |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DCSync by a non-DC account | T1003.006 | **3** | - | - | - | - | - | - | - |
| LSASS dump via comsvcs.dll | T1003.001 | - | **2** | - | - | - | - | - | - |
| Suspicious access to LSASS memory | T1003.001 | - | **2** | **1** | - | - | - | - | - |
| SAM/SYSTEM hive dump via reg.exe | T1003.002 | - | - | - | - | - | **2** | - | - |
| Hidden encoded PowerShell stager or child | T1059.001, T1027 | **1** | - | **1** | **4** | - | **1** | - | **1** |
| Service installed with shell command line | T1569.002, T1543.003 | - | - | - | **1** | - | - | - | - |
| Remote process creation via WMIC | T1047 | - | - | - | - | - | - | - | **2** |
| Local account created via net.exe | T1136.001 | - | - | - | - | - | - | - | **4** |
| Run key set to script interpreter | T1547.001 | - | - | - | - | **1** | - | - | - |
| Suspicious scheduled task | T1053.005 | - | - | - | - | - | - | **2** | - |

The PowerShell-stager row fires on five recordings on purpose: those attacks all used the same
Empire launcher, and every hit is attacker activity.

## ATT&CK coverage

**11 techniques across 5 tactics, all validated in CI.** Load
[`docs/attack-navigator-layer.json`](docs/attack-navigator-layer.json) in the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) ("Open Existing Layer" →
"Upload from local") to see them on the full matrix.

| Technique | Tactics | Rules | Validated on |
|---|---|---|---|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) LSASS Memory | credential-access | 2 | lsass_comsvcs, mimikatz_logonpasswords |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager | credential-access | 1 | sam_reg_dump |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) DCSync | credential-access | 1 | dcsync |
| [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information | defense-evasion | 1 | 5 recordings |
| [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation | execution | 1 | wmic_add_user |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | execution, persistence, privilege-escalation | 1 | schtask_create |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | execution | 1 | 5 recordings |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Local Account | persistence | 1 | wmic_add_user |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service | persistence, privilege-escalation | 1 | psexec |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys | persistence, privilege-escalation | 1 | run_key_persistence |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) Service Execution | execution | 1 | psexec |

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"

detectledger fetch --all        # download the pinned attack recordings, load into data/events.db
detectledger hunt --show        # run every rule against every recording
detectledger timeline           # all alerts in UTC order, duplicates merged
detectledger context <alert_id> # one alert + process launches around it on the same host
detectledger coverage           # ATT&CK coverage table
pytest                          # 75 tests: engine, clock, alerts, MCP server, detection regressions
```

## AI triage with MCP

`detectledger-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server (stdio),
written with **no third-party dependencies**: plain JSON-RPC 2.0 over stdin/stdout.

```bash
claude mcp add detectledger -- /path/to/DetectLedger/.venv/Scripts/detectledger-mcp
```

Then ask Claude Code something like *"Use detectledger to triage the critical alerts."*

| Tool | Purpose |
|---|---|
| `list_alerts` | Alerts in UTC order, filter by severity/recording |
| `get_alert` | Key fields, rule description, known false positives, ATT&CK mapping |
| `get_process_context` | Process launches on the same host around the alert |
| `search_events` | Pivot: one host, bounded time window, event-ID and text filters |
| `detection_coverage` | Rules and the techniques they cover |
| prompt `triage_alert` | Report template: verdict, timeline, ATT&CK, scope, actions, detection notes |

**Security design:** read-only SQLite (`mode=ro`); every result is labeled as untrusted
log-derived data, and the server instructions tell the model never to follow instructions inside
log fields (a test plants `IGNORE PREVIOUS INSTRUCTIONS` in a command line); results and time
windows are bounded.

## How it works

1. **Ingest** ([`ingest.py`](src/detectledger/ingest.py)): newline-delimited JSON recordings →
   SQLite. Indexed columns for common fields; the full original event is kept as JSON so rules can
   match any field. Datasets are pinned to a fixed OTRF commit so test data can't change.
2. **Clock alignment** ([`clock.py`](src/detectledger/clock.py)): learns per-recording offsets from
   events that carry both Sysmon `UtcTime` and another clock, rounded to 15 minutes (time-zone
   granularity, which also strips collector delay), then corrects the Security-log events.
3. **Sigma engine** ([`sigma.py`](src/detectledger/sigma.py)): maps logsources to channels/event
   IDs (`process_creation` → Sysmon 1 **and** Security 4688, with field aliasing), and evaluates
   modifiers, wildcards, null checks, and `and`/`or`/`not`/`1 of`/`all of` conditions.
4. **Alerts** ([`alerts.py`](src/detectledger/alerts.py)): merges duplicate copies of the same
   activity (Sysmon + Security: 20 raw alerts → 11 incidents) and builds investigation context.
5. **CI** ([`.github/workflows/detections.yml`](.github/workflows/detections.yml)): runs all tests
   and posts the detection matrix to every run's summary.

## Limitations

- Rules were written while looking at these recordings, so true positives are expected. The
  meaningful signal is the **false-positive** check, which covers only the background activity in
  8 lab recordings, not a real enterprise baseline.
- The engine implements the Sigma features these rules use, not the full specification.
- Recordings without Sysmon events can't be clock-aligned; their timestamps are used only if they
  explicitly claim UTC, and are flagged `unverified`.

## Credits

Attack telemetry: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (Roberto
Rodriguez and contributors). Detection format: [Sigma](https://sigmahq.io).
Built with AI-assisted tooling (Claude Code).
