# DetectLedger

[![detections](https://github.com/AdrielU2605/DetectLedger/actions/workflows/detections.yml/badge.svg)](https://github.com/AdrielU2605/DetectLedger/actions/workflows/detections.yml)

**Detection-as-code for Windows attacks.** Sigma detection rules, version-controlled and
automatically tested in CI against *real* recorded attack telemetry. Each rule must fire on
the attack it targets and stay quiet on everything else.

> Status: 🚧 in progress. Loader, Sigma engine, 9 rules, and CI done. Next: timelines and AI triage.

## Detection matrix

Every rule runs against every recording (~33,700 real Windows events). Numbers are alerts;
`-` means silent. CI fails if any cell changes unexpectedly.

| Rule | ATT&CK | dcsync | lsass_comsvcs | mimikatz | psexec | run_key | sam_reg_dump | schtask | wmic_add_user |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DCSync by a non-DC account | T1003.006 | **3** | - | - | - | - | - | - | - |
| LSASS dump via comsvcs.dll | T1003.001 | - | **2** | - | - | - | - | - | - |
| Suspicious access to LSASS memory | T1003.001 | - | **2** | **1** | - | - | - | - | - |
| SAM/SYSTEM hive dump via reg.exe | T1003.002 | - | - | - | - | - | **2** | - | - |
| Service installed with shell command line | T1569.002, T1543.003 | - | - | - | **1** | - | - | - | - |
| Remote process creation via WMIC | T1047 | - | - | - | - | - | - | - | **2** |
| Local account created via net.exe | T1136.001 | - | - | - | - | - | - | - | **4** |
| Run key set to script interpreter | T1547.001 | - | - | - | - | **1** | - | - | - |
| Suspicious scheduled task | T1053.005 | - | - | - | - | - | - | **2** | - |

Highlights:
- The LSASS access rule catches Mimikatz **by behavior** (requesting memory-read access to
  lsass.exe), even though it ran in-memory inside PowerShell with no `mimikatz.exe` on disk.
- Process rules match both Sysmon event 1 and Security event 4688, so they keep working if one
  log source is missing.

## Rules

| Rule | ATT&CK | Detects |
|---|---|---|
| [dcsync_replication](rules/credential_access/dcsync_replication.yml) | T1003.006 | AD replication rights requested by a non-machine account (4662) |
| [lsass_dump_comsvcs](rules/credential_access/lsass_dump_comsvcs.yml) | T1003.001 | rundll32 + comsvcs.dll MiniDump (living-off-the-land LSASS dump) |
| [lsass_suspicious_access](rules/credential_access/lsass_suspicious_access.yml) | T1003.001 | Any process opening LSASS with memory-read / full access |
| [sam_hive_dump_reg](rules/credential_access/sam_hive_dump_reg.yml) | T1003.002 | reg.exe saving the SAM / SYSTEM / SECURITY hives |
| [service_install_suspicious_imagepath](rules/execution/service_install_suspicious_imagepath.yml) | T1569.002 | New service whose binary path is a cmd/PowerShell command (PsExec-style) |
| [wmic_remote_process_create](rules/lateral_movement/wmic_remote_process_create.yml) | T1047 | `wmic /node:... process call create` |
| [local_account_created_net](rules/persistence/local_account_created_net.yml) | T1136.001 | `net user ... /add` backdoor accounts |
| [run_key_suspicious_value](rules/persistence/run_key_suspicious_value.yml) | T1547.001 | Run/RunOnce autostart pointing at a script interpreter or temp path |
| [schtask_suspicious_create](rules/persistence/schtask_suspicious_create.yml) | T1053.005 | schtasks /create as SYSTEM, remote, or launching a shell |

## Why

Detection rules are code, so they get the same treatment as code: versioned, reviewed, and
tested. DetectLedger replays public lab recordings of real attacks from
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) and checks every rule
against all of them.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"

detectledger list               # see available attack recordings
detectledger fetch --all        # download + load them into data/events.db
detectledger hunt --show        # run every rule, print alerts
pytest                          # unit tests + detection regression tests
```

## How it works

1. **Ingest:** newline-delimited JSON event recordings → SQLite. Common fields (event ID,
   channel, host, timestamp) become indexed columns; the full original event is kept as JSON
   so rules can match any field. Datasets are pinned to a specific OTRF commit.
2. **Detect:** a small Sigma engine (`src/detectledger/sigma.py`) maps each rule's logsource
   to Windows channels/event IDs (e.g. `process_creation` → Sysmon 1 *and* Security 4688, with
   field aliasing) and evaluates selections, modifiers, wildcards, and conditions.
3. **Validate in CI:** [`tests/expectations.yml`](tests/expectations.yml) records exactly how
   many alerts each rule must produce on its attack, and requires zero on every other dataset.
   GitHub Actions runs it on every push and posts the matrix to the run summary.
4. **Triage:** *(planned)* MCP server that lets an AI assistant pull alerts, enrich them, and
   draft ATT&CK-mapped incident summaries.

## Lessons from real data

- **Silent log-pipeline gaps.** Some recordings were collected by a different pipeline that
  wrote the channel as `security` instead of `Security`. A case-sensitive match made 481
  Security events invisible to every rule. Channel matching is now case-insensitive, with a
  regression test.
- **Substring traps.** A first draft of the SAM rule matched `\system`, which also matches
  `C:\Windows\System32\reg.exe` itself, so any full-path `reg save` would alert. The rule now
  matches full hive paths (`hklm\system`).
- **The tests catch real regressions.** Loosening the LSASS rule to also allow access mask
  `0x1000` (routine svchost queries) immediately fails CI: 3 alerts instead of 1.

## Limitations

- Rules were written while looking at these recordings, so the true-positive results are
  expected. The meaningful signal is the **false-positive** side, and that is limited to the
  background activity inside 8 lab recordings, not a real enterprise baseline.
- The engine supports the Sigma features these rules use, not the full specification.
- Security-log events in some recordings only carry `TimeCreated`, which is offset from the
  Sysmon `UtcTime` in the same recording. Timestamps need normalizing before building
  cross-source timelines.

## Development

Built with AI-assisted tooling (Claude Code).
