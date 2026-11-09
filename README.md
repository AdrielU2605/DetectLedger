# DetectLedger

**Detection-as-code for Windows attacks.** Sigma detection rules, version-controlled and
automatically tested in CI against *real* recorded attack telemetry. Each rule must fire on
the attack it targets and stay quiet on everything else.

> Status: 🚧 in progress. Telemetry loader + Sigma engine + first 3 rules done.

## Current results

Every rule runs against every recording. Each one should fire **only** on its own attack:

```
rule                                          dcsync lsass_coms mimikatz_l psexec run_key_pe sam_reg_du schtask_cr wmic_add_u
LSASS Memory Dump via comsvcs.dll MiniDump         .          2          .      .          .          .          .          .
Suspicious Process Access to LSASS Memory          .          2          1      .          .          .          .          .
SAM / SYSTEM / SECURITY Hive Dump via reg.exe      .          .          .      .          .          2          .          .
```

The LSASS access rule catches Mimikatz **by behavior** (requesting memory-read access to
lsass.exe), even though it ran in-memory inside PowerShell with no `mimikatz.exe` on disk.

## Rules

| Rule | ATT&CK | Detects |
|---|---|---|
| [lsass_dump_comsvcs](rules/credential_access/lsass_dump_comsvcs.yml) | T1003.001 | rundll32 + comsvcs.dll MiniDump (living-off-the-land LSASS dump) |
| [lsass_suspicious_access](rules/credential_access/lsass_suspicious_access.yml) | T1003.001 | Any process opening LSASS with memory-read / full access |
| [sam_hive_dump_reg](rules/credential_access/sam_hive_dump_reg.yml) | T1003.002 | reg.exe saving the SAM / SYSTEM / SECURITY hives |

## Why

Detection rules are code, so they get the same treatment as code: versioned, reviewed, and
tested. DetectLedger replays public lab recordings of real attacks (Mimikatz, DCSync, PsExec,
LSASS dumping, and more) from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
and checks every rule against them.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"

detectledger list               # see available attack recordings
detectledger fetch --all        # download + load them into data/events.db
detectledger stats              # what's loaded
pytest                          # run the test suite
```

## Datasets

| Name | ATT&CK | Attack |
|---|---|---|
| lsass_comsvcs | T1003.001 | LSASS memory dumped with rundll32 + comsvcs.dll |
| mimikatz_logonpasswords | T1003.001 | Mimikatz sekurlsa::logonpasswords |
| dcsync | T1003.006 | DCSync replication of password hashes |
| sam_reg_dump | T1003.002 | SAM hive dumped with reg.exe |
| psexec | T1569.002 | PsExec-style remote service creation |
| schtask_create | T1053.005 | Scheduled task creation |
| wmic_add_user | T1136.001 | Backdoor local account via WMIC |
| run_key_persistence | T1547.001 | Registry Run key persistence |

## How it works

1. **Ingest:** newline-delimited JSON event recordings → SQLite. Common fields (event ID,
   channel, host, timestamp) become indexed columns; the full original event is kept as JSON
   so rules can match any field.
2. **Detect:** a small Sigma engine (`src/detectledger/sigma.py`) maps each rule's logsource
   to Windows channels/event IDs (e.g. `process_creation` → Sysmon 1 *and* Security 4688, with
   field aliasing) and evaluates selections, modifiers, wildcards, and conditions.
   Run it with `detectledger hunt --show`.
3. **Validate in CI:** *(next)* GitHub Actions runs every rule against its true-positive
   dataset and the other datasets as a false-positive check.
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

## Known issues

- Security-log events in some recordings only carry `TimeCreated`, which is offset from the
  Sysmon `UtcTime` in the same recording. Timestamps need normalizing before building
  cross-source timelines.

## Development

Built with AI-assisted tooling (Claude Code).
