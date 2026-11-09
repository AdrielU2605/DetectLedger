# DetectLedger

**Detection-as-code for Windows attacks.** Sigma detection rules, version-controlled and
automatically tested in CI against *real* recorded attack telemetry. Each rule must fire on
the attack it targets and stay quiet on everything else.

> Status: 🚧 in progress. Day 1: telemetry loader done.

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
2. **Detect:** *(next)* Sigma rules compiled to queries over the event store.
3. **Validate in CI:** *(next)* GitHub Actions runs every rule against its true-positive
   dataset and the other datasets as a false-positive check.
4. **Triage:** *(planned)* MCP server that lets an AI assistant pull alerts, enrich them, and
   draft ATT&CK-mapped incident summaries.

## Known issues

- Security-log events in some recordings only carry `TimeCreated`, which is offset from the
  Sysmon `UtcTime` in the same recording. Timestamps need normalizing before building
  cross-source timelines.

## Development

Built with AI-assisted tooling (Claude Code).
