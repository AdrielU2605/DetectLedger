# Sample triage report: alert `842cd0bc-20967`

> Produced by Claude (via Claude Code) using only the DetectLedger MCP tools:
> `get_alert` → `get_process_context` → `search_events`, following the `triage_alert` prompt
> template. The data is the OTRF `wmic_add_user` lab recording, not a real incident.

## Verdict
**True positive: high confidence.** Hands-on-keyboard lateral movement plus persistence: an
encoded Empire PowerShell stager on WORKSTATION5 used WMI to create a backdoor local account on
WORKSTATION6.

## What happened (UTC, 2020-09-14)
| Time | Host | Evidence |
|---|---|---|
| before 12:06:01 | WORKSTATION5 | `powershell.exe -noP -sta -w 1 -enc …` running as `THESHIRE\pgustavo`. Decoded, the stager starts by **disabling PowerShell ScriptBlock logging** (`cachedGroupPolicySettings` tamper), the typical Empire launcher. |
| 12:06:01.826 | WORKSTATION5 | That PowerShell launches `WMIC.exe /node:WORKSTATION6 process call create "net user /add backdoor paw0rd1"` (alert `842cd0bc-20967`, merged with its Security 4688 copy). |
| 12:06:02 | WORKSTATION6 | Security 4624: `pgustavo` network logon (**LogonType 3, Kerberos**) from **172.18.39.5**, most likely WORKSTATION5 (it is the source IP in 33 of WORKSTATION5's own Sysmon network events). |
| 12:06:02.209 | WORKSTATION6 | `WmiPrvSE.exe -secured -Embedding` starts (the WMI provider host that executes remote WMI calls). |
| 12:06:02.316 | WORKSTATION6 | `WmiPrvSE.exe` → `net user /add backdoor paw0rd1` (alert `db696b9d-21216`) → `net1.exe` (alert `db696b9d-21393`). |
| 12:06:02 | WORKSTATION6 | Security **4720** (account `backdoor` created by `pgustavo`) and **4724** (password set). |

## MITRE ATT&CK
| Technique | Evidence |
|---|---|
| T1059.001 PowerShell | Encoded PowerShell parent process on WORKSTATION5 |
| T1027 Obfuscated Files or Information | Base64 `-enc` command line with randomized casing |
| T1562 Impair Defenses | Stager disables ScriptBlock logging before doing anything else |
| T1047 Windows Management Instrumentation | `wmic /node:WORKSTATION6 process call create` |
| T1021 Remote Services / T1078 Valid Accounts | Kerberos network logon to WORKSTATION6 with `pgustavo`'s domain credentials |
| T1136.001 Create Account: Local Account | `net user /add backdoor`, confirmed by 4720 |

## Scope
- **Hosts:** WORKSTATION5 (source, running the stager), WORKSTATION6 (target, backdoor account).
- **Accounts:** `THESHIRE\pgustavo` (compromised or attacker-controlled domain account) and
  `backdoor` (new local account on WORKSTATION6, password `paw0rd1` visible in the command line).
- **Spread:** `pgustavo` has network-logon rights on at least one other workstation. Check every
  host where `pgustavo` logged on (4624) in the surrounding days.

## Recommended actions
1. **Isolate WORKSTATION5** (stager running there) and **WORKSTATION6**.
2. **Disable `backdoor`** on WORKSTATION6 and search the fleet for other new local accounts (4720).
3. **Reset `pgustavo`'s credentials** and review the account's recent logons and group memberships.
4. Collect PowerShell operational logs from WORKSTATION5 to find how the stager first ran (initial
   access), keeping in mind ScriptBlock logging was disabled from the stager onward.
5. Hunt for remote WMI process creation (`WmiPrvSE.exe` spawning shells or `net.exe`) on other hosts.

## Detection notes
- The WMIC rule catches the **source** side. Adding a **target-side** rule (`WmiPrvSE.exe` spawning
  `cmd`, `powershell`, or `net`) would still catch this when attackers use WMI through PowerShell or
  Impacket instead of `wmic.exe`.
- The encoded, logging-disabling PowerShell parent was **not alerted on by itself**: a gap. A rule
  for `powershell -enc` combined with `-w 1` / `-noP`, or for the ScriptBlock-logging tamper string,
  would have fired earlier in the attack.
