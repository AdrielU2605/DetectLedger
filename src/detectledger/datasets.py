"""Catalog of public attack recordings from OTRF Security-Datasets.

Each entry is a real attack that researchers ran in a lab while recording
Windows Security and Sysmon logs. Source: https://github.com/OTRF/Security-Datasets
"""

import urllib.request
from dataclasses import dataclass
from pathlib import Path

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"


@dataclass(frozen=True)
class Dataset:
    name: str
    path: str        # path under BASE
    technique: str   # MITRE ATT&CK technique ID
    summary: str

    @property
    def url(self) -> str:
        return f"{BASE}/{self.path}"


CATALOG: dict[str, Dataset] = {
    d.name: d
    for d in [
        Dataset("lsass_comsvcs", "credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
                "T1003.001", "LSASS memory dumped with rundll32 + comsvcs.dll MiniDump"),
        Dataset("mimikatz_logonpasswords", "credential_access/host/empire_mimikatz_logonpasswords.zip",
                "T1003.001", "Mimikatz sekurlsa::logonpasswords reading LSASS"),
        Dataset("dcsync", "credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
                "T1003.006", "DCSync: replicating password hashes from a domain controller"),
        Dataset("sam_reg_dump", "credential_access/host/empire_shell_reg_dump_sam.zip",
                "T1003.002", "Dumping the SAM registry hive with reg.exe"),
        Dataset("psexec", "lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
                "T1569.002", "PsExec-style remote service creation"),
        Dataset("schtask_create", "lateral_movement/host/schtask_create.zip",
                "T1053.005", "Scheduled task created for execution/persistence"),
        Dataset("wmic_add_user", "lateral_movement/host/empire_wmic_add_user_backdoor.zip",
                "T1136.001", "Backdoor local account created remotely via WMIC"),
        Dataset("run_key_persistence",
                "persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip",
                "T1547.001", "Registry Run key persistence"),
    ]
}


def fetch(name: str, dest_dir: str | Path = "data") -> Path:
    """Download a dataset (if not already present) and return its local path."""
    ds = CATALOG[name]
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{ds.name}.zip"
    if not dest.exists():
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(ds.url, tmp)
        tmp.replace(dest)  # only a complete download gets the real name
    return dest
