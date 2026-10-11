#!/usr/bin/env python3
"""
regripper_triage_report.py

Parse the registry-based artifacts listed in "Evidence Sources.pdf" from a KAPE
triage image's "C" folder using RegRipper 4.0 (rip.exe), and write a single
self-contained HTML report grouped by the PDF's categories. The run_yara plugin
is also run against every hive found, with results under "Malware Execution".

Requirements
    * Python 3.9+ (standard library only)
    * rip.exe (RegRipper 4.0) reachable through the PATH environment variable
    * For run_yara: yara64.exe in the RegRipper 4.0 root (next to rip.exe) and
      the Yara rule files in the same folder as yara64.exe

Efficiency (Big O)
    Let
        A = artifacts in the catalog (a constant, ~40)
        U = user profiles found under C\\Users
        H = hive instances found            = 5 + 2U
        R = (artifact, hive type, plugin) run references in the catalog (constant)
        T = unique (hive instance, plugin) tasks after de-duplication
            T <= R_sys + R_usr * U + H, where R_usr counts per-user runs and
            the + H term is run_yara, which runs once on every hive
        c = cost of one rip.exe run (process start + hive parse), c = O(hive size)
        W = worker threads
        S = total bytes of plugin output

    Hive discovery ........ O(U * d)   one os.scandir per directory level
                                         (d = entries per directory)
    Task planning ......... O(R + U*R_usr + T log T)
                                         hash-set de-duplication, then an LPT sort
    Task execution ........ O(T * c) total CPU work; wall clock
                                         <= (T * c) / W + c_max   (Graham bound)
                                         Largest hives are dispatched first (LPT),
                                         which tightens the c_max term.
    Result lookup ......... O(1) per (hive, plugin) via a dict
    HTML rendering ........ O(S + A + T), streamed to disk in a single pass
    Space ................. O(S + T) for the captured plugin output

    Why it is cheap in practice: a plugin shared by several artifacts (for
    example comdlg32 covers LastVisitedMRU and OpenSaveMRU, run covers every Run
    key) is executed once per hive, never once per artifact; hives that are not
    present are never touched; and the report links to the first rendering of
    repeated output instead of copying it again.

Exit codes
    0  success                              1  finished, some plugin runs failed
    2  rip.exe missing / bad input          3  no registry hives found
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import html
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Hive types
# --------------------------------------------------------------------------- #
SYSTEM, SOFTWARE, SAM, SECURITY = "SYSTEM", "SOFTWARE", "SAM", "SECURITY"
AMCACHE, NTUSER, USRCLASS = "AMCACHE", "NTUSER", "USRCLASS"
USER_HIVES = frozenset({NTUSER, USRCLASS})

# --------------------------------------------------------------------------- #
# Categories, in the order used by Evidence Sources.pdf
# --------------------------------------------------------------------------- #
CAT_MEM = "Memory Acquisition Locations"
CAT_SYS = "System Information"
CAT_FK = "File Knowledge (Whether file exist/existed in system)"
CAT_FFA = "Files and Folders Access"
CAT_DL = "File Downloads"
CAT_EXEC = "Program Execution"
CAT_PS = "PowerShell Activity"
CAT_BROWSE = "Browsing History"
CAT_NET = "Network Usage"
CAT_USB = "USB Activity"
CAT_LAT = "Lateral Movement"
CAT_PERS = "Local Persistence"
CAT_EVADE = "Defence Evasion"
CAT_MAL = "Malware Execution"

CATEGORIES: Tuple[str, ...] = (
    CAT_MEM, CAT_SYS, CAT_FK, CAT_FFA, CAT_DL, CAT_EXEC, CAT_PS,
    CAT_BROWSE, CAT_NET, CAT_USB, CAT_LAT, CAT_PERS, CAT_EVADE, CAT_MAL,
)

NO_REGISTRY_NOTE = (
    "Evidence Sources.pdf lists no registry-based artifacts for this category "
    "(its sources are event logs, files or databases)."
)


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Key:
    path: str
    desc: str


@dataclass(frozen=True)
class Artifact:
    category: str
    name: str
    keys: Tuple[Key, ...]
    runs: Tuple[Tuple[str, str], ...]  # (hive type, RegRipper plugin name)
    note: str = ""


EXPL = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
CV = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
NTCV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
CCS = r"HKLM\SYSTEM\CurrentControlSet"

CATALOG: Tuple[Artifact, ...] = (
    # ---- Memory Acquisition Locations (registry configuration only) ------- #
    Artifact(CAT_MEM, "Pagefile configuration", (
        Key(CCS + r"\Control\Session Manager\Memory Management",
            "Info on the pagefile (pagefile.sys): portions of memory paged out to "
            "disk, analysable with MemProcFS."),
    ), ((SYSTEM, "pagefile"),)),
    Artifact(CAT_MEM, "Kernel-mode crash dump configuration", (
        Key(CCS + r"\Control\CrashControl",
            "Info on crash dumps (%SystemRoot%\\MEMORY.DMP), which are a great "
            "source for memory analysis."),
    ), ((SYSTEM, "crashcontrol"),)),

    # ---- System Information ---------------------------------------------- #
    Artifact(CAT_SYS, "App Paths", (
        Key(CV + r"\App Paths",
            "Apps installed on the system on a system-wide basis. Apps registered "
            "here can be called by Win + R without specifying the full path."),
        Key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths",
            "Apps installed on a per-user basis (same behaviour as above)."),
    ), ((SOFTWARE, "apppaths"), (NTUSER, "apppaths"))),
    Artifact(CAT_SYS, "ComputerName", (
        Key(CCS + r"\Control\ComputerName\ComputerName", "Name of the computer."),
    ), ((SYSTEM, "compname"),)),
    Artifact(CAT_SYS, "CurrentVersion", (
        Key(NTCV, "Version and Service Pack number of the Windows OS."),
    ), ((SOFTWARE, "winver"),)),
    Artifact(CAT_SYS, "FirewallPolicy", (
        Key(CCS + r"\Services\SharedAccess\Parameters\FirewallPolicy\*",
            "Local firewall profiles (Public, Private and Domain) status and "
            "configured rules."),
    ), ((SYSTEM, "fw_config"),)),
    Artifact(CAT_SYS, "Interfaces", (
        Key(CCS + r"\Services\Tcpip\Parameters\Interfaces\*",
            "Basic info about network interfaces."),
    ), ((SYSTEM, "nic2"), (SYSTEM, "ips"))),
    Artifact(CAT_SYS, "LanmanServer\\Shares", (
        Key(CCS + r"\Services\LanmanServer\Shares", "SMB shares hosted by the system."),
    ), ((SYSTEM, "shares"),)),
    Artifact(CAT_SYS, "NetworkList", (
        Key(NTCV + r"\NetworkList\Profiles",
            "Basic network historical info (network name and type, first and last "
            "connection, etc.). Lives in the SOFTWARE hive; the PDF's \"SYSTEM "
            "hive\" label is an error."),
    ), ((SOFTWARE, "networklist"),)),
    Artifact(CAT_SYS, "SECURITY\\Policy (PolAcDmN, PolAcDmS, PolDnDDN, PolPrDmS)", (
        Key(r"HKLM\SECURITY\Policy\PolAcDmN", "Computer name."),
        Key(r"HKLM\SECURITY\Policy\PolAcDmS", "Computer SID."),
        Key(r"HKLM\SECURITY\Policy\PolDnDDN", "Computer's domain name."),
        Key(r"HKLM\SECURITY\Policy\PolPrDmS", "Computer's domain SID."),
    ), ((SECURITY, "polacdms"),),
        "The polacdms plugin is documented for PolAcDmS and PolPrDmS; the other "
        "two values may need Registry Explorer or RECmd."),
    Artifact(CAT_SYS, "ProfileList", (
        Key(NTCV + r"\ProfileList",
            "List of local and domain accounts with interactive logins to the "
            "system. The last write timestamp of each key indicates when the "
            "associated user last logged on."),
    ), ((SOFTWARE, "profilelist"),)),
    Artifact(CAT_SYS, "SAM hive", (
        Key(r"SAM\Domains\Account\Users", "List of local users and their NTLM hashes."),
    ), ((SAM, "samparse"),)),
    Artifact(CAT_SYS, "TimeZoneInformation", (
        Key(CCS + r"\Control\TimeZoneInformation",
            "System timezone info."),
    ), ((SYSTEM, "timezone"),)),
    Artifact(CAT_SYS, "Uninstall", (
        Key(CV + r"\Uninstall",
            "Apps installed on the system on a system-wide basis. Apps listed here "
            "also appear in Add or remove programs in Control Panel."),
        Key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "Apps installed on a per-user basis (same behaviour as above)."),
    ), ((SOFTWARE, "uninstall"), (NTUSER, "uninstall"))),

    # ---- File Knowledge --------------------------------------------------- #
    Artifact(CAT_FK, "Amcache", (
        Key(r"C:\Windows\AppCompat\Programs\Amcache.hve",
            "Entries can be due to automated file discovery or program "
            "installation."),
    ), ((AMCACHE, "amcache"),)),
    Artifact(CAT_FK, "ShimCache", (
        Key(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache",
            "Executables can be recorded in AppCompatCache preemptively by the "
            "operating system, even before execution."),
        Key(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache",
            "Alternate location for the same cache."),
    ), ((SYSTEM, "appcompatcache"),)),

    # ---- Files and Folders Access ---------------------------------------- #
    Artifact(CAT_FFA, "LastVisitedMRU / LastVisitedPidMRU / LastVisitedPidMRULegacy", (
        Key(EXPL + r"\ComDlg32\LastVisitedMRU",
            "Records the programs used to open/save the file tracked in the "
            "OpenSaveMRU registry key."),
    ), ((NTUSER, "comdlg32"),)),
    Artifact(CAT_FFA, "OpenSaveMRU / OpenSavePidlMRU", (
        Key(EXPL + r"\ComDlg32\OpenSaveMRU",
            "Records info on file opening or save through the Open File or Save "
            "File Common Dialogs box."),
        Key(EXPL + r"\ComDlg32\OpenSavePidlMRU", "Same, PIDL-based variant."),
    ), ((NTUSER, "comdlg32"),)),
    Artifact(CAT_FFA, "RecentApps", (
        Key(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps\<GUID>",
            "Tracks program executions and files accessed by tracked programs."),
    ), ((NTUSER, "recentapps"),)),
    Artifact(CAT_FFA, "RunMRU", (
        Key(EXPL + r"\RunMRU", 'Tracks items launched from "Win + R".'),
    ), ((NTUSER, "runmru"),)),
    Artifact(CAT_FFA, "Shellbags", (
        Key(r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            "Folders and network shares to which a given user has navigated "
            "(Windows Explorer activity, UsrClass.dat)."),
        Key(r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
            "Windows Explorer view settings per folder (UsrClass.dat)."),
        Key(r"HKCU\Software\Microsoft\Windows\Shell\BagMRU",
            "Desktop and network locations activity (NTUSER.DAT)."),
        Key(r"HKCU\Software\Microsoft\Windows\Shell\Bags",
            "Desktop and network location view settings (NTUSER.DAT)."),
    ), ((USRCLASS, "shellbags"), (NTUSER, "shellbags"))),
    Artifact(CAT_FFA, "WordWheelQuery", (
        Key(EXPL + r"\WordWheelQuery", "Tracks keywords searched in the Windows Explorer search box."),
    ), ((NTUSER, "wordwheelquery"),)),

    # ---- File Downloads --------------------------------------------------- #
    Artifact(CAT_DL, "OpenSaveMRU / OpenSavePidlMRU", (
        Key(EXPL + r"\ComDlg32\OpenSaveMRU",
            "Records info on file opening or save through the Open File or Save "
            "File Common Dialogs box. Imagine Save As from a web browser."),
        Key(EXPL + r"\ComDlg32\OpenSavePidlMRU", "Same, PIDL-based variant."),
    ), ((NTUSER, "comdlg32"),)),

    # ---- Program Execution ------------------------------------------------ #
    Artifact(CAT_EXEC, "Amcache", (
        Key(r"C:\Windows\AppCompat\Programs\Amcache.hve",
            "If GUI programs are shimmed when executed, an entry is created. "
            "Entries do not guarantee app execution. Tracks first-seen; only file "
            "relocation or modification creates a new entry after that."),
    ), ((AMCACHE, "amcache"),)),
    Artifact(CAT_EXEC, "Background Activity Moderator (BAM) / Desktop Activity Moderator (DAM)", (
        Key(CCS + r"\Services\bam\UserSettings\<SID>",
            "Ties program executions with specific users; each user-specific key "
            "contains a list of executed programs."),
        Key(CCS + r"\Services\dam\UserSettings\<SID>", "Same, DAM."),
        Key(CCS + r"\Services\bam\State\UserSettings\<SID>", "Windows 10 1809+ location (BAM)."),
        Key(CCS + r"\Services\dam\State\UserSettings\<SID>", "Windows 10 1809+ location (DAM)."),
    ), ((SYSTEM, "bam"),),
        "The bam plugin targets BAM; confirm DAM entries with Registry Explorer or RECmd."),
    Artifact(CAT_EXEC, "FeatureUsage", (
        Key(EXPL + r"\FeatureUsage",
            "Tracks how a user has interacted with the taskbar. Only tracks GUI "
            "apps and does not include an execution timestamp."),
    ), ((NTUSER, "featureusage"),)),
    Artifact(CAT_EXEC, "MUICache", (
        Key(r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MUICache",
            "Allows apps to have a single EXE for multiple languages. Only tracks "
            "GUI apps and does not include an execution timestamp."),
        Key(r"HKCU\Local Settings\MuiCache", "Alternate location, same behaviour."),
    ), ((USRCLASS, "muicache"), (NTUSER, "muicache"))),
    Artifact(CAT_EXEC, "RecentApps", (
        Key(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\RecentApps\<GUID>",
            "Tracks program executions and files accessed by tracked programs."),
    ), ((NTUSER, "recentapps"),)),
    Artifact(CAT_EXEC, "RunMRU", (
        Key(EXPL + r"\RunMRU", 'Tracks items launched from "Win + R".'),
    ), ((NTUSER, "runmru"),)),
    Artifact(CAT_EXEC, "ShimCache", (
        Key(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache",
            "Can be used to track application execution but does not guarantee "
            "an app executed (or did not execute). One entry is expected even if "
            "the app executes multiple times."),
        Key(r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache",
            "Alternate location for the same cache."),
    ), ((SYSTEM, "appcompatcache"),)),
    Artifact(CAT_EXEC, "UserAssist", (
        Key(EXPL + r"\UserAssist\<GUID>\Count",
            "References GUI program executions and, starting from Win7, shortcut "
            "executions. {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} = GUI program "
            "execution; {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} = shortcut execution."),
    ), ((NTUSER, "userassist"),)),

    # ---- Browsing History ------------------------------------------------- #
    Artifact(CAT_BROWSE, "TypedURLs", (
        Key(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs",
            "Tracks URLs entered (typed, pasted, or auto-completed) in the "
            "Internet Explorer search bar. Web searches are not stored, only the "
            "URLs entered."),
    ), ((NTUSER, "typedurls"),)),

    # ---- USB Activity ----------------------------------------------------- #
    Artifact(CAT_USB, "DeviceClasses", (
        Key(CCS + r"\Control\DeviceClasses",
            "System-wide info about currently or previously connected plug and "
            "play devices (storage devices, volumes, network devices, Bluetooth "
            "devices, etc.)."),
    ), ((SYSTEM, "devclass"),)),
    Artifact(CAT_USB, "Enum\\SWD\\WPDBUSENUM", (
        Key(CCS + r"\Enum\SWD\WPDBUSENUM",
            "System-wide info about currently or previously connected USB devices."),
    ), ((SYSTEM, "wpdbusenum"),)),
    Artifact(CAT_USB, "Enum\\USB", (
        Key(CCS + r"\Enum\USB",
            "System-wide info about currently or previously connected USB devices."),
    ), ((SYSTEM, "usbdevices"),)),
    Artifact(CAT_USB, "Enum\\USBSTOR", (
        Key(CCS + r"\Enum\USBSTOR",
            "System-wide info about currently or previously connected USB "
            "devices that are related to storage."),
    ), ((SYSTEM, "usbstor3"),)),
    Artifact(CAT_USB, "MountedDevices", (
        Key(r"HKLM\SYSTEM\MountedDevices",
            "System-wide info about currently or previously mounted drives (such "
            "as system drives or USB devices)."),
    ), ((SYSTEM, "mountdev2"),)),
    Artifact(CAT_USB, "VolumeInfoCache", (
        Key(r"HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache",
            "Info on currently or previously mounted volumes. Maps drive letters "
            "to their last associated volume's display name."),
    ), ((SOFTWARE, "volinfocache"),)),
    Artifact(CAT_USB, "Windows Portable Devices", (
        Key(r"HKLM\SOFTWARE\Microsoft\Windows NT\Windows Portable Devices",
            "Info on currently or previously attached media and storage devices, "
            "notably the device volume's friendly name or display name."),
    ), ((SOFTWARE, "removdev"),)),

    # ---- Lateral Movement ------------------------------------------------- #
    Artifact(CAT_LAT, "Map Network Drive MRU", (
        Key(EXPL + r"\Map Network Drive MRU",
            "References network shares recently used by the associated user "
            "(source host)."),
    ), ((NTUSER, "mndmru"),)),
    Artifact(CAT_LAT, "MountPoints2", (
        Key(EXPL + r"\MountPoints2",
            "Helps identify both local and remotely mounted volumes (potential "
            "lateral movement via SMB) (source host)."),
    ), ((NTUSER, "mp2"),)),
    Artifact(CAT_LAT, "PortProxy", (
        Key(CCS + r"\Services\PortProxy\*",
            "Stores port forwards configured on the local system via netsh."),
    ), (), "No stock RegRipper plugin is available; use Registry Explorer or RECmd."),
    Artifact(CAT_LAT, "Services", (
        Key(CCS + r"\Services\<SERVICE_NAME>",
            "Contains details of configured Windows Services (destination host)."),
    ), ((SYSTEM, "services"),)),
    Artifact(CAT_LAT, "Taskcache", (
        Key(NTCV + r"\Schedule\Taskcache\Tasks\<TASK_GUID>",
            "Contains details of configured scheduled tasks (destination host)."),
        Key(NTCV + r"\Schedule\Taskcache\Tree\<TASK_NAME>", "Task tree and names."),
    ), ((SOFTWARE, "taskcache"), (SOFTWARE, "tasks"))),
    Artifact(CAT_LAT, "Terminal Server Client\\Servers", (
        Key(r"HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers\<IP>",
            "Tracks remote hosts an associated user connected to using RDP via "
            "mstsc.exe (source host)."),
    ), ((NTUSER, "tsclient"),)),

    # ---- Local Persistence ------------------------------------------------ #
    Artifact(CAT_PERS, "Auto-Start Extensibility Points (ASEPs)", (
        Key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run and Runonce",
            "Programs that start automatically at user logon."),
        Key(r"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Per-user Winlogon values (shell, logon behaviour)."),
        Key(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Shell",
            "Per-user shell override via policy."),
        Key(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run, Runonce and policies\Explorer\Run",
            "Programs that start automatically at system boot or user logon."),
        Key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "System-wide Winlogon values (shell, userinit)."),
        Key(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\Startup and \Logon",
            "Startup and logon scripts configured by policy."),
    ), ((SOFTWARE, "run"), (NTUSER, "run"), (SOFTWARE, "winlogon"),
        (NTUSER, "winlogon_u"), (SOFTWARE, "psscript"), (NTUSER, "psscript")),
        "psscript covers the related Group Policy\\Scripts keys; the Policies\\...\\"
        "Scripts keys named in the PDF may need Registry Explorer or RECmd."),
    Artifact(CAT_PERS, "KnownDLLs", (
        Key(r"HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls",
            "Contains hardcoded paths for critical DLLs. Attackers can add their "
            "own DLLs here as a form of DLL load order hijacking."),
    ), (), "No stock RegRipper plugin is available; use Registry Explorer or RECmd."),
    Artifact(CAT_PERS, "Services", (
        Key(CCS + r"\Services\<SERVICE_NAME>", "Contains details of configured Windows Services."),
    ), ((SYSTEM, "services"),)),
    Artifact(CAT_PERS, "Userinit key", (
        Key(NTCV + r"\Winlogon\Userinit",
            "Usually, should only contain a reference to userinit.exe."),
    ), ((SOFTWARE, "winlogon"),)),

    # ---- Malware Execution (addition: not a registry source in the PDF) --- #
    Artifact(CAT_MAL, "Yara scan of registry hives (run_yara)", (
        Key("Every registry hive found in the triage image",
            "Yara rules run against Registry data using the run_yara plugin of "
            "RegRipper 4.0. This entry is an addition to Evidence Sources.pdf, "
            "which lists no registry-based sources for this category."),
    ), ((SYSTEM, "run_yara"), (SOFTWARE, "run_yara"), (SAM, "run_yara"),
        (SECURITY, "run_yara"), (AMCACHE, "run_yara"), (NTUSER, "run_yara"),
        (USRCLASS, "run_yara")),
        "Needs yara64.exe in the RegRipper 4.0 root (next to rip.exe) and the Yara "
        "rule files in the same folder as yara64.exe; rip.exe is launched from that "
        "folder so the plugin's .\\yara64.exe call resolves. No rules means no matches."),
)

# --------------------------------------------------------------------------- #
# Hive discovery
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Hive:
    htype: str
    label: str
    path: Path
    size: int


def resolve_ci(base: Path, *parts: str) -> Optional[Path]:
    """Case-insensitive path walk: one os.scandir per level -> O(depth * d)."""
    cur = str(base)
    for part in parts:
        try:
            with os.scandir(cur) as it:
                nxt = next((e.path for e in it if e.name.lower() == part.lower()), None)
        except OSError:
            return None
        if nxt is None:
            return None
        cur = nxt
    return Path(cur)


def normalise_root(path: Path) -> Path:
    """Accept either the 'C' folder itself or its parent."""
    if resolve_ci(path, "Windows", "System32", "config"):
        return path
    child = resolve_ci(path, "C")
    if child and resolve_ci(child, "Windows", "System32", "config"):
        return child
    return path


def discover_hives(root: Path) -> Dict[str, List[Hive]]:
    found: Dict[str, List[Hive]] = {}

    def add(htype: str, label: str, p: Optional[Path]) -> None:
        if p and p.is_file():
            found.setdefault(htype, []).append(Hive(htype, label, p, p.stat().st_size))

    for name in (SYSTEM, SOFTWARE, SAM, SECURITY):
        add(name, name, resolve_ci(root, "Windows", "System32", "config", name))
    add(AMCACHE, "Amcache.hve", resolve_ci(root, "Windows", "AppCompat", "Programs", "Amcache.hve"))

    users = resolve_ci(root, "Users")
    if users:
        with os.scandir(users) as it:
            profiles = [e for e in it if e.is_dir()]
        for prof in profiles:
            p = Path(prof.path)
            add(NTUSER, f"NTUSER.DAT ({prof.name})", resolve_ci(p, "NTUSER.DAT"))
            add(USRCLASS, f"UsrClass.dat ({prof.name})",
                resolve_ci(p, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"))
    return found


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #
NOT_FOUND_RE = re.compile(r"(plugin\s+\S+\s+(?:was\s+)?not\s+found|could not (?:find|locate) plugin)", re.I)

CMD_ERR_RE = re.compile(r"is not recognized as an internal or external command", re.I)

TaskKey = Tuple[str, str]  # (hive path, plugin)


@dataclass
class TaskResult:
    status: str  # ok | empty | error | timeout
    output: str
    stderr: str
    seconds: float


def run_plugin(rip: str, hive: Path, plugin: str, timeout: int) -> TaskResult:
    start = time.perf_counter()
    try:
        cp = subprocess.run(
            [rip, "-r", str(hive), "-p", plugin],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
            # run_yara calls .\\yara64.exe, a path relative to the working directory,
            # so rip.exe must run from the RegRipper folder.
            cwd=os.path.dirname(rip) or None,
        )
    except subprocess.TimeoutExpired:
        return TaskResult("timeout", "", f"Timed out after {timeout}s", time.perf_counter() - start)
    except OSError as exc:
        return TaskResult("error", "", str(exc), time.perf_counter() - start)
    out, err = cp.stdout.strip(), cp.stderr.strip()
    if cp.returncode != 0 or NOT_FOUND_RE.search(out[:500]) or CMD_ERR_RE.search(out + err):
        status = "error"
    elif not out:
        status = "empty"
    else:
        status = "ok"
    return TaskResult(status, out, err, time.perf_counter() - start)


def build_plan(hives: Dict[str, List[Hive]]) -> List[Tuple[Hive, str]]:
    """De-duplicate (hive, plugin) pairs: O(R + T). Largest hives first (LPT)."""
    seen = set()
    plan: List[Tuple[Hive, str]] = []
    for art in CATALOG:
        for htype, plugin in art.runs:
            for hive in hives.get(htype, ()):
                key = (str(hive.path), plugin)
                if key not in seen:
                    seen.add(key)
                    plan.append((hive, plugin))
    plan.sort(key=lambda t: t[0].size, reverse=True)
    return plan


def execute(rip: str, plan: Sequence[Tuple[Hive, str]], workers: int,
            timeout: int, quiet: bool) -> Dict[TaskKey, TaskResult]:
    results: Dict[TaskKey, TaskResult] = {}
    if not plan:
        return results
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(run_plugin, rip, h.path, p, timeout): (h, p) for h, p in plan}
        for n, fut in enumerate(cf.as_completed(futs), 1):
            h, p = futs[fut]
            res = fut.result()
            results[(str(h.path), p)] = res
            if not quiet:
                print(f"[{n}/{len(plan)}] {p:<18} {h.label:<32} {res.status} ({res.seconds:.1f}s)",
                      file=sys.stderr)
    return results


# --------------------------------------------------------------------------- #
# HTML rendering (streamed)
# --------------------------------------------------------------------------- #
CSS = """
*{box-sizing:border-box}body{margin:0;display:flex;font:14px/1.5 system-ui,'Segoe UI',sans-serif;color:#1f2937;background:#f8fafc}
nav{position:sticky;top:0;height:100vh;overflow:auto;width:290px;flex:none;padding:16px;background:#0f172a;color:#e2e8f0}
nav h1{font-size:15px;margin:0 0 10px}nav a{display:block;color:#cbd5e1;text-decoration:none;padding:3px 0;font-size:13px}
nav a:hover{color:#fff}nav input{width:100%;padding:6px;margin:8px 0;border-radius:4px;border:0}
nav button{margin:0 4px 8px 0;padding:4px 8px;border:0;border-radius:4px;cursor:pointer}
main{flex:1;min-width:0;padding:24px 32px;max-width:1300px}
h2{margin-top:36px;padding-bottom:6px;border-bottom:2px solid #cbd5e1}
details.artifact{background:#fff;border:1px solid #e2e8f0;border-radius:6px;margin:10px 0;padding:8px 14px}
details.artifact>summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid #e2e8f0;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f1f5f9}td.key{font-family:Consolas,monospace;word-break:break-all;width:42%}
.run{margin:10px 0}.runhead{font-size:13px}.meta{color:#64748b;font-size:12px}
pre{background:#0b1220;color:#d1e0f5;padding:10px;border-radius:4px;overflow:auto;max-height:520px;font:12px/1.45 Consolas,monospace;white-space:pre-wrap}
.badge{display:inline-block;padding:0 7px;border-radius:9px;font-size:11px;color:#fff}
.ok{background:#16a34a}.empty{background:#64748b}.error,.timeout{background:#dc2626}
.warn{color:#92400e;background:#fef3c7;padding:6px 10px;border-radius:4px}.note{color:#475569;font-style:italic}
.summary span{display:inline-block;margin-right:18px}
"""

JS = """
const q=document.getElementById('q');
q.addEventListener('input',()=>{const v=q.value.toLowerCase();
document.querySelectorAll('details.artifact').forEach(a=>{a.hidden=!!v&&!a.textContent.toLowerCase().includes(v)})});
function setAll(o){document.querySelectorAll('details').forEach(d=>d.open=o)}
"""


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def render(root: Path, hives: Dict[str, List[Hive]], results: Dict[TaskKey, TaskResult],
           elapsed: float, warnings: Sequence[str] = ()) -> Iterator[str]:
    counts = {"ok": 0, "empty": 0, "error": 0, "timeout": 0}
    for r in results.values():
        counts[r.status] += 1
    by_cat: Dict[str, List[Tuple[int, Artifact]]] = {c: [] for c in CATEGORIES}
    for i, art in enumerate(CATALOG):
        by_cat[art.category].append((i, art))

    yield ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           "<title>RegRipper Triage Report</title>"
           f"<style>{CSS}</style></head><body>")
    yield "<nav><h1>RegRipper Triage Report</h1><input id='q' placeholder='Filter artifacts...'>"
    yield "<button onclick='setAll(true)'>Expand all</button><button onclick='setAll(false)'>Collapse all</button>"
    for n, cat in enumerate(CATEGORIES):
        yield f"<a href='#cat{n}'>{esc(cat)} ({len(by_cat[cat])})</a>"
    yield "</nav><main>"

    yield "<h1>Registry Artifact Report</h1><div class='summary'>"
    yield f"<span>Source: <code>{esc(str(root))}</code></span>"
    yield f"<span>Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC</span>"
    yield f"<span>Plugin runs: {len(results)} (ok {counts['ok']}, empty {counts['empty']}, "
    yield f"failed {counts['error'] + counts['timeout']})</span><span>Wall time: {elapsed:.1f}s</span></div>"
    for w in warnings:
        yield f"<p class='warn'>{esc(w)}</p>"

    yield "<h2>Hive inventory</h2><table><tr><th>Type</th><th>Instance</th><th>Path</th><th>Size</th></tr>"
    for htype in (SYSTEM, SOFTWARE, SAM, SECURITY, AMCACHE, NTUSER, USRCLASS):
        items = hives.get(htype)
        if not items:
            yield f"<tr><td>{htype}</td><td colspan='3' class='note'>not found in triage image</td></tr>"
            continue
        for h in items:
            yield (f"<tr><td>{htype}</td><td>{esc(h.label)}</td><td class='key'>{esc(str(h.path))}</td>"
                   f"<td>{h.size:,} bytes</td></tr>")
    yield "</table>"

    first_anchor: Dict[TaskKey, str] = {}
    for n, cat in enumerate(CATEGORIES):
        yield f"<h2 id='cat{n}'>{esc(cat)}</h2>"
        if not by_cat[cat]:
            yield f"<p class='note'>{esc(NO_REGISTRY_NOTE)}</p>"
            continue
        for idx, art in by_cat[cat]:
            yield f"<details class='artifact' id='a{idx}'><summary>{esc(art.name)}</summary>"
            yield "<table><tr><th>Registry key / source</th><th>What it is</th></tr>"
            for k in art.keys:
                yield f"<tr><td class='key'>{esc(k.path)}</td><td>{esc(k.desc)}</td></tr>"
            yield "</table>"
            if art.note:
                yield f"<p class='note'>{esc(art.note)}</p>"
            if not art.runs:
                yield "<p class='warn'>No RegRipper plugin mapped for this artifact.</p>"
            for htype, plugin in art.runs:
                instances = hives.get(htype)
                if not instances:
                    yield f"<p class='warn'>{htype} hive not found in triage image; <b>{esc(plugin)}</b> skipped.</p>"
                    continue
                for h in instances:
                    key = (str(h.path), plugin)
                    r = results[key]
                    yield ("<div class='run'><div class='runhead'>"
                           f"<span class='badge {r.status}'>{r.status}</span> <b>{esc(plugin)}</b> on "
                           f"{esc(h.label)} <span class='meta'>{r.seconds:.1f}s</span></div>")
                    if key in first_anchor:
                        yield (f"<p class='note'>Same plugin output already shown "
                               f"<a href='#{first_anchor[key]}'>above</a>.</p>")
                    else:
                        first_anchor[key] = f"a{idx}"
                        if r.output:
                            yield f"<pre>{html.escape(r.output, quote=False)}</pre>"
                        elif r.status == "empty":
                            yield "<p class='note'>Plugin returned no output (key or values absent).</p>"
                        if r.stderr:
                            yield f"<pre>{html.escape(r.stderr, quote=False)}</pre>"
                    yield "</div>"
            yield "</details>"
    yield f"</main><script>{JS}</script></body></html>"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
RIP_MISSING = (
    "[ERROR] rip.exe was not found in your PATH.\n"
    "        Add the folder that contains rip.exe (for example C:\\Tools\\RegRipper4.0)\n"
    "        to the PATH environment variable, open a new terminal, and run this script again.\n"
    "        cmd.exe    : set PATH=%PATH%;C:\\Tools\\RegRipper4.0\n"
    "        PowerShell : $env:Path += ';C:\\Tools\\RegRipper4.0'"
)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="regripper_triage_report.py",
        description="Parse registry artifacts from a KAPE triage image with RegRipper 4.0 and "
                    "write an HTML report grouped by the categories in Evidence Sources.pdf. "
                    "Also runs the run_yara plugin against every hive found.",
        epilog="Exit codes: 0 ok, 1 some plugin runs failed, 2 rip.exe missing or bad input, "
               "3 no hives found.",
    )
    p.add_argument("triage_dir", type=Path,
                   help='path to the "C" folder of the KAPE triage image (e.g. D:\\KAPE\\Out\\C)')
    p.add_argument("-o", "--output-dir", type=Path, required=True,
                   help="directory in which the HTML report is written (created if missing)")
    p.add_argument("-w", "--workers", type=int, default=os.cpu_count() or 4,
                   help="parallel rip.exe processes (default: CPU count)")
    p.add_argument("-t", "--timeout", type=int, default=300,
                   help="per-plugin timeout in seconds (default: 300)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    rip = shutil.which("rip.exe")
    if not rip:
        print(RIP_MISSING)
        return 2
    if args.workers < 1 or args.timeout < 1:
        print("[ERROR] --workers and --timeout must be positive integers.")
        return 2
    if not args.triage_dir.is_dir():
        print(f"[ERROR] Not a directory: {args.triage_dir}")
        return 2

    warnings: List[str] = []
    if not (Path(rip).parent / "yara64.exe").is_file():
        msg = ("yara64.exe was not found next to rip.exe. The run_yara plugin calls .\\yara64.exe from "
               "the RegRipper folder, so copy yara64.exe into the RegRipper 4.0 root, with the Yara "
               "rule files in the same folder; run_yara results below will likely show errors.")
        warnings.append(msg)
        print("[WARNING] " + msg)

    root = normalise_root(args.triage_dir).resolve()
    hives = discover_hives(root)
    if not hives:
        print(f"[ERROR] No registry hives found under {root}. Point the script at the 'C' folder "
              "of the triage image.")
        return 3

    plan = build_plan(hives)
    if not args.quiet:
        total = sum(len(v) for v in hives.values())
        print(f"Found {total} hive(s); running {len(plan)} unique plugin task(s) "
              f"with {args.workers} worker(s).", file=sys.stderr)

    start = time.perf_counter()
    results = execute(rip, plan, args.workers, args.timeout, args.quiet)
    elapsed = time.perf_counter() - start

    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = args.output_dir / f"regripper_report_{dt.datetime.now():%Y%m%d_%H%M%S}.html"
    with report.open("w", encoding="utf-8") as fh:
        for chunk in render(root, hives, results, elapsed, warnings):
            fh.write(chunk)

    failed = sum(1 for r in results.values() if r.status in ("error", "timeout"))
    print(f"Report written to {report} ({len(results)} plugin runs, {failed} failed).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())