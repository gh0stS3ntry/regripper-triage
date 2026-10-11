# regripper_triage_report.py

Parses the registry-based artifacts from a KAPE triage image using RegRipper 4.0 (`rip.exe`) and writes one self-contained HTML report. Results are grouped into different categories, and each registry key path is shown next to the PDF's description of what it is. The `run_yara` plugin is also run against every hive found, with its results under *Malware Execution*.

## Requirements

- Python 3.9+ (standard library only, nothing to `pip install`)
- RegRipper 4.0 with `rip.exe` reachable through the `PATH` environment variable
- For `run_yara`: `yara64.exe` (from the [Yara releases](https://virustotal.github.io/yara/)) copied into the RegRipper 4.0 root, the same folder as `rip.exe`, with your Yara rule files in the same folder as `yara64.exe`
- A KAPE triage image (the `C` folder), e.g. from the `!SANS_Triage` or `RegistryHives` targets

If `rip.exe` is not on `PATH`, the script prints a message to stdout explaining how to add it and exits with code 2.

```
cmd.exe    : set PATH=%PATH%;C:\Tools\RegRipper4.0
PowerShell : $env:Path += ';C:\Tools\RegRipper4.0'
```

## Usage

```
python regripper_triage_report.py <triage_dir> -o <output_dir> [-w WORKERS] [-t TIMEOUT] [-q]
```

| Argument | Description |
|---|---|
| `triage_dir` | Path to the `C` folder of the KAPE triage image. The parent of `C` is also accepted. |
| `-o`, `--output-dir` | Directory for the HTML report (created if missing). Required. |
| `-w`, `--workers` | Parallel `rip.exe` processes. Default: CPU count. |
| `-t`, `--timeout` | Per-plugin timeout in seconds. Default: 300. |
| `-q`, `--quiet` | Suppress progress output on stderr. |
| `-h`, `--help` | Show the help menu. |

Example:

```
python regripper_triage_report.py D:\KAPE\Out\C -o D:\Reports -w 8
```

The report is written as `regripper_report_<YYYYMMDD_HHMMSS>.html`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Report written, but one or more plugin runs failed or timed out |
| 2 | `rip.exe` not in `PATH`, invalid arguments, or `triage_dir` is not a directory |
| 3 | No registry hives found under `triage_dir` |

## Hives it looks for

| Hive | Location under `C` |
|---|---|
| SYSTEM, SOFTWARE, SAM, SECURITY | `Windows\System32\config\` |
| Amcache | `Windows\AppCompat\Programs\Amcache.hve` |
| NTUSER.DAT (one per profile) | `Users\<user>\NTUSER.DAT` |
| UsrClass.dat (one per profile) | `Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |

Lookups are case-insensitive. Hives that are missing are reported in the HTML and the plugins that need them are skipped.

## Yara scanning (Malware Execution)

For every hive found (SYSTEM, SOFTWARE, SAM, SECURITY, Amcache, and each user's NTUSER.DAT and UsrClass.dat), the script runs `rip.exe -r <hive> -p run_yara`. The results appear in the report under *Malware Execution* as "Yara scan of registry hives (run_yara)".

- Per the RegRipper 4.0 README, `run_yara` needs `yara64.exe` in the RegRipper 4.0 root and the rule files in the same folder as `yara64.exe`. The plugin calls `.\yara64.exe`, a path relative to the working directory, so the script launches every `rip.exe` process with the RegRipper folder (the folder containing `rip.exe`) as its working directory. Having `yara64.exe` in `PATH` is not enough. If `yara64.exe` is not found next to `rip.exe`, the script prints a `[WARNING]` to stdout, shows the same warning in the report, and still runs the plugin, so failures show up as `error` rows. Output containing "is not recognized as an internal or external command" is also marked `error`, even if `rip.exe` exits with code 0.
- With no rule files in place, expect no matches. A clean result only means the rules you supplied did not match.
- Use of RegRipper 4.0 is subject to its license, which at the time of writing allows personal and academic use only. Check the [RegRipper 4.0 repository](https://github.com/keydet89/RegRipper4.0) for current terms.

## What the report contains

- A hive inventory (type, path, size) and run summary (ok, empty, failed, wall time)
- A sidebar with every category, a filter box, and expand/collapse all
- For each artifact: its key paths with the PDF's description, then each plugin run with a status badge (`ok`, `empty`, `error`, `timeout`), the hive instance it ran on, runtime, and the raw RegRipper output
- When several artifacts share the same plugin output (for example OpenSaveMRU appears under both *Files and Folders Access* and *File Downloads*), the later occurrence links to the first one instead of repeating it

Categories follow the order of the PDF. Memory Acquisition Locations has two registry-based entries (pagefile and crash dump configuration), and Malware Execution holds the Yara scan. PowerShell Activity, Network Usage and Defence Evasion have no registry-based artifacts in the PDF, so they appear with a note and no results.

## Artifact to plugin mapping

| Category | Artifacts | Plugins (hive) |
|---|---|---|
| Memory Acquisition | Pagefile config, CrashControl | `pagefile`, `crashcontrol` (SYSTEM) |
| System Information | App Paths, Uninstall | `apppaths`, `uninstall` (SOFTWARE, NTUSER) |
| | ComputerName, FirewallPolicy, Interfaces, Shares, TimeZoneInformation | `compname`, `fw_config`, `nic2` + `ips`, `shares`, `timezone` (SYSTEM) |
| | CurrentVersion, NetworkList, ProfileList | `winver`, `networklist`, `profilelist` (SOFTWARE) |
| | PolAcDmN/S, PolDnDDN, PolPrDmS | `polacdms` (SECURITY) |
| | SAM users | `samparse` (SAM) |
| File Knowledge | Amcache, ShimCache | `amcache` (Amcache), `appcompatcache` (SYSTEM) |
| Files and Folders Access / File Downloads | LastVisitedMRU, OpenSaveMRU | `comdlg32` (NTUSER) |
| | RecentApps, RunMRU, WordWheelQuery | `recentapps`, `runmru`, `wordwheelquery` (NTUSER) |
| | Shellbags | `shellbags` (UsrClass, NTUSER) |
| Program Execution | BAM/DAM | `bam` (SYSTEM) |
| | FeatureUsage, UserAssist | `featureusage`, `userassist` (NTUSER) |
| | MUICache | `muicache` (UsrClass, NTUSER) |
| Browsing History | TypedURLs | `typedurls` (NTUSER) |
| USB Activity | DeviceClasses, WPDBUSENUM, Enum\USB, USBSTOR, MountedDevices | `devclass`, `wpdbusenum`, `usbdevices`, `usbstor3`, `mountdev2` (SYSTEM) |
| | VolumeInfoCache, Windows Portable Devices | `volinfocache`, `removdev` (SOFTWARE) |
| Malware Execution | Yara scan (added) | `run_yara` (all hives found) |
| Lateral Movement | Map Network Drive MRU, MountPoints2, Terminal Server Client | `mndmru`, `mp2`, `tsclient` (NTUSER) |
| | Services | `services` (SYSTEM) |
| | Taskcache | `taskcache`, `tasks` (SOFTWARE) |
| Local Persistence | ASEPs | `run`, `winlogon`, `psscript` (SOFTWARE); `run`, `winlogon_u`, `psscript` (NTUSER) |
| | Services, Userinit | `services` (SYSTEM), `winlogon` (SOFTWARE) |

Plugin names were chosen from the 3R (RegRipper Ripper) key-to-plugin list, which covers RegRipper v2.8 and v3.0. RegRipper 4.0 adds plugins and deprecates some, and I could not check this mapping against a 4.0 plugin folder. A name missing from your 4.0 install shows as `error` in the report; fix it by editing the matching `CATALOG` entry.

### Known gaps

- **PortProxy** and **KnownDLLs** have no stock RegRipper plugin; the report lists them with a note. Use Registry Explorer or RECmd for these.
- **DAM** is not separately covered; `bam` targets BAM.
- **PolAcDmN / PolDnDDN**: the `polacdms` plugin is documented for PolAcDmS and PolPrDmS only.
- **Policies\...\Scripts\Startup/Logon** (ASEPs): `psscript` covers the related Group Policy\Scripts keys, not the exact Policies path in the PDF.
- **NetworkList**: the PDF labels it as a SYSTEM-hive key, but it lives in SOFTWARE, so the script parses SOFTWARE.
- Adding or changing coverage is a one-line edit to the `CATALOG` list at the top of the script.

## Efficiency (Big O)

Definitions: `U` user profiles, `H = 5 + 2U` hives, `R` (artifact, hive type, plugin) references in the catalog (a constant), `T` unique (hive, plugin) tasks, `c` cost of one `rip.exe` run, `W` workers, `S` bytes of plugin output, `d` entries per directory.

| Stage | Cost |
|---|---|
| Hive discovery | `O(U * d)`, one `os.scandir` per directory level |
| Task planning | `O(R + T log T)`: hash-set de-duplication, then a sort by hive size. `T <= R_sys + R_usr*U + H`, where the `H` term is `run_yara` on every hive |
| Task execution | `O(T * c)` total work; wall clock `<= T*c/W + c_max` (Graham's list-scheduling bound) |
| Result lookup | `O(1)` per task (dictionary) |
| HTML rendering | `O(S + A + T)`, streamed to disk in one pass |
| Space | `O(S + T)` |

Design choices behind these numbers:

1. **De-duplication.** A plugin shared by several artifacts runs once per hive, never once per artifact. `comdlg32`, `run`, `winlogon` and `services` are each reused in several places.
2. **Parallelism.** The work is I/O and subprocess bound, so a `ThreadPoolExecutor` overlaps `rip.exe` processes without GIL contention.
3. **Longest-processing-time-first.** Tasks are dispatched largest hive first, which shrinks the `c_max` straggler term.
4. **No wasted runs.** Plugins for hives that are not present are never launched.
5. **Streaming output.** The report is written chunk by chunk, so memory holds one copy of the plugin output, not two.

The dominant constant is `rip.exe` process start plus hive parse, which the script cannot avoid; RegRipper has no multi-plugin call for a single process unless a profile file is placed in its plugins folder.

## Notes and caveats

- **Dirty hives.** KAPE collects transaction logs (`.LOG1`/`.LOG2`) with hives, but RegRipper 4.0 does not process them automatically. If a hive is dirty, replay the logs first (for example with Eric Zimmerman's `rla.exe`) and point the script at the cleaned copies.
- **Plugin output is shown as-is.** Plugin names that do not exist in your RegRipper build show up as `error` in the report; check the `plugins` folder of your install.
- `run_yara` adds one `rip.exe` run per hive, so it grows the task count by `H`. Yara scans of large hives are likely the slowest tasks; raise `-t` if they time out.
- Plugin output is HTML-escaped, so hostile strings in the registry cannot inject markup into the report.
- The script reads hives only and never modifies the triage image.
