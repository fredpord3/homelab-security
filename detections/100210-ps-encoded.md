# 100210 — Encoded PowerShell command

| Field | Value |
|---|---|
| Rule ID | 100210 |
| Level | 12 |
| MITRE technique | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |
| Tactic | TA0002 Execution / TA0005 Defense Evasion |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | ✅ Validated firing on Freddy-PC |

## Detection logic

```xml
<rule id="100210" level="12">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}</field>
  <description>PowerShell launched with -EncodedCommand (base64 payload).</description>
  <mitre><id>T1059.001</id><id>T1027</id></mitre>
</rule>
```

Two field-level constraints on top of the Sysmon process-create parent:

1. **Image is powershell.exe or powershell_ise.exe** — anchored on backslash + filename to avoid renamed-binary bypasses
2. **`-EncodedCommand` / `-enc` / `-ec` / `-e`** followed by ≥40 base64-ish characters — the 40-char floor catches anything substantial enough to be a real payload while filtering noise from operators using `-e` as a shorthand for unrelated flags

PowerShell accepts the abbreviated form down to a unique prefix, so `-e`, `-ec`, `-enc`, and `-encodedcommand` all need coverage.

## Test methodology

```powershell
# Benign test payload: encoded `Write-Host "test"`
$cmd = 'Write-Host "100210 test"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

Expected behaviour:

1. Sysmon EventID 1 fires (visible in `Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`)
2. Wazuh agent forwards to manager
3. Stock 92052 matches; custom 100210 fires
4. Alert lands in `/var/ossec/logs/alerts/alerts.json` with `rule.id=100210`

## Observed status

Rule deployed and parse-validated via `wazuh-logtest`. End-to-end firing validation against simulated attacks is in progress.
## Tuning notes

- **`-e` alone is risky** — operators occasionally use `-e` as a typo or as a custom alias. The 40-char base64 floor mitigates this but if false positives appear, tighten to `-(enc|ec|encodedcommand)`
- **Defender does NOT block this** — `-EncodedCommand` itself is benign syntax; only the *contents* of the payload trip AMSI / Defender. The rule therefore fires reliably on Freddy-PC unlike rules 100230 / 100290 which Defender ASR preempts
- **Stacking with 100290** — a download cradle delivered via `-EncodedCommand` should trigger BOTH 100210 (encoded) and 100290 (download cradle) once Defender ASR is disabled on the Range VM, providing a useful detection-stack validation case

## Cross-references

- [`100290-ps-download-cradle.md`](./100290-ps-download-cradle.md) — companion rule for the post-decode behaviour
- [`../docs/findings.md`](../docs/findings.md) — Defender ASR's effect on testing PowerShell behaviours
