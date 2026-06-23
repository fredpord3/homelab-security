# 100210 — Encoded PowerShell command

| Field | Value |
|---|---|
| Rule ID | 100210 |
| Level | 12 |
| MITRE technique | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |
| Tactic | TA0002 Execution / TA0005 Defense Evasion |
| Parent group | `sysmon_event1` (Sysmon EventID 1, process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Deployed, validation in progress |

## Detection logic

```xml
<rule id="100210" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}</field>
  <description>PowerShell launched with -EncodedCommand (base64 payload).</description>
  <mitre><id>T1059.001</id><id>T1027</id></mitre>
</rule>
```

Two field constraints on top of the Sysmon process-create parent group:

1. **Image is powershell.exe or powershell_ise.exe** — anchored on backslash + filename
2. **`-EncodedCommand` / `-enc` / `-ec` / `-e`** followed by ≥40 base64-ish characters

PowerShell accepts the abbreviated form down to a unique prefix, so all four forms need coverage. The 40-character base64 floor filters noise from operators using `-e` as shorthand for unrelated flags.

## Why tier on the group, not a specific rule ID

The stock ruleset's per-EventID rules (e.g. 92000 — "Scripting interpreter spawned a new process") are themselves chained off `<if_group>sysmon_event1</if_group>`. Tiering directly on the group catches every Sysmon EventID 1 event regardless of which (if any) stock per-event rule it also matched. Tiering on a specific stock rule ID (e.g. 92000) would mean the custom rule only fires when that specific stock rule also fired — which would miss most cases since stock rules are narrowly targeted.

## Stock-coverage check

Reviewed `0800-sysmon_id_1.xml` for existing PowerShell-encoded coverage. Stock has rules for PowerShell-vs-Defender tampering (92008–92015), PowerShell-vs-SAM-hive (92023–92024), PowerShell spawning cmd (92004), and Reg.exe dumping SAM (92026) — but no generic "PowerShell launched with EncodedCommand" detector. Custom rule fills a genuine gap.

## Test methodology

```powershell
# Benign test payload: encoded Write-Host
$cmd = 'Write-Host "100210 test"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

Expected:

1. Sysmon EventID 1 fires (visible in `Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`)
2. Wazuh agent forwards to manager
3. The custom rule fires on the field match
4. Alert lands in `/var/ossec/logs/alerts/alerts.json` with `rule.id=100210`

## Observed status

Rule deployed and parse-validated via `wazuh-analysisd -t`. End-to-end firing validation in progress.

## Tuning notes

- **`-e` alone is the false-positive risk** — operators occasionally use `-e` for unrelated purposes. The 40-char base64 floor mitigates this but does not eliminate it; if FP rate is high after a baseline period, tighten to `-(enc|ec|encodedcommand)`
- **Defender does NOT block this** — `-EncodedCommand` itself is benign syntax; only the contents of the payload trip AMSI. The rule therefore fires reliably on Freddy-PC unlike rules 100250 / 100290 which Defender ASR preempts
- **Stacks naturally with 100290** — a download cradle delivered via `-EncodedCommand` should fire both rules

## Cross-references

- [`100290-ps-download-cradle.md`](./100290-ps-download-cradle.md) — companion rule for the post-decode behaviour
- [`../docs/findings.md`](../docs/findings.md) — Defender ASR effect on testing
