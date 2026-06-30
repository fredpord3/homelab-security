# 100210 — Encoded PowerShell (non-PowerShell parent)
| Field | Value |
|---|---|
| Rule ID | 100210 |
| Level | 12 |
| MITRE technique | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 — Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |
| Tactic | TA0002 Execution / TA0005 Defense Evasion |
| Parent group | `sysmon_event1` (Sysmon EventID 1, process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟢 Verified firing end-to-end on Freddy-PC, 2026-06-30 |
## Detection logic
```xml
<rule id="100210" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.parentImage" negate="yes" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}</field>
  <description>Encoded PowerShell launched by non-PowerShell parent: $(win.eventdata.parentImage)</description>
  <mitre><id>T1059.001</id><id>T1027</id></mitre>
</rule>
```
Three field constraints on top of the Sysmon process-create parent group:
1. **Image is powershell.exe or powershell_ise.exe** — anchored on backslash + filename
2. **Parent image is NOT powershell** — the `negate="yes"` constraint that differentiates this rule from stock 92057 (see below)
3. **`-EncodedCommand` / `-enc` / `-ec` / `-e`** followed by ≥40 base64-ish characters — PowerShell accepts the abbreviated form down to a unique prefix, so all four forms need coverage. The 40-character base64 floor filters noise from operators using `-e` as shorthand for unrelated flags.
## Why tier on the group, not a specific rule ID
The stock ruleset's per-EventID rules (e.g. 92000 — "Scripting interpreter spawned a new process") are themselves chained off `<if_group>sysmon_event1</if_group>`. Tiering directly on the group catches every Sysmon EventID 1 event regardless of which (if any) stock per-event rule it also matched. Tiering on a specific stock rule ID would mean the custom rule only fires when that specific stock rule also fired — which would miss most cases since stock rules are narrowly targeted.
## Stock-coverage finding and the parent-filter rewrite
**Initial draft:** an earlier version of this rule had no parentImage constraint — it fired on any powershell.exe process-create with `-EncodedCommand` in the command line.

**Late discovery:** stock rule `92057` (level 12, MITRE T1059.001) covers exactly the same pattern: "Powershell.exe spawned a powershell process which executed a base64 encoded command." Same level, same MITRE technique, same telemetry source. The original stock-coverage check missed 92057 because the keyword grep used "EncodedCommand" while 92057's description uses "base64 encoded command" — different terminology, identical detection.

**Confirmation:** end-to-end test with `powershell.exe -EncodedCommand <base64>` launched from a PowerShell parent fired stock 92057 but NOT the original draft of 100210 — most likely because 92057 absorbed the event in the rule chain.

**Rewrite:** added `<field name="win.eventdata.parentImage" negate="yes" type="pcre2">(?i)\\powershell(_ise)?\.exe$</field>`. The rule now fires only when encoded PowerShell is launched by a **non-PowerShell parent** — the realistic attacker scenarios that 92057 misses:

| Parent process | Scenario | Stock 92057? | Custom 100210? |
|---|---|---|---|
| powershell.exe | Operator running encoded child from a PS prompt | ✅ fires | ❌ filtered out (avoids redundancy) |
| explorer.exe | User double-clicks a malicious .lnk | ❌ misses | ✅ fires |
| winword.exe / excel.exe | Office macro spawns encoded PowerShell | ❌ misses | ✅ fires |
| taskhost / svchost | Scheduled task action runs encoded PowerShell | ❌ misses | ✅ fires |
| cmd.exe | Batch script invokes encoded PowerShell | ❌ misses | ✅ fires |

This is the test from finding #11: "What event would fire the parent but NOT my rule?" Plenty — every ps-spawning-ps case. The single constraint is real, so the rule earns its rule ID.
## Test methodology
```powershell
# Will NOT fire 100210 (parent is powershell.exe — stock 92057 covers this case)
$cmd = 'Write-Host "100210 test"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

To actually fire 100210, launch PowerShell from a non-PowerShell parent. Paste this into the File Explorer address bar and hit Enter (parent becomes explorer.exe):

```
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAMQAwADAAMgAxADAAIAB0AGUAcwB0ACIA
```

(Decoded payload: `Write-Host "100210 test"`)
## Observed status
Verified firing end-to-end on 2026-06-30. The Explorer-launched test produced an alert with:

- `rule.id` = `100210`
- `rule.level` = `12`
- `rule.description` = "Encoded PowerShell launched by non-PowerShell parent: C:\Windows\explorer.exe"
- `rule.mitre.id` = `T1059.001`, `T1027`
- `data.win.eventdata.parentImage` = `C:\Windows\explorer.exe`
- `data.win.eventdata.commandLine` contained `-EncodedCommand VwByAGkAdABl...`

Full pipeline confirmed: explorer.exe spawn → Sysmon EventID 1 → Wazuh agent → manager `windows_eventchannel` decoder → custom rule match (image + non-PS parent + encoded command pattern) → `alerts.json`.

Screenshot: [`../screenshots/100210-encoded-ps-firing.png`](../screenshots/100210-encoded-ps-firing.png)
## Tuning notes
- **`-e` alone is the false-positive risk** — operators occasionally use `-e` for unrelated purposes. The 40-char base64 floor mitigates this but does not eliminate it; if FP rate is high after a baseline period, tighten to `-(enc|ec|encodedcommand)`
- **Defender does NOT block this** — `-EncodedCommand` itself is benign syntax; only the contents of the payload trip AMSI. The rule therefore fires reliably on Freddy-PC unlike rules 100250 / 100290 which Defender ASR preempts
- **Stacks naturally with 100290** — a download cradle delivered via `-EncodedCommand` from a non-PowerShell parent should fire both rules
- **Pair with stock 92057 for full coverage** — between the two rules, encoded PowerShell is caught regardless of parent: 92057 handles ps-spawning-ps, 100210 handles everything else. Combined dashboard query: `rule.id: (92057 OR 100210)`
## Cross-references
- [`100290-ps-download-cradle.md`](./100290-ps-download-cradle.md) — companion rule for the post-decode behaviour
- [`../docs/findings.md`](../docs/findings.md) #10 — stock-coverage methodology (the discipline that should have caught 92057 earlier)
- [`../docs/findings.md`](../docs/findings.md) #11 — the "tiering rule must add real filter logic" test, which the rewritten 100210 passes
- [`../docs/findings.md`](../docs/findings.md) #1 — Defender ASR effect on testing (does not apply to this rule)
