# 100220 — Defender tampering

| Field | Value |
|---|---|
| Rule ID | 100220 |
| Level | 13 |
| MITRE technique | [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| Tactic | TA0005 Defense Evasion |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Test attempts preempted by Defender Tamper Protection on Freddy-PC |

## Detection logic

```xml
<rule id="100220" level="13">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(set-mppreference.*-disable|sc(\.exe)?\s+(stop|config)\s+windefend|stop-service.*windefend)</field>
  <description>Microsoft Defender tampering attempt</description>
  <mitre><id>T1562.001</id></mitre>
</rule>
```

Single regex against the process-create command line, covering the three most common tampering vectors:

| Pattern | Example |
|---|---|
| `Set-MpPreference -Disable*` | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| `sc.exe stop windefend` / `sc.exe config windefend ...` | `sc stop windefend` |
| `Stop-Service WinDefend` | `Stop-Service WinDefend -Force` |

## Test methodology — and what actually happened

```powershell
# Run from elevated PowerShell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Observed:**

1. Sysmon EventID 1 *was* recorded (the process-create event fires before Defender evaluates the command)
2. The actual `Set-MpPreference` call was **blocked by Tamper Protection** — `Get-MpPreference | Select DisableRealtimeMonitoring` still returned `False`
3. Wazuh alert 100220 **fired correctly** on the attempt itself

This is the desired outcome: the rule detects the *attempt*, regardless of whether the action succeeded. Tamper Protection is a separate enforcement layer that does not need to feed detection. See [`../docs/findings.md`](../docs/findings.md) for the broader pattern of "ASR / Tamper Protection preempts action, but Sysmon still records the attempt, so the detection still fires."

## Observed status

🟡 Partial validation. The PowerShell-cmdlet path (`Set-MpPreference`) fires the rule even when Tamper Protection blocks the action. The `sc.exe stop windefend` path could not be exercised end-to-end on Freddy-PC because `sc.exe` returns `Access denied` before producing the relevant log line in a useful form. Full validation of all three branches is pending the Range VLAN VM with Defender disabled.

## Tuning notes

- **`Set-MpPreference` has many *non-disabling* uses** — e.g. `Set-MpPreference -ScanScheduleDay 0` to set scan schedule. The `-Disable` anchor in the regex is the safety net against false positives from admin configuration runs
- **Watch for renamed binaries** — `sc.exe` is sometimes copied off-box and renamed. The rule keys on the command-line text (`stop windefend`), not the image name, so simple renames are caught. A future enhancement would chain this against Sysmon's `OriginalFileName` field which survives renames
- **Level 13 is intentional** — Defender tampering is rarely benign in a SOC-monitored environment; level 13 routes the alert into the high-severity bucket alongside LSASS access (100230)

## Cross-references

- [`100280-service-stop.md`](./100280-service-stop.md) — companion rule that catches the *successful* service stop event from the SCM channel, complementing this rule's focus on the *attempt*
- [`../docs/findings.md`](../docs/findings.md)
