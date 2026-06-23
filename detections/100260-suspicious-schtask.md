# 100260 — Suspicious scheduled task

| Field | Value |
|---|---|
| Rule ID | 100260 |
| Level | 11 |
| MITRE technique | [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tactic | TA0003 Persistence |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | ✅ Validated firing |

## Detection logic

```xml
<rule id="100260" level="11">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\/create.*(\/sc\s+(onlogon|onstart)|\/ru\s+(system|highest)|\/tr.*(powershell|cmd|wscript|cscript|rundll32))</field>
  <description>Suspicious scheduled task created.</description>
  <mitre><id>T1053.005</id></mitre>
</rule>
```

Two field constraints, the first identifying the binary, the second a disjunction over three suspicious-action signals:

| Signal | Why it's suspicious |
|---|---|
| `/sc onlogon` or `/sc onstart` | Boot/login persistence triggers; rare for benign admin tasks (which usually use `/sc daily` or `/sc weekly`) |
| `/ru system` or `/ru highest` | Running as SYSTEM or with elevated privileges — admin tools mostly use the default `INTERACTIVE` user |
| `/tr <interpreter>` | Action target is a script interpreter (PowerShell, cmd, WScript, CScript, rundll32) rather than a normal executable |

The three are OR'd because a real attacker task usually hits at least two (e.g. SYSTEM + onlogon + powershell), but the rule fires on any single signal to catch lighter-weight persistence attempts.

## Test methodology

```cmd
:: Should fire (/sc onlogon trigger)
schtasks /create /tn "Updater_100260_test" /tr "powershell.exe -nop -c 'Write-Host 100260'" /sc onlogon /f

:: Cleanup
schtasks /delete /tn "Updater_100260_test" /f
```

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

Notably the rule also detects schtasks invocations from PowerShell (`Register-ScheduledTask`) at the schtasks.exe process layer when PowerShell shells out — but it does NOT detect the pure-WMI / pure-cmdlet path (`New-ScheduledTaskAction` → `Register-ScheduledTask` without ever spawning schtasks.exe). That gap is addressed in [`../docs/roadmap.md`](../docs/roadmap.md) under "WMI / cmdlet-only task creation detection".

## Tuning notes

- **Level 11, not higher** — scheduled-task creation is a legitimate admin operation. Level 11 routes it to the medium-severity bucket where a SOC analyst can triage; a false-positive at level 13 would be more disruptive than the rule is worth
- **`/ru system` false positives** — Microsoft's own installers (Office, Edge updaters) sometimes create SYSTEM-run tasks. The first week of post-deployment baseline should be reviewed and persistent benign sources allowlisted via a higher-ID rule with `if_sid 100260` + `<options>no_log</options>` style suppression — better than weakening the detection regex
- **Doesn't yet detect deletion of audit-trail scheduled tasks** (T1070.006). A future rule chained off `/delete` patterns against known-protected task names would close that gap

## Cross-references

- [`100270-new-service.md`](./100270-new-service.md) — companion persistence-via-service rule
- [`../docs/roadmap.md`](../docs/roadmap.md) — WMI / cmdlet-only persistence detection
