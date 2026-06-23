# 100260 — Suspicious scheduled task

| Field | Value |
|---|---|
| Rule ID | 100260 |
| Level | 11 |
| MITRE technique | [T1053.005 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/005/) |
| Tactic | TA0003 Persistence |
| Parent group | `sysmon_event1` (Sysmon EventID 1, process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Deployed, validation in progress |

## Detection logic

```xml
<rule id="100260" level="11">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\/create.*(\/sc\s+(onlogon|onstart)|\/ru\s+(system|highest)|\/tr.*(powershell|cmd|wscript|cscript|rundll32))</field>
  <description>Suspicious scheduled task created.</description>
  <mitre><id>T1053.005</id></mitre>
</rule>
```

Two field constraints — the first identifying the binary, the second a disjunction over three suspicious-action signals:

| Signal | Why suspicious |
|---|---|
| `/sc onlogon` or `/sc onstart` | Boot/login persistence triggers |
| `/ru system` or `/ru highest` | Running as SYSTEM or with elevated privileges |
| `/tr <interpreter>` | Action target is a script interpreter rather than a normal executable |

OR'd together because a real attacker task usually hits two or more, but the rule fires on any one to catch lighter-weight persistence attempts.

## Stock-coverage check

Reviewed `0800-sysmon_id_1.xml`. Stock has rules for various Sysmon EventID 1 patterns but no schtasks.exe-specific detection. Custom rule fills a genuine gap.

## Test methodology

```cmd
:: Should fire (/sc onlogon trigger + powershell as action)
schtasks /create /tn "Updater_100260_test" /tr "powershell.exe -nop -c 'Write-Host 100260'" /sc onlogon /f

:: Cleanup
schtasks /delete /tn "Updater_100260_test" /f
```

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

## Known coverage gaps in this rule

- **PowerShell `Register-ScheduledTask` path is NOT covered** — that cmdlet uses WMI under the hood and may not spawn schtasks.exe, so the rule misses it. Adding coverage for `Microsoft-Windows-TaskScheduler/Operational` EventID 106 would close this gap. Tracked in [`../docs/roadmap.md`](../docs/roadmap.md).
- **Pure-WMI task creation is also missed** — same root cause as above
- **Scheduled task deletion (T1070.006 — covering tracks) is not covered** — a future companion rule against `/delete` patterns would catch audit-trail tampering

## Tuning notes

- **Level 11, not higher** — scheduled-task creation is a legitimate admin operation. Level 11 routes it to the medium-severity bucket for triage; a false positive at level 13 would be more disruptive than the rule is worth
- **`/ru system` false positives expected from Microsoft installers** — Office and Edge updaters occasionally create SYSTEM-run tasks. Baseline review after deployment should produce an allowlist of known benign sources

## Cross-references

- [`100270-new-service.md`](./100270-new-service.md) — companion persistence rule (service-based)
- [`../docs/roadmap.md`](../docs/roadmap.md) — task-scheduler channel ingestion
