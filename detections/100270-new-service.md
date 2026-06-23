# 100270 — New Windows service

| Field | Value |
|---|---|
| Rule ID | 100270 |
| Level | 10 |
| MITRE technique | [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| Tactic | TA0003 Persistence |
| Parent rule | 92052 (Sysmon EventID 1 — process create) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | ✅ Validated firing |

## Detection logic

```xml
<rule id="100270" level="10">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\sc\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)sc(\.exe)?\s+(\\\\[^\s]+\s+)?create\s</field>
  <description>New Windows service created via sc.exe.</description>
  <mitre><id>T1543.003</id></mitre>
</rule>
```

Three constraints:

1. **Image is `sc.exe`** — anchored on backslash + filename
2. **Command line starts with `sc[.exe] create`** — the `(\\\\[^\s]+\s+)?` accommodates the remote-target form (`sc \\target create ...`) which is itself a strong lateral-movement signal
3. **Stock 92052 parent** for log-channel normalization

## Companion telemetry: Security 7045

The Windows Security channel also emits **Event 7045 ("A service was installed in the system")** when a new service is created — whether via sc.exe, the SCM API, PowerShell `New-Service`, or third-party installers. The current rule only catches the sc.exe path; rule **100270-companion** (a future addition tracked in [`../docs/roadmap.md`](../docs/roadmap.md)) would chain off the Security channel parent to catch the cmdlet path and API-direct path. For now, 100270 sees the most common attacker path (sc.exe) but not the most stealthy one.

## Test methodology

```cmd
:: Create — should fire 100270
sc create Updater100270 binPath= "cmd.exe /c echo 100270 test" start= demand

:: Cleanup (does NOT fire 100270 — only "create" matches)
sc delete Updater100270
```

## Observed status

✅ Confirmed firing — same test run as 100260.

The single Sysmon EventID 1 from the `sc create` invocation triggered both stock 92052 and custom 100270. Alert recorded in `alerts.json` with the full binPath visible, which is useful for triage — the binPath often reveals the attacker's actual payload location.

## Tuning notes

- **Legitimate noise sources** — Windows installers, MSI packages, and driver installs create services routinely. The level-10 setting and the lack of further constraints (no SYSTEM filter, no path filter) means this rule WILL generate baseline noise from legitimate sources. That's deliberate for the lab — the first week of alerts becomes the allowlist input. In a production environment, layering with binPath-pattern allowlists (signed Microsoft binaries from `System32`, etc.) would be appropriate before promoting to level 12+
- **Remote service creation** — `sc \\target create` is a textbook lateral-movement pattern; the regex captures it. Worth bumping the level for the remote-target variant via a sub-rule, future work
- **PowerShell `New-Service` path is uncovered** — that path doesn't spawn `sc.exe` and so doesn't match. Companion rule needed (see roadmap)

## Cross-references

- [`100260-suspicious-schtask.md`](./100260-suspicious-schtask.md) — companion persistence rule
- [`100280-service-stop.md`](./100280-service-stop.md) — the inverse: detecting service *stops* (often related to defense evasion)
- [`../docs/roadmap.md`](../docs/roadmap.md) — Security 7045 companion rule
