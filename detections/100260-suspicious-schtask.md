# 100270 — New Windows service

| Field | Value |
|---|---|
| Rule ID | 100270 |
| Level | 10 |
| MITRE technique | [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| Tactic | TA0003 Persistence |
| Parent rule | 61138 (stock: "New Windows Service Created", fires on Security/System channel EventID 7045) |
| Telemetry | Windows System channel EventID 7045 |
| Status | 🟡 Deployed, validation in progress |

## Detection logic

```xml
<rule id="100270" level="10">
  <if_sid>61138</if_sid>
  <description>New Windows service installed (Security 7045) — triage required.</description>
  <mitre><id>T1543.003</id></mitre>
</rule>
```

## Why tier on 61138 instead of Sysmon EventID 1 against sc.exe

An earlier draft of this rule chained off `sysmon_event1` filtered on `sc.exe`. That missed every other path to service installation:

| Service install path | Sysmon-on-sc.exe rule? | EventID 7045 rule? |
|---|---|---|
| `sc.exe create Foo binPath=...` | ✅ catches | ✅ catches |
| PowerShell `New-Service` | ❌ misses (no sc.exe spawn) | ✅ catches |
| Direct SCM API call from C/C++ malware | ❌ misses | ✅ catches |
| MSI installer creating a service | ❌ misses | ✅ catches |

Security/System channel EventID 7045 fires for ALL service installations regardless of the API used to create them. That makes 61138 the strictly better parent.

## Stock 61138 context

Stock 61138 is level 5 (informational) because Windows installers, drivers, and Microsoft Update routinely install services and the noise floor would be intolerable at higher severity. Promoting to level 10 in 100270 surfaces the events for triage without making them critical-alert noisy. The expected workflow is "review new services daily, allowlist known benign sources" rather than "page on every new service."

## Test methodology

```cmd
:: Create — should fire 100270 via 61138
sc create Updater100270 binPath= "cmd.exe /c echo 100270 test" start= demand

:: Also test PowerShell path (the gap that motivated the rewrite)
:: This SHOULD also fire 100270 now that we tier on 61138
powershell -c "New-Service -Name Updater100270PS -BinaryPathName 'cmd.exe /c echo test'"

:: Cleanup
sc delete Updater100270
sc delete Updater100270PS
```

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

## Tuning notes

- **Heavy baseline noise expected** — Windows installs services routinely. The first week of deployment is a baseline-gathering exercise; persistent benign sources (Microsoft updates, signed installers from `%ProgramFiles%`) get allowlisted in a higher-ID rule with `<options>no_log</options>` to suppress
- **Future enhancement: field filter on imagePath** — Filtering on suspicious imagePath patterns (`\Temp\`, `\AppData\`, script interpreters as the service binary) would let the rule sit at level 12+ without baseline allowlisting. The field name (`win.eventdata.imagePath` vs `win.eventdata.binaryPath` vs another variant) needs verification against a live alert before adding this filter. Tracked in [`../docs/roadmap.md`](../docs/roadmap.md)
- **Remote service creation (`sc \\target create`)** — would still trigger this rule because Windows logs EventID 7045 on the target. Worth tightening with a sub-rule that bumps severity when the service was installed remotely

## Cross-references

- [`100260-suspicious-schtask.md`](./100260-suspicious-schtask.md) — companion persistence rule (scheduled tasks)
- [`100280-service-stop.md`](./100280-service-stop.md) — the inverse: detecting service stops
- [`../docs/roadmap.md`](../docs/roadmap.md) — imagePath field-name verification
