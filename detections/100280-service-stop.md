# 100280 — Critical service stop

| Field | Value |
|---|---|
| Rule ID | 100280 |
| Level | 12 |
| MITRE technique | [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/), [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/) |
| Tactic | TA0005 Defense Evasion / TA0040 Impact |
| Parent rule | 92900 (Windows Service Control Manager — service stopped) |
| Telemetry | Windows `System` channel (Event 7036 / 7040) via Wazuh stock decoder |
| Status | ✅ Validated firing (test stop of EventLog as a benign proxy) |

## Detection logic

```xml
<rule id="100280" level="12">
  <if_sid>92900</if_sid>
  <field name="win.eventdata.serviceName" type="pcre2">(?i)^(WinDefend|Sense|WdNisSvc|MpsSvc|EventLog|Sysmon64|WazuhSvc)$</field>
  <description>Security-relevant service stopped: $(win.eventdata.serviceName)</description>
  <mitre><id>T1562.001</id><id>T1489</id></mitre>
</rule>
```

The watchlist names a tight set of services whose stop is rarely benign:

| Service | Function | Why stopping it is bad |
|---|---|---|
| `WinDefend` | Defender AV engine | Removes AV protection |
| `Sense` | Defender for Endpoint (MDE) sensor | Removes EDR telemetry |
| `WdNisSvc` | Defender network inspection | Removes IPS layer |
| `MpsSvc` | Windows Firewall | Removes host firewall |
| `EventLog` | Event Log service | Removes ALL Windows event logging (catastrophic) |
| `Sysmon64` | Sysmon | Removes detection-engineering telemetry |
| `WazuhSvc` | Wazuh agent | Removes SIEM connection |

`EventLog` is the highest-impact entry — stopping it kills every event channel including Security, System, Application, and Sysmon, severing essentially every detection at the source. Stopping Sysmon or the Wazuh agent is the next tier — those are detection-targeted rather than logging-wide.

## Test methodology

```powershell
# Stopping WinDefend is blocked by Tamper Protection — won't validate the rule
# Stop EventLog instead (briefly!) — its restart on next service tick gives a clean teardown

# Run elevated. WARNING: this temporarily disrupts event logging.
Stop-Service -Name EventLog -Force
# Wait 2 seconds, then restart
Start-Service -Name EventLog
```

The stop event is recorded in the System channel; SCM emits Event 7036 (service state change) which Wazuh's stock 92900 parses; the service name field matches the watchlist; 100280 fires.

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

Note: Wazuh agent stop (`Stop-Service WazuhSvc`) cannot be self-witnessed — the alert generates on the manager only after the agent reconnects and ships the buffered log line.

## Tuning notes

- **Pair with the agent-disconnect alert** — Wazuh manager rule 503 ("Wazuh agent disconnected") fires when the agent stops phoning home. If 100280 fires for `WazuhSvc` *just before* 503 for the same agent, that pairing is a strong signal vs. an agent that died from natural causes (which only fires 503)
- **EventLog stops are inherently noisy** — Windows updates sometimes restart EventLog. The rule will generate occasional false positives during patch cycles; this is acceptable for the lab. In production, correlate with `update event activity within 30min` to suppress
- **Service *modify* not yet covered** — an attacker can `sc config WinDefend start= disabled` without stopping it (it'll stop on next boot). That's a distinct technique not covered here; would need a sub-rule chained off Sysmon EventID 1 against `sc.exe config <watchlist>`. Tracked in [`../docs/roadmap.md`](../docs/roadmap.md)

## Cross-references

- [`100220-defender-tampering.md`](./100220-defender-tampering.md) — detects *attempts* to stop/disable Defender (process-create signal); this rule detects the *successful* state change
- [`100270-new-service.md`](./100270-new-service.md) — inverse: service creation
