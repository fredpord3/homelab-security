# 100280 — Critical service stop

| Field | Value |
|---|---|
| Rule ID | 100280 |
| Level | 12 |
| MITRE technique | [T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/), [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/) |
| Tactic | TA0005 Defense Evasion / TA0040 Impact |
| Parent rule | 60002 (stock: System channel base rule) |
| Telemetry | Windows System channel EventID 7036 (service-state change) |
| Status | 🟡 Deployed, validation in progress |

## Detection logic

```xml
<rule id="100280" level="12">
  <if_sid>60002</if_sid>
  <field name="win.system.eventID">^7036$</field>
  <field name="win.system.message" type="pcre2">(?i)(WinDefend|Sense|WdNisSvc|MpsSvc|EventLog|Sysmon64|WazuhSvc).{0,80}entered the stopped state</field>
  <description>Security-relevant service stopped (EventID 7036).</description>
  <mitre><id>T1562.001</id><id>T1489</id></mitre>
</rule>
```

Three field constraints:

1. **Parent 60002** ensures we're matching System channel events
2. **EventID 7036** is "Service Control Manager — service state change"
3. **Message regex** requires both a watchlist service name AND the literal "entered the stopped state" — 7036 also fires for *start* events with "entered the running state", so the message anchor filters to stops only

## Watchlist

| Service | Function | Why stopping it is bad |
|---|---|---|
| `WinDefend` | Defender AV engine | Removes AV protection |
| `Sense` | Defender for Endpoint (MDE) sensor | Removes EDR telemetry |
| `WdNisSvc` | Defender network inspection | Removes IPS layer |
| `MpsSvc` | Windows Firewall | Removes host firewall |
| `EventLog` | Event Log service | Removes ALL Windows event logging |
| `Sysmon64` | Sysmon | Removes detection-engineering telemetry |
| `WazuhSvc` | Wazuh agent | Removes SIEM connection |

`EventLog` is the highest-impact entry — stopping it kills every event channel, severing essentially every detection at the source.

## Stock-coverage check

Reviewed `0585-win-application_rules.xml` and the System rules. Stock Wazuh covers a few specific service-stop events (Software Protection Service via Application channel, Windows Search Service) but does NOT ship a generic SCM watchlist for EventID 7036. This rule fills a genuine gap.

## Test methodology

```powershell
# Run elevated. Stopping WinDefend is blocked by Tamper Protection on a hardened endpoint;
# EventLog stop is the cleanest test because it briefly disrupts logging (auto-restarts).
Stop-Service -Name EventLog -Force
# Restart immediately
Start-Service -Name EventLog
```

Expected:

1. EventLog stops → SCM emits 7036 with message "The Windows Event Log service entered the stopped state."
2. Wazuh agent (if still running — Windows queues a few events) forwards to manager
3. 60002 matches (System channel) → 100280 matches (eventID 7036 + watchlist + stopped state)
4. Alert lands in `alerts.json` with `rule.id=100280` at level 12

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

Note: Wazuh agent stop (`Stop-Service WazuhSvc`) cannot be self-witnessed in real time — the alert is generated on the manager only after the agent reconnects and ships the buffered log line. This is expected and acceptable.

## Tuning notes

- **Pair with the agent-disconnect alert** — Wazuh manager rule 503 ("Wazuh agent disconnected") fires when an agent stops phoning home. If 100280 fires for `WazuhSvc` immediately before 503 for the same agent, that pairing is a strong signal versus a natural-causes disconnect
- **EventLog stops are inherently somewhat noisy** — Windows Update sometimes restarts EventLog. The rule will generate occasional false positives during patch cycles; acceptable for the lab
- **Service *modify* not yet covered** — an attacker can `sc config WinDefend start= disabled` without stopping the live process (it dies on next reboot). That's a distinct technique not covered here. Companion rule tracked in [`../docs/roadmap.md`](../docs/roadmap.md)
- **Future enhancement: include Defender-internal stop reasons** — Defender records its own state changes in `Microsoft-Windows-Windows Defender/Operational` which is a richer telemetry source than the generic SCM channel. Worth ingesting

## Cross-references

- [`100270-new-service.md`](./100270-new-service.md) — inverse: service creation
- [`../docs/findings.md`](../docs/findings.md) #10 — stock-coverage analysis
- [`../docs/roadmap.md`](../docs/roadmap.md) — service-config tampering coverage
