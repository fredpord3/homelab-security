# Detections

8 custom Wazuh rules tiered on stock detections, mapped to MITRE ATT&CK. Authored after a stock-coverage evaluation that identified existing Wazuh rules covering some originally-planned techniques — 2 rules from the initial draft were removed as redundant (see [`../docs/findings.md`](../docs/findings.md) finding #10).

Rules live in [`local_rules.xml`](./local_rules.xml). Each rule has a dedicated writeup linked below covering the detection logic, parent rule, validation methodology, and known constraints.

## Rule index

| ID | Name | Tactic | Technique | Status | Writeup |
|---|---|---|---|---|---|
| 100100 | UDR7 firewall block (base, silent) | — | — | 🟡 Deployed | (helper rule, no writeup) |
| 100200 | Internal scan/probe | Discovery | T1046 | 🟡 Deployed, awaiting Range VLAN attacker | [100200-port-scan.md](./100200-port-scan.md) |
| 100210 | Encoded PowerShell | Execution / Defense Evasion | T1059.001, T1027 | 🟡 Deployed, validation in progress | [100210-ps-encoded.md](./100210-ps-encoded.md) |
| 100240 | Internal SSH brute force | Credential Access / Lateral Movement | T1110.001, T1021.004 | 🟡 Deployed, validation in progress | [100240-ssh-brute-force.md](./100240-ssh-brute-force.md) |
| 100250 | LOLBin abuse | Defense Evasion / Execution | T1218, T1105 | 🟡 Deployed; Defender ASR preempts some paths | [100250-lolbin-abuse.md](./100250-lolbin-abuse.md) |
| 100260 | Suspicious scheduled task | Persistence | T1053.005 | 🟡 Deployed, validation in progress | [100260-suspicious-schtask.md](./100260-suspicious-schtask.md) |
| 100270 | New Windows service | Persistence | T1543.003 | 🟡 Deployed, validation in progress | [100270-new-service.md](./100270-new-service.md) |
| 100280 | Critical service stop | Defense Evasion / Impact | T1562.001, T1489 | 🟡 Deployed, validation in progress | [100280-service-stop.md](./100280-service-stop.md) |
| 100290 | PowerShell download cradle | Ingress Tool Transfer / Execution | T1105, T1059.001 | 🟡 Deployed; Defender ASR preempts on hardened endpoints | [100290-ps-download-cradle.md](./100290-ps-download-cradle.md) |

## Stock-coverage notes

The following techniques were originally planned for custom detection but turned out to be already covered by stock Wazuh rules. These detections rely on the stock rules and are NOT duplicated in custom code:

| Technique | Stock coverage |
|---|---|
| Microsoft Defender tampering via PowerShell | Rules 92008–92015 (8 separate detections for different Defender subcomponents being disabled) |
| LSASS process access (basic detection) | Rule 92900 (level 12, lsass.exe target + access mask + legitimate-source exclusion) |
| certutil masquerade / certutil -decode | Rules 92016–92018 |
| LSASS access with high-privilege masks (variant of 92900) | Rule 92920 (level 14, similar pattern for mstsc.exe — related technique) |

Full reasoning in [`../docs/findings.md`](../docs/findings.md) #10.

## MITRE ATT&CK coverage

```
TA0007 Discovery               ████░░░░░░  100200
TA0002 Execution               ██████████  100210, 100250, 100290
TA0005 Defense Evasion         ██████████  100210, 100250, 100280
TA0006 Credential Access       ████░░░░░░  100240
TA0003 Persistence             ██████████  100260, 100270
TA0011 Command & Control       ████░░░░░░  100290
TA0040 Impact                  ████░░░░░░  100280
TA0008 Lateral Movement (adj)  ████░░░░░░  100240
```

## Telemetry sources

| Source | Channel / log | Parent group / rule used |
|---|---|---|
| Sysmon (SwiftOnSecurity config) | `Microsoft-Windows-Sysmon/Operational` EventID 1 | `<if_group>sysmon_event1</if_group>` |
| Windows System channel | `System` (EventID 7036 service-state change, 7045 service installed) | `60002` (System channel base), `61138` (stock 7045 detector) |
| journald / sshd | `/var/log/auth.log` via journald | `5712` (stock sshd brute force) |
| UDR7 firewall | UDP/514 syslog → custom CEF decoder | `100100` (custom base rule on `decoded_as=unifi-fw`) |

Sysmon config: [`sysmon-swift-base.xml`](./sysmon-swift-base.xml) (SwiftOnSecurity baseline, unmodified — modifications would risk diverging from a vetted reference).

## Custom decoder

UniFi UDR7 emits CEF format with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`; Wazuh's stock decoders do not parse it. Custom decoder in [`decoders/unifi-fw.xml`](./decoders/unifi-fw.xml). Raw event samples and field-mapping notes in [`unifi-fw-samples.md`](./unifi-fw-samples.md).

## Validation methodology

For each rule the writeup documents:

1. **Trigger condition** — exact field match + parent rule
2. **Test command / scenario** — the minimal action that should fire the rule
3. **Constraints** — Defender ASR, missing telemetry, etc.

Validation tools:

```bash
# Syntax-test the rules file before restart
sudo /var/ossec/bin/wazuh-analysisd -t

# Replay an event interactively through the live ruleset
sudo /var/ossec/bin/wazuh-logtest

# Confirm a rule loaded
sudo grep -E "100[0-9]{3}" /var/ossec/logs/ossec.log | tail -20

# Watch alerts live
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '.rule.id, .rule.description'
```

**Diagnostic note**: `wazuh-logtest` surfaces parse warnings (e.g. the `(7612)` duplicate-rule warning, or unknown rule options) that `ossec.log` does NOT print at error/critical level. If a custom rule appears not to fire, run `wazuh-logtest` first and inspect the *startup* output before testing any sample event. See [`../docs/findings.md`](../docs/findings.md) #2.

## Tiering philosophy

Rules tier on stock parents via `if_sid` / `if_group` / `if_matched_sid` rather than being written as standalone matches. Reasons:

- **Reduces alert fatigue** — the parent rule handles channel-format normalization and base filtering; the custom rule fires only when the parent matches *and* the field-level signal is present
- **Inherits stock decoder logic** — fewer field-extraction bugs to chase
- **Survives Wazuh upgrades better** — stock group names (`sysmon_event1`, `sysmon_event_10`, etc.) and stock rule IDs are stable across the 4.x series

Choosing `<if_group>` over `<if_sid>` where possible: groups are more stable across Wazuh upstream changes than specific rule IDs, and they don't anchor on a single stock rule that may itself get re-numbered.

## Layout

```
detections/
├── README.md                       (this file)
├── local_rules.xml                 (the 8 detection rules + 1 helper)
├── sysmon-swift-base.xml           (SwiftOnSecurity Sysmon config, unmodified)
├── unifi-fw-samples.md             (raw CEF samples + field mapping)
├── decoders/
│   ├── README.md                   (decoder overview + deployment notes)
│   └── unifi-fw.xml                (custom CEF decoder for UDR7 syslog)
├── screenshots/                    (firing-rule dashboard captures, populated as rules validate)
└── 1002??-*.md                     (per-rule writeups)
```
