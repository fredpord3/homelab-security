# Detections

10 custom Wazuh rules tiered on stock detections, mapped to MITRE ATT&CK, and validated against simulated attacker behavior where the test environment permits it. Rules live in [`local_rules.xml`](./local_rules.xml); each rule has a dedicated writeup linked below covering the detection logic, parent rule, validation methodology, and known constraints.

## Rule index

| ID | Name | Tactic | Technique | Status | Writeup |
|---|---|---|---|---|---|
| 100200 | Internal port scan | Discovery | T1046 | 🟡 Logic deployed, awaiting Range VLAN | [100200-port-scan.md](./100200-port-scan.md) |
| 100210 | Encoded PowerShell | Execution / Defense Evasion | T1059.001, T1027 | ✅ Validated firing | [100210-ps-encoded.md](./100210-ps-encoded.md) |
| 100220 | Defender tampering | Defense Evasion | T1562.001 | 🟡 Blocked by Defender ASR on Freddy-PC | [100220-defender-tampering.md](./100220-defender-tampering.md) |
| 100230 | LSASS process access | Credential Access | T1003.001 | 🟡 Blocked by Defender ASR; awaits Range VM | [100230-lsass-access.md](./100230-lsass-access.md) |
| 100240 | Internal SSH brute force | Credential Access / Lateral Movement | T1110.001, T1021.004 | ✅ Validated firing | [100240-ssh-brute-force.md](./100240-ssh-brute-force.md) |
| 100250 | LOLBin abuse | Defense Evasion / Execution | T1218, T1105 | 🟡 Partially validated; ASR-preempted on some binaries | [100250-lolbin-abuse.md](./100250-lolbin-abuse.md) |
| 100260 | Suspicious scheduled task | Persistence | T1053.005 | ✅ Validated firing | [100260-suspicious-schtask.md](./100260-suspicious-schtask.md) |
| 100270 | New Windows service | Persistence | T1543.003 | ✅ Validated firing | [100270-new-service.md](./100270-new-service.md) |
| 100280 | Critical service stop | Defense Evasion / Impact | T1562.001, T1489 | ✅ Validated firing (EventLog test stop) | [100280-service-stop.md](./100280-service-stop.md) |
| 100290 | PowerShell download cradle | Ingress Tool Transfer / Execution | T1105, T1059.001 | 🟡 Blocked by Defender ASR; awaits Range VM | [100290-ps-download-cradle.md](./100290-ps-download-cradle.md) |

## MITRE ATT&CK coverage

```
TA0007 Discovery               ████░░░░░░  100200
TA0002 Execution               ██████████  100210, 100250, 100290
TA0005 Defense Evasion         ██████████  100210, 100220, 100250, 100280
TA0006 Credential Access       ████████░░  100230, 100240
TA0003 Persistence             ██████████  100260, 100270
TA0011 Command & Control       ████░░░░░░  100290
TA0040 Impact                  ████░░░░░░  100280
TA0008 Lateral Movement (adj)  ████░░░░░░  100240
```

## Telemetry sources

| Source | Channel / log | Parent rule examples |
|---|---|---|
| Sysmon (SwiftOnSecurity config) | `Microsoft-Windows-Sysmon/Operational` EventID 1 / 10 / 13 | 92052 (proc create), 92065 (proc access), 92053 (registry set) |
| Windows Security Channel | `Security` (Event 7045, 4688) | 60103 (SCM), 92900 (service stopped) |
| auditd / journald | `/var/log/auth.log`, journald | 5710 (sshd fail), 5712 (sshd brute force), 5503 (PAM fail), 5551 (insecure connection) |
| UDR7 firewall | UDP/514 syslog → custom CEF decoder | 92057 (UDR7 firewall block, via `decoders/unifi-fw.xml`) |

Sysmon config: [`sysmon-swift-base.xml`](./sysmon-swift-base.xml) (SwiftOnSecurity baseline, unmodified — modifications would risk diverging from a vetted reference).

## Custom decoder

UniFi UDR7 emits CEF format with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`; Wazuh's stock decoders do not parse it. Custom decoder in [`decoders/unifi-fw.xml`](./decoders/unifi-fw.xml). Raw event samples and field-mapping notes in [`unifi-fw-samples.md`](./unifi-fw-samples.md).

## Validation methodology

For each rule the writeup documents:

1. **Trigger condition** — exact field match + parent rule
2. **Test command / scenario** — the minimal action that should fire the rule
3. **Observed outcome** — what showed up in `alerts.json` (or did not)
4. **Constraints** — Defender ASR, missing telemetry, etc.

Validation tools:

```bash
# Replay a sample event through the ruleset
sudo /var/ossec/bin/wazuh-logtest

# Confirm a rule loaded
sudo grep -E "Rule '?100[0-9]{3}'? " /var/ossec/logs/ossec.log

# Watch alerts in real time
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '.rule.id, .rule.description'
```

**Hard-won diagnostic note**: `wazuh-logtest` surfaces parse warnings (e.g. the `(7612)` duplicate-rule warning, or unknown rule options) that `ossec.log` does NOT print at error/critical level. If a custom rule appears not to fire, run `wazuh-logtest` first and inspect the *startup* output before testing any sample event. See [`../docs/findings.md`](../docs/findings.md) for the war story.

## Tiering philosophy

All 10 rules are tiered on stock parents via `if_sid` / `if_matched_sid` / `if_matched_group` rather than authored as standalone matches. Reasons:

- **Reduces alert fatigue** — the parent rule already handles channel-format normalization and base filtering; the custom rule fires only when the parent matches *and* the field-level signal is present
- **Inherits stock decoder logic** — fewer field-extraction bugs to chase
- **Survives Wazuh upgrades better** — stock rule IDs are stable across the 4.x series; custom rules built on top inherit any decoder improvements upstream

## Screenshots

`screenshots/` holds dashboard captures of firing rules, used as evidence of end-to-end validation. Each file is named after the rule ID it documents (e.g. `100210-firing.png`).

## Layout

```
detections/
├── README.md                       (this file)
├── local_rules.xml                 (the 10 custom rules)
├── sysmon-swift-base.xml           (SwiftOnSecurity Sysmon config, unmodified)
├── unifi-fw-samples.md             (raw CEF samples + field mapping)
├── decoders/
│   └── unifi-fw.xml                (custom CEF decoder for UDR7 syslog)
├── screenshots/
│   └── base/                       (firing-rule dashboard captures)
└── 1002??-*.md                     (per-rule writeups)
```
