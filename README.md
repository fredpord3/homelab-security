# homelab-security

Detection engineering lab built on Proxmox + Wazuh + UniFi, segmented by VLAN, mapped to MITRE ATT&CK. 8 custom Wazuh rules authored after a stock-coverage analysis that surfaced 2 redundancies (removed) and confirmed 8 genuine gaps. Documented end-to-end with the constraints, lessons, and tradeoffs encountered along the way.

## TL;DR

| Component | Detail |
|---|---|
| Hypervisor | Proxmox VE on i7-8700 / 32GB DDR4 |
| SIEM | Wazuh 4.14.5 (manager + indexer + dashboard) on Ubuntu Server, dual-homed (ethernet primary 192.168.20.20, WiFi fallback via netplan route metrics 100/600) |
| Network | UniFi Dream Router 7 + USW Lite 8 PoE, 4 VLANs (Trusted/Lab/IoT/Range) |
| Telemetry | Sysmon (SwiftOnSecurity config) on Windows; auditd + journald on Linux; UniFi syslog for firewall |
| Detection coverage | 6 MITRE tactics across 8 custom rules + 1 silent helper rule |
| Hardening | SSH key-only on port 2222, fail2ban, TOTP MFA, FIM on credential surfaces |

## Architecture

```
                       Internet
                          │
                  ┌───────┴───────┐
                  │  UniFi UDR7   │ syslog ─────┐
                  └───────┬───────┘             │
                          │                     │
                  ┌───────┴───────┐             │
                  │ USW Lite 8 PoE│             │
                  └───────┬───────┘             │
        ┌─────────────────┼─────────────────┐   │
     VLAN 20           VLAN 30           VLAN 40│
      (Lab)             (IoT)            (Range)│
        │                 │                 │   │
        ├── Proxmox host  ├── IoT devices   ├── Kali (attacker)
        │   └── Wazuh VM ─┼─────────────────┼── Metasploitable (no internet)
        │                 │                 ├── Windows 11 (stopped)
        │                 │                 │
        │                 │                 └── (all via port 514) ─┘
        │
        └── Freddy-PC (Win11) ──► port 1514 ──► Wazuh agent
```

VLAN segmentation isolates the detonation range (40) from the analyst workstation (20) and IoT trust boundary (30). Syslog from the UDR7 lands on the Wazuh manager via UDP/514; endpoint agents enroll via TCP/1514 with shared-key authentication.

See [`network/`](./network/) for VLAN design + topology diagram.

## Repo navigation

| Folder | Contents |
|---|---|
| [`hardware/`](./hardware/) | Physical equipment specs, cabling, power |
| [`network/`](./network/) | VLAN architecture, switch port map, firewall rules, UniFi config notes, topology |
| [`platform/`](./platform/) | Proxmox host, Wazuh manager, agent enrollment, deployable config files (`wazuh-agent-windows.conf`, `ufw-rules.txt`), hardening detail |
| [`detections/`](./detections/) | 8 custom Wazuh rules + 1 helper rule with MITRE mapping, per-rule writeups, `local_rules.xml`, `sysmon-swift-base.xml`, `decoders/` subfolder, screenshots |
| [`docs/`](./docs/) | `findings.md` (lessons learned / war stories), `roadmap.md` (what's next) |

## Status

| Layer | State |
|---|---|
| Network segmentation | ✅ Production |
| Wazuh manager + indexer + dashboard | ✅ Production |
| Endpoint agents (Win11, Ubuntu, Proxmox, Kali) | ✅ Enrolled, active |
| Sysmon telemetry pipeline | ✅ Validated end-to-end |
| Stock Wazuh detections | ✅ Validated firing during baseline (5712, 92xxx-series Sysmon rules) |
| Custom rules deployed | ✅ 8 detection rules + 1 helper in `local_rules.xml`, parse-validated via `wazuh-analysisd -t` |
| Custom rules end-to-end validated firing | 🟡 In progress (per-rule status documented) |
| UniFi firewall decoder | 🟡 Functional for block-action events; additional field extraction in progress |
| Range VLAN deployed | ✅ Active (Kali attacker, Metasploitable victim) |
| Range VLAN Windows detonation VM | 🟡 Stopped (Defender-disabled image build pending) |

## Skills demonstrated

- **Detection engineering with stock-coverage analysis**: Authored Sigma-style detections in Wazuh's rule schema. Evaluated each proposed rule against the installed Wazuh ruleset before deployment; identified 2 of 10 initial proposals as already covered by stock rules (Defender tampering by 92008–92015; LSASS access by 92900) and removed them as redundant. Documented decision rationale in [`docs/findings.md`](./docs/findings.md) #10
- **MITRE ATT&CK mapping**: 6 tactics covered across 8 final rules
- **Wazuh rule tiering**: Used `<if_group>` (sysmon_event1, etc.) where possible — more upgrade-stable than tiering on specific stock rule IDs
- **Custom decoder authoring**: Wrote CEF decoder for UniFi UDR7 firewall syslog with field-aliasing to Wazuh canonical names (srcip, dstport, etc.)
- **Network architecture**: 4-VLAN segmentation, syslog routing across VLANs, dual-homed SIEM with route metrics
- **Linux hardening**: SSH key-only on non-standard port, fail2ban, TOTP MFA on web UIs, FIM on credential surfaces
- **SIEM troubleshooting**: Diagnosed ruleset load failures via `wazuh-logtest`, identified silent (7612) duplicate-rule warnings not surfaced in `ossec.log`, traced custom rule non-firing to invalid options blocking entire file parse

## Findings highlighted in [`docs/findings.md`](./docs/findings.md)

- **Stock-coverage analysis reduced custom ruleset by 20%.** Originally planned 10 rules; evaluation against the installed Wazuh ruleset found 2 were redundant with stock detections. Removed.
- Microsoft Defender ASR preempts execution of LOLBins and PowerShell download cradles on hardened endpoints, making certain rules untestable without a dedicated detonation VM
- Wazuh's `(7612)` duplicate-rule warning surfaces only via `wazuh-logtest`, not in `ossec.log`'s error/critical streams — a non-obvious diagnostic path
- A single invalid rule option causes the entire `local_rules.xml` to fail to load rather than skipping the bad rule — silently disabling every custom detection
- UniFi UDR7 syslog uses CEF format with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`; stock decoders do not match, custom decoder required
- UDR7 sources syslog packets from its destination-VLAN interface IP, not its primary IP — UFW rule on primary IP silently drops all syslog
- `<different_dstport />` is not a supported correlation modifier in Wazuh 4.14.5's stock ruleset (only `<different_url />` is); rule 100200 falls back to volume-only correlation
- Lynis baseline audits: Proxmox 65/100, Wazuh 62/100; rkhunter clean on both; FIM configured on `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot` — covering credential surfaces, all binary directories, and the boot partition

## Author

Frederick Pordum III — Mercyhurst University (B.S. Cybersecurity, B.A. Business Management, May 2025) — targeting SOC analyst and detection engineering roles.
