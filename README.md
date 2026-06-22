# homelab-security

Detection engineering lab built on Proxmox + Wazuh + UniFi, segmented by VLAN, mapped to MITRE ATT&CK. Authored 10 custom Wazuh rules tiered on stock detections, validated against simulated attacker behavior, and documented real-world constraints encountered along the way.

## TL;DR

| Component | Detail |
|---|---|
| Hypervisor | Proxmox VE on i7-8700 / 32GB DDR4 |
| SIEM | Wazuh 4.14.5 (manager + indexer + dashboard) on Ubuntu Server, dual-homed (ethernet primary 192.168.20.20, WiFi fallback via netplan route metrics 100/600) |
| Network | UniFi Dream Router 7 + USW Lite 8 PoE, 3 VLANs (Lab/IoT/Range) |
| Telemetry | Sysmon (SwiftOnSecurity config) on Windows; auditd + journald on Linux; UniFi syslog for firewall |
| Detection coverage | 6 MITRE tactics across 10 custom rules |
| Hardening | SSH key-only on port 2222, fail2ban, TOTP MFA, agent-side encryption |

## Architecture

```
                       Internet
                          │
                  ┌───────┴───────┐
                  │  UniFi UDR7   │  syslog ─────┐
                  └───────┬───────┘              │
                          │                      │
                  ┌───────┴───────┐              │
                  │ USW Lite 8 PoE│              │
                  └───────┬───────┘              │
        ┌─────────────────┼─────────────────┐    │
   VLAN 20            VLAN 30           VLAN 40  │
   (Lab)              (IoT)             (Range)  │
        │                 │                 │    │
        ├── Proxmox host  ├── IoT devices   ├── (planned)   │
        │   └── Wazuh VM ─┼─────────────────┼────► port 514─┘
        │                 │                 │
        └── Freddy-PC (Win11) ──► port 1514 ──► Wazuh agent
```

VLAN segmentation isolates the detonation range (40) from the analyst workstation (20) and IoT trust boundary (30). Syslog from the UDR7 lands on the Wazuh manager via UDP/514; endpoint agents enroll via TCP/1514 with shared-key authentication.

See `network/` for VLAN design + topology diagram.

## Repo navigation

| Folder | Contents |
|---|---|
| `hardware/` | Physical equipment specs, cabling, power |
| `network/` | VLAN architecture, firewall rules, topology diagram |
| `platform/` | Proxmox host setup, Wazuh manager + agents, hardening |
| `detections/` | 10 custom Wazuh rules with MITRE mapping, per-rule writeups, screenshots, live `local_rules.xml` |
| `decoders/` | Custom UniFi firewall decoder + log samples |
| `configs/` | Sysmon config, Wazuh agent config, UFW rules |
| `docs/findings.md` | Lessons learned: real-world constraints that shaped the rules |

## Status

| Layer | State |
|---|---|
| Network segmentation | ✅ Production |
| Wazuh manager + indexer + dashboard | ✅ Production |
| Endpoint agents (Win11, Ubuntu, Proxmox) | ✅ Enrolled, active |
| Sysmon telemetry pipeline | ✅ Validated end-to-end (897+ events from Freddy-PC) |
| Stock Wazuh detections | ✅ Validated (5710, 5712, 5503, 5551, 92057, 92900 confirmed firing) |
| Custom rules deployed | ✅ 10 rules in `local_rules.xml` |
| Custom rules validated firing | 🟡 In progress (validation methodology documented per rule) |
| UniFi firewall decoder | 🟡 Partial (UDR7 CEF log format requires further field extraction) |
| Range VLAN detonation VM | ⏳ Planned (required to validate ASR-blocked techniques) |

## Skills demonstrated

- **Detection engineering**: Authored Sigma-style detections in Wazuh's rule schema, tiered custom rules on stock parent rules (`if_sid`, `if_matched_sid`, `if_matched_group`) to reduce alert fatigue
- **MITRE ATT&CK mapping**: 6 tactics covered (Discovery, Execution, Defense Evasion, Credential Access, Persistence, Ingress Tool Transfer)
- **Network architecture**: VLAN segmentation, syslog routing, agent enrollment with cert-pinned channels, dual-homed SIEM with route metrics
- **Linux hardening**: SSH key-only auth on non-standard port, fail2ban, TOTP MFA, FIM on critical paths, kernel-level mitigations
- **SIEM troubleshooting**: Diagnosed ruleset load failures via `wazuh-logtest`, identified silent warnings not surfaced in `ossec.log`, traced custom rule non-firing to invalid options blocking entire file parse

## Findings highlighted in `docs/findings.md`

- Microsoft Defender ASR preempts execution of LOLBins and PowerShell download cradles on hardened endpoints, making certain rules untestable without a dedicated detonation VM
- Wazuh's `(7612)` duplicate rule warning surfaces only via `wazuh-logtest`, not in `ossec.log`'s error/critical streams — a non-obvious diagnostic path
- A single invalid rule option (e.g. `different_destination_port`) causes the *entire* `local_rules.xml` to fail to load rather than skipping the bad rule — silently disabling every custom detection
- UniFi UDR7 syslog uses CEF format with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`; stock decoders do not match and custom decoder is required
- Lynis baseline audits: Proxmox 65/100, Wazuh 62/100; rkhunter clean on both; FIM configured on `/etc/ssh`, `/etc/passwd`, `/etc/shadow` to catch tampering with credential and access-control surfaces
