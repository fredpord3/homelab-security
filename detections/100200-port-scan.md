# 100200 — Internal port scan

| Field | Value |
|---|---|
| Rule ID | 100200 |
| Level | 10 |
| MITRE technique | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| Tactic | TA0007 Discovery |
| Parent rule | 92057 (UDR7 firewall block, custom decoder) |
| Telemetry | UniFi UDR7 syslog (UDP/514, CEF) |
| Status | 🟡 Logic deployed, full validation pending Range VLAN attacker VM |

## Detection logic

```xml
<rule id="100200" level="10" frequency="20" timeframe="60">
  <if_matched_sid>92057</if_matched_sid>
  <same_source_ip />
  <different_dstport />
  <description>Possible internal port scan: $(srcip) hit 20+ distinct destination ports within 60s.</description>
  <mitre><id>T1046</id></mitre>
  <group>recon,discovery,attack.discovery,</group>
</rule>
```

The rule fires when a **single source IP** generates **20+ distinct destination ports** of firewall-blocked traffic within a **60-second window**. The `<same_source_ip />` + `<different_dstport />` combination is the canonical Wazuh idiom for sweep detection.

## Why correlate on firewall blocks rather than connection attempts

Endpoint Sysmon (EventID 3 network connect) only sees *successful* outbound connections from the agent host. A port-scan tool like `nmap -sS` from a host that is *not* running an agent (e.g. a future Range-VLAN Kali VM) leaves no endpoint trace. The UDR7 sits at the inter-VLAN boundary and logs every blocked attempt — making it the natural sensor for cross-VLAN reconnaissance.

## Test methodology

From a host on a separate VLAN (currently a manual exercise; will be automated from the Range VLAN Kali VM):

```bash
# Stealth SYN sweep across 25 ports against the Wazuh manager
nmap -sS -p 1-25 192.168.20.20

# Look for the alert
sudo tail -f /var/ossec/logs/alerts/json.log | jq 'select(.rule.id=="100200")'
```

## Observed status

- ✅ Parent rule 92057 confirmed firing on UDR7 firewall drops (via `unifi-fw.xml` decoder)
- ✅ Rule loaded successfully (`wazuh-logtest` no warnings, no `(7612)` duplicate)
- 🟡 Full firing chain not yet exercised — Range VLAN attacker host pending (see [`../docs/roadmap.md`](../docs/roadmap.md))

## Tuning notes

- **`frequency=20` is conservative** — modern scanners burst 100+ probes/sec. The threshold is set deliberately low for the lab; in production this would be bracketed with a second rule at 5+ ports in 10s (faint sweep) and the existing 20+ in 60s (loud sweep)
- **No `srcip` allowlist yet** — once the Range VLAN is live, the rule can be tightened to fire only on sources from RFC1918 ranges that are NOT the analyst workstation. Currently any internal scan is a finding
- **Watch for false positives from PVE backup jobs** — Proxmox cluster comms can look like port sweeps from `pve` to itself across loopback; the UDR7 decoder only sees inter-VLAN traffic so this is currently not a concern, but flagged for future awareness

## Cross-references

- Custom decoder: [`./decoders/unifi-fw.xml`](./decoders/unifi-fw.xml)
- UDR7 syslog samples: [`./unifi-fw-samples.md`](./unifi-fw-samples.md)
- VLAN architecture: [`../network/vlans.md`](../network/vlans.md)
