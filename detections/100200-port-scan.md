# 100200 — Internal scan/probe

| Field | Value |
|---|---|
| Rule ID | 100200 |
| Level | 10 |
| MITRE technique | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| Tactic | TA0007 Discovery |
| Parent rule | 100100 (custom helper rule that fires on every UDR7 firewall block — see `local_rules.xml`) |
| Telemetry | UniFi UDR7 syslog (UDP/514, CEF) via custom decoder |
| Status | 🟡 Deployed, end-to-end validation awaiting Range VLAN attacker host |

## Detection logic

```xml
<rule id="100100" level="0">
  <decoded_as>unifi-fw</decoded_as>
  <field name="action">block</field>
  <description>UDR7 firewall block (base rule, no alert).</description>
</rule>

<rule id="100200" level="10" frequency="20" timeframe="60">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Possible internal scan/probe: 20+ firewall blocks from $(srcip) in 60s.</description>
  <mitre><id>T1046</id></mitre>
</rule>
```

The rule fires when a single source IP generates 20+ firewall-blocked connections within a 60-second window, regardless of which ports were targeted.

## Why volume-only and not per-port correlation

The original draft of this rule used `<different_dstport />` to detect port-diversity sweeps (the classic nmap signature). Verifying against the installed Wazuh 4.14.5 ruleset showed that `<different_dstport />` is not a supported correlation modifier in this version — the only `<different_*>` element shipped in the stock ruleset is `<different_url />`. Switching to volume-only correlation is the trade-off: it catches loud sweeps but also catches non-scan repeat-connection-attempt patterns. False positives are acceptable for a level-10 detection on a small lab network where 20+ blocks from one host in 60s is itself a signal worth triaging.

## Why correlate on firewall blocks rather than connection attempts

Endpoint Sysmon (EventID 3 network connect) only sees successful outbound connections from the agent host. A port-scan tool like `nmap` from a host that is not running an agent (e.g. the Range VLAN Kali VM) leaves no endpoint trace. The UDR7 sits at the inter-VLAN boundary and logs every blocked attempt, making it the natural sensor for cross-VLAN reconnaissance.

## Test methodology

From a host on a separate VLAN (typically the Range VLAN Kali VM):

```bash
# Stealth SYN sweep against the Wazuh manager
nmap -sS -p 1-25 192.168.20.20

# Watch for the alert
sudo tail -f /var/ossec/logs/alerts/json.log | jq 'select(.rule.id=="100200")'
```

## Observed status

Rule deployed and parse-validated via `wazuh-analysisd -t`. End-to-end firing validation requires generating 20+ blocks against the UDR7 from a single source within 60s — exercised manually from the Range VLAN; full automated test coverage tracked in [`../docs/roadmap.md`](../docs/roadmap.md).

## Tuning notes

- **`frequency=20` is conservative for modern scanners** — nmap defaults can burst 100+ probes/sec. A future enhancement is layering two rules at different thresholds (5+ in 10s = "faint sweep", 20+ in 60s = "loud sweep")
- **No source allowlist yet** — once the Range VLAN is fully populated, the rule can be tightened to fire only on sources from RFC1918 ranges that are NOT the analyst workstation
- **The 100100 silent base rule is deliberately level 0** — it would fire dozens of times per minute on a typical firewall and is meant only to provide a correlation surface for 100200 (and any future correlation rules), not to alert directly

## Cross-references

- Custom decoder: [`./decoders/unifi-fw.xml`](./decoders/unifi-fw.xml)
- UDR7 syslog samples: [`./unifi-fw-samples.md`](./unifi-fw-samples.md)
- VLAN architecture: [`../network/vlans.md`](../network/vlans.md)
