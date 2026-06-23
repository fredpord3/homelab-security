# UniFi UDR7 syslog — raw samples and field mapping

UniFi Dream Router 7 ships syslog in CEF (Common Event Format). Wazuh's stock decoders do not parse it because CEF is a *meta-format* — devices use it but the field semantics differ per vendor — and Ubiquiti is not in Wazuh's shipped vendor list. This document captures real sample events from `/var/ossec/logs/archives/archives.log` on the manager and the mapping to Wazuh's canonical field names.

## Pre-decoding fingerprint

| Field | Value |
|---|---|
| `program_name` | `CEF` |
| `hostname` | `Dream-Router-7-FP` |
| Transport | UDP/514 |
| Source IP | `192.168.20.1` (UDR7's Lab-VLAN interface, NOT its primary 192.168.0.1) |

The source-IP gotcha is documented at length in [`../platform/ufw-rules.txt`](../platform/ufw-rules.txt) — the original UFW rule allowed the gateway's primary IP and silently dropped all syslog. The packets are sourced from the UDR7's interface IP for the *destination's* VLAN.

## Sample events

### Firewall block — typical port-scan candidate

```
CEF:0|Ubiquiti|UniFi|7.x|FW_BLOCK|Firewall Block|5|src=192.168.30.55 spt=51234 dst=192.168.20.20 dpt=22 proto=TCP act=block in=eth1 out=eth2
```

Decoded:

| Wazuh field | Value |
|---|---|
| `decoder.name` | `unifi-fw` |
| `srcip` | `192.168.30.55` |
| `srcport` | `51234` |
| `dstip` | `192.168.20.20` |
| `dstport` | `22` |
| `protocol` | `TCP` |
| `action` | `block` |

### Firewall allow — context noise, suppressed via rule level

```
CEF:0|Ubiquiti|UniFi|7.x|FW_ALLOW|Firewall Allow|3|src=192.168.0.123 spt=58812 dst=8.8.8.8 dpt=53 proto=UDP act=allow
```

Allow events are decoded but not promoted to alert level — they sit in `archives.log` for retrospective analysis only.

### IDS hit (CyberSecure — currently disabled)

CyberSecure is intentionally not enabled (see [`../network/unifi-config-notes.md`](../network/unifi-config-notes.md) — Wazuh provides superior detection coverage). If re-enabled, the format would be:

```
CEF:0|Ubiquiti|UniFi|7.x|IDS_HIT|Suricata Alert|7|src=... dst=... sig=ET POLICY ... cat=...
```

The current decoder ignores these — the `signature_id` extraction stops at `IDS_HIT` without mapping `sig` / `cat` fields to anything actionable.

## Field-mapping notes

| CEF key | Wazuh canonical | Why |
|---|---|---|
| `src` | `srcip` | Matches stock rule expectations (e.g. stock 92057 uses `srcip`) |
| `dst` | `dstip` | Same |
| `spt` | `srcport` | Same |
| `dpt` | `dstport` | Same; required for rule 100200's `<different_dstport />` correlation |
| `proto` | `protocol` | Same |
| `act` | `action` | Same |
| `in` / `out` | (not mapped) | UDR7 reports physical interface names which carry no semantic value in a VLAN-tagged single-trunk topology — interface filtering happens at the gateway already |
| `cs1-cs6` | (not mapped) | UDR7 doesn't currently populate the CEF custom-string slots |

## Gaps and known limitations

1. **No structured `signature_id` for IDS events** — only firewall verdicts (allow/block) are parsed. If CyberSecure is enabled in the future, the decoder needs an extension
2. **No country / GeoIP enrichment** — the UDR7 doesn't ship country codes in its CEF output. GeoIP enrichment would need to happen at the Wazuh manager via the GeoIP integration (not currently configured)
3. **Severity field underused** — UDR7 ships CEF `Severity 1-10`; the decoder extracts it but no rules currently key on it. Could be used for risk-based alert tuning
4. **No interface-to-VLAN mapping** — `in=eth1 out=eth2` is opaque to anyone not looking at the UDR7 config. A lookup table mapping iface→VLAN would make alerts more readable but requires updating whenever the UDR7's interface naming changes

## How to capture more samples

Live capture from the manager (useful for decoder development):

```bash
# Watch raw archives as they arrive
sudo tail -f /var/ossec/logs/archives/archives.log | grep "Dream-Router-7-FP"

# Or capture inbound syslog packets before Wazuh sees them
sudo tcpdump -i any -n -A -s 0 'udp port 514 and host 192.168.20.1'
```

Generate test traffic from any VLAN-30 host (e.g. PS5) by attempting to reach a closed port on a VLAN-20 host — the UDR7 will log the block, which lands in `archives.log` within a couple of seconds.

## Decoder source

[`./decoders/unifi-fw.xml`](./decoders/unifi-fw.xml).

To validate a sample against the decoder:

```bash
sudo /var/ossec/bin/wazuh-logtest
# Then paste a raw log line (without the timestamp/hostname prefix)
```
