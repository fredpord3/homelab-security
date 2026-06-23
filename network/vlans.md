# VLANs

Per-VLAN detail: purpose, subnet, devices, firewall rules.

## VLAN: Trusted (default)

| Field | Value |
|---|---|
| Subnet | 192.168.0.0/24 |
| Gateway | 192.168.0.1 |
| DHCP range | UDR7-managed |
| Purpose | Main household network; analyst workstation (Freddy-PC) |
| Inbound | Allow established/related |
| Outbound to Lab | TCP 1514/1515/55000 to 192.168.20.20 (Wazuh agent enrollment + events) |
| Outbound to IoT | Blocked |
| WiFi SSID | `Pord-Fi` |

**Devices:**

- Freddy-PC (Windows 11, Wazuh agent, Sysmon)
- Personal devices (phone, MacBook)
- Wazuh laptop WiFi fallback interface

## VLAN 20: Lab

| Field | Value |
|---|---|
| Subnet | 192.168.20.0/24 |
| Gateway | 192.168.20.1 |
| DHCP range | UDR7-managed with reservations for SIEM/hypervisor |
| Purpose | Wazuh SIEM, Proxmox host, future lab VMs |
| Inbound from Trusted | TCP 1514/1515/55000 to 192.168.20.20 |
| Inbound from UDR7 | UDP/514 to 192.168.20.20 (syslog) |
| Outbound | Internet + DNS only |
| WiFi SSID | None (wired-only by design) |

**Devices:**

- Wazuh manager (`ffwazuh`, 192.168.20.20, ethernet via Anker USB-C, MAC `6c:6e:07:2d:25:d6`)
- Proxmox host (`pve`, 192.168.20.10, static in `/etc/network/interfaces`)

## VLAN 30: IoT

| Field | Value |
|---|---|
| Subnet | 192.168.30.0/24 |
| Gateway | 192.168.30.1 |
| DHCP range | UDR7-managed |
| Purpose | IoT devices, gaming console; isolated trust boundary |
| Inbound from other VLANs | Blocked |
| Outbound to other VLANs | Blocked (network isolation enabled) |
| Outbound to Internet | Allowed |
| WiFi SSID | None currently |

**Devices:**

- PS5 (port 5 on USW Lite 8 PoE)

## VLAN 40: Range

| Field | Value |
|---|---|
| Subnet | 192.168.40.0/24 |
| Gateway | 192.168.40.1 |
| DHCP range | UDR7-managed |
| Purpose | Detonation environment for testing techniques that Defender ASR blocks on hardened endpoints (LSASS access via procdump, LOLBin abuse, PowerShell download cradles) and for adversary-simulation labs against deliberately-vulnerable targets (Metasploitable) |
| Inbound from other VLANs | Blocked |
| Inbound to Lab from Range | **Allow** TCP 1514/1515 to 192.168.20.20 (Wazuh agent comms from Kali / future Windows VM) — only path out of the Range, and only to the SIEM |
| Outbound to other VLANs | Blocked (no path back to Trusted, Lab, or IoT) |
| Outbound to Internet (per-host) | Kali: **allowed** (tool updates). Metasploitable: **blocked** (deliberately vulnerable, must not phone out). Windows 11 detonation VM (when up): scoped allowlist for C2 simulation traffic only. |
| WiFi SSID | None (Proxmox-bridged, no wireless attach) |

**Devices** (all VMs on Proxmox host `pve`, bridged to the VLAN 40 tag):

- `kali` (192.168.40.x, DHCP) — Kali Linux attacker host. Wazuh agent enrolled; the attacker box is itself instrumented so its own activity feeds detections
- `metasploitable` (192.168.40.x, DHCP) — Metasploitable 2 (Ubuntu 8.04 base). **No internet egress.** No Wazuh agent (the ancient Ubuntu base does not support a modern agent); detection plane is the UDR7 firewall logs watching inbound attacks on this host plus telemetry from Kali's agent
- `windows11` (planned, currently stopped) — Defender disabled, Sysmon installed, Wazuh agent

### Per-host firewall posture inside VLAN 40

| Host | Internet egress | Reachable from Lab | Can reach Lab |
|---|---|---|---|
| `kali` | ✅ Allowed (apt updates, tool installs) | ❌ No | ✅ Yes — TCP 1514/1515 to 192.168.20.20 only (Wazuh) |
| `metasploitable` | ❌ Blocked | ❌ No | ❌ No |
| `windows11` (planned) | 🟡 Scoped allowlist for C2 simulation | ❌ No | ✅ Yes — TCP 1514/1515 to 192.168.20.20 only |

The Metasploitable egress block is enforced at the UDR7's gateway firewall by source-IP rule, not at the VLAN level — the rest of VLAN 40 has different policy. See [`./unifi-config-notes.md`](./unifi-config-notes.md) for the rule list.
