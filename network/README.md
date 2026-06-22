# Network

Layer-2/3 architecture of the homelab: VLAN segmentation, switch port mapping, syslog routing, and firewall posture. Built on UniFi (UDR7 + USW Lite 8 PoE).

## Topology

Diagram pending (`topology.png` — will be added). See ASCII summary in the root [`README.md`](../README.md#architecture) for now.

## Subnet map

| VLAN ID | Name | Subnet | Purpose | Gateway |
|---|---|---|---|---|
| (default) | Trusted | 192.168.0.0/24 | Main household network, analyst workstation | 192.168.0.1 |
| 20 | Lab | 192.168.20.0/24 | Proxmox host, Wazuh SIEM, future lab VMs | 192.168.20.1 |
| 30 | IoT | 192.168.30.0/24 | IoT devices, gaming console, network-isolated | 192.168.30.1 |
| 40 | Range | (planned) | Detonation VMs with Defender disabled, isolated from Lab | (planned) |

See [`vlans.md`](./vlans.md) for per-VLAN device assignments and firewall rules.

## Switch port assignments (USW Lite 8 PoE)

| Port | Device | VLAN (untagged) | Notes |
|---|---|---|---|
| 4 | Wazuh laptop (ethernet primary) | Lab (20) | Anker USB-C 2.5GbE adapter, MAC `6c:6e:07:2d:25:d6`, DHCP reservation to 192.168.20.20 |
| 5 | PS5 | IoT (30) | Network isolation enabled |
| 6 | Proxmox host | Lab (20) | Static IP 192.168.20.10 set in `/etc/network/interfaces` (Proxmox does not use DHCP by default) |
| 7 | Main PC (Freddy-PC) | Trusted (default) | Daily-driver workstation |
| 1–3, 8 | Unused | — | Administratively disabled |

## Syslog forwarding

UDR7 forwards firewall and event logs to Wazuh manager (192.168.20.20) over **UDP/514**. Configured under UniFi Settings → System → Advanced → Activity Logging → SIEM Server.

Format: **CEF** with `program_name="CEF"` and hostname `Dream-Router-7-FP`. Standard Wazuh decoders do not match this format; a custom decoder lives at [`../decoders/unifi-fw.xml`](../decoders/unifi-fw.xml).

## Cross-VLAN firewall rules

Allow agents on Lab/Trusted to reach the Wazuh manager on the Lab VLAN.

| Source | Destination | Ports | Purpose |
|---|---|---|---|
| Trusted (192.168.0.0/24) | 192.168.20.20 | TCP 1514, 1515, 55000 | Wazuh agent enrollment + event forwarding from Freddy-PC |
| Lab (192.168.20.0/24) | 192.168.20.20 | TCP 1514, 1515, 55000 | Local agent (Proxmox) |
| UDR7 | 192.168.20.20 | UDP 514 | Syslog from UniFi gateway |
| IoT (192.168.30.0/24) | * | — | Default deny outbound to other VLANs (isolation) |

## WiFi SSID-to-VLAN

| SSID | VLAN | Purpose |
|---|---|---|
| `Pord-Fi` | Trusted (default) | Primary WiFi for personal devices and Wazuh laptop's fallback interface |

WiFi fallback note: When the Wazuh laptop's ethernet path fails, it switches to `Pord-Fi` on the Trusted VLAN (different subnet). Agents reaching the manager across VLANs must use the manager's hostname rather than a hardcoded subnet-dependent IP — but for this lab's scale, manager-IP-based config is acceptable since agents tolerate brief connection drops.

## DHCP Guarding

Enabled on all VLANs with the UDR7 gateway as the only trusted DHCP server. Prevents rogue DHCP from a compromised lab VM advertising itself as a gateway.

## Hardening posture

- Zero WAN port forwards
- UPnP disabled
- Firmware updated to latest UniFi release
- WPA2/WPA3 enforced on WiFi
- Built-in UniFi CyberSecure IPS/IDS evaluated and skipped in favor of Wazuh (superior coverage + free)
- Upstream Verizon Fios router creates a double-NAT; external VPN reachability blocked at the WAN side (planned: WireGuard VPN through UDR7 with port-forward on Fios)

## Pending

- Range VLAN 40 buildout (subnet + detonation VM)
- WireGuard VPN endpoint on UDR7
- Management VLAN (separate plane for UniFi/Proxmox admin interfaces)
- Inter-VLAN explicit deny rules (currently relying on UniFi default deny semantics)
