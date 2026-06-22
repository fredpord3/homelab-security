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

## VLAN 40: Range (planned)

| Field | Value |
|---|---|
| Subnet | TBD |
| Gateway | TBD |
| DHCP range | TBD |
| Purpose | Detonation environment for testing techniques that Defender ASR blocks on hardened endpoints (LSASS access via procdump, LOLBin abuse, PowerShell download cradles) |
| Inbound from other VLANs | Blocked |
| Outbound | Default deny; manual allowlist for command-and-control simulation traffic |
| WiFi SSID | None |

**Planned devices:**
- Windows 10/11 eval VM (Defender disabled, Sysmon installed, Wazuh agent enrolled)
- Linux victim VM (auditd + Wazuh agent)
