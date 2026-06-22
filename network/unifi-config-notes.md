# UniFi configuration notes

UniFi-specific configuration as deployed in this lab. UniFi's UI changes between versions, so paths reflect the version current at the time of writing (UDR7 firmware late 2025 / early 2026 cycle).

## Initial controller hardening

- Created local backup admin with Super Admin role and **Local Access Only** restriction (separate from Ubiquiti SSO account) → Settings → Admins & Users → Add Admin
- Enabled MFA on the Ubiquiti SSO account at account.ui.com
- Enabled SSH access on devices with key-based auth (Settings → System → Device SSH Authentication)
- Confirmed zero WAN port forwards (Settings → Internet)
- UPnP disabled (Settings → Internet → Advanced)
- Firmware updated to latest stable

## VLAN creation

Each VLAN was created under **Settings → Networks → New Virtual Network**. Per-VLAN config:

| Field | Lab (20) | IoT (30) | Range (40, planned) |
|---|---|---|---|
| VLAN ID | 20 | 30 | 40 |
| Host address | 192.168.20.1/24 | 192.168.30.1/24 | TBD |
| Network isolation | Off | **On** | On |
| DHCP mode | DHCP Server | DHCP Server | TBD |
| DHCP Guarding | **On** (trusted: gateway) | **On** (trusted: gateway) | On |
| Multicast DNS | Off | Off | Off |
| IGMP snooping | Off | Off | Off |

## Switch port assignments (USW Lite 8 PoE)

Under **UniFi Network → Devices → Lite 8 PoE → Port Manager**. Set each port's **Native VLAN / Network** to the relevant network. Unused ports are administratively disabled.

| Port | Native network | Device | Notes |
|---|---|---|---|
| 4 | Lab (20) | Wazuh laptop ethernet | DHCP reservation for MAC `6c:6e:07:2d:25:d6` → 192.168.20.20 |
| 5 | IoT (30) | PS5 | — |
| 6 | Lab (20) | Proxmox host | Static IP 192.168.20.10 in Proxmox's `/etc/network/interfaces` (not DHCP) |
| 7 | Trusted (default) | Freddy-PC | — |
| 1, 2, 3, 8 | — | Unused | **Administratively disabled** in Port Manager |

## DHCP reservations

Under **Settings → Networks → [Network] → DHCP → Reservations**.

| Network | MAC | IP | Hostname |
|---|---|---|---|
| Lab (20) | `6c:6e:07:2d:25:d6` | 192.168.20.20 | ffwazuh (Wazuh manager, ethernet) |

## Syslog forwarding to Wazuh

**Path:** Settings → System → Advanced → Activity Logging → **SIEM Server**

| Field | Value |
|---|---|
| Server IP | 192.168.20.20 |
| Protocol | UDP |
| Port | 514 |
| Format | CEF |

Note: the UDR7 sends logs with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`. Wazuh's stock decoders do not parse this format. A custom decoder is required ([`../decoders/unifi-fw.xml`](../decoders/unifi-fw.xml)). Raw event samples live at `/var/ossec/logs/archives/archives.log` on the manager — see [`../decoders/unifi-fw-samples.md`](../decoders/unifi-fw-samples.md).

## Firewall rules

UniFi's firewall lives under **Settings → Security → Traffic & Firewall Rules**.

| Name | Direction | Source | Destination | Ports | Action |
|---|---|---|---|---|---|
| Wazuh agent (Trusted → Lab) | LAN In | Trusted network | 192.168.20.20 | TCP 1514, 1515, 55000 | Allow |
| Wazuh syslog (UDR7 → Lab) | LAN Local | UDR7 | 192.168.20.20 | UDP 514 | Allow |
| IoT isolation | LAN In | IoT (30) | RFC1918 (Lab, Trusted) | Any | Block |

## Wireless

| SSID | Network | Encryption | Notes |
|---|---|---|---|
| `Pord-Fi` | Trusted (default) | WPA2/WPA3 mixed | Primary WiFi; Wazuh laptop's WiFi fallback uses this SSID |

## Built-in IPS/IDS (CyberSecure)

Evaluated and **not enabled** — Wazuh provides superior detection coverage at no additional cost, and stacking two IDS systems doubles tuning effort without clear benefit at lab scale.

## Pending UniFi config

- WireGuard VPN endpoint (blocked by upstream Verizon Fios double-NAT; requires port forward on Fios router first)
- Management VLAN with dedicated UniFi/Proxmox admin SSID
- Explicit inter-VLAN deny rules (currently relying on default-deny semantics + IoT network isolation)
- Wireless SSID dedicated to lab VMs (currently lab is wired-only)
