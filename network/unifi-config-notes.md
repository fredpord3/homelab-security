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

| Field | Lab (20) | IoT (30) | Range (40) |
|---|---|---|---|
| VLAN ID | 20 | 30 | 40 |
| Host address | 192.168.20.1/24 | 192.168.30.1/24 | 192.168.40.1/24 |
| Network isolation | Off | **On** | **On** |
| DHCP mode | DHCP Server | DHCP Server | DHCP Server |
| DHCP Guarding | **On** (trusted: gateway) | **On** (trusted: gateway) | **On** (trusted: gateway) |
| Multicast DNS | Off | Off | Off |
| IGMP snooping | Off | Off | Off |

## Switch port assignments (USW Lite 8 PoE)

Under **UniFi Network → Devices → Lite 8 PoE → Port Manager**. Set each port's **Native VLAN / Network** to the relevant network. Unused ports are administratively disabled.

| Port | Native network | Device | Notes |
|---|---|---|---|
| 4 | Lab (20) | Wazuh laptop ethernet | DHCP reservation for MAC `6c:6e:07:2d:25:d6` → 192.168.20.20 |
| 5 | IoT (30) | PS5 | — |
| 6 | Lab (20) | Proxmox host | Static IP 192.168.20.10 in Proxmox's `/etc/network/interfaces` (not DHCP). Proxmox carries VLAN 40 as a tagged bridge for Range VMs over this same physical link. |
| 7 | Trusted (default) | Freddy-PC | — |
| 1, 2, 3, 8 | — | Unused | **Administratively disabled** in Port Manager |

Note: Range VMs (Kali, Metasploitable, future Windows 11) don't get dedicated switch ports — they attach to a VLAN-40-tagged bridge on the Proxmox host and reach the rest of the network via the same physical port 6.

## DHCP reservations

Under **Settings → Networks → [Network] → DHCP → Reservations**.

| Network | MAC | IP | Hostname |
|---|---|---|---|
| Lab (20) | `6c:6e:07:2d:25:d6` | 192.168.20.20 | ffwazuh (Wazuh manager, ethernet) |

Range (40) VMs currently use DHCP without reservations — the firewall rules below key on the MAC address of the Metasploitable VM directly, so a changing IP doesn't break the egress block. A future tightening would reserve fixed IPs for Kali / Metasploitable / Windows-11 so rules can use IP-based source matching for readability.

## Syslog forwarding to Wazuh

**Path:** Settings → System → Advanced → Activity Logging → **SIEM Server**

| Field | Value |
|---|---|
| Server IP | 192.168.20.20 |
| Protocol | UDP |
| Port | 514 |
| Format | CEF |

Note: the UDR7 sends logs with `program_name="CEF"` and `hostname="Dream-Router-7-FP"`. Wazuh's stock decoders do not parse this format. A custom decoder is required ([`../detections/decoders/unifi-fw.xml`](../detections/decoders/unifi-fw.xml)). Raw event samples live at `/var/ossec/logs/archives/archives.log` on the manager — see [`../detections/unifi-fw-samples.md`](../detections/unifi-fw-samples.md).

## Firewall rules

UniFi's firewall lives under **Settings → Security → Traffic & Firewall Rules**.

| # | Name | Direction | Source | Destination | Ports | Action |
|---|---|---|---|---|---|---|
| 1 | Wazuh agent (Trusted → Lab) | LAN In | Trusted network | 192.168.20.20 | TCP 1514, 1515, 55000 | Allow |
| 2 | Wazuh syslog (UDR7 → Lab) | LAN Local | UDR7 | 192.168.20.20 | UDP 514 | Allow |
| 3 | IoT isolation | LAN In | IoT (30) | RFC1918 (Lab, Trusted, Range) | Any | Block |
| 4 | Range → Lab (Wazuh agent only) | LAN In | Range (40) | 192.168.20.20 | TCP 1514, 1515 | Allow |
| 5 | Range → other VLANs (block all else) | LAN In | Range (40) | RFC1918 | Any | Block (after rule 4) |
| 6 | Metasploitable internet egress block | WAN Out | MAC `<metasploitable-mac>` | Any | Any | Block |
| 7 | Kali internet egress | WAN Out | Range (40) excluding Metasploitable | Any | Any | Allow |

Rule ordering matters — UniFi evaluates top-to-bottom. The Range → Lab Wazuh allow (rule 4) must precede the Range → RFC1918 block (rule 5), otherwise the agent connection would never get through.

The Metasploitable egress block (rule 6) uses **MAC-based matching** rather than IP, because:

- The VM uses DHCP and its IP could change after a snapshot rollback
- MAC is stable across snapshot revert (the Proxmox VM definition pins it)
- A MAC-based rule survives the VM being re-imaged with a different OS, as long as the same vNIC is reused

If Metasploitable is replaced or rebuilt, refresh the MAC in rule 6. Currently the MAC is recorded in the Proxmox VM definition under VMID 102; check with `qm config 102 | grep net0`.

## Wireless

| SSID | Network | Encryption | Notes |
|---|---|---|---|
| `Pord-Fi` | Trusted (default) | WPA2/WPA3 mixed | Primary WiFi; Wazuh laptop's WiFi fallback uses this SSID |

The Range VLAN has no SSID — Range VMs are Proxmox-bridged only, no wireless attach. This is deliberate: a wireless device joining the Range VLAN would be an entry point for the very techniques the Range is designed to safely contain.

## Built-in IPS/IDS (CyberSecure)

Evaluated and **not enabled** — Wazuh provides superior detection coverage at no additional cost, and stacking two IDS systems doubles tuning effort without clear benefit at lab scale.

## Pending UniFi config

- WireGuard VPN endpoint (blocked by upstream Verizon Fios double-NAT; requires port forward on Fios router first)
- Management VLAN with dedicated UniFi/Proxmox admin SSID
- Explicit inter-VLAN deny rules (currently relying on default-deny semantics + IoT/Range network isolation)
- Wireless SSID dedicated to lab VMs (currently lab is wired-only)
- Promote Range DHCP reservations from DHCP-managed to fixed (improves firewall-rule readability — see DHCP reservations section above)
