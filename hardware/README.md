# Hardware

## Compute

| Role | Host | CPU | RAM | Storage | GPU | Notes |
|---|---|---|---|---|---|---|
| Hypervisor (Proxmox VE) | Custom build, MSI B360 | Intel i7-8700 (6c/12t) | 32 GB DDR4 | 1 TB Kingston SATA SSD (OS + VM disks), 1 TB WD HDD (bulk) | AMD RX 580 | Cooler Master cooler, NZXT case |
| SIEM (Wazuh manager + indexer + dashboard) | HP Envy laptop | AMD Ryzen 5 5625U | 8 GB | 256 GB SSD | iGPU | Dedicated headless SIEM node, lid-closed-on-AC config. Dual-homed: ethernet primary via Anker USB-C adapter, WiFi (SSID `Pord-Fi`) as fallback |
| Analyst workstation (Freddy-PC) | Custom build, ASRock board | Intel i5-13600K (14c/20t) | 32 GB DDR5 | 1 TB NVMe SSD | NVIDIA RTX 4070 | Daily-driver Win11 with Wazuh agent + Sysmon (SwiftOnSecurity config) |

## Network

| Device | Role | Notes |
|---|---|---|
| UniFi Dream Router 7 (UDR7) | Gateway + controller + WiFi 7 | Hosts VLANs 20/30/40, sends syslog to Wazuh manager on UDP/514 in CEF format (hostname `Dream-Router-7-FP`) |
| UniFi USW Lite 8 PoE | Distribution switch | VLAN-aware, PoE for downstream devices |
| Anker USB-C to 2.5GbE adapter | Wazuh ethernet uplink | ASIX AX88179 chipset, MAC `6c:6e:07:2d:25:d6` |

## Power protection

| Device | Role |
|---|---|
| CyberPower CP1500PFCLCD (×2) | UPS for homelab rack and analyst desk |

## Network diagram

See [`../network/topology.png`](../network/topology.png) (Excalidraw source: `../network/topology.excalidraw`).

## Sizing rationale

- **Proxmox host** chosen for available 8th-gen Intel platform with VT-x/VT-d. 32 GB DDR4 sized to support 3-4 concurrent VMs (Wazuh node, future Windows detonation VM on Range VLAN, future Linux victim VM).
- **Wazuh on dedicated laptop** rather than as a Proxmox VM to isolate the SIEM from compromise of the hypervisor. 8 GB is the minimum tolerated by Wazuh 4.x at low event volume; will be upgraded as EPS scales.
- **Dual-homed Wazuh** with ethernet as primary and WiFi as fallback ensures uninterrupted log collection if the wired path is disrupted. Configured via netplan route metrics (ethernet 100, WiFi 600); see `../platform/wazuh-manager.md` for the config.
- **UniFi over pfSense/OPNsense** for unified syslog/IDS/firewall management and integration with VLAN tagging on a single appliance.
