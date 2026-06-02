# Cybersecurity Homelab

A personal cybersecurity lab built for hands-on offensive and defensive security practice.

## Infrastructure

- **Hypervisor:** Proxmox VE on ASRock desktop — Lab VLAN 20 (192.168.20.10)
- **SIEM:** Wazuh 4.14.5 on Ubuntu Server (laptop) — Lab VLAN 20 (192.168.20.20)
- **Gateway:** Ubiquiti Dream Router 7 — FP (WPA2/WPA3, segmented VLANs)
- **Switch:** Ubiquiti USW Lite 8 PoE (managed, adopted)


## What's Running

- Proxmox hypervisor
- Wazuh SIEM (manager + indexer + dashboard)
- Kali Linux VM
- Vulnerable target machines for practice
- Wazuh agent on Proxmox and Windows PC
- UniFi syslog ingestion (Dream Router 7 → Wazuh)


## Hardening Completed

### Network — Gateway (Dream Router 7)

- UniFi OS and Network application updated to latest
- Local backup admin created (Super Admin role, local access only — no Ubiquiti cloud dependency)
- MFA enabled on Ubiquiti account
- Device SSH Authentication configured with strong custom credential

### Network — Switch (USW Lite 8 PoE)

- Switch adopted into UniFi controller
- Switch firmware updated to latest
- All unused ports administratively disabled
- DHCP Guarding enabled on all VLANs (trusted DHCP server pinned per network)

### Network — VLAN Segmentation

- **Default / Trusted (192.168.0.0/24):** Main PC
- **Lab VLAN 20 (192.168.20.0/24):** Proxmox (192.168.20.10 static), Wazuh (192.168.20.20)
- **IoT VLAN 30 (192.168.30.0/24):** PS5 — network isolation enabled, internet access only
- Proxmox static IP updated in /etc/network/interfaces, web UI confirmed accessible at https://192.168.20.10:8006
- Devices assigned to correct switch ports (Daily PC port 8, Proxmox port 7, PS5 port 6, Wazuh port 5)

### Proxmox Host

- Root SSH login disabled
- SSH key-only authentication enforced
- SSH moved to non-standard port
- Non-root admin user created (principle of least privilege)
- TOTP 2FA enabled on web UI
- fail2ban installed for brute force protection
- Lynis security audit: 65/100
- rkhunter scan: 0 rootkits detected
- Wazuh agent enrolled and reporting

### Wazuh Server

- Root SSH login disabled
- SSH key-only authentication enforced
- SSH moved to non-standard port
- Non-root admin user
- fail2ban installed
- File Integrity Monitoring configured on /etc/ssh, /etc/passwd, /etc/shadow
- Lynis security audit: 62/100
- rkhunter scan: 0 rootkits, 0 suspect files
- USB-C to Ethernet adapter configured
- Ethernet primary with WiFi fallback
- Static DHCP reservation on lab VLAN

### Network — Monitoring
- UniFi syslog forwarding to Wazuh confirmed working (UDP 514)
- UDR7 WiFi connect/disconnect events visible in Wazuh dashboard
- Custom UniFi syslog decoder configured (local_decoder.xml)
- Custom UniFi syslog rules configured (local_rules.xml, rule IDs 100002-100003)
- Cross-VLAN firewall rule configured (agent ports 1514, 1515, 55000 → 192.168.20.20)

### Windows Workstation
- Wazuh agent installed and enrolled (ID 002)
- Reporting active to Wazuh manager (192.168.20.20)

## In Progress

- Management VLAN (separate from default network)
- Double-NAT resolution — upstream router port-forward for external VPN access
- WireGuard VPN server configuration
- Phone and laptop WiFi SSIDs assigned to correct VLANs
- Custom Wazuh detection rules
- Let's Encrypt cert for Proxmox (YubiKey WebAuthn 2FA)


## Tools Used

Proxmox VE, Wazuh, Kali Linux, Lynis, rkhunter, fail2ban, Ubiquiti UniFi
