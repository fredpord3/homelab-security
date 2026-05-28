# Cybersecurity Homelab

A personal cybersecurity lab built for hands-on offensive and defensive security practice.

## Infrastructure

- **Hypervisor:** Proxmox VE on bare metal
- **Network:** Ubiquiti Dream Router 7 (WPA2/WPA3)
- **SIEM:** Wazuh 4.14.5 on Ubuntu Server
- **Switch:** Ubiquiti (managed, arriving soon)

## What's Running

- Proxmox VE hypervisor
- Wazuh SIEM (manager + indexer + dashboard)
- Kali Linux VM
- Vulnerable target machines for practice

## Hardening Completed

### Network
- Confirmed zero WAN port forwards
- UPnP disabled
- Firmware updated to latest
- WPA2/WPA3 enforced
- VLAN segmentation in progress (managed switch arriving)

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

## In Progress

- VLAN segmentation (management, lab, personal)
- UniFi syslog forwarding to Wazuh
- Wazuh agent on Windows workstation
- Custom detection rules
- Let's Encrypt cert for Proxmox (YubiKey WebAuthn 2FA)

## Tools Used

Proxmox VE, Wazuh, Kali Linux, Lynis, rkhunter, fail2ban, Ubiquiti UniFi
