# Proxmox host

Hypervisor for the lab's VMs. Hardened Debian base with non-root admin user, key-only SSH on a non-standard port, fail2ban, TOTP MFA on the web UI, and Wazuh agent enrolled for telemetry.

## Specs

See [`../hardware/README.md`](../hardware/README.md) for hardware. Software stack:

| Component | Version |
|---|---|
| proxmox-ve | 9.2.0 |
| pve-manager | 9.2.2 (build `b9984c6d90a4bd80`) |
| Running kernel | 7.0.2-6-pve |

## Network

| Field | Value |
|---|---|
| Hostname | `pve` |
| Static IP | 192.168.20.10/24 |
| Gateway | 192.168.20.1 |
| VLAN | 20 (Lab) |
| Interface config | `/etc/network/interfaces` (Proxmox does not use DHCP by default) |
| Web UI | `https://192.168.20.10:8006` |

See [`../network/README.md`](../network/README.md) for VLAN architecture.

## VMs

| VMID | Name | RAM | Bootdisk | Status | Purpose |
|---|---|---|---|---|---|
| 100 | windows11 | 16 GB | 55 GB | stopped | Range VLAN 40 detonation host (planned: Defender disabled, Sysmon enrolled to Wazuh) |

VM expansion in progress — Kali attacker + Linux victim VMs planned for the detonation environment. See [`../docs/roadmap.md`](../docs/roadmap.md).

## Hardening

### SSH

| Setting | Value |
|---|---|
| Port | 2222 (non-standard, matches Wazuh box) |
| Root login | Disabled |
| Password auth | Disabled (key-only) |
| Allowed users | Non-root admin user + key |
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` |

### Admin users

- **Primary admin**: non-root user with sudo (added to `sudo` group; sudo binary installed manually since Proxmox's minimal Debian base omits it by default)
- **Backup admin**: separate local PAM user, Super Admin role in the Proxmox web UI, retained for break-glass access in case the primary account is compromised or locked out

### MFA

- **Web UI**: TOTP enabled on Datacenter → Permissions → Users for both admin accounts. Secrets stored in Proton Pass.
- **SSH**: No TOTP; key-only auth is the second factor.

### fail2ban

- 1 active jail: `sshd`
- Watches `/var/log/auth.log` for repeated failed auth attempts; bans by IP after threshold
- Confirmed via `fail2ban-client status`

### File Integrity Monitoring (via Wazuh agent)

Monitored paths (configured on the Wazuh manager, agent reports changes):

- `/etc`
- `/usr/bin`, `/usr/sbin`
- `/bin`, `/sbin`
- `/boot`

Covers credential surfaces (`/etc/passwd`, `/etc/shadow`, `/etc/ssh`), all binary directories, and the boot partition.

### Audit baselines

| Tool | Result |
|---|---|
| Lynis (`audit system`) | **65/100** (baseline; not re-run since initial hardening) |
| rkhunter | 0 rootkits, 0 suspect files |
| chkrootkit | (not run) |

### Web UI hardening

- No public internet exposure (firewall blocks WAN access)
- Self-signed TLS cert (Let's Encrypt + DNS-01 challenge planned — see [`../docs/roadmap.md`](../docs/roadmap.md))

## Wazuh agent

Enrolled as agent ID `001`, name `pve`. Reports to `192.168.20.20` (manager) on TCP/1514. See [`./wazuh-agents.md`](./wazuh-agents.md) for enrollment process and what's monitored.

## Notes

- Proxmox's minimal Debian base does not install `sudo` by default. Either install it (`apt install sudo`) or work as root — this lab installs sudo and creates a non-root admin user with sudo privileges.
- The Wazuh manager itself is **not** a Proxmox VM — it runs on a dedicated HP Envy laptop. This is intentional: keeping the SIEM out of the hypervisor's blast radius means a Proxmox compromise doesn't take out the monitoring plane.
