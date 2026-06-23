# Network

VLAN architecture, switch port assignments, firewall rules, UniFi configuration notes, and the topology diagram for the lab.

## Files

| File | Purpose |
|---|---|
| [`vlans.md`](./vlans.md) | Per-VLAN detail: subnet, gateway, devices, inter-VLAN rules |
| [`unifi-config-notes.md`](./unifi-config-notes.md) | UniFi-specific configuration (controller hardening, VLAN creation, port assignments, DHCP reservations, syslog forwarding, firewall rules) |
| [`topology.png`](./topology.png) | Network diagram (rendered) |
| [`topology.excalidraw`](./topology.excalidraw) | Network diagram (Excalidraw source) |

## Network overview

```
                       Internet
                          │
                  ┌───────┴───────┐
                  │  UniFi UDR7   │ syslog ─────┐
                  └───────┬───────┘             │
                          │                     │
                  ┌───────┴───────┐             │
                  │ USW Lite 8 PoE│             │
                  └───────┬───────┘             │
        ┌─────────────────┼─────────────────┐   │
     Trusted           VLAN 20           VLAN 30│   VLAN 40
     (default)          (Lab)            (IoT)  │   (Range, planned)
        │                 │                 │   │       │
        ├── Freddy-PC     ├── Proxmox       ├── PS5     ├── Win VM (planned)
        │   (Win11)       │                 │           ├── Kali VM (planned)
        └── personal      └── Wazuh manager └── (no     └── Linux victim
            devices           (ffwazuh) ────┴──► UDP/514  (planned)
```

## VLANs at a glance

| ID | Name | Subnet | Purpose | Isolation |
|---|---|---|---|---|
| (default) | Trusted | 192.168.0.0/24 | Analyst workstation, personal devices | Egress to Lab on Wazuh ports |
| 20 | Lab | 192.168.20.0/24 | Wazuh SIEM, Proxmox, lab VMs | Egress to internet + DNS |
| 30 | IoT | 192.168.30.0/24 | PS5, future IoT | **Network isolation on** — no inter-VLAN |
| 40 | Range | TBD | Detonation environment (planned) | **Default deny outbound**; manual allowlist for C2 sim |

Full details in [`vlans.md`](./vlans.md).

## Firewall posture

Three-layer defense-in-depth (documented in [`../docs/findings.md`](../docs/findings.md) #5):

1. **UDR7 gateway firewall** — perimeter and inter-VLAN enforcement
2. **UFW** on each Linux host — host-layer enforcement (see [`../platform/ufw-rules.txt`](../platform/ufw-rules.txt))
3. **Wazuh `<allowed-ips>`** in `ossec.conf` — application-layer allowlist for the syslog receiver

All three must permit a source for traffic to flow. When syslog or agent comms break, diagnostic order is gateway → tcpdump → UFW → Wazuh allowlist.

## Switch port assignments (USW Lite 8 PoE)

| Port | Native VLAN | Device |
|---|---|---|
| 1, 2, 3, 8 | — | Administratively disabled |
| 4 | Lab (20) | Wazuh laptop ethernet (DHCP reservation) |
| 5 | IoT (30) | PS5 |
| 6 | Lab (20) | Proxmox host (static IP via `/etc/network/interfaces`) |
| 7 | Trusted | Freddy-PC |

Full UniFi-side config in [`unifi-config-notes.md`](./unifi-config-notes.md).

## Syslog routing

UniFi UDR7 forwards syslog to the Wazuh manager at `192.168.20.20` over UDP/514 in CEF format. The UDR7 sources packets from its Lab-VLAN interface IP `192.168.20.1` — NOT its Trusted-VLAN primary `192.168.0.1`. This caught me out the first time; documented in detail at [`../platform/ufw-rules.txt`](../platform/ufw-rules.txt) and [`../docs/findings.md`](../docs/findings.md) #4.

CEF format does not match Wazuh's stock decoders; custom decoder at [`../detections/decoders/unifi-fw.xml`](../detections/decoders/unifi-fw.xml), with raw samples and field mapping at [`../detections/unifi-fw-samples.md`](../detections/unifi-fw-samples.md).

## Agent enrollment

Wazuh agents enroll over TCP/1515 to the manager's `authd` service, then ship events over TCP/1514 with AES encryption. Per-host enrollment detail in [`../platform/wazuh-agents.md`](../platform/wazuh-agents.md).

| Agent | VLAN | IP |
|---|---|---|
| `ffwazuh` (manager local) | Lab (20) | 127.0.0.1 |
| `pve` (Proxmox host) | Lab (20) | 192.168.20.10 |
| `Freddy-PC` (analyst workstation) | Trusted | (DHCP, name-based registration) |

## Planned

Tracked in [`../docs/roadmap.md`](../docs/roadmap.md): WireGuard remote-access endpoint (blocked by upstream Fios double-NAT), management VLAN with dedicated SSID, Range VLAN with detonation VMs.
