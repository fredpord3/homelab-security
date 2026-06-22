# Wazuh agents

Three active agents + one stale enrollment. All report to manager `192.168.20.20` on TCP/1514.

## Enrolled agents

| ID | Name | OS | IP | Status | Notes |
|---|---|---|---|---|---|
| 000 | `ffwazuh` (server) | Ubuntu Server 24.04 | 127.0.0.1 | Active/Local | The manager itself; monitors own host |
| 001 | `pve` | Proxmox VE (Debian 12 base) | 192.168.20.10 | Active | See [`./proxmox.md`](./proxmox.md) |
| 002 | `windows-pc` | (Windows, retired) | 192.168.0.249 | Disconnected | **Stale** — earlier enrollment of a Windows host, superseded by `Freddy-PC` (ID 003). Retained to demonstrate disconnected-agent state in the dashboard; can be removed with `sudo /var/ossec/bin/manage_agents -r 002` |
| 003 | `Freddy-PC` | Windows 11 | (any — name-based reg) | Active | Daily-driver workstation with Sysmon + Wazuh agent |

## Enrollment process

Agents enroll via TCP/1515 to the manager's `authd` service. Standard workflow:

1. On the manager, register the agent:
```bash
   sudo /var/ossec/bin/manage_agents
   # Choose 'A' to add, supply hostname and either IP or 'any' for name-based reg
```
2. Export the agent's key:
```bash
   sudo /var/ossec/bin/manage_agents -e <ID>
```
3. On the agent host, import the key and start the service:
```bash
   # Linux:
   sudo /var/ossec/bin/manage_agents -i <key>
   sudo systemctl restart wazuh-agent

   # Windows:
   "C:\Program Files (x86)\ossec-agent\manage_agents.exe"
   Restart-Service WazuhSvc
```

## Agent-side configuration

### Linux agents (`pve`, server-side `ffwazuh`)

Ship default `ossec.conf` with localfile blocks for:

- `/var/log/auth.log` (SSH, sudo, fail2ban)
- `/var/log/syslog`
- `journald`
- `/var/log/dpkg.log`

### Windows agent (`Freddy-PC`)

Augmented `ossec.conf` to ingest Sysmon event channel. Key addition:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Full config: [`./wazuh-agent-windows.conf`](./wazuh-agent-windows.conf).

Sysmon itself runs the **SwiftOnSecurity baseline config** (see [`../detections/sysmon-swift-base.xml`](../detections/sysmon-swift-base.xml)). This is what provides the process-create, registry-set, network-connect, file-create, and remote-thread events that the custom detections in [`../detections/`](../detections/) consume.

## Group assignments

All agents currently sit in the `default` group. No custom groups defined — single-tier lab doesn't warrant the overhead.

## Troubleshooting cheatsheet

| Symptom | Check |
|---|---|
| Agent stuck "Disconnected" in dashboard | `sudo /var/ossec/bin/agent_control -l` on manager, then check agent's `ossec.log` |
| Agent log not appearing | Confirm `<localfile>` block on agent points at the right path/channel |
| New rule not firing | Check `ossec.log` for parse errors, run `sudo /var/ossec/bin/wazuh-logtest` interactively, watch for the `(7612)` duplicate rule warning |
| Manager rejects enrollment | `authd` may be off; check `sudo systemctl status wazuh-authd` and `/var/ossec/etc/authd.pass` |

## Stale agent cleanup (when ready)

```bash
sudo /var/ossec/bin/manage_agents -r 002
sudo systemctl restart wazuh-manager
```
