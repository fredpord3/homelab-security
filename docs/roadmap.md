# Roadmap

What's next. Ordered roughly by impact-to-effort.

---

## Near-term (unblocks current 🟡 status items)

### Range VLAN detonation environment

**Goal:** unblock validation of rules 100230 (LSASS), 100250 (LOLBin — mshta/regsvr32 paths), and 100290 (PS download cradle), all of which are preempted by Defender ASR on Freddy-PC.

**Components:**

- Provision VLAN 40 on the UDR7 (subnet, DHCP, network isolation: on)
- Deploy Windows 10/11 eval VM on Proxmox (VMID 100 reserved)
  - Defender disabled, Tamper Protection off, ASR rules cleared
  - Sysmon installed with SwiftOnSecurity config
  - Wazuh agent enrolled, reporting to 192.168.20.20
- Deploy Kali attacker VM
  - SSH key from Freddy-PC for orchestrated tests
  - Wazuh agent enrolled (the attacker VM is itself instrumented — its own activity should fire detections)
- Deploy Linux victim VM (Ubuntu 24.04 minimal)
  - auditd configured with the laurel-style ruleset for execve/connect/setuid coverage
  - Wazuh agent enrolled

**Firewall posture:** Range → other VLANs: default deny. Allow only what's needed for command-and-control simulation traffic.

**Acceptance criteria:**

- `procdump -ma lsass.exe lsass.dmp` succeeds on the Range Windows VM and fires rule 100230 at level 14
- `mshta http://...` and `regsvr32 /i:http://...scrobj.dll` complete on the Range Windows VM and fire rule 100250
- A full IEX download cradle completes and fires both 100210 (encoded payload variant) and 100290 (cradle pattern)

### Stale agent cleanup

Remove disconnected agent ID 002 (`windows-pc`) from the manager. Was retained to demonstrate the disconnected-agent UI state; that demonstration has served its purpose.

```bash
sudo /var/ossec/bin/manage_agents -r 002
sudo systemctl restart wazuh-manager
```

---

## Detection coverage gaps

### PowerShell 4104 script-block logging

The current Wazuh Windows agent config ingests `Microsoft-Windows-Sysmon/Operational` but not `Microsoft-Windows-PowerShell/Operational`. EventID 4104 (script-block logging) captures the *decoded* contents of PowerShell scripts after AMSI sees them, which would dramatically improve rule 100290's signal: instead of pattern-matching the command line shape, the rule could match on the actual code being run.

**Action:**

```xml
<!-- Add to wazuh-agent-windows.conf -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then enable script-block logging via GPO or registry:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
```

Author a companion rule (proposed ID 100291) that matches against 4104's script-block-text field.

### Persistence via PowerShell cmdlet (not sc.exe)

Rule 100270 only catches service creation via `sc.exe`. The PowerShell path (`New-Service -Name X -BinaryPathName Y`) doesn't spawn sc.exe and so doesn't match. Need a companion rule chained off Security channel Event 7045 ("a service was installed in the system") which fires regardless of the creation path.

Stock Wazuh rule for 7045 exists in the 60100+ range — would need to confirm the exact ID and tier on it.

### WMI / scheduled-task cmdlet persistence (not schtasks.exe)

Same gap as above: rule 100260 catches `schtasks.exe /create` but not the `Register-ScheduledTask` cmdlet path or pure-WMI task creation. Companion rule needed against either:

- Microsoft-Windows-TaskScheduler/Operational EventID 106 (task registered)
- Sysmon EventID 1 against `powershell.exe` with `Register-ScheduledTask` in the command line

### Service configuration tampering (not just start/stop)

Rule 100280 detects services *stopped*; an attacker can `sc config WinDefend start= disabled` to neutralize them without stopping the live process (it dies on next reboot). Companion rule: Sysmon EventID 1 with `sc.exe config <watchlist> start= disabled` in the command line.

### Linux EDR-equivalent coverage

The lab's Linux endpoints (Proxmox host, Wazuh manager itself) currently rely on stock Wazuh auditd parsing. There are no custom rules on the Linux side that match the detection density of the Windows side. Specifically missing:

- **Privilege escalation chains** — setuid/setgid execve sequences
- **Container escape candidates** — write to `/sys/fs/cgroup/`, capability changes
- **Reverse-shell command-line patterns** — `bash -i >& /dev/tcp/...` and variants
- **Persistence** — cron, systemd unit creation, `.bashrc` / authorized_keys modification (the last partly covered by FIM)

Could be a productive next chunk of work once the Range VLAN gives somewhere safe to detonate.

---

## Infrastructure hardening

### Let's Encrypt + DNS-01 for Proxmox and Wazuh dashboard

Both currently use self-signed certs. DNS-01 challenge avoids the WAN-exposure that HTTP-01 requires. Cloudflare or Porkbun's DNS API works with acme.sh / certbot's DNS plugin.

### Management VLAN

Currently Proxmox admin (192.168.20.10:8006) and Wazuh dashboard (192.168.20.20:443) are on the Lab VLAN with no separation. A dedicated management VLAN with its own SSID (or wired-only access from a specific port) would mean a compromise of a lab VM cannot trivially pivot to the admin planes.

### WireGuard endpoint for remote access

Blocked by upstream Verizon Fios double-NAT. Requires either:

1. A port-forward on the Fios router (and accepting the increased attack surface), OR
2. Bridge mode on the Fios router (preferred but loses some Fios features)

Once unblocked, WireGuard server on the UDR7 with peers locked to Trusted VLAN only.

### Indexer backup

Currently the Wazuh indexer's data is not backed up — only `/var/ossec/etc/` (config + rules) is in git. At lab scale this is acceptable because alerts can be regenerated by replaying archived events. In a production deployment the indexer would have nightly snapshots to S3 or similar.

---

## Quality-of-life

### Rule unit-test harness

`wazuh-logtest` is interactive. A proper test harness — a directory of `tests/<rule-id>/positive.json` and `negative.json` files, plus a script that pipes each through `wazuh-logtest` and asserts the expected rule.id fires — would make ruleset changes much safer. Possibly with `pytest` driving subprocess calls to `wazuh-logtest`.

### Pre-commit hook for ruleset validation

```bash
# .git/hooks/pre-commit
sudo /var/ossec/bin/wazuh-analysisd -t || exit 1
```

Prevents committing a `local_rules.xml` that fails to parse (the silent-disable failure mode from finding 3).

### Dashboard saved searches per rule ID

For each of the 10 custom rules, a saved discover view in the Wazuh dashboard that's prepopulated to `rule.id: <ID>` over the last 24h. Speeds triage and demonstrates rule firing in screenshots / portfolio.

### Public-portfolio version of this repo

This repo lives under my GitHub account but currently includes (in earlier commits) a couple of internal-network detail points that should be sanitized:

- Specific MAC addresses (cosmetic, not sensitive, but unnecessary)
- The Wazuh dashboard TOTP scheme (the *scheme* is fine to document; the secret is in Proton Pass, not the repo)

A `git filter-branch` or BFG run before any external sharing.

---

## Stretch

### Sigma-rule import pipeline

Wazuh doesn't natively consume Sigma. A pipeline that converts Sigma rules from the [SigmaHQ public ruleset](https://github.com/SigmaHQ/sigma) to Wazuh rule XML would dramatically expand detection coverage. `sigmac` historically targeted other backends; a custom translator would be a substantial but rewarding project.

### Atomic Red Team integration

[Atomic Red Team](https://atomicredteam.io/) provides a YAML library of per-technique tests. Orchestrating them from the Range Kali VM against the Range Windows VM would give automated, repeatable validation of every custom rule against the technique each rule claims to detect.

### MITRE ATT&CK Navigator export

Generate an Navigator JSON file from the rule index in [`../detections/README.md`](../detections/README.md) so coverage is visible at a glance. Once the rule count grows beyond ~20 this becomes more useful than the markdown table.
