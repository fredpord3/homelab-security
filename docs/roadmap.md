# Roadmap

What's next. Ordered roughly by impact-to-effort.

---

## Near-term (unblocks current 🟡 status items)

### Range VLAN Windows 11 detonation VM

**Status:** Range VLAN itself is **deployed** (Kali attacker + Metasploitable victim are live on 192.168.40.0/24). The Windows detonation VM (VMID 100) exists on the Proxmox host but is currently stopped — needs to be brought up with the right hardening posture inverted (Defender disabled, ASR cleared) so it can serve as a target for ASR-preempted techniques.

**Goal:** unblock end-to-end validation of rules 100250 (LOLBin mshta/regsvr32 paths), 100270 (full service-install variants), 100280 (WinDefend stop), and 100290 (full PowerShell download cradle including payload execution).

**Components remaining:**

- Bring up the Windows 11 eval VM on Proxmox (VMID 100, already provisioned)
  - Defender disabled, Tamper Protection off, ASR rules cleared
  - Sysmon installed with SwiftOnSecurity config (same as Freddy-PC)
  - Wazuh agent enrolled, reporting to 192.168.20.20 over the Range → Lab Wazuh-only firewall path
- Add a Linux victim VM (Ubuntu 24.04 minimal) for Linux-side detection development
  - auditd configured with a laurel-style ruleset for execve / connect / setuid coverage
  - Wazuh agent enrolled

**Acceptance criteria for the Windows VM:**

- `mshta http://...` and `regsvr32 /i:http://...scrobj.dll` complete without ASR preemption and fire rule 100250 at level 12
- A full IEX download cradle completes and fires both 100210 (encoded payload variant, if applicable) and 100290 (cradle pattern) at full payload execution, not just process-create
- `Stop-Service WinDefend` succeeds (Tamper Protection off) and fires rule 100280 at level 12

### Stale agent cleanup

Remove disconnected agent ID 002 (`windows-pc`) from the manager. Was retained to demonstrate the disconnected-agent UI state; that demonstration has served its purpose.

```bash
sudo /var/ossec/bin/manage_agents -r 002
sudo systemctl restart wazuh-manager
```

---

## Detection coverage gaps

### PowerShell EventID 4104 (script-block logging)

The Windows agent config ingests `Microsoft-Windows-Sysmon/Operational` but not `Microsoft-Windows-PowerShell/Operational`. EventID 4104 (script-block logging) captures the *decoded* contents of PowerShell scripts after AMSI sees them, which would dramatically improve rule 100290's signal: instead of pattern-matching the command-line shape (which an attacker can easily obfuscate), the rule could match on the actual code being run.

**Action:**

```xml
<!-- Add to wazuh-agent-windows.conf -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then enable script-block logging via GPO or registry on the endpoint:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1
```

Then author a companion custom rule (proposed ID 100291) that matches against 4104's script-block-text field.

### Scheduled-task creation via PowerShell cmdlet or pure WMI

Rule 100260 catches `schtasks.exe /create` but not the `Register-ScheduledTask` cmdlet path or pure-WMI task creation. Companion rule needed against:

- `Microsoft-Windows-TaskScheduler/Operational` EventID 106 (task registered) — requires adding the channel to the Windows agent config
- OR Sysmon EventID 1 against `powershell.exe` with `Register-ScheduledTask` literal in the command line — covers the cmdlet path but misses pure WMI

The EventID 106 path is the cleaner solution.

### Service configuration tampering (not just service stop)

Rule 100280 detects services *stopped*; an attacker can `sc config WinDefend start= disabled` to neutralize them without stopping the live process (it dies on next reboot). Companion rule against Sysmon EventID 1 with `sc.exe config <watchlist> start= disabled` in the command line would close this gap.

### Imagepath-based filter for rule 100270

Rule 100270 currently fires on every new service install via stock 61138 at level 10 — relies on baseline review to allowlist known benign sources. A second-pass enhancement would add a field filter for suspicious imagePath patterns (`\Temp\`, `\AppData\`, `\Users\Public\`, or script interpreters as the service binary). Blocking item: confirm the exact Wazuh field name for the 7045 service-path field by inspecting a real fired-alert JSON.

### Linux EDR-equivalent coverage

The lab's Linux endpoints (Proxmox host, Wazuh manager itself, Kali, the future Ubuntu victim VM) currently rely on stock Wazuh auditd parsing. There are no custom rules on the Linux side that match the detection density of the Windows side. Specifically missing:

- **Privilege escalation chains** — setuid/setgid execve sequences
- **Container escape candidates** — writes to `/sys/fs/cgroup/`, capability changes
- **Reverse-shell command-line patterns** — `bash -i >& /dev/tcp/...` and variants
- **Persistence** — cron, systemd unit creation, `.bashrc` / authorized_keys modification (the last partly covered by FIM)

A productive next chunk of work once the Range VLAN Linux victim VM is online.

---

## Infrastructure hardening

### Let's Encrypt + DNS-01 for Proxmox and Wazuh dashboard

Both currently use self-signed certs. DNS-01 challenge avoids the WAN exposure that HTTP-01 requires. Cloudflare or Porkbun's DNS API works with acme.sh / certbot's DNS plugin.

### Management VLAN

Proxmox admin (192.168.20.10:8006) and Wazuh dashboard (192.168.20.20:443) sit on the Lab VLAN with no separation from lab VM traffic. A dedicated management VLAN with its own SSID (or wired-only access from a specific port) would mean a compromised lab VM cannot trivially pivot to the admin planes.

### WireGuard endpoint for remote access

Blocked by upstream Verizon Fios double-NAT. Requires either:

1. A port-forward on the Fios router (accepts the increased attack surface), OR
2. Bridge mode on the Fios router (preferred, but loses some Fios features)

Once unblocked, WireGuard server on the UDR7 with peers locked to Trusted VLAN only.

### Indexer backup

The Wazuh indexer's data is not backed up — only `/var/ossec/etc/` (config + rules) is in git. At lab scale this is acceptable because alerts can be regenerated from archived events. A production deployment would have nightly snapshots to S3 or similar.

---

## Quality-of-life

### Rule unit-test harness

`wazuh-logtest` is interactive. A proper test harness — a directory of `tests/<rule-id>/positive.json` and `negative.json` files, plus a script that pipes each through `wazuh-logtest` and asserts the expected `rule.id` fires — would make ruleset changes much safer. `pytest` driving subprocess calls to `wazuh-logtest` is the obvious shape.

### Pre-commit hook for ruleset validation

```bash
# .git/hooks/pre-commit
sudo /var/ossec/bin/wazuh-analysisd -t || exit 1
```

Prevents committing a `local_rules.xml` that fails to parse — exactly the failure mode from [`./findings.md`](./findings.md) #3, and which already saved a deployment when caught by `-t` during the 100100 rollout.

### Dashboard saved searches per rule ID

For each of the 8 custom rules, a saved Discover view in the Wazuh dashboard prepopulated to `rule.id: <ID>` over the last 24h. Speeds triage and provides clean screenshots for portfolio documentation.

### Repo sanitization before any external sharing

If the repo is ever shared more broadly than recruiters / hiring panels:

- Strip specific MAC addresses (cosmetic, not sensitive, but unnecessary)
- Confirm no secrets present (passwords and TOTP secrets live in Proton Pass — schemes are fine to document, secrets are not)
- A `git filter-branch` or BFG pass would handle historical commits

---

## Stretch

### Sigma-rule import pipeline

Wazuh doesn't natively consume Sigma. A converter from [SigmaHQ public ruleset](https://github.com/SigmaHQ/sigma) YAML to Wazuh rule XML would dramatically expand detection coverage. `sigmac` historically targeted other backends; a custom translator would be a substantial but rewarding project.

### Atomic Red Team integration

[Atomic Red Team](https://atomicredteam.io/) provides a YAML library of per-technique tests. Orchestrating them from the Range Kali VM against the Range Windows VM would give automated, repeatable validation of every custom rule against the technique each rule claims to detect — turning the rule writeups' "Test methodology" sections into a CI-runnable harness.

### MITRE ATT&CK Navigator export

Generate a Navigator JSON file from the rule index in [`../detections/README.md`](../detections/README.md) so coverage is visible at a glance. Becomes more useful than the markdown table once the custom rule count grows past ~20.
