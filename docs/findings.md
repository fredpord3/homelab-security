# Findings

Lessons learned, gotchas, and non-obvious troubleshooting paths from building this lab. Written for the next person (including future me) who hits the same wall.

---

## 1. Defender ASR silently preempts test coverage on hardened endpoints

**Symptom:** Custom rules 100230 (LSASS access), 100250 (LOLBin abuse), and 100290 (PS download cradle) authored against documented MITRE techniques. Test commands executed on Freddy-PC. Sysmon events present in the local Event Viewer. Yet end-to-end behaviour expected from the attack (LSASS dumped, mshta running a remote .hta, IEX'd payload executing) never occurred.

**Cause:** Microsoft Defender's Attack Surface Reduction (ASR) rules block the *action* before the technique completes, on a fully-patched Windows 11 Pro endpoint with default Defender posture:

Three of Microsoft Defender's ASR rules are particularly relevant here: the rule blocking credential theft from LSASS, the rule blocking JavaScript/VBScript from launching downloaded executable content, and the rule blocking process creations originating from PSExec and WMI commands.

Plus Tamper Protection blocks `Set-MpPreference -Disable*` and `sc stop windefend`.

**What this means for detection engineering:** The detection still fires *on the attempted process-create event* because Sysmon captures the EventID 1 *before* Defender enforces the block. Detection coverage is therefore validated, but the post-detection behaviour the attack *intends* can't be exercised on the hardened endpoint. This is a feature, not a bug — it's exactly the layered defense posture you want — but it complicates demonstration.

**Resolution path:** Build the Range VLAN VM (tracked in [`./roadmap.md`](./roadmap.md)). Defender disabled, Sysmon enrolled, Wazuh agent reporting back to the manager. The detonation environment is the only place the full attack-to-detection chain can be exercised without sacrificing the analyst workstation's posture.

**Lesson:** "I can't make the detection fire" can mean three different things — broken rule, missing telemetry, or successful preemption. They have different fixes and look identical from the dashboard. Always check whether ASR or Tamper Protection silently won before assuming the rule is wrong.

---

## 2. Wazuh's `(7612)` duplicate-rule warning hides in `wazuh-logtest`, not `ossec.log`

**Symptom:** Added rule `100260` to `local_rules.xml`. Restarted manager. `ossec.log` clean — no errors, no warnings at error/critical level. Triggered the test condition. Rule did not fire.

**Initial investigation:** Verified the rule loaded by grepping `ossec.log` for the rule ID. It was listed. Verified Sysmon event arrived (visible in `archives.json`). Verified parent 92052 fired on the same event. Verified my regex against the command line in `wazuh-logtest` interactively — it matched.

**Cause:** A duplicate rule ID elsewhere in the ruleset. Wazuh's behaviour on duplicates is to *keep the first* and *silently discard the second*, with a `(7612): WARNING: Rule ID 'X' is duplicated.` line. That warning is emitted to **stderr during ruleset load** and surfaces in `wazuh-logtest`'s startup banner, but it does **not** appear in `ossec.log` at error or critical level. Skim-reading `ossec.log` for "error" or "critical" misses it entirely.

**Diagnostic path that worked:**

```bash
sudo /var/ossec/bin/wazuh-logtest
# Read the FIRST few lines of output carefully — they include
# any (7612) warnings and any "Failed loading" rule notices.
# Once it gets to "Type one log per line", you've passed the
# warning zone.
```

**Lesson:** `wazuh-logtest`'s startup output is a first-class diagnostic surface, not a UI nicety. Read it every time. If a custom rule won't fire and the rule logic looks right, run `wazuh-logtest`, read the first 20 lines, and you'll usually have your answer.

---

## 3. A single invalid rule option silently disables the entire `local_rules.xml`

**Symptom:** Authored rule 100200 with `<different_destination_port />` (note: invalid option — the correct option is `<different_dstport />`). Restarted manager. No errors in `ossec.log`. All ten custom rules stopped firing — not just 100200, *all of them*.

**Cause:** Wazuh's XML rule parser is all-or-nothing per file. An unknown option in any rule causes the *entire file* to fail to load — but Wazuh logs only a single low-severity warning during startup, *not* a critical error. From the operator's perspective, the manager is "up", logs look normal, the only symptom is the absence of custom alerts.

**How I caught it:** Same as finding 2 — `wazuh-logtest` showed the parse failure. The diagnostic loop is:

1. Custom rule isn't firing → check `wazuh-logtest` startup
2. See a parse-failure or invalid-option warning
3. Fix the option, restart manager
4. Re-run `wazuh-logtest` to confirm clean load

**Lesson:** When `local_rules.xml` parses, ALL rules in it work. When it doesn't, NONE do. This is the most painful single failure mode in Wazuh rule authoring. Validate file-by-file:

```bash
# After editing local_rules.xml, before restarting the manager:
sudo /var/ossec/bin/wazuh-analysisd -t   # syntax-test mode
```

`-t` exits non-zero on parse failures and is much faster than a full manager restart.

---

## 4. UDR7 syslog packets are sourced from the gateway's *destination-VLAN* interface IP

**Symptom:** UFW rule on the Wazuh manager: `allow from 192.168.0.1 to any port 514 proto udp` (the UDR7's "primary" / Trusted-VLAN address). UDR7's SIEM Server config set to forward to 192.168.20.20 over UDP/514. tcpdump on the manager showed packets arriving on UDP/514. Wazuh's `archives.json` showed nothing from the UDR7.

**Cause:** The UDR7 makes a routing decision before transmitting. To reach 192.168.20.20 (the manager, on the Lab VLAN), the UDR7 sources the packet from its Lab-VLAN interface, **192.168.20.1**, not from its primary 192.168.0.1. UFW rejected the packet at the netfilter layer.

The reason tcpdump still showed it: **tcpdump on the inbound path captures *before* netfilter**. Seeing a packet in tcpdump does NOT mean UFW accepted it.

**Fix:** Change the UFW source from `192.168.0.1` to `192.168.20.1`.

**Lesson:** On multi-interface devices, "the device's IP" is context-dependent. The source IP of an outbound packet is determined by the device's routing decision toward the destination, not by which IP you think of as primary. And tcpdump captures pre-netfilter on inbound — visibility in tcpdump is *necessary* but not *sufficient* for "the firewall accepted it."

---

## 5. Defense-in-depth means three independent allowlists, each with its own failure mode

The Wazuh manager has UFW (host firewall), Wazuh's `<allowed-ips>` in `ossec.conf` (application allowlist for the syslog receiver), and the UDR7's gateway firewall rules. All three must permit the source for syslog to flow. When something breaks, the diagnostic question is "which layer is denying."

**Diagnostic order I now use:**

1. **UDR7 firewall rules** — UniFi UI → Settings → Security → Traffic & Firewall Rules. If the gateway isn't sending, nothing else matters.
2. **tcpdump on the manager** — confirms packets reach the host (pre-netfilter).
3. **UFW** — `sudo ufw status numbered verbose` + `sudo journalctl -k -f` for kernel drops with logging enabled.
4. **Wazuh `<allowed-ips>`** — check `/var/ossec/etc/ossec.conf`'s `<remote>` block. Wazuh silently drops syslog from any source not in this list, with no log entry at default verbosity.

Layer 4 is the silent one. UFW logs drops to kern.log if logging is enabled. Wazuh just... doesn't write the event to archives.

---

## 6. Lynis audit scores are useful as a baseline, not a target

Proxmox host: 65/100. Wazuh manager: 62/100. Both are below the 70+ "good" threshold Lynis hints at in its summary.

The gaps that contribute to the gap-from-100 on both:

- USB authorization controls (kernel modules) — not configured; not a meaningful threat in a stationary rack
- IPv6 hardening — IPv6 is disabled at the gateway, so most v6 hardening checks return "not applicable" but still ding the score
- Hardened malloc / kernel exploit mitigation suite — could be added with `linux-hardened` or similar; deferred because the lab isn't a high-exploit-surface environment
- AppArmor / SELinux not in enforce mode on Proxmox's Debian base — Debian ships AppArmor in complain mode by default
- Audit framework not configured for CIS-style auditing — present (auditd) but not configured with a comprehensive ruleset

**Lesson:** A Lynis score isn't a goal. It's a checklist diff. The actionable output is the list of warnings, not the number. Reading the warnings and deciding which apply to the environment is the work; the score is the receipt.

---

## 7. The Wazuh laptop's dual-homing trades convenience for a brief reconnect storm

Setup: ethernet primary (`enx6c6e072d25d6`), WiFi fallback (`wlo1`), netplan route metrics 100/600. Works as advertised — yank the ethernet, all traffic shifts to WiFi within seconds. The catch: the WiFi interface is on the Trusted VLAN (192.168.0.x), so the manager's IP changes from 192.168.20.20 (ethernet, Lab) to whatever DHCP gives it on the Trusted VLAN.

Agents are configured to talk to **192.168.20.20** specifically. When the manager fails over to WiFi, that IP goes away. Agents disconnect, buffer events locally (the `<client_buffer>` block in their config handles up to 5000 events at 500 EPS), and reconnect when the ethernet recovers and 192.168.20.20 comes back.

**Implications:**

- Up to a few seconds of disconnection per failover event
- Agent buffers absorb the gap up to 10 seconds at the configured event rate
- Anything in flight over UDP (syslog from the UDR7) during the failover window is lost — UDP has no retransmit

**Acceptable at lab scale.** In a production deployment, the answer is a Wazuh cluster with two managers behind a VIP, not a dual-homed single node.

---

## 8. Sudo isn't installed by default on Proxmox's minimal Debian base

Trivial gotcha but cost 15 minutes the first time. Proxmox VE's base image is a stripped Debian — no sudo, no nano (vim only), no curl. The first SSH session is as root or fails entirely.

```bash
# As root, on first login
apt install sudo nano curl
adduser <admin>
usermod -aG sudo <admin>
```

Document on first contact rather than the second. Worth noting in the platform docs (added to [`../platform/proxmox.md`](../platform/proxmox.md)).

---

## 9. UFW disables non-destructively — use `at` for lockout safety

Standard lockout-safety pattern for SSH-based UFW changes:

1. `ufw enable` only applies the *currently-saved* ruleset. If the SSH allow rule is missing, the connection drops the moment enable applies.
2. `ufw disable` keeps all rules in the saved config — it just stops enforcing them. `ufw enable` later brings them back exactly as they were.

The pattern for any UFW change made over SSH:

```bash
# Set a 10-minute auto-disable in case I lock myself out
echo "ufw --force disable" | sudo at now + 10 minutes
sudo atq   # confirm the job was queued

# Make the firewall change, verify SSH still works
# ...
sudo ufw enable
sudo ufw status numbered verbose

# Verify everything still works. Then cancel the safety net:
sudo atq && sudo atrm <jobid>
```

Documented in the UFW ruleset comments at [`../platform/ufw-rules.txt`](../platform/ufw-rules.txt).
