# Findings

Lessons learned, gotchas, and non-obvious troubleshooting paths from building this lab.

---

## 1. Defender ASR silently preempts test coverage on hardened endpoints

**Symptom:** Custom rules targeting LSASS access (originally 100230, since removed as redundant), LOLBin abuse (100250), and PowerShell download cradles (100290) were authored against documented MITRE techniques. Test commands executed on Freddy-PC. Sysmon events present in the local Event Viewer. Yet the post-exploit behaviour expected from the attack never occurred.

**Cause:** Microsoft Defender's Attack Surface Reduction (ASR) rules block the action before the technique completes, on a fully-patched Windows 11 endpoint with default Defender posture. Three of Defender's ASR rules are particularly relevant: the rule blocking credential theft from LSASS, the rule blocking JavaScript/VBScript from launching downloaded executable content, and the rule blocking process creations originating from PSExec and WMI commands. Plus Tamper Protection blocks `Set-MpPreference -Disable*` and `sc stop windefend`.

**What this means for detection engineering:** The detection still fires on the attempted process-create event because Sysmon captures EventID 1 *before* Defender enforces the block. Detection coverage is therefore validated at the attempt level, but the post-detection behaviour the attack *intends* can't be exercised on the hardened endpoint. This is a feature, not a bug — it's exactly the layered defense posture you want — but it complicates demonstration.

**Resolution path:** Range VLAN with the Windows detonation VM (Defender disabled, Sysmon enrolled, Wazuh agent reporting). Tracked in [`./roadmap.md`](./roadmap.md).

**Lesson:** "I can't make the detection fire" can mean three different things — broken rule, missing telemetry, or successful preemption. They have different fixes and look identical from the dashboard. Always check whether ASR or Tamper Protection silently won before assuming the rule is wrong.

---

## 2. Wazuh's `(7612)` duplicate-rule warning hides in `wazuh-logtest`, not `ossec.log`

**Symptom:** Added a new rule to `local_rules.xml`. Restarted manager. `ossec.log` clean — no errors at error/critical level. Triggered the test condition. Rule did not fire.

**Initial investigation:** Verified the rule loaded by grepping `ossec.log` for the rule ID. Verified Sysmon event arrived (visible in `archives.json`). Verified parent group fired on the same event. Verified the regex against the command line in `wazuh-logtest` interactively — it matched.

**Cause:** A duplicate rule ID elsewhere in the ruleset. Wazuh's behaviour on duplicates is to keep the first and silently discard the second, with a `(7612): WARNING: Rule ID 'X' is duplicated.` line. That warning is emitted to stderr during ruleset load and surfaces in `wazuh-logtest`'s startup banner, but it does NOT appear in `ossec.log` at error or critical level.

**Diagnostic path that worked:**

```bash
sudo /var/ossec/bin/wazuh-logtest
# Read the FIRST few lines of output carefully — they include
# any (7612) warnings and any "Failed loading" rule notices.
# Once it gets to "Type one log per line", you've passed the warning zone.
```

**Lesson:** `wazuh-logtest`'s startup output is a first-class diagnostic surface. Read it every time. If a custom rule won't fire and the rule logic looks right, run `wazuh-logtest`, read the first 20 lines, usually you'll have your answer.

---

## 3. A single invalid rule option silently disables the entire `local_rules.xml`

**Symptom:** Authored rule 100200 with `<different_destination_port />` (invalid option). Restarted manager. No errors in `ossec.log`. All custom rules stopped firing — not just 100200, all of them.

**Cause:** Wazuh's XML rule parser is all-or-nothing per file. An unknown option in any rule causes the entire file to fail to load — but Wazuh logs only a single low-severity warning during startup, not a critical error. From the operator's perspective, the manager is "up", logs look normal, the only symptom is the absence of custom alerts.

**Diagnostic loop:**

1. Custom rule isn't firing → check `wazuh-logtest` startup
2. See a parse-failure or invalid-option warning
3. Fix the option, restart manager
4. Re-run `wazuh-logtest` to confirm clean load

**Lesson:** When `local_rules.xml` parses, all rules in it work. When it doesn't, none do. This is the most painful single failure mode in Wazuh rule authoring. Validate file-by-file BEFORE restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t   # syntax-test mode
```

`-t` exits non-zero on parse failures and is much faster than a full manager restart.

---

## 4. UDR7 syslog packets are sourced from the gateway's *destination-VLAN* interface IP

**Symptom:** UFW rule on the Wazuh manager: `allow from 192.168.0.1 to any port 514 proto udp` (the UDR7's "primary" / Trusted-VLAN address). UDR7's SIEM Server config set to forward to 192.168.20.20 over UDP/514. tcpdump on the manager showed packets arriving on UDP/514. Wazuh's `archives.json` showed nothing from the UDR7.

**Cause:** The UDR7 makes a routing decision before transmitting. To reach 192.168.20.20 (on the Lab VLAN), the UDR7 sources the packet from its Lab-VLAN interface, 192.168.20.1, not from its primary 192.168.0.1. UFW rejected the packet at netfilter.

Why tcpdump still showed it: **tcpdump on the inbound path captures before netfilter.** Visibility in tcpdump is necessary but not sufficient for "the firewall accepted it."

**Fix:** Change the UFW source from `192.168.0.1` to `192.168.20.1`.

**Lesson:** On multi-interface devices, "the device's IP" is context-dependent. The source IP of an outbound packet is determined by the device's routing decision toward the destination, not by which IP you think of as primary.

---

## 5. Defense-in-depth means three independent allowlists, each with its own failure mode

The Wazuh manager has UFW (host firewall), Wazuh's `<allowed-ips>` in `ossec.conf` (application allowlist for the syslog receiver), and the UDR7's gateway firewall rules. All three must permit the source for syslog to flow.

**Diagnostic order:**

1. **UDR7 firewall rules** — UniFi UI. If the gateway isn't sending, nothing else matters.
2. **tcpdump on the manager** — confirms packets reach the host (pre-netfilter).
3. **UFW** — `sudo ufw status numbered verbose` + kernel-drop logging if enabled.
4. **Wazuh `<allowed-ips>`** — `/var/ossec/etc/ossec.conf` `<remote>` block. **Silent layer** — Wazuh drops syslog from any source not in this list with no log entry at default verbosity.

Layer 4 is the silent one. The others all leave a trace.

---

## 6. Lynis audit scores are useful as a baseline, not a target

Proxmox host: 65/100. Wazuh manager: 62/100. Both below the 70+ "good" threshold Lynis hints at.

Gaps contributing to the score on both: USB authorization controls, IPv6 hardening checks dinging the score despite IPv6 being disabled at the gateway, hardened malloc / kernel exploit mitigation suite not configured, AppArmor in complain mode rather than enforce on Proxmox's Debian base, audit framework present but not configured with a comprehensive ruleset.

**Lesson:** A Lynis score isn't a goal. It's a checklist diff. The actionable output is the list of warnings, not the number.

---

## 7. The Wazuh laptop's dual-homing trades convenience for a brief reconnect storm

Setup: ethernet primary (`enx6c6e072d25d6`), WiFi fallback (`wlo1`), netplan route metrics 100/600. Works as advertised — yank the ethernet, all traffic shifts to WiFi within seconds. The catch: WiFi is on Trusted VLAN (192.168.0.x), so the manager's reachable IP changes from 192.168.20.20 (ethernet, Lab) to whatever DHCP gives it on Trusted.

Agents are configured against **192.168.20.20** specifically. When the manager fails over to WiFi, that IP goes away. Agents disconnect, buffer events locally (the `<client_buffer>` block in their config handles a queue of 5000 events at 500 EPS), and reconnect when ethernet recovers.

**Implications:**

- Brief disconnection per failover event
- Agent buffers absorb the gap up to the configured queue size
- Anything in flight over UDP (UDR7 syslog) during the failover window is lost — UDP has no retransmit

**Acceptable at lab scale.** In a production deployment, the answer is a Wazuh cluster with two managers behind a VIP, not a dual-homed single node.

---

## 8. Sudo isn't installed by default on Proxmox's minimal Debian base

Trivial but worth documenting. Proxmox VE's base image is a stripped Debian — no sudo, no nano, no curl. The first SSH session is as root or fails entirely.

```bash
# As root, on first login
apt install sudo nano curl
adduser <admin>
usermod -aG sudo <admin>
```

Documented in [`../platform/proxmox.md`](../platform/proxmox.md).

---

## 9. UFW disables non-destructively — use `at` for lockout safety

Standard lockout-safety pattern for SSH-based UFW changes:

1. `ufw enable` only applies the currently-saved ruleset. If the SSH allow rule is missing, the connection drops the moment enable applies.
2. `ufw disable` keeps all rules in the saved config — it just stops enforcing them. `ufw enable` later brings them back exactly as they were.

The pattern for any UFW change made over SSH:

```bash
# Set a 10-minute auto-disable in case of lockout
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

---

## 10. Stock Wazuh ruleset coverage analysis preempted 2 of 10 planned custom rules

**Context:** Initial detection plan called for 10 custom rules covering 6 MITRE tactics. Before committing rules to `local_rules.xml`, performed a coverage analysis against the installed Wazuh 4.14.5 stock ruleset to identify whether any planned detections were already implemented.

**Findings:**

| Planned custom rule | Stock coverage discovered |
|---|---|
| Defender tampering via PowerShell (was 100220) | Rules 92008–92015 already cover this — 8 separate stock detections for Defender RTM, IPS, file scanning, script scanning, controlled folder access, network protection, MAPS, and sample submission being disabled by PowerShell |
| LSASS process access (was 100230) | Rule 92900 (level 12) already covers lsass.exe access with the canonical credential-dump access masks (`0x1010`, `0x40`) and excludes legitimate sources (`Program Files`, `wmiprvse.exe`). My custom rule was a strict subset |
| certutil branch of LOLBin abuse (was part of 100250) | Rules 92016–92018 already cover masquerade and `-decode` patterns |

**Decisions made:**

- **Deleted** rule 100220 entirely. Stock 92008–92015 are more granular than my single rule and operate at the same severity. No added value.
- **Deleted** rule 100230 entirely. Stock 92900 has broader detection (catches more access mask values) and a legitimate-source exclusion that mine lacked. My rule's "tighter mask" framing was solving a problem stock already solved better.
- **Rewrote** rule 100250 to drop the certutil branch, keeping the mshta/regsvr32/wmic/bitsadmin paths that stock does NOT cover.

**Lesson:** Custom detections written without reading the stock ruleset are at best duplicative. At worst they fragment alert routing across two rules that fire on the same event, creating tuning headaches without adding coverage. The stock-coverage check should be a mandatory step BEFORE authoring custom rules, not an afterthought. The 30 minutes it takes to grep the stock rules directory pays back enormously.

**Methodology for the next round:** Before authoring rule N, grep stock for similar coverage:

```bash
# What stock rules touch this MITRE technique?
sudo grep -rl '<id>T1543.003</id>' /var/ossec/ruleset/rules/

# What stock rules match on this telemetry source?
sudo grep -E '<if_group>sysmon_event1</if_group>' /var/ossec/ruleset/rules/0800-sysmon_id_1.xml | wc -l

# What stock rules touch this event ID?
sudo grep -rE '7045|7036' /var/ossec/ruleset/rules/
```

If stock has it, either skip the custom rule or tier on the stock rule to add a specific signal (the path taken for 100240 on stock 5712).

---

## 11. Tiering on a stock rule without adding filter logic is a severity relabel, not a detection

**Context:** Rule 100270 was authored to detect new Windows service creation (T1543.003) by tiering on stock rule 61138, which already fires on Security/System channel EventID 7045. The intent was to promote the alert from stock 61138's level 5 (informational) to level 10 (medium) to route service-creation events into the triage queue.

**The rule as written:**

```xml
<rule id="100270" level="10">
  <if_sid>61138</if_sid>
  <description>New Windows service installed (Security 7045) — triage required.</description>
  <mitre><id>T1543.003</id></mitre>
</rule>
```

No additional field filters. No imagePath constraint. No exclusions. The rule fires on exactly the same events as 61138 and nothing else.

**The problem:** This isn't a detection. It's a severity relabel. The rule adds zero discriminating logic on top of stock 61138 — every event that fires 61138 also fires 100270, and vice versa. An interviewer asking "what does your rule add over stock 61138?" gets the answer "it sets the level to 10 instead of 5" — which is a configuration change, not detection engineering.

The same effect can be achieved without a custom rule at all by overriding the level on 61138 itself:

```xml
<rule id="61138" level="10" overwrite="yes">
  <!-- inherits all stock logic, only level changes -->
</rule>
```

**Decision:** Deleted rule 100270 from `local_rules.xml`. Deleted `detections/rules/100270-new-service.md`. A future rule covering this technique requires actual filter logic — the candidates are filtering on suspicious imagePath patterns (`\Temp\`, `\AppData\`, script interpreters as the service binary) and/or filtering on imagePath signature status. The exact field name (`win.eventdata.imagePath` vs `win.eventdata.binaryPath` vs another variant) needs verification against a live 7045 alert before the filter can be authored. Tracked in [`./roadmap.md`](./roadmap.md).

**Lesson:** "Tier on a stock rule to add a custom signal" (the methodology endorsed in finding #10) only adds value when there IS a custom signal. A bare `<if_sid>` with no additional constraints adds zero detection value over the parent. Before committing a tiering rule, ask: "What event would fire the parent but NOT my rule?" If the answer is "none," the rule isn't doing detection work — and the right tool is rule override, not a new rule ID.

Contrast with rule 100240, which tiers on stock 5712 (sshd brute force) with one constraint: `<srcip>192.168.0.0/16</srcip>`. That constraint passes the test — external brute force events fire 5712 but NOT 100240, so the rule meaningfully restricts the firing set. The single-constraint pattern is fine when the constraint is real; the problem with 100270 was that the only "constraint" was the level number.

---

## 12. OpenSSH 9.8 split sshd into sshd + sshd-session, breaking the stock Wazuh decoder on Ubuntu 24.04

**Symptom:** Rule 100240 (SSH brute force, internal source) deployed and parse-validated. Generated 12 failed SSH logins against the manager from Freddy-PC. Watched `alerts.json` — nothing. Not 100240, not stock 5712, not even stock 5710 (the per-event "invalid user" rule). Total silence on a textbook brute-force pattern.

**Initial investigation:** Confirmed sshd was logging the failed attempts to journald:

```
Jun 30 21:43:38 ffwazuh sshd-session[1634886]: Invalid user bogus from 192.168.0.249 port 54797
Jun 30 21:44:16 ffwazuh sshd-session[1634886]: Failed password for invalid user bogus from 192.168.0.249 port 54797 ssh2
```

Confirmed Wazuh was ingesting journald (the `<localfile>` block for journald was present in `ossec.conf`). Confirmed events were reaching the manager — they showed up in `archives.json`, just with no decoder match and no rule fired.

**Cause:** OpenSSH 9.8 (released August 2024, shipped in Ubuntu 24.04) split the sshd daemon into two separate binaries:

- `sshd` — the listener / accept loop
- `sshd-session` — the per-connection process that handles authentication and the session

Auth-related log lines now use `program_name="sshd-session"`, not `sshd`. The stock Wazuh sshd decoder (and every child decoder for "Failed password," "Invalid user," etc.) anchors on `<program_name>sshd</program_name>`. Result: every sshd auth event on Ubuntu 24.04 falls through to the generic decoder, no fields get extracted, no rules fire.

This is a silent failure. Wazuh doesn't emit a warning when a log line fails to match any decoder — it just emits the raw event into `archives.json` (if `logall_json` is enabled) and moves on. From the dashboard, it looks like sshd isn't generating events at all.

Confirmation in `archives.json` — `predecoder.program_name="sshd-session"`, no `decoder` match beyond the generic timestamp parse, no `data` block:

```json
{
  "full_log": "Jun 30 21:44:16 ffwazuh sshd-session[1634886]: Failed password for invalid user bogus from 192.168.0.249 port 54797 ssh2",
  "predecoder": {
    "program_name": "sshd-session",
    "timestamp": "Jun 30 21:44:16",
    "hostname": "ffwazuh"
  },
  "location": "journald"
}
```

Contrast with the one sshd-tagged line that DID parse correctly during the same window — `sshd[507727]: Timeout before authentication...` — which got the full decoder treatment because its program_name was still `sshd`.

**Fix:** Three lines appended to `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="sshd">
  <program_name>^sshd-session$</program_name>
</decoder>
```

This adds a second decoder also named `sshd` (Wazuh allows multiple decoder definitions to share a name) which matches the `sshd-session` program_name. Because all the stock sshd child decoders are anchored on `<parent>sshd</parent>`, they now apply to sshd-session log lines unchanged. No child-decoder rewrites needed.

Validation:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t   # clean parse, exit 0
sudo systemctl restart wazuh-manager
```

After restart, re-ran the brute-force test. Stock 5710 fired on each individual "Invalid user" event (level 5), stock 2502 fired on the aggregate (level 10), stock 5712 fired as the correlation trigger (≥8 failures in 120s, internal, level 10), and custom 100240 fired with the level-12 lateral-movement-candidate description. The `data.srcip` field was correctly populated as `192.168.0.249`, allowing 100240's `<srcip>192.168.0.0/16</srcip>` filter to match.

**Lessons:**

1. **Stable upstream signatures aren't actually stable across OS upgrades.** OpenSSH's binary split is invisible to most operators — SSH still works, login attempts still get logged, the logs look the same except for a hyphenated suffix on the program name. A SIEM decoder anchored on an exact program_name match catches none of it.

2. **Silent decoder failure is the worst failure mode in Wazuh.** No error, no warning, no entry in `ossec.log`. The only signal is the absence of expected alerts. Diagnostic path: when a rule won't fire, check `archives.json` FIRST to confirm events are reaching the manager AND being decoded. If `archives.json` shows events with no `decoder.name` beyond `predecoder`, the issue is upstream of any rule.

3. **An earlier wazuh-logtest result was masked by this issue.** A prior session noted "100240 did not fire in wazuh-logtest despite stock 5712 firing." The actual situation was that *both* rules were broken on live traffic because the decoder was broken — wazuh-logtest happened to work because the test fixture used a hand-typed log line with `sshd` instead of `sshd-session`. The earlier "Wazuh 4.14 quirk with cross-file rule references" hypothesis was wrong; the root cause was always the decoder.

4. **Decoder aliasing via duplicate decoder names is a clean fix pattern.** Three lines, no rewriting of stock child decoders, survives Wazuh upgrades cleanly. The same pattern would work for any other future-split binary (e.g. if systemd splits, or if any other daemon's log program_name changes upstream).

The fix is documented in `/var/ossec/etc/decoders/local_decoder.xml` with a comment block explaining the OpenSSH 9.8 context so future-me (or a future operator) doesn't wonder why a single-purpose decoder file exists for one program name.
