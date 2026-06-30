# 100240 — Internal SSH brute force
| Field | Value |
|---|---|
| Rule ID | 100240 |
| Level | 12 |
| MITRE technique | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004/) |
| Tactic | TA0006 Credential Access / TA0008 Lateral Movement |
| Parent rule | 5712 (stock sshd brute force correlation, ≥8 failed logins in 120s) |
| Telemetry | journald → sshd / sshd-session on Wazuh manager |
| Status | 🟢 Verified firing end-to-end on Freddy-PC, 2026-06-30 |
## Detection logic
```xml
<rule id="100240" level="12">
  <if_sid>5712</if_sid>
  <srcip>192.168.0.0/16</srcip>
  <description>SSH brute force from internal source $(srcip) — lateral movement candidate.</description>
  <mitre><id>T1110.001</id><id>T1021.004</id></mitre>
</rule>
```
Tightens stock 5712 (which fires on ≥8 failed logins in 120s) by filtering on RFC1918 source ranges. External brute force against the lab is uninteresting (SSH port is non-standard 2222 and lab is not WAN-exposed); internal brute force is a strong indicator that an attacker has a foothold and is moving laterally.
## Why narrow stock 5712 rather than write standalone
Stock 5712 already handles log-source parsing (journald sshd), counting failed-login bursts across the time window, and srcip field extraction. Tiering on top with `if_sid` inherits all of that and adds one constraint (internal source), bumping the level from 10 to 12 to route the alert into a higher severity bucket.

This is the inverse case from finding #11 in [`../docs/findings.md`](../docs/findings.md): tiering on a stock rule with a single additional constraint is legitimate detection-engineering work because the constraint (internal vs. external source) materially changes which events fire the rule. Events that fire 5712 from external sources do NOT fire 100240. That's the test for whether a tiering rule earns its rule ID.
## Critical decoder dependency
This rule does NOT work on a default Ubuntu 24.04 + Wazuh 4.14 install. OpenSSH 9.8+ (shipped in Ubuntu 24.04) split sshd into separate binaries: `sshd` (listener) and `sshd-session` (per-connection auth handler). Auth-failure log lines now use `program_name="sshd-session"`, which the stock Wazuh sshd decoder does not match. Without a decoder fix, sshd auth events fall through to the generic decoder, no fields are extracted, and stock 5712 never fires — which means 100240 can never fire either.

Fix applied in `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="sshd">
  <program_name>^sshd-session$</program_name>
</decoder>
```

This adds a second decoder named `sshd` that catches `sshd-session` events, allowing all stock sshd child decoders (Failed password, Invalid user, etc.) to apply unchanged. Full writeup in [`../docs/findings.md`](../docs/findings.md) #12.
## Test methodology
From Freddy-PC (Trusted VLAN, 192.168.0.249), PowerShell:
```powershell
1..12 | ForEach-Object {
    ssh -p 2222 -o ConnectTimeout=3 -o PreferredAuthentications=password `
        -o PubkeyAuthentication=no bogus@192.168.20.20
}
```
Enter wrong passwords at each prompt. Expected sequence:

1. sshd-session logs `Failed password for invalid user bogus from 192.168.0.249` to journald
2. After 8+ attempts inside 120s, stock 5712 fires internally
3. Source IP 192.168.0.249 matches `192.168.0.0/16` → custom 100240 fires at level 12
4. Alert lands in `/var/ossec/logs/alerts/alerts.json` with `rule.id=100240`
## Observed status
Verified firing end-to-end on 2026-06-30. The test loop produced multiple 100240 firings, each correlating across 7–8 failed-login lines in the `previous_output` field of the alert. Alert details:

- `rule.id` = `100240`
- `rule.level` = `12`
- `rule.description` = "SSH brute force from internal source 192.168.0.249 — lateral movement candidate."
- `rule.mitre.id` = `T1110.001`, `T1021.004`
- `data.srcip` = `192.168.0.249`
- `data.srcuser` = `bogus`
- `decoder.parent` = `sshd`, `decoder.name` = `sshd`
- `predecoder.program_name` = `sshd-session`

Stock rule 5712 is firing internally as the correlation trigger but does not surface as a separate alert in `alerts.json` — the `previous_output` field on each 100240 alert preserves the 7–8 sshd-session log lines that triggered the correlation, which is the audit trail.

Full pipeline confirmed: sshd-session → journald → Wazuh agent (local on the manager, agent 000) → custom sshd-session decoder alias → stock sshd child decoders → stock rule 5710 (per-event) → stock rule 5712 (correlation) → custom rule 100240 (internal-source filter) → `alerts.json`.

Screenshot: [`../screenshots/100240-ssh-brute-force-firing.png`](../screenshots/100240-ssh-brute-force-firing.png)
## Tuning notes
- **`srcip` accepts CIDR** — using `192.168.0.0/16` covers Trusted, Lab, IoT, and Range all at once. Tightening to specific subnets would be appropriate in a production multi-tenant environment.
- **Doesn't yet cover key-based brute force** — if an attacker spray-tests a captured key against many accounts, the failures look different in journald. A future rule chained off Wazuh group `authentication_failures` would catch this.
- **No fail2ban interaction in current lab build** — fail2ban is not deployed on the manager. If added later, it would self-limit the rule (banned source IPs stop generating new failed-auth events), turning 100240 into a one-alert-per-burst signal.
- **Earlier wazuh-logtest non-firing was the decoder, not the rule** — initial validation attempts in a prior session showed 100240 not firing in wazuh-logtest despite stock 5712 firing on the same fixture. The root cause turned out to be the sshd-session decoder gap (see finding #12), not anything in 100240's logic. Once decoded events flowed correctly, 100240 fired as designed on the first live test.
## Cross-references
- [`../docs/findings.md`](../docs/findings.md) #12 — OpenSSH 9.8 sshd-session decoder gap on Ubuntu 24.04
- [`../docs/findings.md`](../docs/findings.md) #11 — the inverse case (when single-constraint tiering does NOT earn its rule ID)
- [`../platform/wazuh-manager.md`](../platform/wazuh-manager.md) — SSH hardening on the manager
- [`../platform/proxmox.md`](../platform/proxmox.md) — same on Proxmox host
