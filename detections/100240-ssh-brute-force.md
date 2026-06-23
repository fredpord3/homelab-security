# 100240 — Internal SSH brute force

| Field | Value |
|---|---|
| Rule ID | 100240 |
| Level | 12 |
| MITRE technique | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004/) |
| Tactic | TA0006 Credential Access / TA0008 Lateral Movement |
| Parent rule | 5712 (stock sshd brute force detection) |
| Telemetry | journald → sshd on Proxmox host and Wazuh manager |
| Status | 🟡 Deployed, validation in progress |

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

Stock 5712 already handles log-source parsing (journald, syslog), counting failed-login bursts across the time window, and username field extraction. Tiering on top with `if_sid` inherits all of that and adds one constraint (internal source), bumping the level from 10 to 12 to route the alert into a higher severity bucket.

## Test methodology

From Freddy-PC (Trusted VLAN, 192.168.0.x):

```powershell
# Generate 10+ failed logins against the Wazuh manager
1..10 | ForEach-Object {
    ssh -p 2222 -o ConnectTimeout=3 -o PreferredAuthentications=password `
        -o PubkeyAuthentication=no bogus_user@192.168.20.20
}
```

Expected:

1. sshd logs `Failed password for invalid user bogus_user from 192.168.0.x` to journald
2. After 8+ attempts inside 120s, stock 5712 fires
3. Source IP is in 192.168.0.0/16 → custom 100240 also fires at level 12
4. fail2ban also bans the source IP (sshd jail)

## Observed status

Rule deployed and parse-validated. End-to-end validation in progress.

Expected concurrent behaviour when exercised:

- `alerts.json` should record both 5712 (level 10) and 100240 (level 12)
- `fail2ban-client status sshd` should show the source IP in the banned list
- `journalctl -u sshd` should show the matching failed-password lines

## Tuning notes

- **`srcip` accepts CIDR** — using `192.168.0.0/16` covers Trusted, Lab, IoT, and Range all at once. Tightening to specific subnets would be appropriate in a production multi-tenant environment
- **fail2ban interaction** — once fail2ban bans the source, sshd never sees subsequent attempts, so the rule self-limits. This is desirable: one alert per brute-force burst, not one per second
- **Doesn't yet cover key-based brute force** — if an attacker spray-tests a captured key against many accounts, the failures look different in journald. A future rule chained off Wazuh group `authentication_failures` would catch this

## Cross-references

- [`../platform/wazuh-manager.md`](../platform/wazuh-manager.md) — SSH hardening on the manager
- [`../platform/proxmox.md`](../platform/proxmox.md) — same on Proxmox host
