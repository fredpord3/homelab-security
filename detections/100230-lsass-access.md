# 100230 — LSASS process access

| Field | Value |
|---|---|
| Rule ID | 100230 |
| Level | 14 |
| MITRE technique | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Tactic | TA0006 Credential Access |
| Parent rule | 92065 (Sysmon EventID 10 — process access) |
| Telemetry | Sysmon `Microsoft-Windows-Sysmon/Operational` |
| Status | 🟡 Blocked by Defender ASR + Credential Guard on Freddy-PC; awaits Range VM |

## Detection logic

```xml
<rule id="100230" level="14">
  <if_sid>92065</if_sid>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">^0x(1010|1410|1438|143A|1FFFFF)$</field>
  <description>LSASS memory access — possible credential dump.</description>
  <mitre><id>T1003.001</id></mitre>
</rule>
```

Two field constraints on the Sysmon EventID 10 (`ProcessAccess`) parent:

1. **`targetImage` is `lsass.exe`** — anchored on the path-separator backslash
2. **`grantedAccess` is one of a known-bad set**:

| Mask | Composition | Why it matters |
|---|---|---|
| `0x1010` | `PROCESS_VM_READ \| PROCESS_QUERY_LIMITED_INFORMATION` | Minimal read access — used by minidump-style tools |
| `0x1410` | `0x1010` + `PROCESS_QUERY_INFORMATION` | Common Mimikatz pattern |
| `0x1438` | procdump's default | Stock procdump on lsass |
| `0x143A` | procdump + extra rights | Some procdump variants / forks |
| `0x1FFFFF` | `PROCESS_ALL_ACCESS` | Sledgehammer; trips on legitimate AV but worth alerting on for visibility |

## Why these specific masks

LSASS is accessed legitimately and frequently by Defender, Wazuh's syscollector, Sysmon itself, and Windows internals. Most of that legitimate traffic uses access masks that do *not* include `PROCESS_VM_READ` (0x10). The intersection of "targets lsass" + "asks for VM_READ" + "well-known dumper mask shape" is the classifier that separates credential dumping from background noise.

## Test methodology

```powershell
# Run on a host with Defender disabled — will be blocked on Freddy-PC
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

Expected behaviour with Defender off:

1. procdump opens a handle to lsass with `grantedAccess=0x1438`
2. Sysmon EventID 10 fires
3. Stock 92065 matches; custom 100230 fires at level 14

## Observed status

🟡 Cannot exercise on Freddy-PC:

- **Defender ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`** (Block credential stealing from the Windows local security authority subsystem) preempts the open-handle call
- **Credential Guard** (enabled by default on Win11 Pro with VBS) virtualizes LSASS secrets away from user-mode memory

This is the *intended* end-state for a production endpoint. Validation requires the Range VLAN VM with Defender disabled, Credential Guard off, and procdump available — tracked in [`../docs/roadmap.md`](../docs/roadmap.md).

Stock 92065 *has* been observed firing on Freddy-PC against `lsass.exe` from legitimate sources (Windows Defender, Sysmon itself) — confirming the parent rule and the field extraction. The custom rule does not fire on these because the grantedAccess masks do not match (Defender uses `0x1000` / `0x1400` without the VM_READ bit).

## Tuning notes

- **Add Sysmon `CallTrace` field check** when the Range VM is online — distinguishes user-mode dumpers (call trace into `dbghelp.dll`) from kernel-mode access
- **`OriginalFileName`** field check would harden against renamed `procdump.exe`
- **Watch the `0x1FFFFF` mask** in stock 92065 alerts for ~1 week post-deployment to confirm the AV / Windows internals baseline before relying on this rule in anger; the level-14 escalation makes a noisy false positive painful

## Cross-references

- [`../docs/findings.md`](../docs/findings.md) — Defender ASR effect on test coverage
- [`../docs/roadmap.md`](../docs/roadmap.md) — Range VLAN VM build
