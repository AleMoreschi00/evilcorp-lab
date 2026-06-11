[detection-notes.md](https://github.com/user-attachments/files/28840430/detection-notes.md)
# Blue Team — Detection & Alert Notes

**Lab:** EvilCorp Lab  
**SIEM:** Wazuh (Ubuntu `10.10.10.100`)  
**Agents deployed on:** DC01, DC02, CLIENT01

---

## Objective

Document which attacks generate detectable events in Windows logs, how Wazuh captures them, and what custom rules were created to alert on them.

---

## Key Windows Event IDs — Reference Table

| Event ID | Source | Description | Attack Detected |
|---|---|---|---|
| 4625 | Security | Account failed to log on | Brute force, credential stuffing |
| 4648 | Security | Logon with explicit credentials | Pass-the-hash, lateral movement |
| 4662 | Security | Operation performed on AD object | DCSync (replication rights abuse) |
| 4720 | Security | User account created | Persistence — new account |
| 4728 | Security | Member added to global security group | Privilege escalation |
| 4740 | Security | User account locked out | Brute force |
| 4768 | Security | Kerberos TGT requested | Normal + AS-REP Roasting baseline |
| 4769 | Security | Kerberos service ticket requested | **Kerberoasting** (RC4 flag) |
| 4771 | Security | Kerberos pre-auth failed | Brute force against Kerberos |
| 4776 | Security | NTLM credential validation | Pass-the-hash, NTLM relay |
| 7045 | System | New service installed | Persistence, PSExec activity |
| 1102 | Security | Audit log cleared | Attacker covering tracks |

---

## Attack → Detection Mapping

### Password Spraying

**Attack:** `kerbrute passwordspray` — one password attempt per account

**Detection challenge:** Spray distributes attempts across accounts — no single account reaches lockout threshold. Individual 4625 events may not trigger standard lockout alerts.

**What to look for:**
- Multiple Event ID `4625` from the **same source IP** across **different target accounts** in a short time window
- Logon type 3 (network) across many accounts

**Wazuh rule created:**
```xml
<rule id="100001" level="12">
  <if_matched_sid>18107</if_matched_sid>
  <same_source_ip />
  <options>no_full_log</options>
  <timeframe>60</timeframe>
  <frequency>5</frequency>
  <description>Password spray detected: multiple failed logons from same IP</description>
</rule>
```

**Note:** `kerbrute` sends AS-REQ packets directly to port 88 (Kerberos) — this bypasses NTLM and does **not** generate Event ID 4625. Detection requires monitoring **Event ID 4771** (Kerberos pre-auth failed) instead.

---

### Kerberoasting

**Attack:** `impacket-GetUserSPNs` — requests TGS tickets for accounts with SPNs

**Detection:** Event ID `4769` is generated for every service ticket request. Kerberoasting is identifiable when:
- Ticket encryption type is `0x17` (RC4-HMAC) — modern clients prefer AES
- Requests come from unusual accounts or at unusual times

**What to look for in 4769:**
```
Service Name: sqlsvc
Ticket Encryption Type: 0x17  ← RC4 — suspicious if AES is standard in the environment
Client Address: 10.10.10.50    ← attacker IP
```

**Wazuh rule created:**
```xml
<rule id="100002" level="14">
  <if_sid>60103</if_sid>
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <description>Possible Kerberoasting: RC4 TGS ticket requested</description>
</rule>
```

**Mitigation observed:** `sqlsvc` in Protected Users group forces AES encryption → hash extracted is `$krb5tgs$18` (AES256) instead of `$krb5tgs$23` (RC4) → significantly harder to crack offline.

---

### Kerbrute User Enumeration

**Attack:** AS-REQ packets to port 88 with candidate usernames — valid users get a different error response

**Detection challenge:** This technique generates **no Event ID 4625** (no failed logon). It is the stealthiest enumeration method against AD.

**What to look for:**
- Event ID `4768` with result code `0x6` (KDC_ERR_C_PRINCIPAL_UNKNOWN) — username not found
- High volume of 4768 events from same source IP
- Accounts that do exist: `0x0` (success, pre-auth required)

**Wazuh monitoring:**
- Monitor 4768 with failure codes from external IPs
- Baseline normal AS-REQ volume and alert on spikes

---

### DCSync (not executed — documented for reference)

**Attack:** Attacker with DCSync rights (Replicating Directory Changes All) calls `DRSGetNCChanges` to dump all domain hashes

**Detection:** Event ID `4662` — operation on AD object

**What to look for in 4662:**
```
Object Type: domainDNS
Properties: {1131f6aa...} Replicating Directory Changes
            {1131f6ad...} Replicating Directory Changes All
Account Name: NOT a Domain Controller account ← key indicator
```

**Normal:** DC01 replicating from DC02 generates 4662 — expected  
**Suspicious:** Any non-DC account (e.g. `MSOL_5069fb6c931f`) performing replication operations

---

## Wazuh Setup Notes

### Architecture

```
DC01 (Windows Server 2022)     → Wazuh Agent → Wazuh Manager (Ubuntu 10.10.10.100)
DC02 (Windows Server 2022)     → Wazuh Agent ↗
CLIENT01 (Windows 10)          → Wazuh Agent ↗
```

### Audit Policy — settings applied on DCs

```
Account Logon:
  - Credential Validation: Success, Failure
  - Kerberos Authentication Service: Success, Failure
  - Kerberos Service Ticket Operations: Success, Failure

Account Management:
  - User Account Management: Success, Failure
  - Security Group Management: Success, Failure

DS Access:
  - Directory Service Access: Success, Failure  ← required for DCSync detection

Logon/Logoff:
  - Logon: Success, Failure
  - Account Lockout: Success, Failure

Object Access:
  - Other Object Access Events: Success, Failure  ← required for 7045

System:
  - Security System Extension: Success  ← required for 7045
```

### Sysmon — SwiftOnSecurity config

Deployed on DC01, DC02 and CLIENT01 using [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config).

Key events forwarded to Wazuh:
- **Event ID 1** — Process creation (detects tool execution: nmap, kerbrute, impacket)
- **Event ID 3** — Network connection (detects unusual outbound connections)
- **Event ID 10** — Process access (detects LSASS memory access — credential dumping)
- **Event ID 13** — Registry value set (detects persistence via registry)

---

## Detection Results During Red Team Exercise

| Attack Performed | Event Generated | Detected by Wazuh | Notes |
|---|---|---|---|
| Kerbrute enumeration | 4768 (failure codes) | ✅ Partial | Volume-based detection — low volume may be missed |
| Password spray (NTLM) | 4625 | ✅ Yes | Same-IP frequency rule triggered |
| Password spray (Kerberos) | 4771 | ✅ Yes | Pre-auth failure rule triggered |
| Kerberoasting | 4769 (RC4) | ✅ Yes | RC4 encryption type rule triggered |
| LDAP authenticated query | None significant | ❌ No | Normal authenticated LDAP — no attack indicator |
| PSExec attempt | 7045 | ✅ Yes | New service creation alert |

---

## Lessons Learned

1. **Kerbrute enumeration is nearly silent** — Kerberos-based user enumeration leaves minimal traces. The only reliable detection is monitoring 4768 failure codes at scale.

2. **Password spraying via Kerberos bypasses 4625** — Standard failed-logon alerts miss Kerberos-based spraying. Audit Policy must include Kerberos authentication failures (4771).

3. **Kerberoasting is detectable via encryption type** — If the environment enforces AES, an RC4 ticket request is anomalous. Protected Users group on service accounts is effective mitigation.

4. **Tier Model without password hygiene is ineffective** — The `a-ale` dedicated admin account was correctly segregated but had a guessable password. Operational controls matter as much as technical architecture.

5. **MSOL account is a blind spot** — DCSync rights via ACL are not visible in standard group membership reports. Regular ACL auditing on domain root is essential.
