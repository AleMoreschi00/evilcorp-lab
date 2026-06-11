# 04 — Active Directory Full Compromise

**Date:** 31/05/2026  
**Tester:** Alessandro Moreschi  
**Target:** `evilcorp.local`  
**Outcome:** Domain Admin access achieved

---

## Attack Path Summary

```
Zero credentials
    ↓
Kerbrute user enumeration (no noise, no 4625 events)
    ↓
Password spray → mrossi compromised (Password01!)
    ↓
Authenticated LDAP enumeration → 17 objects mapped
    ↓
Kerberoasting → sqlsvc TGS hash extracted
    ↓
Password spray → Evilcorp! → 6 accounts compromised
    ↓
a-ale (Domain Admin) compromised
    ↓
NTLM blocked (Protected Users) → Kerberos auth required
    ↓
🔴 Full Domain Compromise
```

---

## Critical Findings

### Finding 1 — Weak password on standard user account

| Detail | Value |
|---|---|
| Account | `mrossi` |
| Password | `Password01!` |
| Type | Common seasonal/default password |
| Risk | Initial foothold — authenticated domain access |

---

### Finding 2 — Shared company-themed password across 6 accounts

| Detail | Value |
|---|---|
| Password | `Evilcorp!` |
| Accounts affected | `gverdi`, `backup.admin`, `helpdesk`, `helpdesk2`, `itsupport`, `a-ale` |
| Highest privilege | **Domain Admin** (`a-ale`) |
| Risk | 🔴 Complete domain compromise |

This is the most critical finding. A single password spray with a company-themed word compromised the Domain Admin account. This indicates:
- No password uniqueness enforcement across accounts
- No MFA on privileged accounts
- Tier Model partially implemented (dedicated admin account exists) but undermined by password reuse

---

### Finding 3 — Kerberoastable service account

| Detail | Value |
|---|---|
| Account | `sqlsvc` |
| SPN | `MSSQLSvc/dc01.evilcorp.local:1433` |
| Hash type | `$krb5tgs$23` (RC4) |
| Mitigation present | ✅ Protected Users group → AES encryption |
| Risk | Medium — AES hash is significantly harder to crack offline |

**Note:** The `sqlsvc` account being in Protected Users group is correct hardening — it forces AES encryption for Kerberos tickets, making offline cracking computationally expensive.

---

### Finding 4 — MSOL account with DCSync rights

| Detail | Value |
|---|---|
| Account | `MSOL_5069fb6c931f` |
| Role | Azure AD Connect sync account |
| Risk | High — typically granted DCSync rights via ACL on domain root |
| Notes | Permissions configured as domain root ACL, not group membership — invisible to standard group enumeration |

**Not exploited in this exercise.** In a real engagement, DCSync via MSOL account would allow extraction of all domain password hashes.

---

## NTLM vs Kerberos — Protected Users

The `a-ale` account is a member of **Protected Users** — a built-in security group that enforces:
- NTLM authentication disabled
- No credential caching
- Kerberos AES encryption only
- No delegation

When `crackmapexec` returned `STATUS_ACCOUNT_RESTRICTION`, this confirmed Protected Users membership.

**Next step in a real engagement:** authenticate using Kerberos directly (e.g. `impacket-psexec -k -no-pass`) instead of NTLM.

---

## Recommendations

| Priority | Finding | Recommendation |
|---|---|---|
| 🔴 Critical | Shared password `Evilcorp!` on DA account | Rotate all passwords immediately; enforce password uniqueness |
| 🔴 Critical | No MFA on privileged accounts | Enforce MFA for all admin accounts |
| 🟡 High | `mrossi` weak password | User awareness training; enforce password complexity |
| 🟡 High | MSOL account DCSync rights | Audit MSOL account permissions; apply least privilege |
| 🟡 High | `sqlsvc` Kerberoastable | Use Group Managed Service Account (gMSA) instead |
| 🟢 Medium | `backup.admin` naming convention | Rename accounts to avoid revealing role via name |
| 🟢 Low | LDAP RootDSE publicly accessible | Acceptable — informational only, consider if exposure is a concern |

---

## Positive Security Controls Observed

These hardening measures were in place and working correctly:

- ✅ Anonymous LDAP enumeration blocked
- ✅ SMB null sessions disabled
- ✅ DNS zone transfer restricted
- ✅ `sqlsvc` in Protected Users (AES Kerberoasting only)
- ✅ `a-ale` in Protected Users (NTLM disabled)
- ✅ Tier Model architecture implemented (dedicated admin account)
- ✅ SMBv1 disabled on workstation
- ✅ SMB signing enabled (not required — improvement possible)

---

## Conclusion

The domain was fully compromised through a combination of weak passwords and password reuse. The attack required no exploits, no CVEs, and no advanced tooling — only enumeration and password spraying.

The Tier Model was structurally correct but operationally ineffective: a dedicated admin account with a guessable company-themed password provides no real separation of privilege.

**The primary remediation is operational, not technical:** enforce password uniqueness, MFA on privileged accounts, and regular auditing of password spray exposure.
