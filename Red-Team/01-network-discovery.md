# 01 — Network Discovery & Target Identification

**Date:** 29/05/2026  
**Tester:** Alessandro Moreschi  
**Scope:** `10.10.10.0/24` — Black Box, zero credentials  
**Attacker IP:** `10.10.10.50` (Kali Linux)

---

## Objective

Map the network, identify active hosts and determine their role before selecting attack targets.

---

## Phase 1 — Network Discovery

### Command

```bash
ip a
nmap -sn 10.10.10.0/24
```

### Why

`nmap -sn` performs a ping scan to discover live hosts without triggering a full port scan — low noise, fast results.

### Results

| Host | Status | Notes |
|---|---|---|
| 10.10.10.5 | Active | Unknown — to identify |
| 10.10.10.10 | Active | Unknown — to identify |
| 10.10.10.50 | Active | Attacker (Kali) |
| 10.10.10.60 | Active | Unknown — to identify |

**3 targets identified for further analysis.**

---

## Phase 2 — OS Detection

### Command

```bash
nmap -O --osscan-guess 10.10.10.5 10.10.10.10 10.10.10.60 2>/dev/null \
  | grep -A3 "Nmap scan report\|OS details\|Running"
```

### Why

OS detection helps prioritize targets — a legacy Linux system is likely more vulnerable than a patched Windows host.

### Results

| Host | OS Detection | Notes |
|---|---|---|
| 10.10.10.5 | No result — firewall blocking | Likely hardened server |
| 10.10.10.10 | Windows 10/11/2019 (92%) | Client or member server |
| 10.10.10.60 | Linux 2.6.x | **Outdated kernel — high priority** |

---

## Phase 3 — Service Enumeration on 10.10.10.60 (Linux)

### Command

```bash
nmap -sV --top-ports 100 10.10.10.60
```

### Results

| Port | Service | Version | Risk |
|---|---|---|---|
| 21/tcp | FTP | vsftpd 2.3.4 | 🔴 CVE-2011-2523 backdoor |
| 22/tcp | SSH | OpenSSH 4.7p1 | 🟡 Outdated |
| 23/tcp | Telnet | — | 🔴 Cleartext credentials |
| 80/tcp | HTTP | Apache 2.2.8 | 🟡 Outdated |
| 139/445/tcp | SMB | Samba 3.x | 🟡 Potentially vulnerable |
| 3306/tcp | MySQL | — | 🟡 Default credentials? |
| 5900/tcp | VNC | — | 🟡 Exposed GUI access |
| 2049/tcp | NFS | — | 🟡 Unauthenticated mount? |

### Conclusion

Host extremely vulnerable. `vsftpd 2.3.4` backdoor (CVE-2011-2523) identified as primary attack vector.  
→ See [03-metasploitable-exploit.md](./03-metasploitable-exploit.md)

---

## Phase 4 — Service Enumeration on 10.10.10.5 (DC candidate)

### Command

```bash
sudo nmap -Pn -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389 \
  10.10.10.5 -oN ~/pentest_evilcorp/scans/10.10.10.5_ad_ports.txt
```

### Why

Targeted scan on ports characteristic of Active Directory services instead of full port scan — faster and more focused.

| Port | Service | Significance |
|---|---|---|
| 88/tcp | Kerberos | Confirms KDC / Domain Controller |
| 389/tcp | LDAP | Confirms Active Directory |
| 445/tcp | SMB | Confirms Windows |
| 3268/tcp | Global Catalog | Confirms DC role |

### Conclusion

`10.10.10.5` confirmed as **Active Directory Domain Controller** for `evilcorp.local`.  
→ AD enumeration continues in [02-ad-enumeration.md](./02-ad-enumeration.md)

---

## Phase 5 — SMB Analysis on 10.10.10.10

### Command

```bash
sudo nmap -Pn -p 445 \
  --script smb-protocols,smb2-security-mode,smb2-time,smb-os-discovery \
  10.10.10.10 -oN ~/pentest_evilcorp/scans/10.10.10.10_smb_info.txt
```

### Results

- SMBv1: **not present** ✅
- SMB versions: 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
- SMB signing: **enabled but not required** ⚠️

### Analysis

SMB signing not enforced is a relevant weakness — in the presence of valid credentials or interceptable NTLM authentication, the host could be a candidate for an **SMB relay attack**.

No immediate anonymous access vector identified. Target registered for potential relay attack in a later phase.

---

## Summary

| Host | Role | Priority |
|---|---|---|
| 10.10.10.5 | Domain Controller (`evilcorp.local`) | 🔴 High — AD attack path |
| 10.10.10.10 | Windows workstation/member server | 🟡 Medium — SMB relay candidate |
| 10.10.10.60 | Metasploitable (Linux legacy) | 🔴 High — immediate exploit available |
