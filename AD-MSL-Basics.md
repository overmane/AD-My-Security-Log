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
