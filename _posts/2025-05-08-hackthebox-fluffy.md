---
title: "Hackthebox: Fluffy [Machine] [Season 8]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [
    nmap,
    javascript-decoding,
    web-fuzzing,
    post-exploitation,
    privilege escalation,
    initial access,
  ]
render_with_liquid: false
img_path: /images/hackthebox_fluffy/
image:
  path: room_image.png
---

**Fluffy** machine which is easy rated windows box. This write-up covers <code class="highlight">initial access</code>, <code class="highlight">privilege escalation</code>, and <code class="highlight">post-exploitation</code> techniques.


<style>
    .highlight {
 background-color: #ffeb3b;
      padding: 0 5px;
      color: red;
      border-radius: 3px;
}
</style>

[![Hackthebox Room Link](room_banner.png)](https://app.hackthebox.com/machines/Fluffy)

> As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: <code class="highlight" >j.fleischman </code> / <code class="highlight">J0elTHEM4n1990!</code>

## Initial Enumeration

### Nmap Scan

```console
┌──(celikd㉿kali)-[~/Documents]
└─$ nmap -sC -sV 10.10.66.17
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-25 04:40 EDT
Nmap scan report for 10.10.66.17
Host is up (0.23s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-25 15:41:16Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T15:42:39+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17

445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T15:42:40+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T15:42:39+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-25T15:42:40+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17


5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m00s
| smb2-time:
|   date: 2025-05-25T15:41:59
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.43 seconds
```

There are five open ports:

- **53** (domain)
- **89/tcp**  (kerberos-sec)
- **139/tcp**  (netbios-ssn)
- **389/tcp**   (ldap)
- **445/tcp**   (microsoft-ds?)

Using the given credential if we list the shares available, we will find something interesting

```console
┌──(celikd㉿kali)-[~/Documents]
└─$ nxc smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.10.66.17    445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.66.17    445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.66.17    445    DC01             [*] Enumerated shares
SMB         10.10.66.17    445    DC01             Share           Permissions     Remark
SMB         10.10.66.17    445    DC01             -----           -----------     ------
SMB         10.10.66.17    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.66.17    445    DC01             C$                              Default share
SMB         10.10.66.17    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.66.17    445    DC01             IT              READ,WRITE      
SMB         10.10.66.17    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.66.17    445    DC01             SYSVOL          READ            Logon server share 
```

We have Read + Write access on `IT` share. Write access is interesting and unlocks a lot of attack path. Looking at the content on the `IT` share.

```console
┌──(celikd㉿kali)-[~/Documents]
└─$ smbclient //10.10.66.17/IT U j.fleischman 'JoelTHEM4n1990!'
Try "help" to get a list of possible commands.
smb: \> ls
  ./
  ../
  Everything-1.4.1.1026.x64/         D        Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip      1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58/                      D        Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                   3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                A 169963  Sat May 17 10:31:07 2025
```

Opening `Upgrade_Notice.pdf` shows the system are in upgrade process and have multiple vulnerabilities. 

![cves](01.png){: width="1200" height="800" }

Among the listed CVE’s, `CVE-2025-24071` stands out.

`CVE-2025-24071` : An unauthenticated attacker can exploit this vulnerability by constructing RAR/ZIP files containing a malicious SMB path. Upon decompression, this triggers an SMB authentication request, potentially exposing the user’s NTLM hash

Since we have write access to IT share, we will use [CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071/blob/main/exploit.py) exploit to generate malicious zip file, then upload it to IT share. After certain time it will be unzipped, meanwhile we will setup reponder and catch the victims hash.

## taking break