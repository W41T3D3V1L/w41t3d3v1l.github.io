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

## Box-1 (Web Server - API & XSS)
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

(taking time)