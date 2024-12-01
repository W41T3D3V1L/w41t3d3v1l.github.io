---
title: "Hackthebox: Monitors-Three [Machine] [Season 6]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [Privilege Escalation, Reverse Shell, Nmap, SQLi, Exploitation, (CVE-2024-25641)]
render_with_liquid: false
img_path: /images/hackthebox_monitorthree/
image:
  path: room_image.webp
---

**MonitorsThree** is a Medium HackTheBox machine where we start by enumerating a web server finding an SQLi that leads to data leak for then gaining a reverse shell by exploiting a vulnerability in cacti `(CVE-2024-25641)` , user pivoting by cracking a user’s hash and then exploit a Duplicati web app running locally to gain root access.

## Initial Enumeration

### Nmap Scan

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ nmap -sC -sV 10.129.200.79 -oN monitors.out -T4    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-26 16:30 CET
Nmap scan report for 10.129.200.79
Host is up (0.084s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.77 seconds
```

<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <style>
    .note-containers {
      max-width: 600px;
      width: 100%;
      padding: 20px;
      background-color: #28a745;
      color: white;
      border-radius: 15px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      text-align: center;
      margin: 0 auto; /* Ensures the second container is centered */
    }

    .note-containers p {
      font-size: 1.2rem;
      line-height: 1.6;
    }

    .note-containers strong {
      font-weight: bold;
      font-size: 1.3rem;
      color: #ffdd57;
    }
  </style>
</head>
<body>
  <div class="note-containers">
    <p>
      This writeup will be released <strong>soon!</strong>
    </p>
  </div>
</body>
</html>
