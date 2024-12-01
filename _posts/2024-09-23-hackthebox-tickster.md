---
title: "Hackthebox: Tickster [Machine] [Season 6]"
author: c3l1kd
categories: [Hackthebox]
tags: [Privilege Escalation, Reverse Shell, Nmap, wfuzz, Exploitation, Web Server]
render_with_liquid: false
img_path: /images/hackthebox_tickster/
image:
  path: room_image.webp
---

**Trickster** starts off by discovering a subdoming which uses PrestaShop. Dumping a leaked .git folder gives source code and admin panel is found. Chaining XSS and Theme Upload, www-data user is reached. A docker is found inside the box which hosts a Changedetection.io. Abusing SSTI, we are root inside the docker. Credentials can be found on .history which can be used to login as root on the box. The root path got changed a few weeks after box got released. The fixed path goes on like this. We won't find credentials on .history but there is a datastore directory which has 2 backup files. Opening one of the files gives us a .txt.br file which gives credentials to adam user. Adam user can use pursaslicer as root without password. Malicous scripts can be executed with prusaslicer after a .3mf file is sliced and get shell as root.

## Initial Enumeration

### Nmap Scan

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ nmap -sVC -p- 10.129.215.104
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 17:15 +03
Nmap scan report for 10.129.215.104
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://trickster.htb/
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.75 seconds
```

We have identified `2` ports using nmap,

- **22/SSH** - (`open`)
- **80/HTTP** - (`open`)

Also gives the domain on port `80` as `trickster.htb`. Adding it to the `/etc/hosts` file.

## Trickster.htb — Port 80

Got a web page. Nothing interesting.

![/etc/hosts](01.png){: width="1200" height="800" }

Clicking the buttons below and one of them gives a new domain `shop.trickster.htb`.

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
