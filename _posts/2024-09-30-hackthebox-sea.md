---
title: "Hackthebox: sea [Machine] [Season 6]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [Privilege Escalation, Reverse Shell, Nmap, wfuzz, Exploitation, Web Server]
render_with_liquid: false
img_path: /images/hackthebox_sea/
image:
  path: room_image.png
---

## Initial Enumeration

### Nmap Scan
```console
└─$ nmap -sV 10.10.11.28
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-15 00:29 CST
Nmap scan report for 10.10.11.28
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.39 seconds
```
We have identified `2` ports using nmap,

- **22/SSH** - (`open`)
- **80/HTTP** - (`open`)
I took whatweb a look, but I didn’t see the hostname. I browsed with a browser and saw [http://sea.htb/contact.php.]Add hostname to /etc/hosts:
```console
└──╼ [★]$ echo "10.10.11.28 sea.htb" | sudo tee -a /etc/hosts 
10.10.11.28 sea.htb
```
## Let’s scan the path:
```console
└──╼ [★]$ ffuf -u http://sea.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 94ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 95ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 96ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 191ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 285ms]
# Copyright 2007 James Fisher [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 328ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 378ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 422ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 516ms]
0                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 93ms]
themes                  [Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 93ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 941ms]
data                    [Status: 301, Size: 228, Words: 14, Lines: 8, Duration: 93ms]
                        [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 3404ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 3404ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 3404ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 2335ms]
# on atleast 2 different hosts [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 3502ms]
plugins                 [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 92ms]
messages                [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 92ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 93ms]
```
Find some paths that will redirect, and then scan down:

```console
└──╼ [★]$ ffuf -u http://sea.htb/themes/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/themes/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 92ms]
%20                     [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 92ms]
bike                    [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 111ms]
video games             [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 96ms]
spyware doctor          [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 92ms]
4%20Color%2099%20IT2    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 93ms]
```
You will be redirected when you see bike, and then scan down to see:
```console
└──╼ [★]$ ffuf -u http://sea.htb/themes/bike/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/themes/bike/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

img                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 94ms]
                        [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 94ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 95ms]
# Priority ordered case sensative list, where entries were found  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 95ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 95ms]
#                       [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 788ms]
#                       [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 1791ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 1791ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 93ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 2792ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 2794ms]
# on atleast 2 different hosts [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3796ms]
# This work is licensed under the Creative Commons  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3797ms]
# directory-list-2.3-medium.txt [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3801ms]
# Copyright 2007 James Fisher [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3802ms]
#                       [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 3805ms]
css                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 93ms]
#                       [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 4804ms]
summary                 [Status: 200, Size: 66, Words: 9, Lines: 2, Duration: 92ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 93ms]
LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 98ms]
%20                     [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 98ms]
video games             [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 96ms]
spyware doctor          [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 95ms]
4%20Color%2099%20IT2    [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 96ms]
nero 7                  [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 93ms]
cell phones             [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 93ms]
```
If you have the information, try to visit summary and LICENSE and you will see:
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
