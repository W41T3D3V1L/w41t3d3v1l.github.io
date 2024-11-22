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

**Jet [Fortress]**In this lab, you will explore various security challenges. First, you'll <code>Connect</code> to the environment and get started. As you progress, begin <code class="highlight">Digging in</code> to uncover hidden information. Move <code>Going Deeper</code> to analyze and bypass authentication mechanisms. You'll learn how to handle **<code>Command</code> execution vulnerabilities and buffer <code>Overflown</code> exploits. There’s also a hidden <code>Secret Message</code> that requires careful extraction. Understand the concept of <code>Elasticity</code> in environments, and manage users with the <code>Member Manager</code> feature. Lastly, uncover <code>More Secrets</code> in the system and decode the final <code>Memo</code>.

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
