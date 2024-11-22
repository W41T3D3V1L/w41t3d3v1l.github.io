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




<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <style>
    .note-container {
      border: 2px solid #4CAF50;
      font-family: Arial, sans-serif;
      border-radius: 10px;
      padding: 20px;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
      max-width: 600px;
      text-align: center;
      margin: 0 auto; /* Center horizontally */
    }
    .note-containers {
      margin-top: 20px; /* Space below the .note-container */
      max-width: 600px;
      text-align: center;
      color: white;
      font-size: 1.1rem;
      line-height: 1.6;
      background-color: #4CAF50; /* Background color for better visibility */
      border-radius: 10px;
      padding: 20px;
      margin: 0 auto; /* Center horizontally */
    }
  </style>
</head>
<body>
  <div class="note-container">
    <h1>Important Note</h1>
  </div>
  <div class="note-containers">
    <p>
      This writeup will be released <strong>soon!</strong>.
    </p>
  </div>
</body>
</html>
