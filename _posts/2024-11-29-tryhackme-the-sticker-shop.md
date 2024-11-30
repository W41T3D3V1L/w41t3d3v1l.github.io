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

Can you read the flag at `http://10.10.49.166:8080/flag.txt?`  
{: .prompt-tip }