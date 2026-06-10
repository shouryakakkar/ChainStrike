"""
Mock outputs for testing ChainStrike without running real scans.
"""

NMAP_MOCK_OUTPUT = """
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-15 10:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0012s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http        Apache httpd 2.4.49 ((Unix))
443/tcp   open  ssl/https   Apache httpd 2.4.49 ((Unix))
3306/tcp  open  mysql       MySQL 5.7.34
8080/tcp  open  http-proxy  Apache Tomcat 9.0.45
8443/tcp  open  ssl/https-alt Apache Tomcat 9.0.45
27017/tcp open  mongodb     MongoDB 4.2.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.34 seconds
"""

GOBUSTER_MOCK_OUTPUT = """
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Medhurst (@MediocreHacker)
===============================================================
[+] Url:                     http://192.168.1.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2024/01/15 10:02:00 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 316] [--> http://192.168.1.100/admin/]
/backup               (Status: 200) [Size: 1024]
/config               (Status: 403) [Size: 289]
/dashboard            (Status: 302) [Size: 0] [--> /login]
/.git                 (Status: 200) [Size: 2048]
/.env                 (Status: 200) [Size: 512]
/api                  (Status: 200) [Size: 4096]
/phpmyadmin           (Status: 200) [Size: 8192]
/upload               (Status: 200) [Size: 256]
/robots.txt           (Status: 200) [Size: 64]
/wp-admin             (Status: 301) [Size: 320] [--> http://192.168.1.100/wp-admin/]
===============================================================
2024/01/15 10:04:30 Finished
===============================================================
"""

NIKTO_MOCK_OUTPUT = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    192.168.1.100
+ Target Port:        80
+ Start Time:         2024-01-15 10:05:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.49 (Unix)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.49 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ CVE-2021-41773: Apache HTTP Server 2.4.49 Path Traversal - allows unauthenticated remote attackers to map URLs to files outside the directories configured by Alias-like directives.
+ OSVDB-3233: /icons/README: Apache default file found.
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3092: /backup/: This might be interesting...
+ /phpmyadmin/: phpMyAdmin directory found
+ CVE-2021-42013: Apache HTTP Server 2.4.49 and 2.4.50 - Path traversal and remote code execution.
+ OSVDB-3268: /config/: Directory indexing found.
+ /login.php: Admin login page/section found.
+ OSVDB-3093: /.git/: .git directory found.
+ Server leaks inodes via ETags, header found with file /robots.txt
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, DELETE, TRACE
+ TRACE HTTP method is active, suggesting the host is vulnerable to XST
+ CVE-2021-26855: Microsoft Exchange Server Remote Code Execution Vulnerability
+ X-Powered-By: PHP/7.2.34 header found
+ /upload/: Upload directory found - files may be uploaded to this location
+ 8726 requests: 0 error(s) and 20 item(s) reported on remote host
+ End Time:           2024-01-15 10:15:00 (GMT0) (600 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""
