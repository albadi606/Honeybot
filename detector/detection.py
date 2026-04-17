"""Attack pattern detection. Regex precompiled at import time."""
import re

ATTACK_PATTERNS = {
    "SQL Injection": {
        "patterns": [
            r"('\s*(OR|AND)\s+')",
            r"(UNION\s+(ALL\s+)?SELECT)",
            r"(SELECT\s+.*\s+FROM)",
            r"(INSERT\s+INTO)",
            r"(DROP\s+TABLE)",
            r"(DELETE\s+FROM)",
            r"(UPDATE\s+.*\s+SET)",
            r"(--\s*$)",
            r"(/\*.*\*/)",
            r"(SLEEP\s*\()",
            r"(BENCHMARK\s*\()",
            r"(WAITFOR\s+DELAY)",
            r"(;\s*(DROP|SELECT|INSERT|UPDATE|DELETE))",
            r"(0x[0-9a-fA-F]{6,})",
            r"(CHAR\s*\()",
            r"('\s*;\s*--)",
        ],
        "severity": "CRITICAL",
    },
    "XSS Attack": {
        "patterns": [
            r"(<script[\s>])",
            r"(javascript\s*:)",
            r"(on(error|load|click|mouseover|focus|blur)\s*=)",
            r"(alert\s*\()",
            r"(document\.(cookie|location|write))",
            r"(eval\s*\()",
            r"(<iframe)",
            r"(<img\s+.*on\w+\s*=)",
            r"(String\.fromCharCode)",
            r"(<svg\s+.*on\w+\s*=)",
        ],
        "severity": "HIGH",
    },
    "Brute Force": {
        "patterns": [
            r"(?:^|\s)(admin|root|administrator|superuser|test|guest)(?:\s|$)",
            r"(?:^|\s)(password|123456|12345678|qwerty|abc123|password123|admin123|root123|letmein|welcome)(?:\s|$)",
        ],
        "severity": "MEDIUM",
    },
    "Command Injection": {
        "patterns": [
            r"(;\s*(whoami|id|uname|cat|ls|pwd|wget|curl|nc|ncat))",
            r"(\|\s*(cat|ls|whoami|id|passwd))",
            r"(&&\s*(ls|cat|whoami|id|rm|wget))",
            r"(`[^`]+`)",
            r"(\$\([^)]+\))",
            r"(&\s*netstat)",
            r"(\|\|\s*\w+)",
        ],
        "severity": "CRITICAL",
    },
    "Directory Traversal": {
        "patterns": [
            r"(\.\./){2,}",
            r"(\.\.\\){2,}",
            r"(/etc/(passwd|shadow|hosts))",
            r"(C:\\Windows\\)",
            r"(/proc/self/)",
            r"(%2e%2e[/\\])",
            r"(\.\.%2f)",
        ],
        "severity": "HIGH",
    },
    "LFI (Local File Inclusion)": {
        "patterns": [
            r"(php://(filter|input|data))",
            r"(file://)",
            r"(expect://)",
            r"(zip://)",
            r"(phar://)",
            r"(data://text)",
            r"(/var/log/)",
        ],
        "severity": "HIGH",
    },
    "RFI (Remote File Inclusion)": {
        "patterns": [
            r"(https?://[^\s]+\.(php|txt|sh|py|pl))",
            r"(ftp://[^\s]+)",
            r"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        ],
        "severity": "HIGH",
    },
    "Scanner/Recon": {
        "patterns": [
            r"(sqlmap|nikto|nmap|masscan|acunetix|wpscan|dirbuster|gobuster|ffuf|burpsuite|hydra|metasploit)",
            r"(/wp-login\.php)",
            r"(/phpmyadmin)",
            r"(/\.git/)",
            r"(/\.env)",
        ],
        "severity": "MEDIUM",
    },
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Precompile all patterns once at module load
_COMPILED = {
    name: {
        "patterns": [re.compile(p, re.IGNORECASE) for p in cfg["patterns"]],
        "severity": cfg["severity"],
    }
    for name, cfg in ATTACK_PATTERNS.items()
}


def detect_attack(*inputs):
    """Scan arbitrary string inputs for attack patterns. Returns (name, severity)."""
    combined = " ".join(str(i) for i in inputs if i)
    if not combined.strip():
        return "Anomaly Detected", "LOW"

    detected = []
    for name, cfg in _COMPILED.items():
        for rx in cfg["patterns"]:
            if rx.search(combined):
                detected.append((name, cfg["severity"]))
                break

    if not detected:
        return "Anomaly Detected", "LOW"

    detected.sort(key=lambda x: SEVERITY_ORDER.get(x[1], 0), reverse=True)
    return detected[0]


def scan_request(request):
    """Pull all user-controlled surfaces from Django request and scan them."""
    parts = [
        request.path,
        request.META.get('QUERY_STRING', ''),
        request.META.get('HTTP_USER_AGENT', ''),
        request.META.get('HTTP_REFERER', ''),
    ]
    if request.method == 'POST':
        for k, v in request.POST.items():
            parts.append(f"{k}={v}")
    return detect_attack(*parts)
