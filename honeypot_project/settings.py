"""
Django settings for honeypot_project.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-dev-only-change-me-in-prod-33qtj=%jl!b=6x_@=#!ll=j85h)o1w)&(qgq)qobifyglykvn='
)

DEBUG = os.environ.get('DEBUG', '1') == '1'  # dev default; set DEBUG=0 in prod

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,0.0.0.0').split(',')

# Trust X-Forwarded-For when behind proxy (toggle in prod via env)
# Set USE_X_FORWARDED_FOR=1 to trust X-Forwarded-For from localhost (for fake_attacker.py testing)
USE_X_FORWARDED_HOST = os.environ.get('USE_X_FORWARDED_FOR', '0') == '1'
TRUSTED_PROXIES = os.environ.get('TRUSTED_PROXIES', '127.0.0.1').split(',') if os.environ.get('USE_X_FORWARDED_FOR', '0') == '1' else []

HONEYPOT_ANALYST_NAME = os.environ.get('ANALYST_NAME', 'CyberSentinel Analyst')

# ==== Honeypot firewall / alerting config ====
FIREWALL_ENABLED = os.environ.get('FIREWALL_ENABLED', '1') == '1'
FIREWALL_OBSERVE_ONLY = os.environ.get('FIREWALL_OBSERVE_ONLY', '0') == '1'
FIREWALL_OS_INTEGRATION = os.environ.get('FIREWALL_OS_INTEGRATION', '0') == '1'  # iptables/netsh hook

# Whitelist — never blocked, never rate-limited. Always includes loopback.
FIREWALL_WHITELIST = set(
    os.environ.get('FIREWALL_WHITELIST', '127.0.0.1,::1,0.0.0.0,localhost').split(',')
)
# In DEBUG dev mode, also skip blocking private/loopback ranges entirely
FIREWALL_SKIP_PRIVATE_IN_DEBUG = os.environ.get('FIREWALL_SKIP_PRIVATE_IN_DEBUG', '1') == '1'

# Auto-block thresholds (seconds window, hit count, block duration seconds)
FIREWALL_RULES = {
    'CRITICAL': {'window': 60,  'threshold': 1,  'duration': 86400},   # 1 critical -> 24h
    'HIGH':     {'window': 600, 'threshold': 3,  'duration': 3600},    # 3 HIGH /10m -> 1h
    'MEDIUM':   {'window': 600, 'threshold': 5,  'duration': 1800},    # 5 MED  /10m -> 30m
    'LOW':      {'window': 300, 'threshold': 10, 'duration': 900},     # 10 LOW /5m  -> 15m
}
FIREWALL_PERMABAN_REPEAT = int(os.environ.get('FIREWALL_PERMABAN_REPEAT', '5'))  # 5th block = permanent

# Alerting webhook (Slack/Discord/generic)
ALERT_WEBHOOK_URL = os.environ.get('ALERT_WEBHOOK_URL', '')
ALERT_MIN_SEVERITY = os.environ.get('ALERT_MIN_SEVERITY', 'CRITICAL')

# GeoIP database path (MaxMind GeoLite2-City.mmdb). Optional.
GEOIP_DB_PATH = os.environ.get('GEOIP_DB_PATH', '')

# TOR exit node list refresh
TOR_EXIT_NODE_URL = 'https://check.torproject.org/torbulkexitlist'

# Retention (hours) for attack logs before purge task truncates payload column
LOG_RETENTION_HOURS = int(os.environ.get('LOG_RETENTION_HOURS', '720'))

# Canary tokens — list of endpoint slugs that trigger CRITICAL on any access
CANARY_ENDPOINTS = ['.env', 'id_rsa', 'backup.sql', 'wp-admin', '.git/config']


INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'detector',
]

MIDDLEWARE = [
    'detector.firewall.FirewallMiddleware',  # runs first — block known-bad IPs
    'detector.firewall.RateLimitMiddleware',  # per-IP flood guard
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'honeypot_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'honeypot_project.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Riyadh'  # UTC+3 Arabian Standard Time
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'  # for collectstatic in prod
LOGIN_URL = '/admin/login/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

JAZZMIN_SETTINGS = {
    "site_title": "HoneyPot Admin",
    "site_header": "Honeypot Forensic Lab",
    "site_brand": "CYBER-SENTINEL",
    "welcome_sign": "Authorized Personnel Only - Forensic Monitoring Active",
    "copyright": "CyberSentinel Security Solutions",
    "topmenu_links": [
        {"name": "Home",  "url": "admin:index"},
        {"name": "Live Dashboard", "url": "/dashboard/"},
        {"name": "Firewall", "url": "/firewall/"},
    ],
    "show_ui_builder": True,
    "theme": "darkly",
}
