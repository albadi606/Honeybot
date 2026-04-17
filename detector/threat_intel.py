"""IP enrichment: GeoIP, TOR, reputation. All network calls graceful-fail."""
import ipaddress
import logging
import threading
import time
import urllib.request
from django.conf import settings

logger = logging.getLogger(__name__)

# ---- TOR exit node cache ----
_tor_cache = {'ips': set(), 'loaded_at': 0}
_tor_lock = threading.Lock()
_TOR_TTL = 3600  # refresh hourly


def _load_tor_list():
    """Fetch TOR exit node list; silently fail offline."""
    try:
        url = getattr(settings, 'TOR_EXIT_NODE_URL', '')
        if not url:
            return set()
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberSentinel/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            text = resp.read().decode('utf-8', errors='ignore')
        return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')}
    except Exception as e:
        logger.debug("tor list fetch failed: %s", e)
        return set()


def is_tor_exit(ip):
    with _tor_lock:
        if time.time() - _tor_cache['loaded_at'] > _TOR_TTL:
            fresh = _load_tor_list()
            if fresh:
                _tor_cache['ips'] = fresh
                _tor_cache['loaded_at'] = time.time()
        return ip in _tor_cache['ips']


# ---- GeoIP (optional geoip2) ----
_geo_reader = None
_geo_loaded = False


def _geo():
    global _geo_reader, _geo_loaded
    if _geo_loaded:
        return _geo_reader
    _geo_loaded = True
    path = getattr(settings, 'GEOIP_DB_PATH', '')
    if not path:
        return None
    try:
        import geoip2.database  # type: ignore
        _geo_reader = geoip2.database.Reader(path)
    except Exception as e:
        logger.info("geoip2 unavailable: %s", e)
        _geo_reader = None
    return _geo_reader


def lookup_geo(ip):
    """Returns dict: {country, country_code, asn}. Empty on failure."""
    r = _geo()
    if not r:
        return {}
    try:
        rec = r.city(ip)
        return {
            'country': rec.country.name or '',
            'country_code': rec.country.iso_code or '',
            'asn': '',  # separate DB if needed
        }
    except Exception:
        return {}


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def enrich(ip):
    """One-stop enrichment: returns all intel fields at once."""
    result = {'country': '', 'country_code': '', 'asn': '', 'is_tor': False, 'threat_score': 0}
    if not ip or is_private(ip):
        return result

    geo = lookup_geo(ip)
    result.update(geo)
    if is_tor_exit(ip):
        result['is_tor'] = True
        result['threat_score'] = max(result['threat_score'], 70)
    return result
