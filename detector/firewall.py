"""Adaptive firewall: detect -> decide -> respond. Also rate-limits."""
import ipaddress
import subprocess
import platform
import logging
from datetime import timedelta
from collections import defaultdict, deque
from threading import Lock
from django.http import HttpResponseForbidden, JsonResponse
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)

# Bypass paths — admin/static never firewalled (avoid locking yourself out)
_BYPASS_PREFIXES = ('/admin/', '/static/', '/favicon.ico',
                    '/dashboard/', '/firewall/', '/simulate/', '/export-pdf/', '/export-iocs/')


def get_client_ip(request):
    """Return real client IP, honoring X-Forwarded-For only if proxy trusted."""
    if getattr(settings, 'USE_X_FORWARDED_HOST', False):
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if xff:
            # leftmost is client; trust only if remote_addr in trusted proxies
            remote = request.META.get('REMOTE_ADDR', '')
            trusted = getattr(settings, 'TRUSTED_PROXIES', [])
            if not trusted or remote in trusted:
                return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def is_whitelisted(ip):
    """True if IP should never be firewalled — loopback, private in DEBUG, or explicit whitelist."""
    wl = getattr(settings, 'FIREWALL_WHITELIST', set())
    if ip in wl:
        return True
    if getattr(settings, 'DEBUG', False) and getattr(settings, 'FIREWALL_SKIP_PRIVATE_IN_DEBUG', True):
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_private:
                return True
        except ValueError:
            pass
    return False


# ============================================================
# Firewall middleware — checks BlockedIP before request handled
# ============================================================
class FirewallMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, 'FIREWALL_ENABLED', True):
            return self.get_response(request)

        if request.path.startswith(_BYPASS_PREFIXES):
            return self.get_response(request)

        ip = get_client_ip(request)
        if is_whitelisted(ip):
            return self.get_response(request)

        # Lazy import to avoid app-loading order issue
        from .models import BlockedIP, AttackLog

        block = BlockedIP.objects.filter(ip_address=ip).first()

        if block and block.is_active():
            # Still log the attempt (intel)
            try:
                AttackLog.objects.create(
                    attack_type='BLOCKED_REQUEST',
                    severity=block.severity,
                    ip_address=ip,
                    request_uri=request.path,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    http_method=request.method,
                )
                block.hits = (block.hits or 0) + 1
                block.save(update_fields=['hits'])
            except Exception as e:
                logger.warning("firewall log failed: %s", e)

            if getattr(settings, 'FIREWALL_OBSERVE_ONLY', False):
                return self.get_response(request)

            if request.path.startswith('/dashboard/api/'):
                return JsonResponse({'error': 'blocked'}, status=403)
            return HttpResponseForbidden(
                b"<h1>403 - Access Denied</h1><p>Your IP is firewalled by CyberSentinel.</p>"
            )

        return self.get_response(request)


# ============================================================
# Rate limit middleware — in-memory sliding window per IP
# ============================================================
_hit_windows = defaultdict(lambda: deque(maxlen=200))
_rl_lock = Lock()
_RL_WINDOW_SECONDS = 10
_RL_MAX_HITS = 60  # >60 req / 10s => block


class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(_BYPASS_PREFIXES):
            return self.get_response(request)

        ip = get_client_ip(request)
        if is_whitelisted(ip):
            return self.get_response(request)
        now = timezone.now()

        with _rl_lock:
            dq = _hit_windows[ip]
            dq.append(now)
            cutoff = now - timedelta(seconds=_RL_WINDOW_SECONDS)
            while dq and dq[0] < cutoff:
                dq.popleft()
            hit_count = len(dq)

        if hit_count > _RL_MAX_HITS:
            apply_block(
                ip,
                reason=f"Rate limit: {hit_count} req in {_RL_WINDOW_SECONDS}s",
                severity='HIGH',
                duration_seconds=900,
            )
            return HttpResponseForbidden(b"429 - Slow down.")
        return self.get_response(request)


# ============================================================
# Block helpers — decide + persist + (optional) OS-level block
# ============================================================
def apply_block(ip, reason, severity='MEDIUM', duration_seconds=3600, permanent=False):
    """Create/refresh a BlockedIP record, escalate to permanent if repeat offender."""
    if is_whitelisted(ip):
        return None  # never block whitelisted IPs
    from .models import BlockedIP
    from .alerts import send_alert

    expires = None if permanent else timezone.now() + timedelta(seconds=duration_seconds)
    obj, created = BlockedIP.objects.get_or_create(
        ip_address=ip,
        defaults={
            'reason': reason,
            'severity': severity,
            'expires_at': expires,
            'permanent': permanent,
        },
    )
    if not created:
        obj.block_count = (obj.block_count or 0) + 1
        obj.reason = reason
        obj.severity = severity
        obj.expires_at = expires
        # Escalate to permanent after N repeat blocks
        threshold = getattr(settings, 'FIREWALL_PERMABAN_REPEAT', 5)
        if obj.block_count >= threshold:
            obj.permanent = True
            obj.expires_at = None
        obj.save()

    # Optional OS-level firewall integration
    if getattr(settings, 'FIREWALL_OS_INTEGRATION', False) and not obj.os_firewall_applied:
        if _apply_os_block(ip):
            obj.os_firewall_applied = True
            obj.save(update_fields=['os_firewall_applied'])

    try:
        send_alert(
            title=f"IP Blocked: {ip}",
            body=f"{reason}\nSeverity: {severity}\nDuration: {'permanent' if permanent else f'{duration_seconds}s'}",
            severity=severity,
        )
    except Exception as e:
        logger.warning("alert failed: %s", e)

    return obj


def _apply_os_block(ip):
    """Best-effort host firewall rule. Requires privileged process; never crashes app."""
    try:
        system = platform.system()
        if system == 'Linux':
            subprocess.run(
                ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=False, timeout=5, capture_output=True,
            )
        elif system == 'Windows':
            rule_name = f"CyberSentinel_Block_{ip}"
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=in', 'action=block', f'remoteip={ip}'],
                check=False, timeout=5, capture_output=True,
            )
        return True
    except Exception as e:
        logger.warning("OS firewall apply failed for %s: %s", ip, e)
        return False


def evaluate_auto_block(ip, severity):
    """Check rolling counters and auto-block if thresholds tripped."""
    from .models import AttackLog
    rules = getattr(settings, 'FIREWALL_RULES', {})
    rule = rules.get(severity)
    if not rule:
        return None

    window_start = timezone.now() - timedelta(seconds=rule['window'])
    hits = AttackLog.objects.filter(
        ip_address=ip,
        severity=severity,
        timestamp__gte=window_start,
    ).count()

    if hits >= rule['threshold']:
        return apply_block(
            ip,
            reason=f"Auto: {hits}x {severity} in {rule['window']}s",
            severity=severity,
            duration_seconds=rule['duration'],
        )
    return None


def unblock_ip(ip):
    """Manual unblock; also attempt OS rule removal."""
    from .models import BlockedIP
    qs = BlockedIP.objects.filter(ip_address=ip)
    removed = 0
    for b in qs:
        if b.os_firewall_applied:
            _remove_os_block(ip)
        b.delete()
        removed += 1
    return removed


def _remove_os_block(ip):
    try:
        system = platform.system()
        if system == 'Linux':
            subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=False, timeout=5, capture_output=True,
            )
        elif system == 'Windows':
            rule_name = f"CyberSentinel_Block_{ip}"
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                check=False, timeout=5, capture_output=True,
            )
    except Exception as e:
        logger.warning("OS firewall remove failed for %s: %s", ip, e)
