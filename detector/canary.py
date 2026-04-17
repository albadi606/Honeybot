"""Canary endpoints — decoy files that scream CRITICAL when touched."""
from django.http import HttpResponse, Http404
from django.conf import settings
from .firewall import get_client_ip, apply_block
from .alerts import send_alert


_CANARY_CONTENT = {
    '.env': b"DB_HOST=localhost\nDB_USER=root\nDB_PASS=p@ssw0rd123\nAPI_KEY=sk-REDACTED\n",
    'id_rsa': b"-----BEGIN RSA PRIVATE KEY-----\n[REDACTED_HONEYPOT_DECOY]\n-----END RSA PRIVATE KEY-----\n",
    'backup.sql': b"-- MySQL dump 10.13\n-- Host: localhost  Database: prod\n-- ------ HONEYPOT DECOY ------\n",
    'wp-admin': b"<html><body>WordPress &rsaquo; Login</body></html>",
    '.git/config': b"[core]\n  repositoryformatversion = 0\n[remote \"origin\"]\n  url = git@internal:prod/app.git\n",
}


def canary_view(request, token):
    """Any access = critical incident. Log, alert, block."""
    from .models import CanaryHit, AttackLog

    allowed = getattr(settings, 'CANARY_ENDPOINTS', [])
    if token not in allowed and token not in _CANARY_CONTENT:
        raise Http404()

    ip = get_client_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '')

    CanaryHit.objects.create(
        token=token,
        ip_address=ip,
        user_agent=ua,
        request_uri=request.path,
    )
    AttackLog.objects.create(
        attack_type=f"CANARY_TRIGGERED: {token}",
        severity='CRITICAL',
        ip_address=ip,
        user_agent=ua,
        request_uri=request.path,
        http_method=request.method,
        threat_score=100,
    )

    # Immediate block — any canary hit = malicious intent
    apply_block(
        ip,
        reason=f"Canary triggered: {token}",
        severity='CRITICAL',
        duration_seconds=86400,
    )
    send_alert(
        title=f"CANARY TRIGGERED: {token}",
        body=f"IP {ip} accessed decoy token {token} at {request.path}\nUA: {ua}",
        severity='CRITICAL',
    )

    content = _CANARY_CONTENT.get(token, b"# not found\n")
    return HttpResponse(content, content_type='text/plain')
