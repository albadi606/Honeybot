"""Alert dispatcher: webhook (Slack/Discord/generic JSON)."""
import json
import logging
import urllib.request
import urllib.error
from django.conf import settings

logger = logging.getLogger(__name__)

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _should_send(severity):
    min_sev = getattr(settings, 'ALERT_MIN_SEVERITY', 'CRITICAL')
    return _SEV_ORDER.get(severity, 0) >= _SEV_ORDER.get(min_sev, 4)


def send_alert(title, body, severity='HIGH'):
    """Fire-and-forget webhook. Never raise — alerting must not break request flow."""
    url = getattr(settings, 'ALERT_WEBHOOK_URL', '')
    if not url:
        return False
    if not _should_send(severity):
        return False

    # Auto-detect Slack vs Discord vs generic by hostname
    if 'slack.com' in url:
        payload = {"text": f"*{title}*\n```{body}```"}
    elif 'discord' in url:
        payload = {"content": f"**{title}**\n```{body}```"}
    else:
        payload = {"title": title, "body": body, "severity": severity}

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=3)
        return True
    except (urllib.error.URLError, TimeoutError) as e:
        logger.warning("alert webhook failed: %s", e)
        return False
    except Exception as e:
        logger.warning("alert unexpected error: %s", e)
        return False
