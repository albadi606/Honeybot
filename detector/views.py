import json
from datetime import timedelta
from django.shortcuts import render, redirect
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.conf import settings

from .models import AttackLog, BlockedIP, CanaryHit
from .detection import detect_attack, scan_request, ATTACK_PATTERNS
from .firewall import get_client_ip, apply_block, unblock_ip, evaluate_auto_block
from .threat_intel import enrich

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def _log_and_react(request, attack_name, severity, username='', password=''):
    """Shared: persist AttackLog with enrichment + fire auto-block rules."""
    ip = get_client_ip(request)
    intel = enrich(ip)

    log = AttackLog.objects.create(
        attack_type=attack_name,
        severity=severity,
        username=username,
        password=password,
        ip_address=ip,
        http_method=request.method,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        request_uri=request.path,
        payload=request.META.get('QUERY_STRING', '')[:2000] or None,
        country=intel.get('country', ''),
        country_code=intel.get('country_code', ''),
        asn=intel.get('asn', ''),
        is_tor=intel.get('is_tor', False),
        threat_score=intel.get('threat_score', 0),
        session_key=request.session.session_key if hasattr(request, 'session') else None,
    )
    evaluate_auto_block(ip, severity)
    return log


@csrf_exempt
def honeypot_login(request):
    """Fake login — CSRF exempt so real bots/scanners actually submit."""
    if request.method == "POST":
        uname = request.POST.get('username', '')
        pword = request.POST.get('password', '')
        # Scan full request (not just creds) — user-agent, URI, referer
        attack_name, severity = scan_request(request)
        # Also scan creds directly in case scan_request didn't trip
        cred_name, cred_sev = detect_attack(uname, pword)
        if cred_sev != 'LOW':
            attack_name, severity = cred_name, cred_sev

        _log_and_react(request, attack_name, severity, username=uname, password=pword)
        return render(request, 'detector/fake_area.html')
    return render(request, 'detector/login.html')


@login_required
def simulate_attack_view(request):
    result = None
    severity = None
    if request.method == "POST":
        manual_payload = request.POST.get('manual_payload', '').strip()
        selected_type = request.POST.get('attack_type')

        if manual_payload:
            attack_name, severity = detect_attack(manual_payload, manual_payload)
            AttackLog.objects.create(
                attack_type=f"LAB_TEST: {attack_name}",
                severity=severity,
                username="analyst_lab",
                password=manual_payload,
                ip_address="127.0.0.1",
                request_uri="/simulate/",
            )
            result = f"MANUAL_DETECTION: {attack_name}"
        else:
            sev = ATTACK_PATTERNS.get(selected_type, {}).get("severity", "MEDIUM")
            AttackLog.objects.create(
                attack_type=f"SIMULATED: {selected_type}",
                severity=sev,
                username="analyst_bot",
                password="automated_payload_vector",
                ip_address="127.0.0.1",
                request_uri="/simulate/",
            )
            result = f"SIMULATION_SUCCESS: {selected_type}"
            severity = sev

    return render(request, 'detector/simulate.html', {'result': result, 'severity': severity})


@login_required
def admin_dashboard(request):
    logs = AttackLog.objects.all().order_by('-timestamp')[:50]
    total = AttackLog.objects.count()

    # Aggregate in SQL (was O(N) Python loop)
    def _clean(name):
        if not name:
            return 'Unknown'
        for prefix in ("SIMULATED: ", "LAB_TEST: ", "MANUAL_LAB: ", "CANARY_TRIGGERED: "):
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    # Exclude firewall/meta rows from threat-vector pie
    _EXCLUDE = {'BLOCKED_REQUEST'}
    # Legacy/alias labels → canonical name
    _ALIASES = {
        'XSS': 'XSS Attack',
        'xss': 'XSS Attack',
        'Cross-Site Scripting': 'XSS Attack',
        'SQLI': 'SQL Injection',
        'SQLi': 'SQL Injection',
        'sqli': 'SQL Injection',
        'SQL': 'SQL Injection',
        'CMD Injection': 'Command Injection',
        'CMDi': 'Command Injection',
        'Path Traversal': 'Directory Traversal',
        'LFI': 'LFI (Local File Inclusion)',
        'RFI': 'RFI (Remote File Inclusion)',
        'Recon': 'Scanner/Recon',
        'Scanner': 'Scanner/Recon',
    }
    stats_dict = {name: 0 for name in ATTACK_PATTERNS.keys()}
    stats_dict["Anomaly Detected"] = 0
    for row in AttackLog.objects.values('attack_type').annotate(count=Count('id')):
        if row['attack_type'] in _EXCLUDE:
            continue
        key = _clean(row['attack_type'])
        # Keep printable ASCII only to avoid glyph garbage in UI
        key = ''.join(c for c in key if 32 <= ord(c) < 127).strip() or 'Unknown'
        # Normalize aliases to canonical label
        key = _ALIASES.get(key, key)
        stats_dict[key] = stats_dict.get(key, 0) + row['count']

    # Drop zero-count entries from chart (cleaner pie)
    chart_pairs = [(k, v) for k, v in stats_dict.items() if v > 0]
    chart_pairs.sort(key=lambda x: x[1], reverse=True)
    chart_labels = [p[0] for p in chart_pairs]
    chart_data = [p[1] for p in chart_pairs]
    stats_list = [{'attack_type': k, 'count': v} for k, v in stats_dict.items()]

    sev_rows = AttackLog.objects.values('severity').annotate(count=Count('id'))
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in sev_rows:
        severity_counts[r['severity']] = r['count']

    top_ips = list(
        AttackLog.objects.exclude(ip_address__isnull=True)
        .values('ip_address')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    last_24h = timezone.now() - timedelta(hours=24)
    timeline_qs = (
        AttackLog.objects.filter(timestamp__gte=last_24h)
        .annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(count=Count('id'))
        .order_by('hour')
    )
    timeline_labels = [entry['hour'].strftime("%H:%M") for entry in timeline_qs]
    timeline_data = [entry['count'] for entry in timeline_qs]

    # Firewall summary
    active_blocks = BlockedIP.objects.filter(
        permanent=False, expires_at__gt=timezone.now()
    ).count() + BlockedIP.objects.filter(permanent=True).count()

    context = {
        'logs': logs,
        'total_attacks': total,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
        'stats': stats_list,
        'severity_counts': json.dumps(severity_counts),
        'top_ips': top_ips,
        'timeline_labels': json.dumps(timeline_labels),
        'timeline_data': json.dumps(timeline_data),
        'active_blocks': active_blocks,
    }
    return render(request, 'detector/dashboard.html', context)


@login_required
def dashboard_api(request):
    logs = AttackLog.objects.all().order_by('-timestamp')[:50]
    total = AttackLog.objects.count()
    log_list = [{
        'ip_address': log.ip_address or 'N/A',
        'attack_type': log.attack_type,
        'severity': log.severity or 'LOW',
        'country': log.country or '',
        'is_tor': log.is_tor,
        'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
    } for log in logs]
    return JsonResponse({'logs': log_list, 'total': total})


@login_required
def firewall_view(request):
    """Firewall control panel — view/unblock IPs."""
    now = timezone.now()
    blocks = BlockedIP.objects.all().order_by('-blocked_at')[:200]
    active = [b for b in blocks if b.permanent or (b.expires_at and b.expires_at > now)]
    expired = [b for b in blocks if not b.permanent and b.expires_at and b.expires_at <= now]

    context = {
        'active_blocks': active,
        'expired_blocks': expired,
        'total_active': len(active),
        'total_ever': BlockedIP.objects.count(),
        'observe_only': getattr(settings, 'FIREWALL_OBSERVE_ONLY', False),
        'os_integration': getattr(settings, 'FIREWALL_OS_INTEGRATION', False),
    }
    return render(request, 'detector/firewall.html', context)


@login_required
@require_POST
def firewall_unblock(request):
    ip = request.POST.get('ip', '').strip()
    if not ip:
        return JsonResponse({'ok': False, 'error': 'no ip'}, status=400)
    removed = unblock_ip(ip)
    return JsonResponse({'ok': True, 'removed': removed})


@login_required
@require_POST
def firewall_manual_block(request):
    ip = request.POST.get('ip', '').strip()
    reason = request.POST.get('reason', 'Manual block by analyst')
    duration = int(request.POST.get('duration', '3600'))
    permanent = request.POST.get('permanent') == 'on'
    if not ip:
        return JsonResponse({'ok': False, 'error': 'no ip'}, status=400)
    b = apply_block(ip, reason=reason, severity='HIGH',
                    duration_seconds=duration, permanent=permanent)
    return JsonResponse({'ok': True, 'id': b.id})


@login_required
def export_forensic_pdf(request):
    analyst_name = getattr(settings, 'HONEYPOT_ANALYST_NAME', 'CyberSentinel Analyst')
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="CyberSentinel_Forensic_Report.pdf"'
    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("CYBER-SENTINEL: FORENSIC AUDIT REPORT", styles['Title']))
    elements.append(Paragraph(f"Analyst: {analyst_name}", styles['Normal']))
    elements.append(Paragraph(f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    total = AttackLog.objects.count()
    critical = AttackLog.objects.filter(severity="CRITICAL").count()
    high = AttackLog.objects.filter(severity="HIGH").count()
    blocked = BlockedIP.objects.count()
    elements.append(Paragraph(
        f"Total Incidents: {total} | Critical: {critical} | High: {high} | Blocked IPs: {blocked}",
        styles['Normal']
    ))
    elements.append(Spacer(1, 20))

    data = [['IP ADDRESS', 'ATTACK VECTOR', 'SEVERITY', 'COUNTRY', 'TIMESTAMP']]
    # Cap to latest 500 to avoid memory blow
    for log in AttackLog.objects.all().order_by('-timestamp')[:500]:
        data.append([
            log.ip_address or 'N/A',
            log.attack_type,
            log.severity or 'LOW',
            log.country_code or '-',
            log.timestamp.strftime("%Y-%m-%d %H:%M"),
        ])

    t = Table(data, colWidths=[90, 170, 60, 55, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00ff41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
    ]))
    elements.append(t)
    doc.build(elements)
    return response


@login_required
def export_ioc_json(request):
    """Export blocked IPs as a threat-intel IOC feed."""
    feed = [{
        'ip': b.ip_address,
        'reason': b.reason,
        'severity': b.severity,
        'first_seen': b.blocked_at.isoformat(),
        'permanent': b.permanent,
    } for b in BlockedIP.objects.all()]
    return JsonResponse({'generated_at': timezone.now().isoformat(), 'iocs': feed})


def home_choice(request):
    return render(request, 'detector/choice.html')
