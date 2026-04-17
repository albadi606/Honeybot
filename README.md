# CyberSentinel Honeypot

An interactive honeypot + adaptive firewall built on Django. It lures attackers with a fake login portal, identifies attack patterns (SQLi, XSS, command injection, traversal, LFI/RFI, brute-force, scanner fingerprints), logs every request with geo/TOR enrichment, fires webhook alerts, exposes canary/decoy files, and auto-blocks malicious IPs with both application-level and (optional) OS-level firewall rules.

---

## Features

### Attack Detection
- Regex-based classifier covering 8 attack vectors
- Patterns precompiled at startup (fast path on every request)
- Scans the **full request surface** — path, query string, POST body, User-Agent, Referer, credentials
- Per-vector severity tiers (CRITICAL / HIGH / MEDIUM / LOW)

### Adaptive Firewall
- `FirewallMiddleware` — blocks known-bad IPs before the view runs
- `RateLimitMiddleware` — in-memory sliding window (60 req / 10 s default), triggers auto-block on flood
- Configurable auto-block rules per severity tier (count + window → duration)
- Repeat-offender escalation → permanent ban after N blocks
- Optional OS-level integration via `iptables` (Linux) or `netsh advfirewall` (Windows)
- Observe-only mode (log, don't enforce) for staging
- Admin UI at `/firewall/` — view, manual block, manual unblock

### Threat Intelligence
- GeoIP lookup (MaxMind GeoLite2 DB, optional)
- TOR exit-node list auto-refresh (hourly)
- Per-IP threat score
- IOC export endpoint `/export-iocs/` → JSON feed of blocked IPs

### Canary / Decoy Tokens
- Endpoints for `.env`, `id_rsa`, `backup.sql`, `wp-admin`, `.git/config`
- Any access = instant CRITICAL log + 24h auto-block + alert

### Alerting
- Webhook dispatcher (auto-detects Slack / Discord / generic JSON)
- Configurable minimum severity
- Fire-and-forget (never blocks request flow)

### Forensics
- Real-time dashboard with Chart.js (threat distribution, 24h timeline, severity pie, top IPs)
- PDF export (ReportLab) — analyst-branded forensic report
- JSON IOC export for SIEM ingestion
- Session keys on each log for replay correlation

---

## Architecture

```
 +-----------------+
 |  Attacker HTTP  |
 +--------+--------+
          |
          v
 +-----------------------------+
 | FirewallMiddleware          |  <-- known-bad IP? short-circuit 403
 +-----------------------------+
          |
          v
 +-----------------------------+
 | RateLimitMiddleware         |  <-- flood guard (in-memory deque)
 +-----------------------------+
          |
          v
 +-----------------------------+
 | Django view (honeypot_login)|
 +--------+--------------------+
          |
          v
 +-----------------------------+
 | detection.scan_request()    |  <-- regex classifier
 +--------+--------------------+
          |
          v
 +-----------------------------+
 | threat_intel.enrich()       |  <-- geo + TOR
 +--------+--------------------+
          |
          v
 +-----------------------------+
 | AttackLog saved             |
 +--------+--------------------+
          |
          v
 +-----------------------------+
 | evaluate_auto_block()       |  <-- threshold tripped?
 +--------+--------------------+
          |
          v
 +-----------------------------+
 | apply_block() + send_alert()|
 +-----------------------------+
```

---

## Project Layout

```
honeypot_project/
  Dockerfile
  docker-compose.yml
  manage.py
  requirements.txt
  honeypot_project/
    settings.py        # hardened config + FIREWALL_RULES
    urls.py            # routes + canary endpoints
  detector/
    models.py          # AttackLog, BlockedIP, CanaryHit
    detection.py       # regex classifier
    firewall.py        # middleware + apply_block/unblock
    threat_intel.py    # GeoIP + TOR
    alerts.py          # webhook dispatcher
    canary.py          # decoy endpoints
    views.py           # login, dashboard, firewall UI, exports
    admin.py           # Django admin registrations
    migrations/
      0003_firewall_and_enrichment.py
    templates/detector/
      login.html, dashboard.html, firewall.html, simulate.html, choice.html, fake_area.html
```

---

## Setup

### Local (dev)

```bash
python -m venv .venv
source .venv/bin/activate                # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd honeypot_project
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8000
```

### Docker

```bash
docker compose up --build
```

---

## Configuration

All via environment variables. Defaults are sane for dev; override in prod.

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | insecure dev key | **Set in prod** |
| `DEBUG` | `0` | `1` enables Django debug pages |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames |
| `USE_X_FORWARDED_HOST` | `0` | Trust `X-Forwarded-For` (behind reverse proxy) |
| `TRUSTED_PROXIES` | _empty_ | Comma-separated proxy IPs |
| `FIREWALL_ENABLED` | `1` | Master switch |
| `FIREWALL_OBSERVE_ONLY` | `0` | Log blocks but don't enforce |
| `FIREWALL_OS_INTEGRATION` | `0` | Apply iptables/netsh rules |
| `FIREWALL_PERMABAN_REPEAT` | `5` | Blocks before permanent ban |
| `ALERT_WEBHOOK_URL` | _empty_ | Slack/Discord/generic URL |
| `ALERT_MIN_SEVERITY` | `CRITICAL` | Minimum sev to fire alert |
| `GEOIP_DB_PATH` | _empty_ | Path to `GeoLite2-City.mmdb` |
| `ANALYST_NAME` | `CyberSentinel Analyst` | Printed on PDF report |
| `LOG_RETENTION_HOURS` | `720` | Retention horizon (hours) |

### Firewall rules

Defined in `settings.FIREWALL_RULES`. Defaults:

| Severity | Window | Threshold | Block duration |
|---|---|---|---|
| CRITICAL | 60 s    | 1 hit  | 24 h |
| HIGH     | 600 s   | 3 hits | 1 h |
| MEDIUM   | 600 s   | 5 hits | 30 m |
| LOW      | 300 s   | 10 hits| 15 m |

Override by editing the dict in `settings.py`.

---

## URLs

| Path | Purpose |
|---|---|
| `/`                 | Landing page |
| `/login/`           | Honeypot fake login (CSRF-exempt on purpose) |
| `/dashboard/`       | Live forensics dashboard (auth required) |
| `/dashboard/api/`   | JSON feed for auto-refresh |
| `/firewall/`        | Block list + manual block/unblock |
| `/simulate/`        | Analyst payload simulator |
| `/export-pdf/`      | Forensic PDF report |
| `/export-iocs/`     | IOC feed (JSON) |
| `/admin/`           | Django admin — NEVER firewalled |
| `/.env`, `/id_rsa`, `/backup.sql`, `/wp-admin`, `/.git/config` | Canary decoys |

---

## Security Hardening (already applied)

- Regex precompiled once at import (no per-request recompile)
- `X-Forwarded-For` only honored when proxy is in `TRUSTED_PROXIES`
- Admin + static paths bypass firewall (no lock-out footgun)
- DB indexes on `ip_address`, `severity`, `timestamp` for dashboard aggregates done in SQL (not Python loop)
- PDF export capped at latest 500 logs (was unbounded)
- CSRF enforced on dashboard APIs; disabled only on honeypot login by design
- `simulate_attack_view` now requires login

---

## Enabling OS-Level Firewall

`FIREWALL_OS_INTEGRATION=1` makes `apply_block()` shell out:

- **Linux**: `iptables -A INPUT -s <ip> -j DROP`
- **Windows**: `netsh advfirewall firewall add rule name=CyberSentinel_Block_<ip> ...`

Requires the app to run with sufficient privilege (CAP_NET_ADMIN / Administrator). If the call fails, the app still logs the block in the DB — nothing crashes.

**Recommended alternative**: leave `FIREWALL_OS_INTEGRATION=0` and let a `fail2ban` jail tail the Django log — safer privilege model.

---

## Extending

- **Add a new attack vector**: append to `ATTACK_PATTERNS` in `detector/detection.py`. Patterns auto-compile on startup.
- **Add a new canary token**: add to `_CANARY_CONTENT` dict in `detector/canary.py` and register a `re_path` in `honeypot_project/urls.py`.
- **Change webhook format**: edit `send_alert()` in `detector/alerts.py`.
- **Add SSH honeypot**: run Cowrie as a sidecar container; stream its JSON log into `AttackLog` via a management command.
- **ML anomaly layer**: train an IsolationForest on request inter-arrival + payload entropy; call from `_log_and_react()`.

---

## Why the Firewall Improves the Honeypot

1. **Signal-to-noise** — same scanner hitting 10 000 times becomes 1 block row + N hit-counter increments instead of 10 000 noisy logs.
2. **CPU savings** — middleware short-circuits known-bad IPs before the regex layer runs.
3. **Active-defense narrative** — the system closes the loop: detect → decide → respond. Useful for threat-model write-ups and thesis/portfolio.
4. **IOC output** — `/export-iocs/` turns this into a threat feed other tooling can consume.
5. **Graduated response** — mild anomalies get warnings, confirmed attacks get bans, repeat offenders get permabans. Avoids brittle all-or-nothing rules.
6. **Reversible by design** — observe-only mode, manual unblock, expiry timestamps all shield against misconfiguration locking legitimate traffic out.

---

## Roadmap / Known Gaps

- Rate limit state is in-process memory — lost on restart and not shared across gunicorn workers. Swap for Redis before scaling horizontally.
- No distributed locking on `apply_block` (double-insert race is benign due to `unique=True` + `get_or_create`, but merits attention under high load).
- TOR list fetch is best-effort only; no retry or staleness alert.
- Canary decoys are static content — consider dynamic-per-IP payloads with embedded canarytokens.org beacons.
- No structured log shipping yet; add syslog or JSON logging handler for ELK/Splunk.

---

## License

Educational / research use. No warranty. Do not deploy on unauthorized networks.
