from django.db import models
from django.utils import timezone


class AttackLog(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    attack_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='LOW')
    username = models.CharField(max_length=150, blank=True, null=True)
    password = models.CharField(max_length=150, blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    http_method = models.CharField(max_length=10, default="POST")
    user_agent = models.TextField(blank=True, null=True)
    request_uri = models.TextField(blank=True, null=True)
    payload = models.TextField(blank=True, null=True)
    # Enrichment
    country = models.CharField(max_length=64, blank=True, null=True)
    country_code = models.CharField(max_length=4, blank=True, null=True)
    asn = models.CharField(max_length=128, blank=True, null=True)
    is_tor = models.BooleanField(default=False)
    threat_score = models.IntegerField(default=0)  # 0-100 reputation
    session_key = models.CharField(max_length=40, blank=True, null=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.attack_type} - {self.timestamp}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.CharField(max_length=200)
    severity = models.CharField(max_length=10, default='LOW')
    hits = models.IntegerField(default=1)
    block_count = models.IntegerField(default=1)  # times this IP has been blocked
    blocked_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    permanent = models.BooleanField(default=False)
    os_firewall_applied = models.BooleanField(default=False)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-blocked_at']

    def is_active(self):
        if self.permanent:
            return True
        return self.expires_at is not None and self.expires_at > timezone.now()

    def __str__(self):
        state = 'PERMA' if self.permanent else 'TEMP'
        return f"[{state}] {self.ip_address} ({self.reason})"


class CanaryHit(models.Model):
    """Triggered when attacker accesses a decoy endpoint/file."""
    token = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    request_uri = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"CANARY[{self.token}] from {self.ip_address}"
