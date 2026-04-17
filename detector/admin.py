from django.contrib import admin
from .models import AttackLog, BlockedIP, CanaryHit


@admin.register(AttackLog)
class AttackLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'attack_type', 'severity', 'country_code',
                    'is_tor', 'threat_score', 'username', 'timestamp')
    list_filter = ('attack_type', 'severity', 'is_tor', 'country_code', 'timestamp')
    search_fields = ('ip_address', 'username', 'attack_type', 'country')
    readonly_fields = ('ip_address', 'attack_type', 'severity', 'username', 'password',
                       'user_agent', 'request_uri', 'payload', 'country', 'country_code',
                       'asn', 'is_tor', 'threat_score', 'session_key', 'timestamp')
    list_per_page = 50


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'severity', 'hits',
                    'block_count', 'permanent', 'expires_at', 'blocked_at')
    list_filter = ('severity', 'permanent', 'os_firewall_applied')
    search_fields = ('ip_address', 'reason')
    actions = ['make_permanent', 'remove_block']

    @admin.action(description="Promote to permanent block")
    def make_permanent(self, request, queryset):
        queryset.update(permanent=True, expires_at=None)

    @admin.action(description="Remove block (unblock IP)")
    def remove_block(self, request, queryset):
        from .firewall import unblock_ip
        for b in queryset:
            unblock_ip(b.ip_address)


@admin.register(CanaryHit)
class CanaryHitAdmin(admin.ModelAdmin):
    list_display = ('token', 'ip_address', 'request_uri', 'timestamp')
    list_filter = ('token', 'timestamp')
    search_fields = ('ip_address', 'token')
    readonly_fields = ('token', 'ip_address', 'user_agent', 'request_uri', 'timestamp')
