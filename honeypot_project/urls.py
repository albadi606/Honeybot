from django.contrib import admin
from django.urls import path, re_path
from detector import views
from detector.canary import canary_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home_choice, name='choice'),
    path('login/', views.honeypot_login, name='user_login'),
    path('dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/api/', views.dashboard_api, name='dashboard_api'),
    path('simulate/', views.simulate_attack_view, name='simulate'),
    path('export-pdf/', views.export_forensic_pdf, name='export_pdf'),
    path('export-iocs/', views.export_ioc_json, name='export_iocs'),
    path('firewall/', views.firewall_view, name='firewall'),
    path('firewall/unblock/', views.firewall_unblock, name='firewall_unblock'),
    path('firewall/block/', views.firewall_manual_block, name='firewall_block'),

    # Canary decoy endpoints — any access = CRITICAL + auto-block
    re_path(r'^(?P<token>\.env)/?$', canary_view, name='canary_env'),
    re_path(r'^(?P<token>id_rsa)/?$', canary_view, name='canary_id_rsa'),
    re_path(r'^(?P<token>backup\.sql)/?$', canary_view, name='canary_sql'),
    re_path(r'^(?P<token>wp-admin)/?$', canary_view, name='canary_wp'),
    re_path(r'^(?P<token>\.git/config)$', canary_view, name='canary_git'),
]
