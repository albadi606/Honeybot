from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detector', '0002_add_severity_remove_inquiry'),
    ]

    operations = [
        migrations.AddField(
            model_name='attacklog',
            name='payload',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='country',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='country_code',
            field=models.CharField(blank=True, max_length=4, null=True),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='asn',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='is_tor',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='threat_score',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='attacklog',
            name='session_key',
            field=models.CharField(blank=True, db_index=True, max_length=40, null=True),
        ),
        migrations.AlterField(
            model_name='attacklog',
            name='ip_address',
            field=models.GenericIPAddressField(blank=True, db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name='attacklog',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True, db_index=True),
        ),
        migrations.AddIndex(
            model_name='attacklog',
            index=models.Index(fields=['ip_address', 'timestamp'], name='detector_at_ip_ts_idx'),
        ),
        migrations.AddIndex(
            model_name='attacklog',
            index=models.Index(fields=['severity', 'timestamp'], name='detector_at_sev_ts_idx'),
        ),
        migrations.CreateModel(
            name='BlockedIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('ip_address', models.GenericIPAddressField(db_index=True, unique=True)),
                ('reason', models.CharField(max_length=200)),
                ('severity', models.CharField(default='LOW', max_length=10)),
                ('hits', models.IntegerField(default=1)),
                ('block_count', models.IntegerField(default=1)),
                ('blocked_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('permanent', models.BooleanField(default=False)),
                ('os_firewall_applied', models.BooleanField(default=False)),
                ('notes', models.TextField(blank=True, null=True)),
            ],
            options={'ordering': ['-blocked_at']},
        ),
        migrations.CreateModel(
            name='CanaryHit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('token', models.CharField(max_length=100)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('request_uri', models.TextField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
            options={'ordering': ['-timestamp']},
        ),
    ]
