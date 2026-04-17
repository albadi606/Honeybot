# Generated manually for CyberSentinel improvements

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detector', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='attacklog',
            name='severity',
            field=models.CharField(
                choices=[('CRITICAL', 'Critical'), ('HIGH', 'High'), ('MEDIUM', 'Medium'), ('LOW', 'Low')],
                default='LOW',
                max_length=10,
            ),
        ),
        migrations.DeleteModel(
            name='Inquiry',
        ),
        migrations.AlterModelOptions(
            name='attacklog',
            options={'ordering': ['-timestamp']},
        ),
    ]
