
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=2048)),
                ('scan_date', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('status', models.CharField(choices=[('queued', 'Queued'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], db_index=True, default='queued', max_length=16)),
                ('security_score', models.PositiveSmallIntegerField(default=0)),
                ('scan_duration', models.FloatField(default=0)),
                ('is_demo', models.BooleanField(default=False)),
                ('failure_message', models.CharField(blank=True, max_length=240)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scans', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-scan_date'],
            },
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=180)),
                ('category', models.CharField(db_index=True, max_length=80)),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Informational')], db_index=True, max_length=12)),
                ('description', models.TextField()),
                ('evidence', models.TextField(blank=True)),
                ('impact', models.TextField()),
                ('recommendation', models.TextField()),
                ('detected_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vulnerabilities', to='scanner.scan')),
            ],
            options={
                'ordering': ['severity', '-detected_at'],
            },
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['user', '-scan_date'], name='scanner_sca_user_id_c1742e_idx'),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['user', 'status'], name='scanner_sca_user_id_432214_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['scan', 'severity'], name='scanner_vul_scan_id_65e102_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['category', 'severity'], name='scanner_vul_categor_0065f0_idx'),
        ),
    ]
