
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AIAnalysis',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('explanation', models.TextField()),
                ('impact_analysis', models.TextField()),
                ('remediation', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('vulnerability', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='analyses', to='scanner.vulnerability')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
