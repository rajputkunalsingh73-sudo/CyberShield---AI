
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ai_analysis', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='aianalysis',
            name='evidence_explanation',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='aianalysis',
            name='priority_explanation',
            field=models.TextField(blank=True, default=''),
        ),
    ]
