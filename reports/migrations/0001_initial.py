
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_file', models.FileField(upload_to='reports/%Y/%m/')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='scanner.scan')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
