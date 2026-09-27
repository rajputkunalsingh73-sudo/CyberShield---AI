
import reports.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='report',
            name='report_file',
            field=models.FileField(storage=reports.models.PrivateReportStorage(), upload_to=reports.models.private_report_path),
        ),
    ]
