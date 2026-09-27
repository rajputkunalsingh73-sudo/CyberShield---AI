import uuid

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils.deconstruct import deconstructible
from django.db import models


@deconstructible
class PrivateReportStorage(FileSystemStorage):
    def __init__(self):
        super().__init__(location=settings.PRIVATE_REPORT_ROOT, base_url="/__private_reports_not_servable__/")


def private_report_path(instance, filename):
    return f"{instance.scan.user_id}/{uuid.uuid4().hex}.pdf"


class Report(models.Model):
    scan = models.ForeignKey("scanner.Scan", on_delete=models.CASCADE, related_name="reports")
    report_file = models.FileField(upload_to=private_report_path, storage=PrivateReportStorage())
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Report for scan {self.scan_id}"
