from django.conf import settings
from django.db import models


class Scan(models.Model):
    STATUS_CHOICES = [("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans")
    target_url = models.URLField(max_length=2048)
    scan_date = models.DateTimeField(auto_now_add=True, db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="queued", db_index=True)
    security_score = models.PositiveSmallIntegerField(default=0)
    scan_duration = models.FloatField(default=0)
    is_demo = models.BooleanField(default=False)
    failure_message = models.CharField(max_length=240, blank=True)

    class Meta:
        ordering = ["-scan_date"]
        indexes = [models.Index(fields=["user", "-scan_date"]), models.Index(fields=["user", "status"])]

    def __str__(self):
        return f"{self.target_url} · {self.status}"

    @property
    def findings_count(self):
        return self.vulnerabilities.count()

    @property
    def severity_counts(self):
        counts = {key: 0 for key, label in Vulnerability.SEVERITY_CHOICES}
        for item in self.vulnerabilities.values("severity").annotate(total=models.Count("id")):
            counts[item["severity"]] = item["total"]
        return counts


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Informational")]
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="vulnerabilities")
    name = models.CharField(max_length=180)
    category = models.CharField(max_length=80, db_index=True)
    severity = models.CharField(max_length=12, choices=SEVERITY_CHOICES, db_index=True)
    description = models.TextField()
    evidence = models.TextField(blank=True)
    impact = models.TextField()
    recommendation = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["severity", "-detected_at"]
        indexes = [models.Index(fields=["scan", "severity"]), models.Index(fields=["category", "severity"])]

    def __str__(self):
        return self.name
