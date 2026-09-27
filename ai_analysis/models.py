from django.db import models


class AIAnalysis(models.Model):
    vulnerability = models.ForeignKey("scanner.Vulnerability", on_delete=models.CASCADE, related_name="analyses")
    explanation = models.TextField()
    impact_analysis = models.TextField()
    evidence_explanation = models.TextField(blank=True, default="")
    remediation = models.TextField()
    priority_explanation = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
