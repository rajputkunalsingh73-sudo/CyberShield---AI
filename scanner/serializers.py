from rest_framework import serializers
from .models import Scan, Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)

    class Meta:
        model = Vulnerability
        fields = ("id", "name", "category", "severity", "severity_label", "description", "evidence", "impact", "recommendation", "detected_at")


class ScanSerializer(serializers.ModelSerializer):
    findings_count = serializers.IntegerField(read_only=True)
    findings = VulnerabilitySerializer(source="vulnerabilities", many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ("id", "target_url", "scan_date", "status", "security_score", "scan_duration", "is_demo", "findings_count", "findings")
        read_only_fields = ("scan_date", "status", "security_score", "scan_duration", "is_demo")


class ReportSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    target_url = serializers.CharField(source="scan.target_url", read_only=True)

    class Meta:
        from reports.models import Report
        model = Report
        fields = ("id", "scan_id", "target_url", "created_at", "download_url")

    def get_download_url(self, obj):
        request = self.context.get("request")
        path = f"/api/reports/{obj.pk}/download/"
        return request.build_absolute_uri(path) if request else path
