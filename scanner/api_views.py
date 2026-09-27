from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from ai_analysis.models import AIAnalysis
from ai_analysis.services import analyze_finding
from audit_logs.services import record_event
from reports.services import generate_report
from reports.models import Report
from .models import Scan, Vulnerability
from .serializers import ReportSerializer, ScanSerializer, VulnerabilitySerializer
from .services import SafeScanError, create_user_scan, run_scan


class ScanThrottle(UserRateThrottle):
    rate = "5/hour"


class ScanListCreateView(generics.ListCreateAPIView):
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]

    def get_throttles(self):
        if self.request.method == "POST":
            return [ScanThrottle()]
        return super().get_throttles()

    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user).prefetch_related("vulnerabilities")

    def create(self, request, *args, **kwargs):
        if request.data.get("authorized") not in (True, "true", "on", "1", 1):
            return Response({"detail": "Scanning requires confirmation that you are authorized to assess this target."}, status=status.HTTP_400_BAD_REQUEST)
        target = request.data.get("target_url", "")
        if not isinstance(target, str) or not target.strip() or len(target) > 2048:
            return Response({"detail": "Please enter a valid HTTP/HTTPS URL."}, status=status.HTTP_400_BAD_REQUEST)
        scan = create_user_scan(request.user.pk, target.strip())
        if scan is None:
            return Response({"detail": "The hourly scan limit has been reached. Please try again later."}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        record_event("scan_started", request, detail=f"Scan {scan.pk} queued")
        try:
            run_scan(scan)
        except SafeScanError as exc:
            scan.status = "failed"
            scan.failure_message = str(exc)[:240]
            scan.save(update_fields=["status", "failure_message"])
            record_event("scan_failed", request, detail=f"Scan {scan.pk} failed")
            return Response({"detail": str(exc), "scan_id": scan.pk}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            scan.status = "failed"
            scan.failure_message = "Security scan could not be completed. Please verify the target is reachable and try again."
            scan.save(update_fields=["status", "failure_message"])
            record_event("scan_failed", request, detail=f"Scan {scan.pk} failed")
            return Response({"detail": scan.failure_message, "scan_id": scan.pk}, status=status.HTTP_502_BAD_GATEWAY)
        record_event("scan_completed", request, detail=f"Scan {scan.pk} completed with score {scan.security_score}")
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)


class VulnerabilityListView(generics.ListAPIView):
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Vulnerability.objects.filter(scan__user=self.request.user).select_related("scan")


class VulnerabilityDetailView(generics.RetrieveAPIView):
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    lookup_url_kwarg = "vulnerability_id"

    def get_queryset(self):
        return Vulnerability.objects.filter(scan__user=self.request.user)


class ReportListView(generics.ListAPIView):
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(scan__user=self.request.user).select_related("scan")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ai_analysis_view(request, vulnerability_id):
    vulnerability = get_object_or_404(Vulnerability, pk=vulnerability_id, scan__user=request.user)
    record_event("ai_analysis_requested", request, detail=f"Finding {vulnerability.pk}")
    result = analyze_finding(vulnerability)
    analysis = AIAnalysis.objects.create(vulnerability=vulnerability, explanation=result["explanation"], impact_analysis=result["impact_analysis"], evidence_explanation=result["evidence_explanation"], remediation=result["remediation"], priority_explanation=result["priority_explanation"])
    return Response({"id": analysis.pk, **result})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_report_view(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id, user=request.user, status="completed")
    report = generate_report(scan)
    record_event("report_generated", request, detail=f"Report for scan {scan.pk}")
    return Response({"id": report.pk, "download_url": f"/api/reports/{report.pk}/download/"}, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def download_report_view(request, report_id):
    report = get_object_or_404(Report, pk=report_id, scan__user=request.user)
    try:
        file_handle = report.report_file.open("rb")
    except (FileNotFoundError, ValueError):
        raise Http404
    return FileResponse(file_handle, as_attachment=True, filename=report.report_file.name.rsplit("/", 1)[-1], content_type="application/pdf")
