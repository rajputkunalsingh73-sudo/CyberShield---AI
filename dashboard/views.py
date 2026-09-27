import json
import os

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from django.db.models import Case, IntegerField, When
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.conf import settings as django_settings
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from ai_analysis.models import AIAnalysis
from ai_analysis.services import analyze_finding
from audit_logs.services import record_event
from reports.services import generate_report
from scanner.models import Scan, Vulnerability
from scanner.services import SafeScanError, create_demo_scan, create_user_scan, run_scan


def priority_order(queryset):
    return queryset.order_by(Case(When(severity="critical", then=0), When(severity="high", then=1), When(severity="medium", then=2), When(severity="low", then=3), When(severity="info", then=4), default=5, output_field=IntegerField()), "-detected_at")


def home(request):
    return render(request, "dashboard/home.html")


@login_required
def dashboard(request):
    scans = Scan.objects.filter(user=request.user)
    recent = scans[:6]
    all_findings = Vulnerability.objects.filter(scan__user=request.user)
    severity_counts = {key: all_findings.filter(severity=key).count() for key, label in Vulnerability.SEVERITY_CHOICES}
    categories = list(all_findings.values_list("category", flat=True).distinct()[:7])
    category_counts = [all_findings.filter(category=category).count() for category in categories]
    score_points = list(scans.filter(status="completed").order_by("-scan_date").values_list("scan_date", "security_score")[:8])[::-1]
    score_values = [score for scan_date, score in score_points]
    score_labels = [scan_date.strftime("%d %b") for scan_date, score in score_points]
    context = {
        "total_scans": scans.count(),
        "total_findings": all_findings.count(),
        "high_risk": all_findings.filter(severity__in=["critical", "high"]).count(),
        "avg_score": round(sum(score_values) / len(score_values)) if score_values else 0,
        "recent_scans": recent,
        "severity_labels": json.dumps(["Critical", "High", "Medium", "Low", "Informational"]),
        "severity_values": json.dumps([severity_counts.get(key, 0) for key in ["critical", "high", "medium", "low", "info"]]),
        "category_labels": json.dumps(categories),
        "category_values": json.dumps(category_counts),
        "score_labels": json.dumps(score_labels),
        "score_values": json.dumps(score_values),
        "severity_counts": severity_counts,
    }
    return render(request, "dashboard/dashboard.html", context)


@login_required
def new_scan(request):
    if request.method == "POST":
        target = request.POST.get("target_url", "").strip()
        authorized = request.POST.get("authorized") == "on"
        if not authorized:
            messages.error(request, "Scanning requires confirmation that you are authorized to assess this target.")
            return render(request, "dashboard/new_scan.html", {"target": target})
        if not target or len(target) > 2048:
            messages.error(request, "Please enter a valid HTTP/HTTPS URL.")
            return render(request, "dashboard/new_scan.html", {"target": target})
        scan = create_user_scan(request.user.pk, target)
        if scan is None:
            messages.error(request, "The hourly scan limit has been reached. Please try again later.")
            return render(request, "dashboard/new_scan.html", {"target": target})
        record_event("scan_started", request, detail=f"Scan {scan.pk} queued")
        try:
            run_scan(scan)
        except SafeScanError as exc:
            scan.status = "failed"
            scan.failure_message = str(exc)[:240]
            scan.save(update_fields=["status", "failure_message"])
            record_event("scan_failed", request, detail=f"Scan {scan.pk} failed")
            messages.error(request, str(exc))
            return redirect("scan_detail", scan_id=scan.pk)
        except Exception:
            scan.status = "failed"
            scan.failure_message = "Security scan could not be completed. Please verify the target is reachable and try again."
            scan.save(update_fields=["status", "failure_message"])
            record_event("scan_failed", request, detail=f"Scan {scan.pk} failed")
            messages.error(request, scan.failure_message)
            return redirect("scan_detail", scan_id=scan.pk)
        record_event("scan_completed", request, detail=f"Scan {scan.pk} completed with score {scan.security_score}")
        messages.success(request, "Security check complete. Review the results below.")
        return redirect("scan_detail", scan_id=scan.pk)
    return render(request, "dashboard/new_scan.html")


@login_required
@require_POST
def demo_scan(request):
    scan = create_demo_scan(request.user)
    record_event("scan_completed", request, detail=f"Demo scan {scan.pk} created")
    messages.info(request, "DEMO DATA loaded. No real website was contacted.")
    return redirect("scan_detail", scan_id=scan.pk)


@login_required
def history(request):
    scans = Scan.objects.filter(user=request.user).prefetch_related("vulnerabilities")
    query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "")
    sort = request.GET.get("sort", "-scan_date")
    if query:
        scans = scans.filter(target_url__icontains=query)
    if status_filter in {"completed", "failed", "running", "queued"}:
        scans = scans.filter(status=status_filter)
    if sort in {"-scan_date", "scan_date", "security_score", "-security_score"}:
        scans = scans.order_by(sort)
    page_obj = Paginator(scans, 15).get_page(request.GET.get("page"))
    return render(request, "dashboard/history.html", {"scans": page_obj, "page_obj": page_obj, "query": query, "status_filter": status_filter, "sort": sort})


@login_required
def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan.objects.prefetch_related("vulnerabilities__analyses"), pk=scan_id, user=request.user)
    latest_analyses = {item.vulnerability_id: item for item in AIAnalysis.objects.filter(vulnerability__scan=scan).order_by("-created_at")}
    return render(request, "dashboard/detail.html", {"scan": scan, "findings": priority_order(scan.vulnerabilities.all()), "severity_counts": scan.severity_counts, "analyses": latest_analyses})


@login_required
@require_POST
def analyze_finding_view(request, vulnerability_id):
    finding = get_object_or_404(Vulnerability, pk=vulnerability_id, scan__user=request.user)
    record_event("ai_analysis_requested", request, detail=f"Finding {finding.pk}")
    result = analyze_finding(finding)
    AIAnalysis.objects.create(vulnerability=finding, explanation=result["explanation"], impact_analysis=result["impact_analysis"], evidence_explanation=result["evidence_explanation"], remediation=result["remediation"], priority_explanation=result["priority_explanation"])
    messages.success(request, "AI explanation prepared. No external AI provider is configured unless enabled by the operator.")
    return redirect("scan_detail", scan_id=finding.scan_id)


@login_required
@require_POST
def download_pdf(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id, user=request.user, status="completed")
    report = generate_report(scan)
    record_event("report_generated", request, detail=f"Report for scan {scan.pk}")
    return FileResponse(report.report_file.open("rb"), as_attachment=True, filename=f"cybershield-scan-{scan.pk}.pdf", content_type="application/pdf")


@login_required
def settings_page(request):
    if request.method == "POST":
        email = request.POST.get("email", "")[:254]
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Please enter a valid email address.")
            return render(request, "dashboard/settings.html", {"ai_provider_ready": bool(os.getenv("AI_API_URL", "").strip() and os.getenv("AI_API_KEY", "").strip()), "severity_penalties": django_settings.SEVERITY_PENALTIES})
        if request.user.__class__.objects.filter(email__iexact=email).exclude(pk=request.user.pk).exists():
            messages.error(request, "That email address is already associated with another account.")
            return render(request, "dashboard/settings.html", {"ai_provider_ready": bool(os.getenv("AI_API_URL", "").strip() and os.getenv("AI_API_KEY", "").strip()), "severity_penalties": django_settings.SEVERITY_PENALTIES})
        request.user.first_name = request.POST.get("first_name", "")[:150]
        request.user.email = email
        request.user.save(update_fields=["first_name", "email"])
        messages.success(request, "Account profile updated.")
        return redirect("settings")
    return render(request, "dashboard/settings.html", {"ai_provider_ready": bool(os.getenv("AI_API_URL", "").strip() and os.getenv("AI_API_KEY", "").strip()), "severity_penalties": django_settings.SEVERITY_PENALTIES})


@login_required
def vulnerabilities(request):
    findings = priority_order(Vulnerability.objects.filter(scan__user=request.user).select_related("scan"))
    query = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "")
    if query:
        findings = findings.filter(name__icontains=query) | findings.filter(category__icontains=query)
    if severity in {"critical", "high", "medium", "low", "info"}:
        findings = findings.filter(severity=severity)
    page_obj = Paginator(findings, 15).get_page(request.GET.get("page"))
    return render(request, "dashboard/vulnerabilities.html", {"findings": page_obj, "page_obj": page_obj, "query": query, "severity_filter": severity})


@login_required
def report_history(request):
    from reports.models import Report
    reports = Report.objects.filter(scan__user=request.user).select_related("scan")
    page_obj = Paginator(reports, 15).get_page(request.GET.get("page"))
    return render(request, "dashboard/reports.html", {"reports": page_obj, "page_obj": page_obj})


@login_required
def finding_detail(request, vulnerability_id):
    finding = get_object_or_404(Vulnerability.objects.select_related("scan").prefetch_related("analyses"), pk=vulnerability_id, scan__user=request.user)
    references = {
        "Security Headers": ("OWASP HTTP Security Response Headers Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html", "The scanner inspected the bounded public HTTP response headers for the named security control."),
        "HTTPS/TLS": ("OWASP Transport Layer Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html", "The scanner followed at most three same-host redirects, validated the HTTPS certificate against its system trust store, and recorded the negotiated protocol where available."),
        "Cookie Security": ("OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html", "The scanner inspected Set-Cookie attribute names only and did not store cookie values."),
        "CORS Configuration": ("OWASP CORS Origin Header Scrutiny", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny", "The scanner made a safe OPTIONS preflight using a reserved .invalid origin and reviewed returned CORS policy headers."),
        "HTTP Methods": ("OWASP REST Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html", "The scanner used the OPTIONS response Allow header; it did not send TRACE, write, or other state-changing requests."),
        "Information Disclosure": ("OWASP Top 10", "https://owasp.org/www-project-top-ten/", "The scanner reviewed public server headers and a response excerpt capped at 32 KB for limited common debug-error markers; response bodies were not stored."),
        "Technology Detection": ("OWASP Top 10", "https://owasp.org/www-project-top-ten/", "The scanner inferred only broad technology hints exposed in public response headers and did not probe detected software."),
    }
    latest_analysis = finding.analyses.first()
    reference = references.get(finding.category, ("OWASP Top 10", "https://owasp.org/www-project-top-ten/", "The scanner recorded a bounded, passive observation from the public response."))
    return render(request, "dashboard/finding_detail.html", {"finding": finding, "analysis": latest_analysis, "reference": reference, "detection_method": reference[2]})
