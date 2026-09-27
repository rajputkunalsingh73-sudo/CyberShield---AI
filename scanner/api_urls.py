from django.urls import path
from .api_views import ReportListView, ScanListCreateView, VulnerabilityDetailView, VulnerabilityListView, ai_analysis_view, create_report_view, download_report_view
from .views import scan_detail_api_view

urlpatterns = [
    path("scans/", ScanListCreateView.as_view(), name="api_scans"),
    path("scans/<int:scan_id>/", scan_detail_api_view, name="api_scan_detail"),
    path("scans/<int:scan_id>/results/", scan_detail_api_view, name="api_scan_results"),
    path("scans/<int:scan_id>/generate-report/", create_report_view, name="api_create_report"),
    path("vulnerabilities/", VulnerabilityListView.as_view(), name="api_vulnerabilities"),
    path("vulnerabilities/<int:vulnerability_id>/", VulnerabilityDetailView.as_view(), name="api_vulnerability_detail"),
    path("vulnerabilities/<int:vulnerability_id>/ai-analysis/", ai_analysis_view, name="api_ai_analysis"),
    path("reports/", ReportListView.as_view(), name="api_reports"),
    path("reports/<int:report_id>/download/", download_report_view, name="api_download_report"),
]
