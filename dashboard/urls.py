from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("scans/new/", views.new_scan, name="new_scan"),
    path("scans/demo/", views.demo_scan, name="demo_scan"),
    path("scans/history/", views.history, name="scan_history"),
    path("vulnerabilities/", views.vulnerabilities, name="vulnerabilities"),
    path("reports/", views.report_history, name="report_history"),
    path("findings/<int:vulnerability_id>/", views.finding_detail, name="finding_detail"),
    path("scans/<int:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scans/<int:scan_id>/report/", views.download_pdf, name="download_pdf"),
    path("findings/<int:vulnerability_id>/analyze/", views.analyze_finding_view, name="analyze_finding"),
    path("settings/", views.settings_page, name="settings"),
]
