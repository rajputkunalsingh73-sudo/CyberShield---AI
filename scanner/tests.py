import ipaddress
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .models import Scan
from .services import SafeScanError, create_demo_scan, normalize_url, score_for


class SafeTargetTests(TestCase):
    def test_localhost_is_blocked_without_dns_lookup(self):
        with self.assertRaises(SafeScanError):
            normalize_url("http://localhost/")

    def test_private_addresses_are_blocked(self):
        records = [(2, 1, 6, "", ("10.0.0.2", 80))]
        with patch("scanner.services.socket.getaddrinfo", return_value=records):
            with self.assertRaises(SafeScanError):
                normalize_url("http://private.example/")

    def test_mixed_public_and_private_answers_are_blocked(self):
        records = [(2, 1, 6, "", ("8.8.8.8", 80)), (2, 1, 6, "", ("192.168.1.4", 80))]
        with patch("scanner.services.socket.getaddrinfo", return_value=records):
            with self.assertRaises(SafeScanError):
                normalize_url("http://mixed.example/")

    def test_nonstandard_port_is_blocked(self):
        with self.assertRaises(SafeScanError):
            normalize_url("http://example.com:8080/")

    def test_invalid_scheme_is_blocked(self):
        with self.assertRaises(SafeScanError):
            normalize_url("file:///etc/passwd")

    def test_score_uses_documented_severity_weights(self):
        findings = [type("Finding", (), {"severity": "high"})(), type("Finding", (), {"severity": "medium"})(), type("Finding", (), {"severity": "info"})()]
        self.assertEqual(score_for(findings), 77)


class WorkspaceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="owner", password="safe-demo-password", email="owner@example.test")
        self.other = User.objects.create_user(username="other", password="safe-demo-password", email="other@example.test")

    def test_register_page_available(self):
        response = self.client.get(reverse("register"))
        self.assertEqual(response.status_code, 200)

    def test_private_scan_object_not_visible_to_other_user(self):
        scan = Scan.objects.create(user=self.user, target_url="https://demo.example", status="completed", is_demo=True)
        self.client.force_login(self.other)
        response = self.client.get(reverse("scan_detail", args=[scan.pk]))
        self.assertEqual(response.status_code, 404)

    def test_demo_scan_does_not_contact_network_and_is_labeled(self):
        scan = create_demo_scan(self.user)
        self.assertTrue(scan.is_demo)
        self.assertEqual(scan.target_url, "https://demo.example")
        self.assertGreater(scan.vulnerabilities.count(), 0)
        self.assertEqual(scan.status, "completed")

    def test_authenticated_workspace_pages_render(self):
        scan = create_demo_scan(self.user)
        self.client.force_login(self.user)
        for route in ["dashboard", "new_scan", "scan_history", "settings"]:
            response = self.client.get(reverse(route))
            self.assertEqual(response.status_code, 200, route)
        response = self.client.get(reverse("scan_detail", args=[scan.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DEMO DATA")

    def test_demo_pdf_and_ai_explanation_flow(self):
        scan = create_demo_scan(self.user)
        finding = scan.vulnerabilities.first()
        self.client.force_login(self.user)
        ai_response = self.client.post(reverse("analyze_finding", args=[finding.pk]))
        self.assertEqual(ai_response.status_code, 302)
        self.assertTrue(finding.analyses.exists())
        pdf_response = self.client.post(reverse("download_pdf", args=[scan.pk]))
        self.assertEqual(pdf_response.status_code, 200)
        self.assertEqual(pdf_response["Content-Type"], "application/pdf")


    def test_api_scan_requires_authorization_confirmation(self):
        self.client.force_login(self.user)
        response = self.client.post("/api/scans/", {"target_url": "https://example.com", "authorized": False}, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Scan.objects.count(), 0)

    def test_vulnerability_and_report_lists_render(self):
        scan = create_demo_scan(self.user)
        from reports.services import generate_report
        generate_report(scan)
        self.client.force_login(self.user)
        for route in ["vulnerabilities", "report_history"]:
            response = self.client.get(reverse(route))
            self.assertEqual(response.status_code, 200, route)

    def test_report_api_is_private_and_user_scoped(self):
        from pathlib import Path
        from django.conf import settings
        from reports.services import generate_report
        scan = create_demo_scan(self.user)
        report = generate_report(scan)
        self.assertFalse(Path(report.report_file.path).is_relative_to(settings.MEDIA_ROOT))
        self.client.force_login(self.user)
        listing = self.client.get("/api/reports/")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.data), 1)
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(f"/api/reports/{report.pk}/download/").status_code, 404)


    def test_demo_link_creates_only_labeled_demo_after_signup(self):
        response = self.client.get(reverse("register") + "?demo=1")
        self.assertEqual(response.status_code, 200)
        response = self.client.post(reverse("register"), {"first_name": "New Demo", "email": "new-demo@example.test", "username": "new-demo", "password1": "Long-Preview-Only-73!Mountain", "password2": "Long-Preview-Only-73!Mountain"})
        self.assertEqual(response.status_code, 302)
        demo = Scan.objects.get(user__username="new-demo")
        self.assertTrue(demo.is_demo)
        self.assertEqual(demo.target_url, "https://demo.example")

    def test_hourly_scan_quota_uses_database_records(self):
        from .services import create_user_scan
        for index in range(5):
            Scan.objects.create(user=self.user, target_url=f"https://example-{index}.test", status="failed")
        self.assertIsNone(create_user_scan(self.user.pk, "https://blocked.example"))
        self.assertIsNotNone(create_user_scan(self.other.pk, "https://allowed.example"))

    def test_certificate_validation_failure_becomes_a_finding(self):
        from .services import CertificateCheckError, run_scan
        scan = Scan.objects.create(user=self.user, target_url="https://cert.example")
        with patch("scanner.services.normalize_url", return_value=("https://cert.example/", "cert.example", 443, "8.8.8.8")), patch("scanner.services.request_same_host", side_effect=CertificateCheckError("invalid")):
            run_scan(scan)
        scan.refresh_from_db()
        self.assertEqual(scan.status, "completed")
        self.assertTrue(scan.vulnerabilities.filter(name="HTTPS certificate validation failed").exists())
        self.assertEqual(scan.security_score, 92)


    def test_login_accepts_email_address_and_remember_me(self):
        response = self.client.post(reverse("login"), {"username": self.user.email, "password": "safe-demo-password", "remember": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session.get_expiry_age(), 1209600)

    def test_finding_detail_is_scoped_and_renders_owasp_reference(self):
        scan = create_demo_scan(self.user)
        finding = scan.vulnerabilities.filter(category="Security Headers").first()
        self.client.force_login(self.user)
        response = self.client.get(reverse("finding_detail", args=[finding.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "OWASP")
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(reverse("finding_detail", args=[finding.pk])).status_code, 404)

    def test_api_scan_list_and_finding_detail_are_user_scoped(self):
        scan = create_demo_scan(self.user)
        finding = scan.vulnerabilities.first()
        create_demo_scan(self.other)
        self.client.force_login(self.user)
        scan_response = self.client.get("/api/scans/")
        self.assertEqual(scan_response.status_code, 200)
        self.assertEqual(len(scan_response.data), 1)
        finding_response = self.client.get(f"/api/vulnerabilities/{finding.pk}/")
        self.assertEqual(finding_response.status_code, 200)
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(f"/api/vulnerabilities/{finding.pk}/").status_code, 404)

    def test_score_penalties_can_be_configured(self):
        from django.test import override_settings
        findings = [type("Finding", (), {"severity": "critical"})()]
        with override_settings(SEVERITY_PENALTIES={"critical": 42, "high": 15, "medium": 8, "low": 3, "info": 0}):
            self.assertEqual(score_for(findings), 58)
