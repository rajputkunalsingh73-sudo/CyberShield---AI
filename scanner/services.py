import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import timedelta
from urllib.parse import urljoin, urlsplit, urlunsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import transaction
from django.utils import timezone

from .models import Scan, Vulnerability

TIMEOUT_SECONDS = 5
MAX_BODY_BYTES = 32768
MAX_REDIRECTS = 3
MAX_FINDINGS = 40
HEADER_CHECKS = {
    "content-security-policy": ("medium", "Helps limit script injection and other browser-side content risks.", "Define a restrictive Content-Security-Policy tailored to the application."),
    "strict-transport-security": ("high", "Instructs browsers to prefer HTTPS for future visits.", "After confirming required hosts support HTTPS, enable HSTS with a carefully selected max-age."),
    "x-content-type-options": ("low", "Reduces MIME-type sniffing by browsers.", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Controls how much referrer information is sent to other sites.", "Set an appropriate Referrer-Policy such as strict-origin-when-cross-origin."),
    "permissions-policy": ("low", "Restricts access to selected browser features.", "Set a Permissions-Policy aligned with the browser features the site needs."),
    "x-frame-options": ("medium", "Can help prevent unwanted framing in browsers that do not enforce CSP frame-ancestors.", "Set X-Frame-Options: DENY or SAMEORIGIN, and define CSP frame-ancestors."),
}


class SafeScanError(Exception):
    pass


class CertificateCheckError(SafeScanError):
    pass


@transaction.atomic
def create_user_scan(user_id, target_url, limit=5):
    get_user_model().objects.select_for_update().get(pk=user_id)
    recent = Scan.objects.filter(user_id=user_id, is_demo=False, scan_date__gte=timezone.now() - timedelta(hours=1)).count()
    if recent >= limit:
        return None
    return Scan.objects.create(user_id=user_id, target_url=target_url)


def resolve_public(hostname, port):
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SafeScanError("The target hostname could not be resolved.") from exc
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise SafeScanError("The target hostname has no address records.")
    for address in addresses:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
        if not parsed.is_global:
            raise SafeScanError("Targets resolving to private, local, reserved, or non-public addresses are blocked.")
    return addresses[0]


def normalize_url(raw_url):
    value = (raw_url or "").strip()
    if len(value) > 2048:
        raise SafeScanError("The target URL is too long.")
    try:
        URLValidator(schemes=["http", "https"])(value)
        parts = urlsplit(value)
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except (ValidationError, ValueError) as exc:
        raise SafeScanError("Please enter a valid HTTP or HTTPS URL.") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise SafeScanError("Only public HTTP or HTTPS URLs without embedded credentials can be scanned.")
    if port != (443 if parts.scheme == "https" else 80):
        raise SafeScanError("Only the standard HTTP and HTTPS ports are allowed.")
    hostname = parts.hostname.lower()
    if hostname in {"localhost", "localhost.localdomain"}:
        raise SafeScanError("Local targets are blocked.")
    pinned_ip = resolve_public(hostname, port)
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    return clean, hostname, port, pinned_ip


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(PinnedHTTPConnection):
    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        context = ssl.create_default_context()
        self.sock = context.wrap_socket(raw, server_hostname=self.host)


def one_request(url, expected_host, method="GET"):
    normalized, hostname, port, pinned_ip = normalize_url(url)
    if hostname != expected_host:
        raise SafeScanError("Cross-host redirects are blocked.")
    parts = urlsplit(normalized)
    connection_class = PinnedHTTPSConnection if parts.scheme == "https" else PinnedHTTPConnection
    connection = connection_class(hostname, port, pinned_ip, TIMEOUT_SECONDS)
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        connection.putheader("Host", parts.netloc)
        connection.putheader("User-Agent", "CyberShieldAI-Defensive-Scanner/1.0")
        connection.putheader("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
        if method == "OPTIONS":
            connection.putheader("Origin", "https://cybershield.invalid")
            connection.putheader("Access-Control-Request-Method", "GET")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        headers = response.getheaders()
        if parts.scheme == "https" and getattr(connection, "sock", None):
            tls_version = connection.sock.version()
            if tls_version:
                headers.append(("__cybershield_tls_version__", tls_version))
        body = response.read(MAX_BODY_BYTES)
        return response.status, headers, body, normalized
    except ssl.SSLCertVerificationError as exc:
        raise CertificateCheckError("The HTTPS certificate could not be validated.") from exc
    except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
        raise SafeScanError("The target did not complete a safe HTTP/TLS check.") from exc
    finally:
        connection.close()


def request_same_host(url, expected_host, method="GET"):
    current = url
    followed = False
    for hop in range(MAX_REDIRECTS + 1):
        status, headers, body, current = one_request(current, expected_host, method=method)
        locations = [value for key, value in headers if key.lower() == "location"]
        if status not in {301, 302, 303, 307, 308} or not locations:
            return status, headers, body, current, followed
        if hop >= MAX_REDIRECTS:
            raise SafeScanError("The target exceeded the same-host redirect limit.")
        next_url = urljoin(current, locations[-1])
        next_host = (urlsplit(next_url).hostname or "").lower()
        if next_host != expected_host:
            raise SafeScanError("Cross-host redirects are blocked.")
        normalize_url(next_url)
        current = next_url
        followed = True
    raise SafeScanError("The target redirect chain could not be completed safely.")


def add_finding(scan, name, category, severity, description, evidence, impact, recommendation):
    if scan.vulnerabilities.count() >= MAX_FINDINGS:
        return
    Vulnerability.objects.create(scan=scan, name=name, category=category, severity=severity, description=description, evidence=str(evidence)[:1200], impact=impact, recommendation=recommendation)


def score_for(findings):
    penalties = settings.SEVERITY_PENALTIES
    return max(0, min(100, 100 - sum(penalties.get(item.severity, 0) for item in findings)))


def run_scan(scan):
    started = time.monotonic()
    scan.status = "running"
    scan.save(update_fields=["status"])
    url, hostname, _, _ = normalize_url(scan.target_url)
    try:
        status, headers, body, final_url, redirected = request_same_host(url, hostname, "GET")
    except CertificateCheckError:
        add_finding(scan, "HTTPS certificate validation failed", "HTTPS/TLS", "medium", "The TLS certificate could not be validated by the scanner's system trust store.", "Python TLS certificate verification returned a failure; certificate contents were not stored.", "Visitors may see browser warnings or fail to establish a trusted encrypted connection.", "Verify the certificate chain, validity dates, hostname, and renewal configuration.")
        scan.security_score = score_for(scan.vulnerabilities.all())
        scan.status = "completed"
        scan.scan_duration = round(time.monotonic() - started, 2)
        scan.save(update_fields=["security_score", "status", "scan_duration"])
        return scan
    header_map = {}
    cookie_headers = []
    tls_version = ""
    for key, value in headers:
        lower = key.lower()
        if lower == "__cybershield_tls_version__":
            tls_version = value
        elif lower == "set-cookie":
            cookie_headers.append(value)
        else:
            header_map[lower] = value
    is_https = final_url.startswith("https://")
    if not is_https:
        add_finding(scan, "HTTPS not enforced", "HTTPS/TLS", "high", "The checked page remained on plain HTTP.", f"Final URL scheme: http; HTTP status: {status}", "Traffic may be exposed or modified in transit, depending on the network and application.", "Enable HTTPS and redirect HTTP requests to HTTPS. Consider HSTS after validating the HTTPS deployment.")
    elif url.startswith("http://") and redirected:
        add_finding(scan, "HTTP redirects to HTTPS", "HTTPS/TLS", "info", "The initial HTTP request redirected to HTTPS.", f"Final URL: {final_url}", "Redirecting helps browsers reach the encrypted service, though an initial HSTS policy may still be useful.", "Keep the redirect in place and configure HSTS only after confirming the HTTPS deployment.")
    if tls_version:
        add_finding(scan, "TLS protocol negotiated", "HTTPS/TLS", "info", "A standards-based TLS handshake completed and the server certificate passed the configured trust-store validation.", f"Negotiated protocol: {tls_version}; certificate validation succeeded.", "This confirms the observed endpoint presented a certificate trusted by the scanner at assessment time; it does not establish the security of every route or client.", "Maintain a current certificate chain and modern TLS configuration. This passive check does not audit cipher preferences or every protocol option.")
    for name, (severity, purpose, recommendation) in HEADER_CHECKS.items():
        if not header_map.get(name, "").strip():
            display_name = "-".join(part.upper() if part.lower() == "csp" else part.capitalize() for part in name.split("-"))
            if name == "content-security-policy":
                display_name = "Content-Security-Policy"
            if name == "strict-transport-security":
                display_name = "Strict-Transport-Security"
            add_finding(scan, f"Missing {display_name}", "Security Headers", severity, f"The target response did not include the {display_name} header.", f"Header absent on HTTP {status} response", purpose, recommendation)
    server_value = header_map.get("server", "")
    powered_value = header_map.get("x-powered-by", "")
    if server_value or powered_value:
        evidence = "; ".join(value for value in [f"Server: {server_value}" if server_value else "", f"X-Powered-By: {powered_value}" if powered_value else ""] if value)
        add_finding(scan, "Technology details disclosed in response headers", "Information Disclosure", "info", "Response headers reveal implementation or server metadata.", evidence, "Version and platform details can help an observer fingerprint the service; this is generally low impact by itself.", "Remove unnecessary version strings from Server and X-Powered-By headers where practical.")
    body_text = body.decode("utf-8", errors="ignore")
    if re.search(r"traceback \(most recent call last\)|werkzeug debugger|django technical 500|stack trace", body_text, re.IGNORECASE):
        marker = re.search(r"traceback \(most recent call last\)|werkzeug debugger|django technical 500|stack trace", body_text, re.IGNORECASE).group(0)
        add_finding(scan, "Server error details appear in the public response", "Information Disclosure", "high", "The bounded response body contains a recognizable debug traceback marker.", f"Matched response marker: {marker}; response body was truncated to {MAX_BODY_BYTES} bytes and was not saved.", "Public exception details may reveal implementation and internal context that should not be returned to unauthenticated visitors.", "Return a generic error page to visitors, disable production debug mode, and keep detailed exceptions in restricted server logs.")
    for cookie in cookie_headers[:20]:
        parts = [part.strip() for part in cookie.split(";")]
        name = parts[0].split("=", 1)[0][:80] if parts else "cookie"
        attrs = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in attrs]
        if missing:
            severity = "medium" if "secure" in missing or "httponly" in missing else "low"
            add_finding(scan, f"Cookie attributes need review: {name}", "Cookie Security", severity, "A cookie response is missing one or more protective attributes.", f"Cookie name: {name}; missing attributes: {', '.join(missing)}; cookie values are not stored.", "Without suitable cookie flags, session or preference data may be exposed to unintended browser contexts or transport conditions.", "Set Secure for HTTPS cookies, HttpOnly for cookies not read by JavaScript, and an intentional SameSite policy.")
    if not cookie_headers:
        add_finding(scan, "No Set-Cookie headers observed", "Cookie Security", "info", "The checked response did not set cookies.", "No Set-Cookie headers in the inspected response.", "No cookie-specific risk was observed in this response; other routes may behave differently.", "Review authentication and application routes separately if they issue cookies.")
    try:
        _, options_headers, _, _, _ = request_same_host(final_url, hostname, "OPTIONS")
        allow_values = [value for key, value in options_headers if key.lower() == "allow"]
        allow_value = ", ".join(allow_values)
        for key, value in options_headers:
            if key.lower() in {"access-control-allow-origin", "access-control-allow-credentials"}:
                header_map[key.lower()] = value
    except SafeScanError:
        allow_value = ""
    methods = {method.strip().upper() for method in allow_value.split(",") if method.strip()}
    if "TRACE" in methods:
        add_finding(scan, "Potentially unnecessary TRACE method advertised", "HTTP Methods", "medium", "The Allow response advertises the TRACE method.", f"Allow: {allow_value}; no TRACE request was sent.", "TRACE is rarely needed by public applications and can increase exposure when combined with other weaknesses.", "Disable TRACE unless a documented operational requirement exists.")
    if methods.intersection({"PUT", "DELETE", "CONNECT"}):
        add_finding(scan, "State-changing HTTP methods advertised", "HTTP Methods", "medium", "The Allow response advertises methods that may change server state.", f"Allow: {allow_value}; no state-changing request was sent.", "Unneeded write or tunnel methods increase the exposed interface and should be reviewed.", "Confirm each method is required and ensure routes enforce authentication and authorization.")
    cors_origin = header_map.get("access-control-allow-origin", "")
    cors_credentials = header_map.get("access-control-allow-credentials", "").lower() == "true"
    if cors_origin == "https://cybershield.invalid":
        severity = "high" if cors_credentials else "medium"
        add_finding(scan, "CORS origin appears to be reflected", "CORS Configuration", severity, "The response matched the reserved test origin supplied with the safe OPTIONS preflight.", "Access-Control-Allow-Origin matched https://cybershield.invalid; only the reserved .invalid test origin was used.", "If arbitrary untrusted origins are reflected, browser scripts on those origins may be able to read cross-origin resources; credential allowance can increase impact.", "Use an explicit allowlist of trusted origins and validate Origin values before returning CORS headers.")
    if cors_origin == "*" and cors_credentials:
        add_finding(scan, "Wildcard CORS origin with credentials", "CORS Configuration", "high", "The response combines a wildcard origin with credential allowance.", "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true", "This configuration is inconsistent with browser credentialed CORS rules and may indicate an unsafe or ineffective policy.", "Use an explicit allowlist of trusted origins and avoid reflecting untrusted Origin values.")
    elif cors_origin == "*":
        add_finding(scan, "Wildcard CORS origin", "CORS Configuration", "low", "The response allows cross-origin reads from any origin for non-credentialed requests.", "Access-Control-Allow-Origin: *", "Public response content may be readable cross-origin; this can be intentional but should match data sensitivity.", "Restrict allowed origins if the response contains non-public data.")
    elif not cors_origin:
        add_finding(scan, "No permissive CORS policy observed", "CORS Configuration", "info", "The inspected response did not advertise an Access-Control-Allow-Origin policy.", "No Access-Control-Allow-Origin response header.", "No cross-origin read policy was observed on this route.", "No change is needed unless the application intentionally requires cross-origin access.")
    body_lower = body[:MAX_BODY_BYTES].lower()
    if any(marker in body_lower for marker in (b"django.core.exceptions", b"traceback (most recent call last)", b"stack trace", b"fatal error:")):
        add_finding(scan, "Possible debug or exception details in response", "Information Disclosure", "medium", "The response body contains a common exception or stack-trace marker.", "A generic error/debug marker was observed; response body content was not stored.", "Detailed errors can disclose internal paths or implementation details.", "Disable debug output in production and return generic error responses to clients.")
    if status >= 500:
        add_finding(scan, "Server error response", "Information Disclosure", "low", "The inspected route returned a server-side error status.", f"HTTP status: {status}", "Unexpected server errors may affect availability or indicate misconfiguration.", "Review server-side logs and ensure client-facing error pages do not reveal implementation details.")
    findings = list(scan.vulnerabilities.all())
    scan.security_score = score_for(findings)
    scan.status = "completed"
    scan.failure_message = ""
    scan.scan_duration = round(time.monotonic() - started, 2)
    scan.save(update_fields=["security_score", "status", "failure_message", "scan_duration"])
    return scan


def create_demo_scan(user):
    scan = Scan.objects.create(user=user, target_url="https://demo.example", status="completed", security_score=0, scan_duration=2.4, is_demo=True)
    samples = [
        ("Missing Strict-Transport-Security", "Security Headers", "high", "The demo response does not include an HSTS header.", "Header absent in demo response", "Browsers are not told to enforce HTTPS for future visits.", "Configure HSTS after confirming HTTPS works across required subdomains."),
        ("Missing Content-Security-Policy", "Security Headers", "medium", "The demo response does not define a content policy.", "Header absent in demo response", "A content policy can reduce the impact of some browser-side injection issues.", "Set a restrictive CSP and test it in report-only mode first."),
        ("Cookie missing Secure attribute", "Cookie Security", "medium", "A demo session cookie is missing the Secure flag.", "Cookie name: sessionid; missing: Secure", "A cookie could be sent over an unencrypted connection if the site permits HTTP.", "Set the Secure attribute on cookies served over HTTPS."),
        ("Wildcard CORS origin", "CORS Configuration", "low", "A demo public endpoint permits any origin.", "Access-Control-Allow-Origin: *", "Public response content can be read cross-origin.", "Limit origins for any response containing non-public data."),
        ("Server banner visible", "Information Disclosure", "info", "The demo response includes general server information.", "Server: example-httpd", "The banner may make broad technology fingerprinting easier.", "Remove unnecessary version details from response headers."),
        ("Missing Referrer-Policy", "Security Headers", "low", "The demo response does not state a referrer policy.", "Header absent in demo response", "Navigations may send more referrer data than intended.", "Set an intentional Referrer-Policy such as strict-origin-when-cross-origin."),
        ("Missing X-Content-Type-Options", "Security Headers", "low", "The demo response omits the nosniff control.", "Header absent in demo response", "Some browsers may infer content types in unexpected ways.", "Set X-Content-Type-Options: nosniff."),
        ("Technology metadata present", "Technology Detection", "info", "The demo exposes a broad technology hint.", "Header family: Server", "This is informational and does not prove a vulnerable component is present.", "Keep dependencies patched and reduce unnecessary public metadata."),
        ("Missing Permissions-Policy", "Security Headers", "low", "The demo response does not define browser feature access policy.", "Header absent in demo response", "Browser capabilities remain governed by browser defaults.", "Set a Permissions-Policy for features the site does not need."),
    ]
    for name, category, severity, description, evidence, impact, recommendation in samples:
        Vulnerability.objects.create(scan=scan, name=name, category=category, severity=severity, description=description, evidence=evidence, impact=impact, recommendation=recommendation)
    scan.security_score = score_for(scan.vulnerabilities.all())
    scan.save(update_fields=["security_score"])
    return scan
