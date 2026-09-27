from io import BytesIO
from xml.sax.saxutils import escape

from django.conf import settings
from django.core.files.base import ContentFile
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import Report


def generate_report(scan):
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter, rightMargin=0.7 * inch, leftMargin=0.7 * inch, topMargin=0.72 * inch, bottomMargin=0.68 * inch, title="CyberShield AI Security Assessment", author="CyberShield AI")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CSBody", parent=styles["BodyText"], leading=15, spaceAfter=7, textColor=colors.HexColor("#253746")))
    styles.add(ParagraphStyle(name="CSSection", parent=styles["Heading2"], textColor=colors.HexColor("#087eaa"), spaceBefore=15, spaceAfter=8, fontSize=14))
    styles.add(ParagraphStyle(name="CSTitle", parent=styles["Title"], textColor=colors.HexColor("#06283a"), alignment=TA_LEFT, fontSize=29, leading=34, spaceAfter=8))
    styles.add(ParagraphStyle(name="CSSubTitle", parent=styles["Heading2"], textColor=colors.HexColor("#287c91"), fontSize=17, leading=22, spaceAfter=10))
    styles.add(ParagraphStyle(name="CSLabel", parent=styles["BodyText"], textColor=colors.HexColor("#4c6675"), fontSize=8, leading=12, spaceAfter=3))
    styles.add(ParagraphStyle(name="CSCoverNote", parent=styles["BodyText"], textColor=colors.HexColor("#5a6d79"), fontSize=9, leading=14))
    flow = [Spacer(1, 1.0 * inch), Paragraph("CYBERSHIELD AI", styles["CSTitle"]), Paragraph("Web Security Assessment Report", styles["CSSubTitle"]), Spacer(1, 8)]
    demo = "DEMO DATA · " if scan.is_demo else ""
    summary = [["ASSESSMENT TARGET", scan.target_url], ["SCAN DATE", scan.scan_date.strftime("%d %B %Y, %H:%M UTC")], ["ASSESSMENT STATUS", scan.get_status_display()], ["SECURITY SCORE", f"{scan.security_score} / 100"], ["OBSERVATIONS", str(scan.vulnerabilities.count())], ["SCOPE", "Controlled demonstration" if scan.is_demo else "Non-destructive public-response checks"]]
    table = Table([[Paragraph(f"<b>{escape(a)}</b>", styles["CSLabel"]), Paragraph(escape(b), styles["CSBody"])] for a, b in summary], colWidths=[1.65 * inch, 5.1 * inch], rowHeights=None)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f7f9")), ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#cedde3")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 11), ("RIGHTPADDING", (0, 0), (-1, -1), 11), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    flow += [table, Spacer(1, 17), Paragraph(f"{demo}CONFIDENTIAL · PREPARED FOR AUTHORIZED REVIEW", styles["CSLabel"]), Spacer(1, 6), Paragraph("This report contains the results of bounded, non-destructive configuration checks. Findings are heuristic observations and are not proof of exploitation, a penetration test, or a compliance certification.", styles["CSCoverNote"]), PageBreak()]
    findings = list(scan.vulnerabilities.all())
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (severity_order.get(item.severity, 5), item.detected_at))
    counts = scan.severity_counts
    flow += [Paragraph("Executive summary", styles["CSSection"]), Paragraph(f"The assessment completed with a score of <b>{scan.security_score}/100</b> and recorded <b>{len(findings)} observations</b>. Review the severity summary and confirm each item in the context of the target application before remediation.", styles["CSBody"]), Paragraph("Risk classification", styles["CSSection"])]
    severity_rows = [["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], [str(counts.get(key, 0)) for key in ["critical", "high", "medium", "low", "info"]]]
    severity_table = Table(severity_rows, colWidths=[1.35 * inch] * 5)
    severity_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fbe8e9")), ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#fff0e3")), ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#fff6df")), ("BACKGROUND", (3, 0), (3, -1), colors.HexColor("#e7f5f8")), ("BACKGROUND", (4, 0), (4, -1), colors.HexColor("#edf1f3")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#526977")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("GRID", (0, 0), (-1, -1), 0.4, colors.white), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    penalties = settings.SEVERITY_PENALTIES
    methodology = f"The score begins at 100 and subtracts {penalties['critical']} per Critical, {penalties['high']} per High, {penalties['medium']} per Medium, and {penalties['low']} per Low finding. Informational observations carry no penalty. Scores are bounded from 0 to 100."
    flow += [severity_table, Paragraph("Security score methodology", styles["CSSection"]), Paragraph(escape(methodology), styles["CSBody"]), Paragraph("Detailed findings and remediation", styles["CSSection"])]
    for index, finding in enumerate(findings, 1):
        flow += [Paragraph(f"{index}. {escape(finding.name)} · {escape(finding.get_severity_display().upper())}", styles["Heading3"]), Paragraph(f"<b>Category:</b> {escape(finding.category)}", styles["CSBody"]), Paragraph(f"<b>Description:</b> {escape(finding.description)}", styles["CSBody"]), Paragraph(f"<b>Evidence:</b> {escape(finding.evidence or 'No response evidence recorded.')}", styles["CSBody"]), Paragraph(f"<b>Potential impact:</b> {escape(finding.impact)}", styles["CSBody"]), Paragraph(f"<b>Recommendation:</b> {escape(finding.recommendation)}", styles["CSBody"])]
        latest_analysis = finding.analyses.order_by("-created_at").first()
        if latest_analysis:
            flow += [Paragraph("AI security analysis", styles["CSSection"]), Paragraph(f"<b>Plain-language explanation:</b> {escape(latest_analysis.explanation)}", styles["CSBody"]), Paragraph(f"<b>Impact analysis:</b> {escape(latest_analysis.impact_analysis)}", styles["CSBody"]), Paragraph(f"<b>Evidence context:</b> {escape(latest_analysis.evidence_explanation)}", styles["CSBody"]), Paragraph(f"<b>Remediation:</b> {escape(latest_analysis.remediation)}", styles["CSBody"]), Paragraph(f"<b>Severity priority:</b> {escape(latest_analysis.priority_explanation)}", styles["CSBody"])]
        flow += [Spacer(1, 9)]
    flow += [Spacer(1, 12), Paragraph("Final summary and scope", styles["CSSection"]), Paragraph("The scanner sends bounded GET and OPTIONS requests, blocks non-public IP destinations, limits redirects to the original host, and does not crawl or attempt exploitation. Confirm written authorization and independently verify findings. Address high-severity configuration concerns first, then reassess after remediation.", styles["CSBody"])]

    def draw_page(canvas: Canvas, document):
        canvas.saveState()
        width, height = letter
        canvas.setStrokeColor(colors.HexColor("#d8e5e9"))
        canvas.setLineWidth(0.5)
        canvas.line(0.7 * inch, 0.48 * inch, width - 0.7 * inch, 0.48 * inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#718692"))
        canvas.drawString(0.7 * inch, 0.32 * inch, "CYBERSHIELD AI · DEFENSIVE SECURITY ASSESSMENT")
        canvas.drawRightString(width - 0.7 * inch, 0.32 * inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(flow, onFirstPage=draw_page, onLaterPages=draw_page)
    report = Report(scan=scan)
    report.report_file.save(f"cybershield_scan_{scan.pk}.pdf", ContentFile(output.getvalue()), save=True)
    return report
