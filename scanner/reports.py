from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime

class ReportGenerator:
    def __init__(self, findings, target, filename="scan_report.pdf"):
        self.findings = findings
        self.target = target
        self.filename = filename

    def generate(self):
        c = canvas.Canvas(self.filename, pagesize=letter)
        width, height = letter

        # Title
        c.setFont("Helvetica-Bold", 20)
        c.drawCentredString(width / 2, height - 50, "Vulnerability Scan Report")

        # Executive Summary
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 100, "Executive Summary")
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 120, f"Target: {self.target}")
        c.drawString(50, height - 140, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 160, f"Total Findings: {len(self.findings)}")
        
        # Add some spacing
        y = height - 200

        # Findings Section
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Detailed Findings")
        y -= 30

        c.setFont("Helvetica", 12)

        if not self.findings:
            c.drawString(50, y, "No vulnerabilities detected.")
        else:
            for finding in self.findings:
                if y < 120:  # Page break
                    c.showPage()
                    y = height - 80
                    c.setFont("Helvetica", 12)

                name = finding.get("name", "Unknown Issue")
                severity = finding.get("severity", "Info")
                desc = finding.get("description", "No description available.")
                remediation = finding.get("remediation", "No remediation provided.")

                # Draw box around each finding
                c.setFillColor(colors.black)
                c.setFont("Helvetica-Bold", 12)
                c.drawString(50, y, f"Finding: {name}")
                y -= 15
                c.setFont("Helvetica", 11)
                c.setFillColor(colors.red if severity in ["Critical", "High"] else colors.orange if severity == "Medium" else colors.green)
                c.drawString(70, y, f"Severity: {severity}")
                c.setFillColor(colors.black)
                y -= 15
                c.drawString(70, y, f"Description: {desc}")
                y -= 15
                c.drawString(70, y, f"Remediation: {remediation}")
                y -= 30

        # Conclusion
        if y < 150:
            c.showPage()
            y = height - 100

        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Conclusion")
        c.setFont("Helvetica", 12)
        y -= 20
        c.drawString(50, y, "This report provides an overview of detected vulnerabilities.")
        y -= 15
        c.drawString(50, y, "Remediation should be prioritized based on severity levels.")
        y -= 15
        c.drawString(50, y, "It is recommended to re-scan after fixes are applied.")

        c.save()
