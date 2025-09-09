from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_project_report(filename="Project_Report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    # Title Page
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width / 2, height - 100, "Project Report")
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width / 2, height - 140, "Python Vulnerability Scanner")
    c.setFont("Helvetica", 12)
    c.drawCentredString(width / 2, height - 180, "Submitted by: Yoru (Sidhanth)")
    c.showPage()

    def section(title, y, font_size=16):
        c.setFont("Helvetica-Bold", font_size)
        c.drawString(50, y, title)
        return y - 20

    def paragraph(text, y, font_size=12, spacing=14):
        c.setFont("Helvetica", font_size)
        for line in text.split("\n"):
            c.drawString(60, y, line.strip())
            y -= spacing
        return y

    # Introduction
    y = section("1. Introduction", height - 50)
    intro = ("This project implements a lightweight Python-based vulnerability scanner. "
             "It helps identify issues like SQL Injection, Cross-Site Scripting (XSS), "
             "Open Redirects, and missing security headers. "
             "It also uses a signature-based detection mechanism for outdated software versions "
             "and generates a professional PDF report for security teams.")
    y = paragraph(intro, y)

    # Objectives
    y = section("2. Objectives", y - 20)
    objectives = [
        "Develop an automated scanning tool to detect common vulnerabilities.",
        "Implement signature-based detection for outdated or insecure software.",
        "Provide structured vulnerability reports with remediation steps.",
        "Design a tool that is easy to extend with new checks and signatures."
    ]
    for obj in objectives:
        c.drawString(80, y, f"• {obj}")
        y -= 14

    # Tools & Technologies
    y = section("3. Tools & Technologies", y - 20)
    tools = ("- Programming Language: Python 3.12\n"
             "- Libraries: requests, beautifulsoup4, pyyaml, reportlab\n"
             "- Data Source: signatures.yml containing known vulnerable software versions")
    y = paragraph(tools, y)

    c.showPage()

    # Architecture
    y = section("4. System Architecture", height - 50)
    architecture = ("The scanner follows a modular architecture:\n"
                    "1. Core Scanner (core.py) - Performs active vulnerability checks.\n"
                    "2. Signature Engine (utils.py + signatures.yml) - Detects outdated software.\n"
                    "3. Reporting Module (reports.py) - Generates PDF reports.\n"
                    "4. CLI Interface (main.py) - Allows scans from terminal.")
    y = paragraph(architecture, y)

    # Features
    y = section("5. Features", y - 20)
    features = [
        "Detects Cross-Site Scripting (XSS)",
        "Detects SQL Injection (SQLi)",
        "Detects Open Redirects",
        "Detects Missing Security Headers",
        "Signature Matching against known vulnerable versions",
        "Severity Classification (Critical, High, Medium, Low)",
        "Detailed PDF Report with findings and remediation"
    ]
    for feat in features:
        c.drawString(80, y, f"✓ {feat}")
        y -= 14

    # Workflow
    y = section("6. Sample Workflow", y - 20)
    workflow = ("1. User runs the scanner with target URL.\n"
                "2. The scanner performs active tests and matches signatures.\n"
                "3. Vulnerabilities are classified by severity.\n"
                "4. A PDF report is generated with Executive Summary, Findings, Fixes.")
    y = paragraph(workflow, y)

    c.showPage()

    # Findings
    y = section("7. Example Findings", height - 50)
    findings = ("- [High] Apache 2.4.49 Path Traversal (CVE-2021-41773)\n"
                "  Remediation: Upgrade to Apache 2.4.51 or later.\n\n"
                "- [Medium] Missing Security Headers\n"
                "  Remediation: Configure server with X-Frame-Options, CSP, X-Content-Type-Options.")
    y = paragraph(findings, y)

    # Conclusion
    y = section("8. Conclusion", y - 20)
    conclusion = ("This project demonstrates how a Python-based vulnerability scanner can be built with modular design, "
                  "signature-driven detection, and professional reporting. "
                  "It is not a replacement for enterprise-grade tools but provides a lightweight and extensible "
                  "alternative for learning, awareness training, and small-scale scans.\n\n"
                  "Future enhancements: Add port scanning, integrate OWASP Top 10 checks, expand signatures with CVE feeds, "
                  "and generate HTML/JSON reports alongside PDF.")
    y = paragraph(conclusion, y)

    c.save()
    return filename

report_file = generate_project_report()
report_file
