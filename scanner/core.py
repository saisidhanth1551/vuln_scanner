import requests

class VulnerabilityScanner:
    def __init__(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        self.url = url
        self.findings = []

    def add_finding(self, name, severity, description, remediation):
        """Helper to add structured findings"""
        self.findings.append({
            "name": name,
            "severity": severity,
            "description": description,
            "remediation": remediation
        })

    def check_xss(self):
        test_url = f"{self.url}/?q=<script>alert(1)</script>"
        try:
            r = requests.get(test_url, timeout=5)
            if "<script>alert(1)</script>" in r.text:
                self.add_finding(
                    name="Reflected XSS",
                    severity="High",
                    description="Target echoed unsanitized input into the response.",
                    remediation="Implement proper input validation and output encoding."
                )
        except Exception:
            self.add_finding(
                name="XSS check failed",
                severity="Low",
                description="Scanner could not connect to the target for XSS test.",
                remediation="Ensure the target is reachable."
            )

    def check_sql_injection(self):
        test_url = f"{self.url}/?id=1' OR '1'='1"
        try:
            r = requests.get(test_url, timeout=5)
            errors = ["sql syntax", "mysql_fetch", "syntax error", "odbc", "mysqli"]
            if any(e.lower() in r.text.lower() for e in errors):
                self.add_finding(
                    name="SQL Injection",
                    severity="Critical",
                    description="Target responded with database error messages.",
                    remediation="Use parameterized queries (prepared statements) and ORM protections."
                )
        except Exception:
            self.add_finding(
                name="SQL Injection check failed",
                severity="Low",
                description="Scanner could not connect to the target for SQLi test.",
                remediation="Ensure the target is reachable."
            )

    def check_open_redirect(self):
        test_url = f"{self.url}/?next=http://evil.com"
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=True)
            if "evil.com" in r.url:
                self.add_finding(
                    name="Open Redirect",
                    severity="Medium",
                    description="Target allowed redirection to an external domain.",
                    remediation="Validate and sanitize all user-supplied redirect parameters."
                )
        except Exception:
            self.add_finding(
                name="Open Redirect check failed",
                severity="Low",
                description="Scanner could not connect to the target for redirect test.",
                remediation="Ensure the target is reachable."
            )

    def check_headers(self):
        try:
            r = requests.get(self.url, timeout=5)
            missing_headers = []
            security_headers = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]

            for header in security_headers:
                if header not in r.headers:
                    missing_headers.append(header)

            if missing_headers:
                self.add_finding(
                    name="Missing Security Headers",
                    severity="Medium",
                    description=f"The following headers are missing: {', '.join(missing_headers)}.",
                    remediation="Configure the web server to include recommended security headers."
                )
        except Exception:
            self.add_finding(
                name="Header check failed",
                severity="Low",
                description="Scanner could not fetch headers from target.",
                remediation="Ensure the target is reachable."
            )

    def run(self):
        self.findings.clear()
        self.check_xss()
        self.check_sql_injection()
        self.check_open_redirect()
        self.check_headers()

        if not self.findings:
            self.add_finding(
                name="No vulnerabilities detected",
                severity="Info",
                description="Scanner did not find any obvious vulnerabilities.",
                remediation="Continue regular security testing and patching."
            )

        return self.findings
