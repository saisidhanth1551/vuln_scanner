import argparse
from core import VulnerabilityScanner
from reports import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g. http://example.com)")
    parser.add_argument("-o", "--output", default="scan_report.pdf", help="Output PDF filename")
    args = parser.parse_args()

    print(f"[+] Starting scan on {args.url}...")

    # Run scanner
    scanner = VulnerabilityScanner(args.url)
    findings = scanner.run()

    # Generate PDF report
    report = ReportGenerator(findings, args.url, filename=args.output)
    report.generate()

    print(f"[+] Scan completed. Report saved to {args.output}")

if __name__ == "__main__":
    main()
