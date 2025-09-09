
# Python Vulnerability Scanner

A simple Python-based vulnerability scanner that detects common web application issues and generates PDF reports.

## Features
- Detects Cross-Site Scripting (XSS)
- Detects SQL Injection (SQLi)
- Detects Open Redirects
- Checks for Missing Security Headers
- Uses signatures.yml for detecting outdated/vulnerable software
- Generates PDF report with findings

## Tech Stack
- Python 3.12
- Libraries: requests, bs4, pyyaml, reportlab

## Project Structure
vuln_scanner/
│── scanner/
│   ├── core.py          # Main vulnerability checks
│   ├── utils.py         # Helpers (headers, signatures)
│   ├── reports.py       # PDF report generator
│   ├── main.py          # CLI entry point
│── signatures.yml       # Known vulnerability patterns
│── requirements.txt     # Dependencies

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/saisidhanth1551/vuln_scanner.git
   cd vuln_scanner
   ```


2. Create virtual environment and install dependencies:

   ```bash
   python -m venv venv
   venv\Scripts\activate   # Windows
   source venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```

3. Run the scanner:

   ```bash
   python -m scanner.main http://example.com -o report.pdf
   ```

## Future Enhancements

* Add port scanning
* Integrate OWASP Top 10 checks
* Update CVE signatures regularly
* Export reports in HTML/JSON formats

