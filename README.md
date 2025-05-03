# Subdomain-Takeover-Scanner
Detects subdomain takeovers by checking CNAME records against known vulnerable services


A comprehensive tool to detect potential subdomain takeover vulnerabilities with multi-format reporting.

## Features

- 🕵️‍♂️ Detects subdomain takeovers by checking CNAME records against known vulnerable services
- 🌐 Verifies HTTP response status codes for unclaimed services
- ⚡ Multi-threaded scanning for fast results
- 📊 Generates interactive HTML reports with filtering capabilities
- 📝 Creates detailed text reports
- 📈 Progress tracking with visual progress bar
- 🔍 Supports 100+ vulnerable services (AWS, GitHub, Heroku, etc.)

## Installation

1. Clone the repository:

git clone https://github.com/Profanatic/Subdomain-Takeover-Scanner

cd subdomain-takeover-scanner

Install dependencies:

pip3 install -r requirements.txt

Usage
Basic scan with default settings:


python3 scanner.py -l subdomains.txt

Advanced scan with custom threads and output files:

python3 scanner.py -l subdomains.txt -t 20 -o custom_results.txt --html report.html

HTML Report
HTML Report Screenshot

Supported Services

The scanner checks for vulnerabilities in these services (and more):

AWS (S3, CloudFront)

GitHub Pages

Heroku

Shopify

Azure

Google Cloud

Fastly

And 100+ others...

Contributing
Contributions are welcome! Please open an issue or submit a pull request.

License
This project is licensed under the MIT License - see the LICENSE file for details.
