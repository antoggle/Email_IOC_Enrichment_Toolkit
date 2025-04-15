# Email IOC Enrichment Toolkit

A hands-on security tool to extract and enrich IPs and domains from phishing email headers using the VirusTotal API. Perfect for analysts and learners practicing email threat triage.

## Features

-  Extract IOCs from raw email headers (domains + IPs)
-  Enrich using real-time VirusTotal verdicts
-  Outputs JSON results + Markdown triage report template
-  Secure API key handling with `.env`
-  Designed for portfolio use and early-career AppSec/CTI roles

## Project Structure

```
email-ioc-enrichment-toolkit/
├── email_header_enricher.py
├── email_header.txt
├── email_header_enrichment_results.json
├── triage_report.md
├── .env.example
└── README.md
```

## How to Use

1. Paste your email header in `email_header.txt`
2. Create a `.env` file with your VirusTotal API key
3. Install requirements:
   ```bash
   pip install requests python-dotenv
   ```
4. Run:
   ```bash
   python email_header_enricher.py
   ```

## Sample Output

```json
[
  {
    "ioc": "phishy-login.com",
    "type": "domain",
    "malicious": 17,
    "suspicious": 3
  }
]
```

## Triage Report Template

Use `triage_report.md` to document your findings, IOC verdicts, and recommendations for action.

## Learning Goals

- Practice IOC extraction and enrichment
- Work with APIs and JSON data
- Develop triage and threat analysis skills
- Build AppSec/CTI hands-on experience for job applications
