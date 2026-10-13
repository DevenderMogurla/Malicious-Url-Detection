# LinkSentinel — Malicious URL Detection

A polished Flask web application for analyzing URLs with explainable heuristic checks and an optional Google Safe Browsing reputation lookup.

## Features

- Web interface with risk score, verdict, signal explanations, technical details, and copyable report.
- Detects common warning signs: HTTP instead of HTTPS, embedded `@`/credentials, punycode, raw IP hosts, URL shorteners, unusually long URLs, suspicious words, excessive subdomains/hyphens, and risky executable/script extensions.
- Optional Google Safe Browsing API v4 check for known malware, social engineering/phishing, unwanted software, and potentially harmful applications.
- JSON API: `POST /api/scan`
- Health endpoint: `GET /api/health`
- URL SHA-256 fingerprint for report identification.
- Does not automatically open scanned links or follow redirects.

## Important limitation

No tool can truthfully guarantee that **any** link is safe. This project combines simple heuristics with an optional threat-intelligence check. A low score means “no obvious threat detected,” not “confirmed safe.” New, private, cloaked, or targeted malicious URLs may evade detection. Avoid opening suspicious links even when this tool reports low risk.

## Requirements

- Python 3.10+
- Internet access only if you want to use the optional Google Safe Browsing API.

## Run on Windows (PowerShell)

```powershell
cd malicious_url_detection_pro
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, use Command Prompt:

```bat
.venv\Scripts\activate.bat
```

## Run on Git Bash

```bash
cd malicious_url_detection_pro
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
python app.py
```

Then open: http://127.0.0.1:5000

If port 5000 is already in use, use PowerShell:

```powershell
$env:PORT=5001
python app.py
```

Then open http://127.0.0.1:5001.

## Enable live reputation checks

1. Create a Google Cloud project.
2. Enable the Safe Browsing API and create an API key according to Google's current setup instructions.
3. Set the key as an environment variable. Do not commit it to GitHub.

PowerShell:
```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY"
python app.py
```

Git Bash:
```bash
export GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY"
python app.py
```

The app works without this key, but the reputation panel will clearly say the service is not configured. API access, quota, billing/eligibility, and terms depend on Google's current service setup.

## API usage

Request:

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Success response includes `risk_score`, `verdict`, `findings`, `reputation`, `hostname`, and `url_sha256`.

## Suggested demo cases

Use known benign domains you control, and synthetic suspicious examples such as:
- `http://example.com/login/verify`
- `https://192.0.2.10/account`
- `https://example.com/download/file.exe`
- `https://bit.ly/example`

These examples demonstrate heuristic flags; they are not claims that the destinations are malicious. Do not test by visiting suspicious URLs.

## Project structure

```text
malicious_url_detection_pro/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```

## Security notes for deployment

- Do not expose the development server directly to the public internet.
- For production, run behind a production WSGI server and HTTPS reverse proxy, add rate limiting and logging controls, and keep dependencies updated.
- Treat submitted URLs as untrusted input. This version does not fetch the submitted destination, which helps avoid server-side request forgery risks.
- Never place API keys in frontend JavaScript or commit them to source control.
