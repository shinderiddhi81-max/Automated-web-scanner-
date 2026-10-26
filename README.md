# Automated Web Scanner

A small Python defensive-auditing tool that checks a website's HTTP security headers and looks for basic CORS policy warning signs.

## Features
- Checks six common security headers: HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Sends a benign request with a synthetic `Origin` header to inspect CORS response headers.
- Prints a readable summary and can save complete results as JSON.
- Uses request timeouts and TLS certificate verification by default.

## Technologies
- Python 3.9+
- `requests` for HTTP requests
- `argparse`, `json`, `datetime`, and `urllib.parse` from the Python standard library

## Dataset
No external dataset is required. The scanner evaluates live HTTP response headers from a target URL supplied by the operator. For safe practice, use a local test server or a site you own / have explicit permission to assess.

## Setup
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Run
```bash
python AutomatedWebScanner.py https://example.com
```

Save machine-readable results:
```bash
python AutomatedWebScanner.py https://example.com --json report.json
```

Optional timeout:
```bash
python AutomatedWebScanner.py https://example.com --timeout 12
```

## Output interpretation
- `PASS`: the header is present.
- `REVIEW`: the header is absent or a policy needs review.
- CORS results are heuristic signals, not a complete security verdict. Confirm findings manually against the site's intended policy and browser behavior.

## Limitations
- This is a basic header/CORS checker, not a full vulnerability scanner.
- It does not crawl links, test authenticated endpoints, or test every preflight/request method.
- A missing header is not automatically an exploitable vulnerability.
- CORS behavior may differ by endpoint, origin, cookies, and browser.
- It follows redirects and reports the final URL.

## Responsible use
Only scan websites you own or have explicit authorization to test. The scanner makes ordinary GET requests only; do not use it to scan systems without permission.

## Project files
- `RiddhiShinde_AutomatedWebScanner.py` — complete scanner code
- `requirements.txt` — Python dependency
- `RiddhiShinde_ProjectReport.docx` — project documentation
- `README.md` — setup and usage guide
- `RiddhiShinde_AutomatedWebScanner.ipynb` — notebook version of the code
