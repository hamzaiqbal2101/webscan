# WebScan

A Python command-line web vulnerability scanner, built for the PNY Trainings
Web Application Security final project (instructor: Abdul Mannan).

WebScan scans one target at a time and prints a findings report with a
severity for each finding — and saves the same report to `webscan-report.txt`.

## What it checks

- **Page fetch** — status code and page title of the target URL.
- **Same-site links** — collects links that stay on the target site only.
- **Security headers** — reports which of these four are missing:
  Strict-Transport-Security, Content-Security-Policy,
  X-Content-Type-Options, X-Frame-Options.
- **Forms** — lists every form on the page with its action, method and
  input names.
- **Reflected XSS clues** — sends a harmless test string (`WebScanTest123`)
  through each form input and reports it when the string comes back in the
  response.
- **SQL injection clues** — sends a single quote (`'`) in each form input
  and looks for database error messages in the response. Findings are
  reported as "possible" only — WebScan never extracts data.
- **Findings report** — every finding gets a severity (High / Medium / Low),
  printed on screen and saved to `webscan-report.txt`.

## How to run

Requirements: Python 3.10 or newer.

```bash
pip install requests beautifulsoup4
python webscan.py http://localhost:3000
```

The target URL is taken from the command line. If no scheme is given,
`http://` is assumed.

## Example output (OWASP Juice Shop lab)

```
Status: 200
Title: OWASP Juice Shop
Links (0):
Security headers (2 missing):
  Strict-Transport-Security: MISSING
  Content-Security-Policy: MISSING
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
Forms (0):
XSS probe (marker: WebScanTest123):
  No forms to probe.
SQLi probe (payload: '):
  No forms to probe.

WebScan Report
========================================
Target: http://localhost:3000
Status: 200
Title: OWASP Juice Shop
Links found: 0
Forms found: 0

Findings (2):
[High] Missing security header: Strict-Transport-Security
  The server does not send this header.
[Medium] Missing security header: Content-Security-Policy
  The server does not send this header.

Summary: 2 findings (1 High, 1 Medium, 0 Low)
Report saved to: webscan-report.txt
```

## Lab-only scope

WebScan is tested only against my own OWASP Juice Shop instance running in
Docker on my own machine. **Never point WebScan at a real website you do
not own.** Unauthorised access is an offence under PECA 2016.

One honest limitation, found while testing: Juice Shop is an Angular
single-page app, so its home-page HTML contains no links and no forms —
`Links (0)` and `Forms (0)` are expected there. The link collector and both
probes were verified on local test pages with real links and forms.

## Project files

- `webscan.py` — the whole tool (270 lines, seven small functions)
- `README.md` — this file
- `DEMO.md` — demo run on Juice Shop plus one finding explained

## How it was built

Seven steps, each tested before moving on:

| Step | What was added | Tested |
| --- | --- | --- |
| 1 | Fetch one page (status + title) | Juice Shop home: 200, "OWASP Juice Shop" |
| 2 | Collect same-site links | Juice Shop: Links (0), expected for the SPA |
| 3 | Check security headers | Juice Shop: HSTS + CSP missing |
| 4 | Find forms | Juice Shop: Forms (0), expected for the SPA |
| 5 | Reflected XSS probe | Test page: reflecting form reported, clean form not reported |
| 6 | SQL injection clue probe | Test page: error page reported, clean form not reported |
| 7 | Findings report with severities | Full scan: report printed and saved to file |

All seven steps tested and passing, 13–14 November 2026.

## Author

Hamza Iqbal — PNY Trainings, Web Application Security track.
