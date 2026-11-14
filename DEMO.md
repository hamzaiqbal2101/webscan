# WebScan — Demo & Write-up

## The lab

OWASP Juice Shop running in Docker on my own machine, at
`http://localhost:3000`. Nothing was scanned except my own lab instance.

## The run

```bash
python webscan.py http://localhost:3000
```

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

A note on the zeros: Juice Shop is an Angular single-page app. Its
home-page HTML contains no links and no forms — the app builds them in
the browser — so `Links (0)` and `Forms (0)` are expected. The probes
were verified separately on local test pages with real forms: a form
that reflected the test string was reported, a form that did not was
not reported, and a form that returned a database error on a single
quote was reported as a possible SQL injection.

## One finding, explained: Missing Strict-Transport-Security (High)

**What it is.** Strict-Transport-Security (HSTS) is a response header a
server sends over HTTPS. It tells the browser: "for this site, only ever
use HTTPS, for the next year" — for example,
`Strict-Transport-Security: max-age=31536000; includeSubDomains`.
After the first HTTPS visit, the browser remembers and refuses to load
the site over plain HTTP.

**Why it matters.** Without HSTS, the very first visit to a site can
still happen over plain HTTP, and an attacker on the same network can
intercept that first request and strip the HTTPS upgrade away (an
SSL-stripping attack). The user then talks to the attacker instead of
the real site, and passwords or session cookies can be read or changed
in transit. HSTS closes that first-visit gap, which is why WebScan
rates a missing HSTS header as High.

**How to fix it.** On the production HTTPS server (or reverse proxy),
send the header on every HTTPS response:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Start with a short `max-age` (for example 300 seconds) while testing,
then raise it to one year once the site works fully over HTTPS. The
header only works over HTTPS, so it cannot be applied to this lab
instance itself — the lab runs over plain HTTP on localhost — but every
real deployment of the app must send it.

## What WebScan does not do

- It does not log in, bypass authentication, or extract data.
- It reports "possible" findings only — a human confirms each one.
- It never scans a site the user does not own (PECA 2016).
