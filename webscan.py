#!/usr/bin/env python3
"""WebScan — Step 7: fetch one page, check its links, security headers and forms,
probe them for reflected XSS and SQL injection clues, then print a findings
report with a severity per finding and save it to a text file.

Usage:
    python webscan.py <target-url>

Example (your own Juice Shop lab only):
    python webscan.py http://localhost:3000
"""

import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
]


def fetch_page(url):
    """Fetch a page and return (status_code, html, headers)."""
    response = requests.get(url, timeout=10)
    return response.status_code, response.text, response.headers


def get_title(html):
    """Return the page title, or a placeholder when there is none."""
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else "(no title found)"


def collect_links(html, base_url):
    """Return the page's links that stay on the same site, in order."""
    base_host = urlparse(base_url).netloc
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        full_url = urljoin(base_url, href).split("#")[0]
        if urlparse(full_url).netloc == base_host and full_url not in links:
            links.append(full_url)
    return links


def check_headers(headers):
    """Return {header name: value or None} for the main security headers."""
    return {name: headers.get(name) for name in SECURITY_HEADERS}


def find_forms(html):
    """Return a list of forms: {action, method, inputs} for each <form>."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name and name not in inputs:
                inputs.append(name)
        forms.append({
            "action": form.get("action", ""),
            "method": (form.get("method") or "get").lower(),
            "inputs": inputs,
        })
    return forms


XSS_MARKER = "WebScanTest123"


def probe_xss(base_url, forms):
    """Probe each form input with a harmless marker.

    Returns a list of (form number, input name) where the marker came back
    in the response — a possible reflected XSS.
    """
    findings = []
    for i, form in enumerate(forms, start=1):
        action_url = urljoin(base_url, form["action"] or base_url)
        for input_name in form["inputs"]:
            data = {name: "test" for name in form["inputs"]}
            data[input_name] = XSS_MARKER
            try:
                if form["method"] == "post":
                    response = requests.post(action_url, data=data, timeout=10)
                else:
                    response = requests.get(action_url, params=data, timeout=10)
            except requests.exceptions.RequestException:
                continue
            if XSS_MARKER in response.text:
                findings.append((i, input_name))
    return findings


SQL_ERROR_WORDS = [
    "sql syntax",
    "mysql",
    "sqlite",
    "postgresql",
    "ora-",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc",
    "jdbc",
    "sqlstate",
]


def probe_sqli(base_url, forms):
    """Probe each form input with a single quote.

    Returns a list of (form number, input name) where the response contains
    database error words — a possible SQL injection clue.
    """
    findings = []
    for i, form in enumerate(forms, start=1):
        action_url = urljoin(base_url, form["action"] or base_url)
        for input_name in form["inputs"]:
            data = {name: "test" for name in form["inputs"]}
            data[input_name] = "'"
            try:
                if form["method"] == "post":
                    response = requests.post(action_url, data=data, timeout=10)
                else:
                    response = requests.get(action_url, params=data, timeout=10)
            except requests.exceptions.RequestException:
                continue
            text = response.text.lower()
            if any(word in text for word in SQL_ERROR_WORDS):
                findings.append((i, input_name))
    return findings


def build_findings(headers, xss_findings, sqli_findings):
    """Collect findings as (severity, title, detail) tuples."""
    header_severity = {
        "Strict-Transport-Security": "High",
        "Content-Security-Policy": "Medium",
        "X-Content-Type-Options": "Low",
        "X-Frame-Options": "Medium",
    }
    findings = []
    for name, value in check_headers(headers).items():
        if value is None:
            findings.append((
                header_severity[name],
                f"Missing security header: {name}",
                "The server does not send this header.",
            ))
    for form_no, input_name in xss_findings:
        findings.append((
            "High",
            f"Possible reflected XSS in Form {form_no}, input '{input_name}'",
            "The harmless test string was reflected in the response.",
        ))
    for form_no, input_name in sqli_findings:
        findings.append((
            "High",
            f"Possible SQL injection in Form {form_no}, input '{input_name}'",
            "A single quote produced a database error message.",
        ))
    return findings


def write_report(url, status, title, links, forms, findings, path="webscan-report.txt"):
    """Build the report text, save it to a file, and return the text."""
    lines = []
    lines.append("WebScan Report")
    lines.append("=" * 40)
    lines.append(f"Target: {url}")
    lines.append(f"Status: {status}")
    lines.append(f"Title: {title}")
    lines.append(f"Links found: {len(links)}")
    lines.append(f"Forms found: {len(forms)}")
    lines.append("")
    lines.append(f"Findings ({len(findings)}):")
    for severity, finding, detail in findings:
        lines.append(f"[{severity}] {finding}")
        lines.append(f"  {detail}")
    lines.append("")
    high = sum(1 for f in findings if f[0] == "High")
    medium = sum(1 for f in findings if f[0] == "Medium")
    low = sum(1 for f in findings if f[0] == "Low")
    lines.append(f"Summary: {len(findings)} findings ({high} High, {medium} Medium, {low} Low)")
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return text


def main():
    if len(sys.argv) < 2:
        print("Usage: python webscan.py <target-url>")
        print("Example: python webscan.py http://localhost:3000")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        status, html, headers = fetch_page(url)
    except requests.exceptions.RequestException as exc:
        print(f"Could not fetch {url}: {exc}")
        sys.exit(1)

    print(f"Status: {status}")
    print(f"Title: {get_title(html)}")

    links = collect_links(html, url)
    print(f"Links ({len(links)}):")
    for link in links:
        print(f"  {link}")

    checked = check_headers(headers)
    missing = [name for name, value in checked.items() if value is None]
    print(f"Security headers ({len(missing)} missing):")
    for name, value in checked.items():
        print(f"  {name}: {value if value is not None else 'MISSING'}")

    forms = find_forms(html)
    print(f"Forms ({len(forms)}):")
    for i, form in enumerate(forms, start=1):
        print(f"  Form {i}: action={form['action']}, method={form['method']}")
        print(f"    inputs: {', '.join(form['inputs']) if form['inputs'] else '(none)'}")

    print(f"XSS probe (marker: {XSS_MARKER}):")
    xss_findings = []
    if not forms:
        print("  No forms to probe.")
    else:
        xss_findings = probe_xss(url, forms)
        if xss_findings:
            for form_no, input_name in xss_findings:
                print(f"  Possible reflected XSS in Form {form_no}, input '{input_name}'")
        else:
            print("  No reflections found.")

    print("SQLi probe (payload: '):")
    sqli_findings = []
    if not forms:
        print("  No forms to probe.")
    else:
        sqli_findings = probe_sqli(url, forms)
        if sqli_findings:
            for form_no, input_name in sqli_findings:
                print(f"  Possible SQL injection in Form {form_no}, input '{input_name}'")
        else:
            print("  No database errors found.")

    findings = build_findings(headers, xss_findings, sqli_findings)
    report = write_report(url, status, get_title(html), links, forms, findings)
    print()
    print(report, end="")
    print("Report saved to: webscan-report.txt")


if __name__ == "__main__":
    main()
