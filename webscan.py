#!/usr/bin/env python3
"""WebScan — Step 4: fetch one page, show its status code, title, same-site links,
the state of its main security headers, and the forms on the page.

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


if __name__ == "__main__":
    main()
