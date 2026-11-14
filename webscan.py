#!/usr/bin/env python3
"""WebScan — Step 3: fetch one page, show its status code, title, same-site links
and the state of its main security headers.

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


if __name__ == "__main__":
    main()
