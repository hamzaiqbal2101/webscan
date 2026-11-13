#!/usr/bin/env python3
"""WebScan — Step 1: fetch one page and show its status code and title.

Usage:
    python webscan.py <target-url>

Example (your own Juice Shop lab only):
    python webscan.py http://localhost:3000
"""

import re
import sys

import requests


def fetch_page(url):
    """Fetch a page and return (status_code, title)."""
    response = requests.get(url, timeout=10)
    match = re.search(r"<title>(.*?)</title>", response.text,
                      re.IGNORECASE | re.DOTALL)
    title = match.group(1).strip() if match else "(no title found)"
    return response.status_code, title


def main():
    if len(sys.argv) < 2:
        print("Usage: python webscan.py <target-url>")
        print("Example: python webscan.py http://localhost:3000")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        status, title = fetch_page(url)
    except requests.exceptions.RequestException as exc:
        print(f"Could not fetch {url}: {exc}")
        sys.exit(1)

    print(f"Status: {status}")
    print(f"Title: {title}")


if __name__ == "__main__":
    main()
