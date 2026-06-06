"""
sslbl_harvester.py
==================
Automated IoC harvester for the Abuse.ch SSL Blacklist (SSLBL).

Abuse.ch SSLBL tracks SSL/TLS certificates used by botnet C2 infrastructure.
Each entry contains a SHA1 fingerprint, the certificate's Common Name, the
listing reason (malware family), and associated C2 socket (IP:port).

This module:
    1. Fetches the main SSLBL page to collect all known SHA1 hashes.
    2. For each hash, navigates to the detail page and extracts CN, reason,
       and the most recent C2 socket.
    3. Outputs a structured CSV for use with mass_grabber.py.

Rate limiting: 0.5s delay between requests (polite scraping per Abuse.ch ToS).

Data source: https://sslbl.abuse.ch/ssl-certificates/
"""

import requests
from bs4 import BeautifulSoup
import csv
import time

BASE_URL    = "https://sslbl.abuse.ch/ssl-certificates/"
OUTPUT_FILE = "sslbl_threat_intel.csv"
HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}
REQUEST_DELAY = 0.5   # seconds between requests

def get_sha1_list() -> list:
    """Collects all SHA1 certificate fingerprints listed on the SSLBL main page."""
    print("[*] Connecting to Abuse.ch SSLBL...")
    try:
        r = requests.get(BASE_URL, headers=HEADERS, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        hashes = []
        for a in soup.find_all('a', href=True):
            if '/ssl-certificates/sha1/' in a['href']:
                sha1 = a['href'].split('/')[-2]
                if sha1 not in hashes:
                    hashes.append(sha1)
        return hashes
    except Exception as e:
        print(f"[!] Error fetching main list: {e}")
        return []

def get_details(sha1: str) -> dict | None:
    """
    Fetches the detail page for a specific SHA1 hash and extracts:
        - cn        : X.509 Common Name of the certificate
        - reason    : Malware family or threat category
        - socket    : Most recent C2 IP:port (from Malware Samples table)
        - last_seen : Timestamp of the most recent sighting
    """
    url = f"{BASE_URL}sha1/{sha1}/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')

        data = {"sha1": sha1, "cn": "N/A", "reason": "N/A",
                "socket": "N/A", "last_seen": "N/A"}

        # Parse "Database Entry" table for CN and reason
        entry_table = soup.find('table', {'class': 'table'})
        if entry_table:
            for row in entry_table.find_all('tr'):
                cols = row.find_all(['th', 'td'])
                if len(cols) == 2:
                    key, val = cols[0].text.strip(), cols[1].text.strip()
                    if "Common Name" in key:     data["cn"] = val
                    if "Listing reason" in key:  data["reason"] = val

        # Parse "Malware Samples" table - pick the first row (most recent)
        all_tables = soup.find_all('table', {'class': 'table'})
        if len(all_tables) > 1:
            rows = all_tables[-1].find_all('tr')
            if len(rows) > 1:
                first_row = rows[1]
                cols = first_row.find_all('td')
                if len(cols) >= 5:
                    data["last_seen"] = cols[0].text.strip()
                    data["socket"]    = cols[-1].text.strip()

        return data
    except Exception as e:
        print(f"\n[!] Error on {sha1[:10]}: {e}")
        return None

def main() -> None:
    hashes = get_sha1_list()
    if not hashes:
        print("[!] No records found on SSLBL.")
        return

    print(f"[+] Found {len(hashes)} threats. Harvesting C2 socket data...")

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["sha1", "cn", "reason", "socket", "last_seen"])
        writer.writeheader()

        for i, sha1 in enumerate(hashes):
            print(f"  [{i+1}/{len(hashes)}] {sha1[:10]}... ", end="", flush=True)
            details = get_details(sha1)
            if details:
                writer.writerow(details)
                print(f"✓  C2: {details['socket']}  ({details['reason']})")
            else:
                print("✗  FAILED")
            time.sleep(REQUEST_DELAY)

    print(f"\n[+] Threat Intelligence saved to: {OUTPUT_FILE}")
    print(f"[*] Next step: run mass_grabber.py to capture and verify PEM certificates.")

if __name__ == "__main__":
    main()
