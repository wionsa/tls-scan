"""
updater.py
==========
Automatic Threat Intelligence database synchronizer.

Sources used (all open, freely accessible feeds):
  1. Abuse.ch SSLBL - SSL Certificate Blacklist, C2 infrastructure fingerprints
     https://sslbl.abuse.ch/blacklist/sslblacklist.csv
  2. URLhaus - Recent malware distribution URLs (past 30 days)
     https://urlhaus.abuse.ch/downloads/text_recent/
  3. OpenPhish - Active phishing URLs (community feed)
     https://openphish.com/feed.txt
  4. Phishing.Database - Community-maintained active phishing domains
     https://github.com/mitchellkrogza/Phishing.Database

Sync policy: 24-hour cooldown to respect feed rate limits.
"""

import requests
import pandas as pd
import os
import socket
import io
import re
import time

DB_PATH = "certverifier/data/malicious_subjectCN.csv"

SOURCES = {
    "Abuse.ch SSLBL (C2 Certs)":
        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "URLhaus (Recent Malware URLs)":
        "https://urlhaus.abuse.ch/downloads/text_recent/",
    "OpenPhish (Active Phishing)":
        "https://openphish.com/feed.txt",
    "Phishing.Database (Community)":
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
}

# Domains that appear in threat feeds but are false positives
WHITELIST = {
    'google.com', 'microsoft.com', 'apple.com', 'github.com',
    'bing.com', 'duckdns.org', 'cloudflare.com', 'amazonaws.com',
}

JUNK_TOKENS = {
    'http', 'https', 'online', 'offline', 'url_status', 'status',
    'nan', 'none', 'null', 'url', 'domain',
}

def has_internet_connection() -> bool:
    """Validates internet connectivity via Google DNS (8.8.8.8:53)."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def is_valid_domain(domain) -> bool:
    """
    Validates that a string is a plausible domain name.
    Filters out: IP addresses, junk tokens, strings without dots,
    and strings shorter than 4 characters.
    """
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if domain in JUNK_TOKENS or len(domain) < 4:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return False   # IPv4 address
    if "." not in domain or domain.replace(".", "").isdigit():
        return False
    return True

def _normalize_domain(raw: str) -> str:
    """Strips protocol prefixes, wildcards, paths, and ports."""
    return (raw.strip().lower()
            .replace('http://', '')
            .replace('https://', '')
            .replace('*.', '')
            .split('/')[0]
            .split(':')[0]
            .strip())

def update_malicious_database(force: bool = False) -> None:
    """
    Synchronizes the local CN blacklist with open Threat Intelligence feeds.

    Args:
        force: If True, bypasses the 24-hour freshness check and forces sync.
    """
    # ── Freshness check ───────────────────────────────────────────────────────
    if not force and os.path.exists(DB_PATH):
        file_age = time.time() - os.path.getmtime(DB_PATH)
        if file_age < 86400:
            last_sync = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(os.path.getmtime(DB_PATH))
            )
            print(f"[*] Intelligence database is fresh (Last sync: {last_sync}).")
            return

    if not has_internet_connection():
        print("[!] No internet connection. Operating with cached data.")
        return

    print("[*] Synchronizing Threat Intelligence sources...")
    collected_dfs = []
    headers = {'User-Agent': 'CertVerifier-IDS/2.0'}

    for name, url in SOURCES.items():
        try:
            print(f"    [>] Fetching {name}...")
            r = requests.get(url, headers=headers, timeout=20)
            r.raise_for_status()

            if "SSLBL" in name:
                clean_lines = [l for l in r.text.splitlines() if not l.startswith('#')]
                df = pd.read_csv(io.StringIO("\n".join(clean_lines)),
                                 names=['Date', 'SHA1', 'CN'])
                domains = df['CN'].dropna().tolist()
            else:
                domains = [
                    line.strip()
                    for line in r.text.splitlines()
                    if line.strip() and not line.startswith('#')
                ]

            if domains:
                temp_df = pd.DataFrame({'subject.CN': domains})
                temp_df['source'] = name
                collected_dfs.append(temp_df)
                print(f"    [+] {len(domains)} entries from {name}")

        except Exception as e:
            print(f"    [!] Skipped {name}: {e}")

    if not collected_dfs:
        print("[!] No threat data retrieved. Keeping existing database.")
        return

    try:
        df_new = pd.concat(collected_dfs, ignore_index=True)
        df_new['subject.CN'] = df_new['subject.CN'].astype(str).apply(_normalize_domain)
        df_new = df_new[df_new['subject.CN'].apply(is_valid_domain)]
        df_new = df_new[~df_new['subject.CN'].isin(WHITELIST)]

        if os.path.exists(DB_PATH):
            df_old = pd.read_csv(DB_PATH)
            if 'source' not in df_old.columns:
                df_old['source'] = 'Legacy Source'
            combined = pd.concat([df_new, df_old], ignore_index=True)
        else:
            combined = df_new

        final_db = (combined
                    .drop_duplicates(subset=['subject.CN'], keep='first')
                    .dropna())

        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        final_db.to_csv(DB_PATH, index=False, quoting=1)
        print(f"[+] Sync complete. Database: {len(final_db)} unique threat entries.")

        print("\n" + "─" * 55)
        print(f"{'THREAT SOURCE':<38} | {'COUNT':<10}")
        print("─" * 55)
        for src, count in final_db['source'].value_counts().items():
            print(f"{src:<38} | {count:<10}")
        print("─" * 55 + "\n")

    except Exception as e:
        print(f"[!] Database merge error: {e}")

if __name__ == "__main__":
    update_malicious_database(force=True)
