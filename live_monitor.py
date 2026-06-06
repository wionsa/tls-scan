"""
live_monitor.py
===============
Real-time SSL/TLS traffic monitor with multi-threaded certificate analysis.

Architecture:
    Scapy packet sniffer → IP queue → Worker thread pool →
    X.509 extraction → Hybrid analysis → Terminal alert

External intelligence feeds (synchronized at startup):
    - Tranco Top-1000 whitelist (popular domain suppression)
    - StevenBlack hosts list (ad/tracker noise reduction)
    - Abuse.ch SSLBL SHA1 fingerprint blacklist (C2 detection)

Scientific note on threading model:
    Worker pool of 15 threads handles the I/O-bound TLS handshake
    latency (~200-800ms per host). A 60-second deduplication window
    prevents re-analysis of the same server during a browsing session.
"""

import os
import sys
import ssl
import threading
import queue
import warnings
import hashlib
import socket
import time
import re

import pandas
import requests
from scapy.all import sniff, IP, IPv6, TCP
from OpenSSL import crypto
from pathlib import Path
from colorama import init, Fore, Style

from certverifier.features import (
    load_classifiers, load_count_vectorizers,
    get_class_dict, classify_cert, pkgfile,
)
from certverifier.utils import print_report
from updater import update_malicious_database

init(autoreset=True)
warnings.filterwarnings("ignore")

# ── Globals ───────────────────────────────────────────────────────────────────
packet_queue = queue.Queue()
processed_hosts: dict = {}
processed_lock = threading.Lock()
ALERT_LOG = "network_alerts.log"
WORKER_COUNT = 15
DEDUP_WINDOW_SECS = 60

# Cache paths
CACHE_DIR = Path("certverifier/data/cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)
WHITE_CACHE  = CACHE_DIR / "tranco_whitelist.txt"
AD_CACHE     = CACHE_DIR / "adaway_hosts.txt"
SSL_BL_CACHE = CACHE_DIR / "sslbl_hashes.txt"

# Intelligence sets (populated at startup by sync_external_feeds)
WHITELIST:          set = set()
AD_TRACKER_LIST:    set = set()
C2_SSL_FINGERPRINTS: set = set()

# Domains that generate high-frequency benign noise
NOISE_TOKENS = [
    "invalid2.invalid", "localhost", "none", "local",
    "null", "badssl-fallback", "connectivity-check",
]

def log_alert(hostname: str, ip: str, reason: str, sha1: str) -> None:
    """Appends a structured alert entry to the log file."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(ALERT_LOG, "a") as f:
        f.write(
            f"[{ts}] ALERT | host={hostname} | ip={ip} "
            f"| sha1={sha1[:16]}... | reason={reason}\n"
        )

def sync_external_feeds() -> None:
    """
    Synchronizes three intelligence feed categories:

      1. Tranco Top-1000 whitelist — suppresses popular-domain alerts.
         Published by: Le Pochat et al. (2019) "Tranco: A Research-Oriented
         Top Sites Ranking Hardened Against Manipulation."
         https://tranco-list.eu

      2. StevenBlack unified hosts — reduces ad/tracker alert noise.
         https://github.com/StevenBlack/hosts

      3. Abuse.ch SSLBL SHA1 fingerprints — direct C2 certificate matching.
         Provides ground-truth blacklist with ~99% precision on matched hashes.
    """
    global WHITELIST, AD_TRACKER_LIST, C2_SSL_FINGERPRINTS
    print(f"{Fore.CYAN}[*] Synchronizing Dynamic Intelligence Feeds...")

    headers = {'User-Agent': 'CertVerifier-IDS/2.0'}

    # 1. Tranco whitelist
    tranco_urls = [
        "https://tranco-list.eu/download/K2N9J/1000",
        "https://raw.githubusercontent.com/jsha/tranco/master/tranco_K2N9J-1000.csv",
    ]
    for url in tranco_urls:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200 and len(r.text) > 100:
                WHITELIST = {
                    line.split(',')[1].strip().lower()
                    for line in r.text.splitlines() if ',' in line
                }
                if len(WHITELIST) > 100:
                    WHITE_CACHE.write_text("\n".join(WHITELIST))
                    break
        except Exception:
            continue
    if not WHITELIST and WHITE_CACHE.exists():
        WHITELIST = set(WHITE_CACHE.read_text().splitlines())

    # 2. Ad/Tracker hosts
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            timeout=12
        )
        if r.status_code == 200:
            AD_TRACKER_LIST = set(
                re.findall(r"(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+)", r.text)
            )
            AD_CACHE.write_text("\n".join(AD_TRACKER_LIST))
    except Exception:
        if AD_CACHE.exists():
            AD_TRACKER_LIST = set(AD_CACHE.read_text().splitlines())

    # 3. SSLBL SHA1 fingerprints
    try:
        r = requests.get(
            "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
            timeout=12
        )
        if r.status_code == 200:
            C2_SSL_FINGERPRINTS = {
                line.split(',')[1].strip().lower()
                for line in r.text.splitlines()
                if not line.startswith('#') and ',' in line
            }
            SSL_BL_CACHE.write_text("\n".join(C2_SSL_FINGERPRINTS))
    except Exception:
        if SSL_BL_CACHE.exists():
            C2_SSL_FINGERPRINTS = set(SSL_BL_CACHE.read_text().splitlines())

    print(
        f"[+] Feeds loaded: {len(WHITELIST)} whitelisted | "
        f"{len(AD_TRACKER_LIST)} ad-trackers | "
        f"{len(C2_SSL_FINGERPRINTS)} C2 fingerprints"
    )

def get_cert_via_sni(ip: str, hostname: str):
    """
    Performs a full TLS handshake with SNI extension to retrieve the actual
    certificate presented for the specific hostname (bypasses CDN wildcard certs).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
    except Exception:
        return None

def worker(clfs, vecs, patterns, local_blacklist) -> None:
    """
    Thread worker: retrieves certificate → extracts features →
    runs hybrid analysis → prints or logs result.
    """
    while True:
        ip_addr = packet_queue.get()
        if ip_addr is None:
            break
        try:
            temp_pem = ssl.get_server_certificate((ip_addr, 443), timeout=1.5)
            temp_cert = crypto.load_certificate(crypto.FILETYPE_PEM, temp_pem)
            hostname = str(temp_cert.get_subject().CN).replace("*.", "").lower()

            if any(n in hostname for n in NOISE_TOKENS) or len(hostname) < 4:
                packet_queue.task_done()
                continue

            cert = get_cert_via_sni(ip_addr, hostname)
            if not cert:
                packet_queue.task_done()
                continue

            sha1 = hashlib.sha1(
                crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
            ).hexdigest().lower()

            base_domain = ".".join(hostname.split(".")[-2:])
            is_popular = hostname in WHITELIST or base_domain in WHITELIST
            is_ad = hostname in AD_TRACKER_LIST or base_domain in AD_TRACKER_LIST

            c_dict = get_class_dict(cert, clfs, vecs)
            verdict = classify_cert(cert, "123", False, c_dict, patterns, local_blacklist)

            is_threat = False
            status_label = verdict

            if sha1 in C2_SSL_FINGERPRINTS:
                status_label = "CRITICAL: BLACKLISTED C2 (SHA1 Match)"
                is_threat = True
            elif verdict != "CLEAN" and not is_popular:
                is_threat = True

            if is_threat:
                sys.stdout.write('\a')  # terminal bell
                log_alert(hostname, ip_addr, status_label, sha1)
                issuer_dn = ", ".join(
                    f"{k.decode()}={v.decode()}"
                    for k, v in cert.get_issuer().get_components()
                )
                print_report(
                    target_name=f"LIVE:{ip_addr}",
                    cn=hostname,
                    c_dict=c_dict,
                    verdict=status_label,
                    ip=ip_addr,
                    serial=hex(cert.get_serial_number()),
                    sig_algo=cert.get_signature_algorithm().decode(),
                    issuer_dn=issuer_dn,
                )
            else:
                ts = time.strftime('%H:%M:%S')
                if is_popular:
                    label, color = "POPULAR", Fore.CYAN
                elif is_ad:
                    label, color = "AD-HOST", Fore.WHITE + Style.DIM
                else:
                    label, color = "CLEAN  ", Fore.GREEN
                print(
                    f"{color}[{ts}] {label} | {hostname:38} | "
                    f"H={c_dict['entropy']:.2f} | "
                    f"age={c_dict['cert_age_days']}d"
                )

        except Exception:
            pass
        packet_queue.task_done()

def packet_handler(pkt) -> None:
    """Scapy callback: enqueues destination IP for analysis on TCP:443 packets."""
    if not (pkt.haslayer(TCP) and pkt[TCP].dport == 443):
        return
    dst = (pkt[IP].dst if pkt.haslayer(IP)
           else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None))
    if not dst:
        return
    now = time.time()
    with processed_lock:
        if dst not in processed_hosts or (now - processed_hosts[dst]) > DEDUP_WINDOW_SECS:
            processed_hosts[dst] = now
            packet_queue.put(dst)

def main() -> None:
    update_malicious_database(force=False)
    sync_external_feeds()

    clfs = load_classifiers()
    vecs = load_count_vectorizers()

    p_df = pandas.read_csv(pkgfile("data/malicious-patterns-with-malware.csv"))
    patterns = p_df.drop('malware', axis=1).values.tolist()

    b_df = pandas.read_csv(pkgfile("data/malicious_subjectCN.csv"))
    local_blacklist = b_df['subject.CN'].values.tolist()
    source_stats = (
        b_df['source'].value_counts()
        if 'source' in b_df.columns
        else {"Legacy": len(b_df)}
    )

    for _ in range(WORKER_COUNT):
        threading.Thread(
            target=worker,
            args=(clfs, vecs, patterns, local_blacklist),
            daemon=True,
        ).start()

    print("\n" + "=" * 100)
    print(f"{Fore.GREEN}{Style.BRIGHT} 🛡  X.509 FORENSIC ENGINE | INTELLIGENCE-DRIVEN LIVE IDS")
    print(f" {Fore.WHITE}Dynamic Feeds:")
    print(f"   {Fore.YELLOW}» {len(WHITELIST):<8}{Fore.WHITE} Popular Domains (Tranco)")
    print(f"   {Fore.YELLOW}» {len(AD_TRACKER_LIST):<8}{Fore.WHITE} Ad/Tracker Domains (StevenBlack)")
    print(f"   {Fore.YELLOW}» {len(C2_SSL_FINGERPRINTS):<8}{Fore.WHITE} C2 SHA1 Fingerprints (Abuse.ch SSLBL)")
    print(f"\n {Fore.WHITE}Local Threat DB (by source):")
    for src, count in source_stats.items():
        print(f"   {Fore.CYAN}» {count:<8}| {src}")
    print(f"\n {Fore.CYAN}Monitoring port 443... Alerts logged to: '{ALERT_LOG}'")
    print("=" * 100 + "\n")

    try:
        sniff(filter="tcp dst port 443", prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
