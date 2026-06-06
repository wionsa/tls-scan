"""
mass_grabber.py
===============
Verified TLS certificate capture module.

For each entry in the SSLBL threat intel CSV (produced by sslbl_harvester.py):
    1. Opens a direct TCP + TLS connection to the C2 server (with SNI).
    2. Captures the raw certificate bytes.
    3. Computes SHA1 fingerprint and compares against the expected hash.
    4. If they match → saves as PEM in verified_malicious_certs/.
    5. If they don't match → logs as MASKED/CHANGED (CDN proxy or rotation).
    6. If connection fails → logs as OFFLINE.

The SHA1 integrity check is critical: malicious servers behind Cloudflare
or other CDN proxies will present a different certificate, which would
contaminate the signature database with legitimate CDN certs.

This module was designed to address that: only certificates with a verified
SHA1 match against the SSLBL ground-truth fingerprint are saved.
"""

import hashlib
import os
import ssl
import socket

import pandas as pd
from OpenSSL import crypto

OUTPUT_DIR   = "verified_malicious_certs"
INPUT_CSV    = "sslbl_threat_intel.csv"
CONNECT_TIMEOUT = 5   # seconds per connection attempt

def get_cert_fingerprint(cert_bin: bytes) -> str:
    """Computes SHA1 fingerprint of raw DER-encoded certificate bytes."""
    return hashlib.sha1(cert_bin).hexdigest().lower()

def capture_and_verify(ip_port: str, hostname: str, expected_sha1: str):
    """
    Connects to ip_port, captures the TLS certificate, and verifies its SHA1.

    Returns:
        (True,  pem_bytes) — certificate verified, PEM-encoded bytes
        (False, reason_str) — mismatch or connection failure
    """
    try:
        host, port = ip_port.split(':')
        port = int(port)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode   = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)

        actual_sha1 = get_cert_fingerprint(cert_bin)

        if actual_sha1 == expected_sha1.lower():
            cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
            pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_obj)
            return True, pem_data
        else:
            return False, f"MASKED_OR_CHANGED (actual: {actual_sha1[:8]}...)"

    except Exception as e:
        return False, f"OFFLINE ({e})"

def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(INPUT_CSV):
        print(f"[!] {INPUT_CSV} not found. Run sslbl_harvester.py first.")
        return

    df = pd.read_csv(INPUT_CSV)
    total = len(df)
    print(f"[*] Starting Verified Capture for {total} entries...")
    stats = {"success": 0, "masked": 0, "offline": 0}

    for idx, row in df.iterrows():
        sha1       = row['sha1']
        cn         = row['cn']
        socket_str = row['socket']
        reason     = str(row['reason']).replace(' ', '_').replace('/', '-')

        print(f"  [{idx+1}/{total}] {reason[:30]:30} ({socket_str})... ", end="", flush=True)

        success, result = capture_and_verify(socket_str, cn, sha1)

        if success:
            filename = f"{reason}_{sha1[:8]}.pem"
            with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
                f.write(result)
            print("✅  VERIFIED & SAVED")
            stats["success"] += 1
        elif "MASKED" in result:
            print(f"❌  MISMATCH — {result}")
            stats["masked"] += 1
        else:
            print("💤  OFFLINE")
            stats["offline"] += 1

    print("\n" + "=" * 45)
    print("     CAPTURE RESULTS SUMMARY")
    print("=" * 45)
    print(f" Successfully Verified : {stats['success']}")
    print(f" Masked / Changed      : {stats['masked']}")
    print(f" Servers Offline       : {stats['offline']}")
    print(f" Verified certs saved  : ./{OUTPUT_DIR}/")
    print("=" * 45)
    print("[*] Next step: run batch_update_signatures.py to update the pattern DB.")

if __name__ == "__main__":
    main()
