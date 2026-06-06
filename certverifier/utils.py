"""
certverifier/utils.py
=====================
Terminal output formatting and report generation utilities.
"""

import os
from time import time
from typing import List, Dict, Optional

def print_help():
    print("\n" + "=" * 68)
    print("| cert-verifier - X.509 Certificate Security Intelligence Tool |")
    print("=" * 68)
    print("Usage: python3 cert_verifier.py -i <infile> [-o <outfile>] [-m 1/2/3] [-s]")
    print("\nArguments:")
    print("  -i <path>   Input: single .PEM file or directory of .PEM files")
    print("  -o <path>   Output CSV file for batch scan results")
    print("  -m <modes>  Detection modes (combine: -m 123 = all modes)")
    print("              1 = Bad Issuers (botnet C2 infrastructure)")
    print("              2 = Phishing Templates (mass-campaign malware)")
    print("              3 = Structural Anomalies (novel malware patterns)")
    print("  -s          Strict mode: requires CN in known-malicious blacklist")
    print("\nHeuristic Modules (always active):")
    print("  Shannon Entropy > 4.2  → DGA/Botnet C2 detection")
    print("  Punycode xn-- prefix   → IDN Homograph phishing detection")
    print("  Age < 3d + Self-signed → Short-lived phishing certificate")
    print("=" * 68 + "\n")

def _verdict_color(verdict: str) -> str:
    if "MALICIOUS" in verdict or "CRITICAL" in verdict:
        return "\033[1;31m"   # bold red
    if "SUSPICIOUS" in verdict:
        return "\033[1;33m"   # bold yellow
    return "\033[1;32m"       # bold green

def print_report(target_name: str, cn: str, c_dict: Dict, verdict: str,
                 ip: Optional[str] = None,
                 serial: Optional[str] = None,
                 sig_algo: Optional[str] = None,
                 issuer_dn: Optional[str] = None):
    """Generates a structured forensic report card for a single certificate."""
    color = _verdict_color(verdict)
    reset = "\033[0m"
    sep = "─" * 80

    print(f"\n{color}{sep}{reset}")
    print(f"{color} ▶ VERDICT: {verdict}{reset}")
    print(f" TARGET : {target_name}")
    if ip:
        print(f" IP ADDR: {ip}")
    print(f"{color}{sep}{reset}")
    print(f"  [X.509 Identity]")
    print(f"    Subject CN : {cn}")
    if issuer_dn:
        print(f"    Issuer DN  : {issuer_dn}")
    if serial:
        print(f"    Serial     : {serial}")
    if sig_algo:
        print(f"    Algorithm  : {sig_algo}")
    print(f"  [Heuristic Analysis]")
    print(f"    Entropy    : {c_dict['entropy']:.4f} bits  "
          f"{'⚠ ABOVE 4.2 THRESHOLD' if c_dict['entropy'] > 4.2 else '✓ within normal range'}")
    print(f"    Cert Age   : {c_dict['cert_age_days']} days  "
          f"{'⚠ FRESHLY ISSUED' if c_dict['cert_age_days'] < 3 else ''}")
    print(f"    Punycode   : {'⚠ DETECTED (xn--)' if c_dict['punycode_detected'] else '✓ none'}")
    print(f"    Self-signed: {'⚠ YES' if c_dict['self.signed'] else '✓ CA-issued'}")
    print(f"{color}{sep}{reset}\n")

def print_header(outfile):
    print("file,status,entropy,cert_age_days,punycode,self_signed,verdict", file=outfile)


def print_to_file(outfile, filename, verdict_text, c_dict):
    status = "benign" if ("CLEAN" in verdict_text or "SAFE" in verdict_text) else "malign"
    print(
        f"{filename},{status},{c_dict['entropy']:.4f},"
        f"{c_dict['cert_age_days']},{c_dict['punycode_detected']},"
        f"{c_dict['self.signed']},{verdict_text}",
        file=outfile
    )

def print_classification_time(start_time: float):
    elapsed = round(time() - start_time, 3)
    print(f"\n[+] Classification time: {elapsed}s")

def print_certificate_counts(results: List[str]):
    total = len(results)
    malicious = sum(1 for r in results if "MALICIOUS" in r)
    suspicious = sum(1 for r in results if "SUSPICIOUS" in r)
    clean = total - malicious - suspicious
    print("─" * 40)
    print(" BATCH SCAN SUMMARY")
    print("─" * 40)
    print(f" Total Processed : {total}")
    print(f" 🔴 Malicious    : {malicious}")
    print(f" 🟡 Suspicious   : {suspicious}")
    print(f" 🟢 Clean/Safe   : {clean}")
    print("─" * 40)
