"""
cert_verifier.py
================
Main CLI entry point for X.509 certificate security analysis.

Usage:
    python3 cert_verifier.py -i <infile|dir> [-o output.csv] [-m 123] [-s]

Detection pipeline:
    1. Load ML models (Naive Bayes classifiers, CountVectorizers)
    2. Load malicious pattern database and CN blacklist
    3. For each certificate: extract 17-dim feature vector → classify
    4. Output structured report or CSV batch results

Scientific basis: see certverifier/features.py for full citations.
"""

import os
import sys
import getopt
import warnings
import pandas

from OpenSSL import crypto
from time import time
from pathlib import Path

from certverifier.utils import (
    print_help, print_report, print_header,
    print_to_file, print_classification_time, print_certificate_counts
)
from certverifier.features import (
    get_class_dict, classify_cert, load_classifiers,
    load_count_vectorizers, pkgfile
)

warnings.filterwarnings("ignore")

# Attempt to load the automatic database synchronizer
try:
    from updater import update_malicious_database
except ImportError:
    update_malicious_database = None

def main():
    argv = sys.argv[1:]
    infile, outfile, mode, strict = "", "output.csv", "123", False

    try:
        opts, _ = getopt.getopt(argv, "hi:o:m:s", ["infile=", "outfile=", "mode=", "strict"])
    except Exception:
        print_help()
        sys.exit(1)

    for opt, arg in opts:
        if opt == "-h":
            print_help(); sys.exit(0)
        if opt == "-i": infile = arg
        if opt == "-o": outfile = arg
        if opt == "-m": mode = arg
        if opt == "-s": strict = True

    if not infile or not os.path.exists(infile):
        print(f"\n[!] Error: Input path '{infile}' not found.")
        print_help()
        return

    # ── Database sync (24h freshness check) ───────────────────────────────────
    if update_malicious_database:
        try:
            update_malicious_database(force=False)
        except Exception as e:
            print(f"[*] Threat Intelligence sync skipped: {e}")

    print("[*] Initializing X.509 Intelligence Engines...")
    try:
        patterns = (
            pandas.read_csv(pkgfile("data/malicious-patterns-with-malware.csv"))
            .drop('malware', axis=1)
            .values.tolist()
        )
        blacklist = (
            pandas.read_csv(pkgfile("data/malicious_subjectCN.csv"))
            ['subject.CN'].values.tolist()
        )
        clfs = load_classifiers()
        vecs = load_count_vectorizers()
    except Exception as e:
        print(f"[!] Critical Error: Could not load data or models: {e}")
        return

    # ── SINGLE FILE MODE ──────────────────────────────────────────────────────
    if os.path.isfile(infile):
        try:
            with open(infile, 'rb') as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            issuer_dn = ", ".join(
                f"{k.decode()}={v.decode()}"
                for k, v in issuer.get_components()
            )
            c_dict = get_class_dict(cert, clfs, vecs)
            verdict = classify_cert(cert, mode, strict, c_dict, patterns, blacklist)
            print_report(
                target_name=os.path.basename(infile),
                cn=str(subject.CN),
                c_dict=c_dict,
                verdict=verdict,
                serial=hex(cert.get_serial_number()),
                sig_algo=cert.get_signature_algorithm().decode(),
                issuer_dn=issuer_dn,
            )
        except Exception as e:
            print(f"[!] Analysis error: {e}")

    # ── BATCH DIRECTORY MODE ──────────────────────────────────────────────────
    elif os.path.isdir(infile):
        start_time = time()
        all_verdicts = []
        pem_files = sorted(
            f for f in os.listdir(infile) if f.endswith(".pem")
        )

        print(f"[*] Batch Mode: Analyzing {len(pem_files)} certificates...")
        skipped = 0

        with open(outfile, 'w') as out:
            print_header(out)
            for filename in pem_files:
                filepath = os.path.join(infile, filename)
                try:
                    with open(filepath, 'rb') as f:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                    c_dict = get_class_dict(cert, clfs, vecs)
                    verdict = classify_cert(cert, mode, strict, c_dict, patterns, blacklist)
                    print_to_file(out, filename, verdict, c_dict)
                    all_verdicts.append(verdict)
                    status_sym = "🔴" if "MALICIOUS" in verdict else ("🟡" if "SUSPICIOUS" in verdict else "🟢")
                    print(f"  {status_sym} {filename:45} → {verdict}")
                except Exception:
                    print(f"  ⏭  {filename:45} → [SKIPPED: not a valid X.509 PEM]")
                    skipped += 1

        if skipped:
            print(f"\n[*] {skipped} file(s) skipped (non-certificate or corrupted).")

        print_classification_time(start_time)
        print_certificate_counts(all_verdicts)
        print(f"[+] Results saved to: {outfile}")

    else:
        print(f"[!] Path '{infile}' is neither a file nor a directory.")

if __name__ == "__main__":
    main()
