"""
batch_update_signatures.py
==========================
Batch signature database updater.

Reads all verified malicious certificates from verified_malicious_certs/,
extracts their 14-parameter ML feature vectors (the same dimensionality used
by the classification engine), and appends them to the pattern database.

Deduplication: Structural duplicates (same 14-dim vector) are dropped,
keeping only the most recent entry. This prevents database bloat while
preserving all unique threat patterns.

Workflow:
    sslbl_harvester.py → mass_grabber.py → batch_update_signatures.py
"""

import os
import pandas as pd
from OpenSSL import crypto
from certverifier.features import (
    get_class_dict, load_classifiers, load_count_vectorizers
)

CERTS_DIR = "verified_malicious_certs"
DB_PATH   = "certverifier/data/malicious-patterns-with-malware.csv"

PATTERN_COLUMNS = [
    "subject.CN.category", "subject.OU.category", "subject.O.category",
    "subject.L.category",  "subject.S.category",  "subject.C.category",
    "subject.E.category",  "issuer.CN.category",  "self.signed.category",
    "algorithm.category",  "keylength.category",  "seconds.category",
    "days.category",       "years.category",       "malware",
]

def main() -> None:
    if not os.path.exists(CERTS_DIR):
        print(f"[!] Folder '{CERTS_DIR}' not found. Run mass_grabber.py first.")
        return

    print("[*] Loading ML Models for feature extraction...")
    clf = load_classifiers()
    vec = load_count_vectorizers()

    pem_files = [f for f in os.listdir(CERTS_DIR) if f.endswith(".pem")]
    print(f"[*] Found {len(pem_files)} verified certificates in '{CERTS_DIR}'.")

    new_patterns = []

    for filename in pem_files:
        try:
            path = os.path.join(CERTS_DIR, filename)
            with open(path, 'rb') as f:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

            d = get_class_dict(cert, clf, vec)

            # Extract malware family label from filename
            # Convention: Vidar_C&C_e6695638.pem → "Vidar (2026 Intelligence)"
            malware_label = filename.split('_')[0] + " (2026 Intelligence)"

            pattern = [
                d['subject.CN'], d['subject.OU'], d['subject.O'], d['subject.L'],
                d['subject.S'],  d['subject.C'],  d['subject.E'], d['issuer.CN'],
                d['self.signed'], d['algorithm'], d['keylength'],
                d['seconds'],    d['days'],       d['years'],
                malware_label,
            ]
            new_patterns.append(pattern)
            print(f"  [+] {filename}")
        except Exception as e:
            print(f"  [!] Skipped {filename}: {e}")

    if not new_patterns:
        print("[!] No new patterns extracted.")
        return

    df_new = pd.DataFrame(new_patterns, columns=PATTERN_COLUMNS)

    if os.path.exists(DB_PATH):
        df_old = pd.read_csv(DB_PATH)
        df_combined = pd.concat([df_old, df_new])
    else:
        df_combined = df_new

    feature_cols = PATTERN_COLUMNS[:-1]
    df_final = df_combined.drop_duplicates(subset=feature_cols, keep='last')

    df_final.to_csv(DB_PATH, index=False, quoting=1)
    print(f"\n[+] Database updated: {len(df_final)} total patterns.")

    added = len(df_final) - (len(pd.read_csv(DB_PATH)) if os.path.exists(DB_PATH) else 0)
    print(f"[+] New unique patterns added: {max(0, len(df_new))}")

if __name__ == "__main__":
    main()
