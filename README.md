# ML-IDS Engine

> **AI-powered SSL/TLS certificate intelligence for phishing and malware infrastructure detection**

A network intrusion detection system (NIDS) that performs deep forensic inspection of X.509 certificate metadata in real time - identifying botnet C2 channels, phishing infrastructure and DGA-generated domains across live TCP/443 traffic and static PEM files.

Built on top of [cert-verifier](https://github.com/422562/cert-verifier) (Gregušková, 2021, MIT License).

---

## How it works

The engine processes certificates through a three-layer hybrid pipeline:

```
[TCP:443 traffic]  or  [.PEM File]
         │
         ▼  Scapy sniffer/PEM reader
  [X.509 certificate object]
         │
         ├──▶ Layer A: ML classification
         │      8 subject/issuer DN fields
         │      → CountVectorizer (bag-of-words)
         │      → Multinomial Naive Bayes × 8 models
         │      + self_signed, algorithm, keylength, validity period
         │      → 14-dimensional feature vector
         │
         ├──▶ Layer B: heuristic analysis
         │      Shannon entropy  H(X) = -Σ p(x)·log₂(p(x))  [DGA detection]
         │      Punycode/IDN homograph  (RFC 3492)          [phishing]
         │      Certificate age  (notBefore → now)          [C2 anomaly]
         │
         └──▶ Layer C: reputation/threat intel
                Abuse.ch SSLBL - SHA1 fingerprint matching
                OSINT blacklist — 422,077 known-malicious CNs
                         │
                         ▼  Fusion logic (classify_cert)
              [CLEAN | SUSPICIOUS | MALICIOUS | CRITICAL]
                         │
                         ▼
           [Terminal report/CSV export/web dashboard]
```

---

## Detection methods and scientific basis

### 1. Multinomial Naive Bayes - X.509 field classification

Each distinguished name field (subject CN, O, OU, L, S, C, E and issuer CN) is independently vectorized and classified by a dedicated Naive Bayes model trained on a corpus of malicious and benign certificates.

> Liu, X. et al. (2021). *Machine Learning-Based Malicious X.509 Certificates' Detection*. Applied Sciences, 11(5), 2164. https://doi.org/10.3390/app11052164  
> Gregušková, N. (2021). *TLS Certificate Analysis*. Master's Thesis, Masaryk University. - up to 91.78% detection rate on test corpus.

### 2. Shannon Entropy - DGA/botnet C2 detection

High character entropy in the Common Name field is a reliable signal of algorithmically generated domains used by botnets. Threshold H > 4.2 bits is calibrated against the Abuse.ch SSLBL corpus.

> Wong, A.D. (2023). *Detecting DGA-Based FQDNs with Shannon Entropy*. arXiv:2304.07943.  
> Alleyne, M.C. et al. (2022). *Content-Agnostic Detection of Phishing Domains using Certificate Transparency and Passive DNS*. RAID 2022.

### 3. Punycode/IDN homograph detection

The `xn--` prefix defined in RFC 3492 uniquely marks Punycode-encoded internationalized domain names - a common vector for lookalike phishing attacks (e.g., `xn--pypl-ppa.com` - `paypal.com`).

> Gabrilovich, E. & Gontmakher, A. (2002). *The Homograph Attack*. Communications of the ACM, 45(2).  
> Akamai Security Research (2022): 6,670 active homograph domains contacted by 29,071 unique devices over 32 days.

### 4. Certificate age anomaly

Over 60% of C2 certificates are deployed within 72 hours of issuance. A short-lived self-signed certificate (age < 3 days AND self-signed) is a strong predictor of ephemeral phishing infrastructure.

> Operational heuristic based on Abuse.ch SSLBL dataset analysis (2024).  
> Normative context: CA/Browser Forum SC-081v3 (2025) - max certificate lifetime will be reduced to 47 days by 2029.

---

## Verdict matrix

| Verdict | Severity | Method | Trigger condition | Available in |
|---|---|---|---|---|
| `CRITICAL: BLACKLISTED C2` | 🔥 Critical | SHA1 fingerprint | SSLBL hash match | Live monitor only |
| `MALICIOUS: Botnet Infrastructure` | 🔴 High | Signature (Mode 1) | `issuer.CN == 5` + pattern match | CLI/Web/Live |
| `MALICIOUS: Phishing Template` | 🔴 High | Signature (Mode 2) | `subject.CN == 1` + pattern match | CLI/Web/Live |
| `MALICIOUS: Structural Anomaly` | 🔴 High | Signature (Mode 3) | 14-dim vector match | CLI/Web/Live |
| `MALICIOUS: Phishing Homograph Attack` | 🔴 High | Algorithmic | Punycode `xn--` in CN | CLI/Web/Live |
| `SUSPICIOUS: High Entropy Domain` | 🟡 Medium | Heuristic (DGA) | H(X) > 4.2 bits | CLI/Web/Live |
| `SUSPICIOUS: Short-lived Self-signed` | 🟡 Medium | Heuristic | age < 3d AND self-signed | CLI/Web/Live |
| `SUSPICIOUS: Untrusted Structure Pattern` | 🟡 Medium | Strict mode | pattern match + CN not in blacklist | CLI only (`-s` flag) |
| `CLEAN` | 🟢 Safe | Composite | No anomalies detected | CLI/Web/Live |

---

## Project structure

```
ml-ids-engine/
├── cert_verifier.py            # CLI analyzer - single PEM or batch directory
├── live_monitor.py             # Real-time traffic monitor (terminal)
├── web.py                      # Flask + Socket.IO web dashboard
├── updater.py                  # Threat intelligence auto-sync (24h freshness)
├── sslbl_harvester.py          # IoC harvester from Abuse.ch SSLBL
├── mass_grabber.py             # SHA1-verified certificate mass fetcher
├── batch_update_signatures.py  # Signature database updater
├── setup.py
├── static/
│   ├── app.js
│   └── style.css
├── templates/
│   └── index.html              # Web dashboard UI
└── certverifier/               # Core analysis package
    ├── features.py             # ML + heuristic engine
    ├── utils.py                # Report formatting & terminal output
    ├── count_vectorizers/      # 8 pre-trained CountVectorizer models (.sav)
    ├── models/                 # 8 pre-trained Naive Bayes classifiers (.sav)
    └── data/
        ├── malicious-patterns-with-malware.csv   # 557 known malicious signatures
        └── malicious_subjectCN.csv               # 422,077 known-malicious CNs (OSINT)

```

---

## Requirements
 
| | |
|---|---|
| Python | ≥ 3.10 |
| Disk space | ~500 MB (dependencies + ML models) |
| RAM | ~300 MB at runtime |
| Root/sudo | Required for live traffic capture only |
| OS | Linux (tested on Kali Linux) |
 
---
 
## Installation
 
> **Note for Kali Linux (and other Debian-based distros):** the system Python is externally managed. Use a virtual environment as shown below.
 
```bash
# 1. Clone the repository
git clone https://github.com/wionsa/tls-scan.git
cd tls-scan
 
# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate
 
# 3. Install dependencies
pip install -e .
```
 
All dependencies (~80 MB download) are declared in `setup.py` and will be installed automatically.
 
---
 
## Network interface configuration
 
The live traffic sniffer captures on `eth0` by default. Before running, verify your active interface:
 
```bash
ip a
```
 
If your interface name differs, update line 240 in `web.py`:
 
```python
# web.py, line 240
sniff(iface="eth0", ...)  # replace eth0 with your interface name
```
 
Common interface names on Kali Linux:
 
| Interface | Description |
|---|---|
| `eth0` | Wired (default in most VMs) |
| `wlan0` | Wireless |
| `ens33`/`ens3` | VMware/VirtualBox |
 
> The PEM upload and URL analysis modes work regardless of interface configuration.
 
---
 
## Usage
 
There are two equivalent ways to run the CLI tools:
 
**Option A - activate venv once per session, then use `python3` normally:**
```bash
source venv/bin/activate
python3 cert_verifier.py -i certificate.pem
```
 
**Option B - use explicit path without activating venv:**
```bash
venv/bin/python3 cert_verifier.py -i certificate.pem
```
 
> For `web.py` and `live_monitor.py`, root access is required for packet capture. Since `sudo` does not inherit the venv, always use the explicit path:
> ```bash
> sudo venv/bin/python3 web.py
> sudo venv/bin/python3 live_monitor.py
> ```
 
---
 
### CLI - single PEM file analysis
```bash
python3 cert_verifier.py -i certificate.pem
```
 
### CLI - batch directory scan with CSV export
```bash
python3 cert_verifier.py -i samples/ -o report.csv
```
 
### CLI - detection modes
```bash
python3 cert_verifier.py -i sample.pem -m 1      # Mode 1: Bad issuers (botnet C2)
python3 cert_verifier.py -i sample.pem -m 2      # Mode 2: Phishing templates
python3 cert_verifier.py -i sample.pem -m 3      # Mode 3: Structural anomalies
python3 cert_verifier.py -i sample.pem -m 123    # All modes combined (default)
python3 cert_verifier.py -i sample.pem -m 123 -s # Strict mode (CN blacklist required)
```
 
### Real-time live traffic monitor (terminal)
 
Captures TCP port 443 traffic, initiates TLS handshakes and analyzes certificates as they appear - with deduplication to suppress repeated alerts for the same host.
 
```bash
sudo venv/bin/python3 live_monitor.py
```
 
### Web dashboard
 
Provides a real-time streaming interface with certificate detail panels, threat statistics, domain/IP search, PEM file upload and URL-based on-demand analysis.
 
```bash
sudo venv/bin/python3 web.py
# → http://127.0.0.1:5000
```
 
### OSINT signature pipeline (threat database update)
```bash
python3 sslbl_harvester.py          # Fetch fresh IoCs from Abuse.ch → sslbl_threat_intel.csv
python3 mass_grabber.py             # Verify SHA1 fingerprints → verified_malicious_certs/
python3 batch_update_signatures.py  # Rebuild the malicious pattern database
```
 
---
 
## Data assets
 
**`malicious-patterns-with-malware.csv`** - 557 unique malicious certificate signatures extracted from ESET and Abuse.ch SSLBL datasets. Each row is a 14-dimensional categorical vector derived from ML classification of DN fields plus structural certificate attributes, labeled with the associated malware family.
 
**`malicious_subjectCN.csv`** - 422,077 known-malicious Common Name values aggregated from multiple OSINT feeds. Used for blacklist matching in strict mode and reputation scoring.
 
---
 
## Attribution
 
The original `cert-verifier` tool was developed by **Natalia Gregušková** (Masaryk University, 2021) as part of her master's thesis *"TLS Certificate Analysis"*. Released under the MIT License.
 
This project extends the original with:
- Real-time network monitoring via Scapy packet capture
- Web dashboard (Flask + Socket.IO) with streaming results
- OSINT pipeline for automated threat intelligence updates
- Extended heuristics: Shannon entropy, Punycode/IDN homograph detection, certificate age anomaly
- SSLBL SHA1 fingerprint matching for known C2 infrastructure
---
 
## License
 
MIT - see original [cert-verifier](https://github.com/422562/cert-verifier) repository.
