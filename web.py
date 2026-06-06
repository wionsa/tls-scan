import os, ssl, time, json, warnings, threading, pandas, socket
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from scapy.all import sniff, IP, IPv6, TCP
from OpenSSL import crypto
from pathlib import Path
from werkzeug.utils import secure_filename

from certverifier.features import (
    load_classifiers, load_count_vectorizers,
    get_class_dict, classify_cert, pkgfile
)
from updater import update_malicious_database

warnings.filterwarnings("ignore")

# ── Flask app ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── ML ─────────────────────────────────────────────────────────────────────
clfs     = load_classifiers()
vecs     = load_count_vectorizers()
patterns = pandas.read_csv(pkgfile("data/malicious-patterns-with-malware.csv")) \
                 .drop('malware', axis=1).values.tolist()
blacklist = pandas.read_csv(pkgfile("data/malicious_subjectCN.csv"))['subject.CN'].values.tolist()

processed_ips = {}

LIVE_MODE = "123"

TECHNICAL_DOMAINS = [
    'invalid2.invalid', 'normandy', 'mozgcp.net', 'push.services.mozilla.com',
    'sni-347-default', 'gcp.gvt2.com', 'connectivity-check',
]

# ── Event history ──────────────────────────────────────────────────────────
HISTORY_PATH = Path(__file__).resolve().parent / "event_history.json"
HISTORY_MAX  = 1000
history_lock = threading.Lock()
event_history = []

def load_history():
    global event_history
    if HISTORY_PATH.exists():
        try:
            event_history = json.loads(HISTORY_PATH.read_text(encoding='utf-8'))
        except Exception:
            event_history = []

def save_history():
    try:
        with history_lock:
            HISTORY_PATH.write_text(
                json.dumps(event_history[-HISTORY_MAX:], ensure_ascii=False, indent=1),
                encoding='utf-8'
            )
    except Exception as e:
        print(f"[!] Failed to save history: {e}")

def append_history(event: dict):
    with history_lock:
        event_history.append(event)
        if len(event_history) > HISTORY_MAX:
            del event_history[:-HISTORY_MAX]
    save_history()

# ── Mode validation ────────────────────────────────────────────────────────
def sanitize_mode(raw) -> str:
    if not raw:
        return "123"
    allowed = {c for c in str(raw) if c in "123"}
    return "".join(sorted(allowed)) if allowed else "123"

# ── Building a complete record (event) ─────────────────────────────────────
def build_event(cert, source: str, source_ip: str = "", requested: str = "", mode: str = "123"):
    """
    source: 'traffic' | 'url' | 'file'
    mode: combination of '1','2','3' - signature detection modes
    """
    subject = cert.get_subject()
    issuer  = cert.get_issuer()
    cn = str(subject.CN).replace("*.", "").lower() if subject.CN else "(unknown)"

    c_dict  = get_class_dict(cert, clfs, vecs)
    verdict = classify_cert(cert, mode, False, c_dict, patterns, blacklist)

    status_tag = (
        "MALICIOUS"   if ("MALICIOUS" in verdict or "CRITICAL" in verdict) else
        "SUSPICIOUS"  if "SUSPICIOUS" in verdict else
        "SAFE"
    )

    issuer_dn = ", ".join(
        f"{k.decode()}={v.decode()}" for k, v in issuer.get_components()
    )

    mismatch = False
    if requested and source == 'url':
        req_norm = requested.replace("*.", "").lower()
        cn_norm  = cn.replace("*.", "")
        if req_norm != cn_norm and not req_norm.endswith("." + cn_norm) and cn_norm not in req_norm:
            mismatch = True

    return {
        'time':       time.strftime('%H:%M:%S'),
        'ts':         time.time(),
        'source':     source,
        'mode':       mode,
        'requested':  requested,
        'domain':     cn,
        'ip':         source_ip,
        'entropy':    round(c_dict['entropy'], 2),
        'age':        c_dict['cert_age_days'],
        'puny':       "Yes" if c_dict['punycode_detected'] else "No",
        'self_signed':"Yes" if c_dict['self.signed'] else "No",
        'mismatch':   mismatch,
        'serial':     hex(cert.get_serial_number()),
        'sig_algo':   cert.get_signature_algorithm().decode(),
        'issuer_dn':  issuer_dn,
        'verdict':    status_tag,
        'detail':     verdict,
    }

def emit_event(event: dict):
    append_history(event)
    socketio.emit('new_result', event)
    return event['verdict'], event['detail']

# ── Obtaining a certificate by host (SNI) ───────────────────────────────────
def fetch_cert_from_host(host: str, port: int = 443, timeout: float = 5.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            peer_ip  = ssock.getpeername()[0]
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
    return cert, peer_ip

# ── Routes ─────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/history')
def get_history():
    with history_lock:
        return jsonify(event_history[-HISTORY_MAX:])

@app.route('/analyze_pem', methods=['POST'])
def analyze_pem():
    f = request.files.get('pem')
    if not f:
        return jsonify({'error': 'No file'}), 400

    filename = secure_filename(f.filename or 'cert.pem')
    if not any(filename.endswith(ext) for ext in ('.pem', '.crt', '.cer')):
        return jsonify({'error': 'Unsupported format'}), 400

    mode = sanitize_mode(request.form.get('mode'))

    try:
        pem_data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
        event = build_event(cert, source='file', source_ip='file-upload',
                            requested=filename, mode=mode)
        _, detail = emit_event(event)
        return jsonify({'status': 'ok', 'file': filename, 'mode': mode, 'verdict': detail})
    except Exception as e:
        return jsonify({'error': str(e)}), 422

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json(silent=True) or {}
    raw = (data.get('target') or '').strip()
    mode = sanitize_mode(data.get('mode'))

    target = raw.replace('https://', '').replace('http://', '')
    target = target.split('/')[0].split(':')[0].strip().lower()

    if not target or '.' not in target:
        return jsonify({'error': 'Invalid domain'}), 400

    try:
        cert, peer_ip = fetch_cert_from_host(target)
    except socket.gaierror:
        return jsonify({'error': f'DNS: host {target} not found'}), 422
    except (socket.timeout, TimeoutError):
        return jsonify({'error': f"Connection timeout with {target}"}), 422
    except ConnectionRefusedError:
        return jsonify({'error': f'{target} rejected the connection (port 443 is closed)'}), 422
    except Exception as e:
        return jsonify({'error': f'Unable to obtain certificate: {e}'}), 422

    try:
        event = build_event(cert, source='url', source_ip=peer_ip,
                            requested=target, mode=mode)
        _, detail = emit_event(event)
        return jsonify({'status': 'ok', 'target': target, 'ip': peer_ip,
                       'mode': mode, 'verdict': detail})
    except Exception as e:
        return jsonify({'error': f'Analysis error: {e}'}), 422

# ── Sniffer ────────────────────────────────────────────────────────────────
def packet_handler(pkt):
    if not (pkt.haslayer(TCP) and pkt[TCP].dport == 443):
        return
    ip_dst = (pkt[IP].dst if pkt.haslayer(IP)
               else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None))
    if not ip_dst:
        return

    now = time.time()
    if ip_dst in processed_ips and (now - processed_ips[ip_dst]) < 20:
        return
    processed_ips[ip_dst] = now

    try:
        cert_pem = ssl.get_server_certificate((ip_dst, 443), timeout=1.2)
        cert     = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        cn       = str(cert.get_subject().CN).replace("*.", "").lower()

        if any(d in cn for d in TECHNICAL_DOMAINS):
            return
        if cn in ('none', '*', 'default cert'):
            return
        if any(k in cn for k in ('kubernetes', 'ingress', 'haproxy')):
            return

        event = build_event(cert, source='traffic', source_ip=ip_dst, mode=LIVE_MODE)
        emit_event(event)
    except Exception:
        pass

def run_sniffer():
    print("[*] Sniffer started - monitoring port 443...")
    sniff(iface="eth0", filter="tcp dst port 443", prn=packet_handler, store=0)

# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == '__main__':
    load_history()
    print(f"[*] Loaded {len(event_history)} history records.")
    update_malicious_database(force=False)
    threading.Thread(target=run_sniffer, daemon=True).start()

    print("\n" + "=" * 60)
    print("  ML-IDS ENGINE - DASHBOARD ACTIVE")
    print("=" * 60 + "\n")

    socketio.run(app, host='0.0.0.0', port=5000,
                 use_reloader=False, log_output=False, debug=False)
