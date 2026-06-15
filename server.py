#!/usr/bin/env python3
"""
Archiver Spam Cleaner Server
============================
Web UI + API fuer RBL-Checks und Spammer-Verwaltung.

Usage:
  python3 server.py [--port 5000] [--api-url http://192.168.2.130:4000]
"""

import argparse
import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from functools import wraps
from pathlib import Path
from threading import Lock

from flask import Flask, request, jsonify, send_from_directory

# ─── Configuration ──────────────────────────────────────────────────────────

DB_PATH = Path(__file__).parent / "spammers.db"
HTML_PATH = Path(__file__).parent / "archiver.html"

API_URL = os.environ.get("ARCHIVER_API_URL", "http://192.168.2.130:4000")
API_WRITE_URL = os.environ.get("ARCHIVER_API_WRITE_URL", "http://192.168.2.130:4000")

DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]

DOMAIN_BLACKLIST = {
    "mail.ru",
}

EMAIL_PATTERN_BLACKLIST = [
    "noreply@", "no-reply@", "donotreply@",
]

# ─── Flask App ──────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=None)
db_lock = Lock()

# In-Memory Scan Cache: token_hash -> { sender: [email_id, ...] }
scan_cache = {}
scan_cache_tokens = {}  # token -> cached data


# ─── Database ───────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS spammers (
            sender TEXT PRIMARY KEY,
            reason TEXT DEFAULT '',
            email_count INTEGER DEFAULT 0,
            flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            checked_at TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def get_spammers():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT sender, reason, email_count, flagged_at, checked_at FROM spammers ORDER BY email_count DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_spammer(sender):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT sender, reason, email_count, flagged_at, checked_at FROM spammers WHERE sender = ?",
        (sender,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_spammer(sender, reason="", email_count=0):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT INTO spammers (sender, reason, email_count, flagged_at, checked_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(sender) DO UPDATE SET
            reason = excluded.reason,
            email_count = excluded.email_count,
            flagged_at = CURRENT_TIMESTAMP,
            checked_at = CURRENT_TIMESTAMP
    """, (sender, reason, email_count))
    conn.commit()
    conn.close()


def delete_spammer(sender):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM spammers WHERE sender = ?", (sender,))
    conn.commit()
    conn.close()


def delete_all_spammers():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM spammers")
    conn.commit()
    conn.close()


# ─── Helpers ────────────────────────────────────────────────────────────────

def extract_domain(email):
    try:
        return email.split("@")[1].lower().strip()
    except (IndexError, AttributeError):
        return ""


def reverse_ip(ip_str):
    try:
        return ".".join(reversed(ip_str.split(".")))
    except Exception:
        return ""


def check_dnsbl(query_str, dnsbl):
    try:
        socket.gethostbyname(f"{query_str}.{dnsbl}")
        return True
    except (socket.gaierror, Exception):
        return False


def check_sender(sender_email):
    domain = extract_domain(sender_email)
    reasons = []

    # 1. Statische Domain-Blackliste
    if domain in DOMAIN_BLACKLIST:
        reasons.append(f"Domain-Blacklist ({domain})")

    # 2. Pattern-Check
    sender_lower = sender_email.lower()
    for pattern in EMAIL_PATTERN_BLACKLIST:
        if sender_lower.startswith(pattern):
            reasons.append(f"Pattern ({pattern})")

    # 3. DNSBLs
    try:
        ip = socket.gethostbyname(domain)
        rev = reverse_ip(ip)
        for dnsbl in DNSBLS:
            if check_dnsbl(rev, dnsbl):
                reasons.append(f"DNSBL ({dnsbl})")
    except (socket.gaierror, socket.herror):
        pass

    if reasons:
        return {"spam": True, "reasons": reasons, "reason": ", ".join(reasons)}
    return {"spam": False, "reasons": [], "reason": None}


# ─── CORS ────────────────────────────────────────────────────────────────────

def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


def handle_options(*args, **kwargs):
    return add_cors_headers(jsonify({"ok": True}))


# ─── API Routes ─────────────────────────────────────────────────────────────

@app.after_request
def cors(response):
    return add_cors_headers(response)


@app.route("/api/senders/check", methods=["POST", "OPTIONS"])
def api_check_senders():
    if request.method == "OPTIONS":
        return handle_options()

    data = request.get_json(silent=True) or {}
    senders = data.get("senders", [])

    if not senders:
        return jsonify({"error": "No senders provided"}), 400

    results = {}
    total = len(senders)

    for i, sender in enumerate(senders):
        sender = sender.lower().strip()
        if not sender:
            continue
        results[sender] = check_sender(sender)

    return jsonify({"results": results, "total": total})


@app.route("/api/spammers", methods=["GET", "POST", "DELETE", "OPTIONS"])
def api_spammers():
    if request.method == "OPTIONS":
        return handle_options()

    if request.method == "GET":
        spammers = get_spammers()
        return jsonify({"spammers": spammers, "total": len(spammers)})

    if request.method == "DELETE":
        delete_all_spammers()
        return jsonify({"ok": True, "message": "Alle Spammer geloescht"})

    # POST: Einen oder mehrere Spammer markieren
    data = request.get_json(silent=True) or {}
    senders = data.get("senders", [])

    if isinstance(senders, str):
        senders = [senders]

    if not senders:
        return jsonify({"error": "No senders provided"}), 400

    reason = data.get("reason", "manuell")

    for sender in senders:
        sender = sender.lower().strip()
        if sender:
            upsert_spammer(sender, reason=reason, email_count=data.get("count", 0))

    return jsonify({"ok": True, "count": len(senders)})


@app.route("/api/spammers/<path:sender>", methods=["DELETE", "OPTIONS"])
def api_spammer_delete(sender):
    if request.method == "OPTIONS":
        return handle_options()

    sender = sender.lower().strip()
    delete_spammer(sender)
    return jsonify({"ok": True})


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def api_scan():
    if request.method == "OPTIONS":
        return handle_options()

    data = request.get_json(silent=True) or {}
    token = data.get("token")

    if not token:
        return jsonify({"error": "Token required"}), 400

    return jsonify(_run_scan(token, data.get("minCount", 2)))


@app.route("/api/delete-spam", methods=["POST", "OPTIONS"])
def api_delete_spam():
    if request.method == "OPTIONS":
        return handle_options()

    data = request.get_json(silent=True) or {}
    token = data.get("token")
    senders = data.get("senders", [])

    if not token:
        return jsonify({"error": "Token required"}), 400
    if not senders:
        return jsonify({"error": "No senders provided"}), 400

    return jsonify(_delete_sender_emails(token, senders))


# ─── Scan Logic ─────────────────────────────────────────────────────────────

def _archiver_api(method, path, token=None, data=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(data).encode() if data else None
    url = f"{API_URL}{path}"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode()
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {err_body}")


def _run_scan(token, min_count=2):
    result = {
        "total_emails": 0,
        "total_senders": 0,
        "senders": [],
        "spam_senders": [],
        "errors": [],
    }

    # 1. Ingestion Sources
    try:
        sources = _archiver_api("GET", "/v1/ingestion-sources", token=token)
    except Exception as e:
        return {**result, "errors": [f"Sources: {e}"]}

    if not isinstance(sources, list):
        return {**result, "errors": [f"Sources: invalid response"]}

    # 2. Alle Emails sammeln
    sender_counts = {}
    sender_ids = {}

    for source in sources:
        source_id = source.get("id")
        source_name = source.get("name", source_id)
        page = 1

        while True:
            try:
                resp = _archiver_api(
                    "GET",
                    f"/v1/archived-emails/ingestion-source/{source_id}?page={page}&limit=100",
                    token=token,
                )
            except Exception as e:
                result["errors"].append(f"{source_name}: Page {page}: {e}")
                break

            items = resp.get("items", [])
            if not items:
                break

            for email in items:
                sender = (email.get("senderEmail") or "").lower().strip()
                if not sender:
                    continue
                sender_counts[sender] = sender_counts.get(sender, 0) + 1
                if sender not in sender_ids:
                    sender_ids[sender] = []
                sender_ids[sender].append(email["id"])
                result["total_emails"] += 1

            total = resp.get("total", 0)
            if len(items) < 100 or result["total_emails"] >= total:
                break
            page += 1
            time.sleep(0.05)

    result["total_senders"] = len(sender_counts)

    # 3. Absender mit min_count pruefen
    spammers = get_spammers()
    spammer_set = {s["sender"] for s in spammers}

    for sender, count in sorted(sender_counts.items(), key=lambda x: x[1], reverse=True):
        entry = {
            "sender": sender,
            "count": count,
            "ids": sender_ids.get(sender, []),
            "spam": False,
            "reason": None,
            "flagged": sender in spammer_set,
        }

        if count >= min_count:
            check = check_sender(sender)
            entry["spam"] = check["spam"]
            entry["reason"] = check["reason"]

        if entry["spam"] or entry["flagged"]:
            result["spam_senders"].append(entry)

        result["senders"].append(entry)

    # 4. Spam-Status in DB aktualisieren
    for entry in result["spam_senders"]:
        if entry["spam"]:
            upsert_spammer(entry["sender"], reason=entry["reason"] or "auto", email_count=entry["count"])

    # 5. IDs im Cache speichern (für delete-spam als Fallback)
    scan_cache_tokens[token] = {
        "sender_ids": sender_ids,
        "cached_at": time.time(),
    }

    return result


def _delete_archiver_email(token, email_id):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{API_WRITE_URL}/v1/archived-emails/{email_id}"
    req = urllib.request.Request(url, headers=headers, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True, None
    except urllib.error.HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        if e.code == 429:
            return False, "RATE_LIMIT"
        msg = f"HTTP {e.code} {url}: {err_body[:300]}"
        print(f"  DELETE ERROR: {msg}", flush=True)
        return False, msg
    except Exception as e:
        msg = f"EXCEPTION {url}: {e}"
        print(f"  DELETE ERROR: {msg}", flush=True)
        return False, msg


def _delete_sender_emails(token, senders):
    result = {"deleted": 0, "errors": 0, "total": 0, "details": []}

    cached = scan_cache_tokens.get(token)
    if not cached:
        result["error"] = "Keine Scan-Daten. Bitte zuerst scannen."
        result["errors"] = len(senders)
        return result

    sender_ids = cached["sender_ids"]

    for sender in senders:
        sender = sender.lower().strip()
        ids = sender_ids.get(sender, [])
        sender_deleted = 0
        sender_errors = 0

        first_error = None
        remaining = list(ids)
        while remaining:
            batch_failures = 0
            new_remaining = []
            for email_id in remaining:
                ok, err = _delete_archiver_email(token, email_id)
                if ok:
                    sender_deleted += 1
                elif err == "RATE_LIMIT":
                    batch_failures += 1
                    new_remaining.append(email_id)
                else:
                    sender_errors += 1
                    if first_error is None:
                        first_error = err
                time.sleep(0.05)

            if batch_failures > 0:
                print(f"  Rate-Limit erreicht, warte 65s... ({batch_failures} offen)", flush=True)
                time.sleep(65)
                remaining = new_remaining
            else:
                break

        result["deleted"] += sender_deleted
        result["errors"] += sender_errors
        result["total"] += sender_deleted + sender_errors
        result["details"].append({
            "sender": sender,
            "deleted": sender_deleted,
            "errors": sender_errors,
            "first_error": first_error,
        })

    return result


# ─── API Proxy to Archiver ──────────────────────────────────────────────────

@app.route("/v1/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy_archiver(subpath):
    if request.method == "OPTIONS":
        return handle_options()

    url = f"{API_URL}/v1/{subpath}"
    if request.query_string:
        url += f"?{request.query_string.decode()}"

    body = request.get_data() if request.method in ("POST", "PUT") else None
    headers = dict(request.headers)
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    req = urllib.request.Request(url, data=body, headers=headers, method=request.method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp_body = resp.read()
            content_type = resp.headers.get("Content-Type", "application/json")
            return (resp_body, resp.status, {"Content-Type": content_type})
    except urllib.error.HTTPError as e:
        err_body = e.read() if e.fp else b"{}"
        content_type = e.headers.get("Content-Type", "application/json") if e.headers else "application/json"
        return (err_body, e.code, {"Content-Type": content_type})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ─── Static Files ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(Path(__file__).parent, "archiver.html")


# ─── Main ───────────────────────────────────────────────────────────────────

def run_cron(api_url, api_write_url, email, password):
    """Einmaliger Scan + Loeschlauf fuer markierte Spammer."""
    os.environ["TZ"] = "Europe/Berlin"
    try:
        time.tzset()
    except AttributeError:
        pass

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Auto-Cleanup gestartet")
    print(f"  API: {api_url} (Read) / {api_write_url} (Write)")
    print()

    # Login
    login_resp = _archiver_api("POST", "/v1/auth/login",
                               data={"email": email, "password": password})
    token = login_resp.get("accessToken") or login_resp.get("access_token")
    if not token:
        print("  FEHLER: Login fehlgeschlagen")
        return 1
    print(f"  Login OK")

    # Scan
    scan_result = _run_scan(token)
    print(f"  Scan: {scan_result['total_emails']} Emails, {scan_result['total_senders']} Absender")
    print(f"  Spam-Verdacht: {len(scan_result['spam_senders'])}")

    # Markierte Spammer aus DB holen
    spammers = get_spammers()
    if not spammers:
        print("  Keine markierten Spammer in DB -> nichts zu tun")
        return 0

    spammer_emails = [s["sender"] for s in spammers]
    print(f"  Markierte Spammer in DB: {len(spammer_emails)}")

    # Loeschen
    delete_result = _delete_sender_emails(token, spammer_emails)
    print(f"  Geloescht: {delete_result['deleted']}")
    print(f"  Fehler:    {delete_result['errors']}")

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Auto-Cleanup beendet")
    return 0


def main():
    global API_URL, API_WRITE_URL

    parser = argparse.ArgumentParser(description="Archiver Spam Cleaner Server")
    parser.add_argument("--port", type=int, default=5000, help="Server Port (default: 5000)")
    parser.add_argument("--api-url", default=None, help=f"Archiver API URL (default: {API_URL})")
    parser.add_argument("--api-write-url", default=None, help=f"Archiver API Write URL (default: {API_WRITE_URL})")
    parser.add_argument("--email", default=None, help="Admin Email (fuer --cron)")
    parser.add_argument("--password", default=None, help="Admin Passwort (fuer --cron)")
    parser.add_argument("--cron", action="store_true", help="Einmaliger Auto-Cleanup (kein Webserver)")
    parser.add_argument("--debug", action="store_true", help="Flask Debug Mode")
    args = parser.parse_args()

    if args.api_url:
        API_URL = args.api_url
    if args.api_write_url:
        API_WRITE_URL = args.api_write_url

    init_db()

    if args.cron:
        email = args.email or os.environ.get("ARCHIVER_ADMIN_EMAIL")
        password = args.password or os.environ.get("ARCHIVER_ADMIN_PASSWORD")
        if not email or not password:
            print("FEHLER: --email und --password (oder ARCHIVER_ADMIN_EMAIL/PASSWORD) erforderlich")
            return 1
        return run_cron(API_URL, API_WRITE_URL, email, password)

    print(f"  Server startet auf Port {args.port}")
    print(f"  Read-API:  {API_URL}  (Scan)")
    print(f"  Write-API: {API_WRITE_URL}  (Löschen)")
    print(f"  DB: {DB_PATH}")
    print(f"  UI: http://localhost:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
