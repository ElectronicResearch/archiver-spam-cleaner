#!/usr/bin/env python3
"""
Open Archiver Spam Cleaner
=========================
Prueft alle archivierten Emails gegenueber Spamhaus Zen RBL + zusaetzliche Blacklists.
Emails von gelisteten Absendern werden geloescht.

Verwendung:
  python3 archiver_spam_cleaner.py --email ADMIN_EMAIL --password PASSWORD [--dry-run] [--min-count 2] [--api-url http://192.168.2.130:4000]

Optionen:
  --dry-run      Nur analysieren, nichts loeschen
  --min-count    Min. Vorkommen eines Absenders fuer Pruefung (default: 2)
"""

import argparse
import collections
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────

API_URL = "http://192.168.2.130:4000"
PAGE_LIMIT = 100  # Emails per API call

# Spamhaus Zen RBL + weitere DNSBLs
DNSBLS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
]

# Zusaetzlich: statische Domain-Blackliste (bekannte Spam-Domains)
DOMAIN_BLACKLIST = {
    # Bekannte Spam/Werbung-Domains - erweitern nach Bedarf
    "mail.ru",  # oft Spam von Mail.ru
}

# Statische E-Mail-Pattern-Blackliste
EMAIL_PATTERN_BLACKLIST = [
    "noreply@", "no-reply@", "donotreply@",
]

# ─── HTTP Helper ────────────────────────────────────────────────────────────

def http(method, url, data=None, headers=None, token=None):
    """Simple HTTP request wrapper."""
    if headers is None:
        headers = {}
    headers.setdefault("Content-Type", "application/json")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode()
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        raise Exception(f"HTTP {e.code}: {err_body}") from e


# ─── API Functions ──────────────────────────────────────────────────────────

def login(api_url, email, password):
    """Login und Token zurueckgeben."""
    resp = http("POST", f"{api_url}/v1/auth/login", data={"email": email, "password": password})
    token = resp.get("access_token") or resp.get("accessToken") or resp.get("token")
    if not token:
        raise Exception(f"Login fehlgeschlagen. Response: {resp}")
    return token


def get_ingestion_sources(api_url, token):
    """Alle Ingestion Sources abrufen."""
    return http("GET", f"{api_url}/v1/ingestion-sources", token=token)


def get_all_emails(api_url, token, source_id, page_limit=PAGE_LIMIT):
    """Alle Emails einer Source paginated abrufen."""
    all_emails = []
    page = 1
    while True:
        resp = http("GET",
            f"{api_url}/v1/archived-emails/ingestion-source/{source_id}"
            f"?page={page}&limit={page_limit}",
            token=token)
        items = resp.get("items", [])
        if not items:
            break
        all_emails.extend(items)

        total = resp.get("total", 0)
        resp_pages = resp.get("totalPages")
        if resp_pages is not None:
            if page >= resp_pages:
                break
        else:
            # Fallback: wenn keine totalPages, pruefe ob wir alle haben
            if len(all_emails) >= total:
                break

        page += 1
        # Rate limiting
        time.sleep(0.1)

    return all_emails


def delete_email(api_url, token, email_id):
    """Eine Email per ID loeschen."""
    headers = {"Authorization": f"Bearer {token}"}
    req = urllib.request.Request(
        f"{api_url}/v1/archived-emails/{email_id}",
        headers=headers,
        method="DELETE"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status == 204
    except urllib.error.HTTPError as e:
        return False


# ─── RBL Check ──────────────────────────────────────────────────────────────

def extract_domain(email):
    """Domain aus E-Mail-Adresse extrahieren."""
    try:
        return email.split("@")[1].lower().strip()
    except (IndexError, AttributeError):
        return ""


def reverse_ip(ip_str):
    """IP fuer RBL-Query umdrehen."""
    try:
        parts = ip_str.split(".")
        return ".".join(reversed(parts))
    except Exception:
        return ""


def check_dnsbl(domain_or_ip, dnsbl):
    """Pruefe ob Domain/IP in einer DNSBL gelistet ist."""
    try:
        query = f"{domain_or_ip}.{dnsbl}"
        socket.gethostbyname(query)
        return True  # Gelistet!
    except socket.gaierror:
        return False  # Nicht gelistet
    except Exception:
        return False


def check_domain_rbl(domain):
    """Domain gegen alle DNSBLs pruefen."""
    # DNSBLs koennen nur IPs nicht Domains pruefen
    # Wir muessen die Domain erst aufloesen
    try:
        ip = socket.gethostbyname(domain)
        rev = reverse_ip(ip)
        for dnsbl in DNSBLS:
            if check_dnsbl(rev, dnsbl):
                return True, dnsbl
        return False, None
    except (socket.gaierror, socket.herror):
        return False, None


def is_blacklisted_sender(sender_email):
    """
    Mehrstufige Pruefung:
    1. Statische Domain-Blackliste
    2. Statische Pattern-Blackliste
    3. Spamhaus Zen RBL (via DNS)
    Weitere DNSBLs optional
    """
    domain = extract_domain(sender_email)

    # Schritt 1: Statische Domain-Blackliste
    if domain in DOMAIN_BLACKLIST:
        return True, f"Domain-Blacklist ({domain})"

    # Schritt 2: Pattern-Check
    sender_lower = sender_email.lower()
    for pattern in EMAIL_PATTERN_BLACKLIST:
        if sender_lower.startswith(pattern):
            # Nur warnen, nicht automatisch loeschen
            pass

    # Schritt 3: Spamhaus Zen RBL
    listed, rbl = check_domain_rbl(domain)
    if listed:
        return True, f"Spamhaus Zen ({rbl})"

    return False, None


# ─── Summary Printer ────────────────────────────────────────────────────────

def print_separator(char="═", length=70):
    print(char * length)


def print_report(report):
    """Formatierten Report ausgeben."""
    print()
    print_separator("═")
    print("  OPEN ARCHIVER SPAM CLEANER - REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator("═")
    print()

    # Statistiken
    print(f"  Emails insgesamt geprueft:    {report['total_emails']}")
    print(f"  Unique Absender:              {report['total_senders']}")
    print(f"  Absender mit >= {report['min_count']} Vorkommen:   {report['senders_with_min_count']}")
    print(f"  Absender auf Blacklist:       {report['blacklisted_senders']}")
    print(f"  Emails zum Loeschen:          {report['emails_to_delete']}")
    print()

    # Top Absender (meistes Vorkommen)
    print_separator("─")
    print("  TOP 30 ABSENDER (Häufigkeit)")
    print_separator("─")
    sorted_senders = sorted(report["sender_counts"].items(), key=lambda x: x[1], reverse=True)
    for sender, count in sorted_senders[:30]:
        print(f"    {count:>6}x  {sender}")
    print()

    if report.get("blacklisted_sender_details"):
        print_separator("─")
        print("  AUF BLACKLIST GEFUNDENE ABSENDER")
        print_separator("─")
        print(f"  {'Absender':<45} {'Emails':>6} {'Grund'}")
        print(f"  {'─'*45} {'─'*6} {'─'*30}")
        for detail in report["blacklisted_sender_details"]:
            print(f"  {detail['email']:<45} {detail['count']:>6}  {detail['reason']}")
        print()

    if report.get("deleted_emails", 0) > 0:
        print_separator("─")
        print(f"  GELÖSCHTE EMAILS: {report['deleted_emails']}")
        if report.get("delete_errors", 0) > 0:
            print(f"  FEHLER BEIM LÖSCHEN: {report['delete_errors']}")
        print_separator("─")
        print()

    if report.get("dry_run"):
        print("  ⚠  DRY RUN MODUS — nichts wurde geloeschen!")
        print()


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Open Archiver Spam Cleaner")
    parser.add_argument("--email", required=True, help="Admin E-Mail")
    parser.add_argument("--password", required=True, help="Admin Passwort")
    parser.add_argument("--api-url", default=API_URL, help=f"API URL (default: {API_URL})")
    parser.add_argument("--dry-run", action="store_true", help="Nur analysieren, nichts loeschen")
    parser.add_argument("--min-count", type=int, default=2, help="Min. Vorkommen (default: 2)")
    parser.add_argument("--skip-rbl", action="store_true", help="RBL-Check überspringen")
    args = parser.parse_args()

    report = {
        "total_emails": 0,
        "total_senders": 0,
        "min_count": args.min_count,
        "senders_with_min_count": 0,
        "blacklisted_senders": 0,
        "emails_to_delete": 0,
        "deleted_emails": 0,
        "delete_errors": 0,
        "sender_counts": {},
        "blacklisted_sender_details": [],
        "dry_run": args.dry_run,
    }

    # ── 1. Login ──
    print("  [1/5] Login...")
    try:
        token = login(args.api_url, args.email, args.password)
        print(f"        OK - Token erhalten")
    except Exception as e:
        print(f"        FEHLER: {e}")
        sys.exit(1)

    # ── 2. Ingestion Sources ──
    print("  [2/5] Ingestion Sources abrufen...")
    try:
        sources = get_ingestion_sources(args.api_url, token)
        print(f"        OK - {len(sources)} Sources gefunden")
    except Exception as e:
        print(f"        FEHLER: {e}")
        sys.exit(1)

    # ── 3. Alle Emails sammeln ──
    print("  [3/5] Alle Emails sammeln...")
    sender_counts = collections.Counter()
    all_emails_by_sender = collections.defaultdict(list)

    for source in sources:
        source_id = source["id"]
        source_name = source.get("name", source_id)
        print(f"        Source: {source_name}...")
        try:
            emails = get_all_emails(args.api_url, token, source_id)
            print(f"          {len(emails)} Emails geladen")
            report["total_emails"] += len(emails)

            for email_item in emails:
                sender = email_item.get("senderEmail", "").lower().strip()
                if sender:
                    sender_counts[sender] += 1
                    all_emails_by_sender[sender].append(email_item["id"])
        except Exception as e:
            print(f"          FEHLER: {e}")

    report["total_senders"] = len(sender_counts)
    report["sender_counts"] = dict(sender_counts)
    print(f"        OK - {report['total_emails']} Emails, {report['total_senders']} Unique Absender")

    # ── 4. Absender pruefen ──
    print(f"  [4/5] Absender >= {args.min_count} Vorkommen pruefen...")

    senders_to_check = {s: c for s, c in sender_counts.items() if c >= args.min_count}
    report["senders_with_min_count"] = len(senders_to_check)
    print(f"        {len(senders_to_check)} Absender werden geprueft")

    blacklisted = {}
    checked = 0

    for sender, count in sorted(senders_to_check.items(), key=lambda x: x[1], reverse=True):
        checked += 1
        if checked % 20 == 0:
            print(f"        ... {checked}/{len(senders_to_check)} geprueft")

        is_listed, reason = is_blacklisted_sender(sender)
        if is_listed:
            blacklisted[sender] = {"count": count, "reason": reason}
            print(f"        ⚠  GELISTET: {sender} ({count}x) - {reason}")

        # RBL-Queries sind langsam, kleines Delay
        if not args.skip_rbl:
            time.sleep(0.05)

    report["blacklisted_senders"] = len(blacklisted)
    report["blacklisted_sender_details"] = [
        {"email": s, "count": d["count"], "reason": d["reason"]}
        for s, d in blacklisted.items()
    ]

    # Emails zum Loeschen
    emails_to_delete = []
    for sender, data in blacklisted.items():
        emails_to_delete.extend(all_emails_by_sender.get(sender, []))

    report["emails_to_delete"] = len(emails_to_delete)
    print(f"        OK - {len(blacklisted)} Absender auf Blacklist, {len(emails_to_delete)} Emails zum Loeschen")

    # ── 5. Loeschen ──
    if args.dry_run:
        print("  [5/5] DRY RUN - kein Loeschen")
    elif emails_to_delete:
        print(f"  [5/5] {len(emails_to_delete)} Emails loeschen...")
        for i, email_id in enumerate(emails_to_delete):
            try:
                if delete_email(args.api_url, token, email_id):
                    report["deleted_emails"] += 1
                else:
                    report["delete_errors"] += 1
            except Exception:
                report["delete_errors"] += 1

            if (i + 1) % 50 == 0:
                print(f"        ... {i + 1}/{len(emails_to_delete)} geloescht")

            time.sleep(0.05)  # Rate limiting

        print(f"        OK - {report['deleted_emails']} geloescht, {report['delete_errors']} Fehler")
    else:
        print("  [5/5] Keine Emails zum Loeschen")

    # ── Report ──
    print_report(report)

    return report


if __name__ == "__main__":
    main()
