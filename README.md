# Archiver Spam Cleaner

Tool zur Spam-Bereinigung für [Open Archiver](https://github.com/LogicLabs-OU/OpenArchiver).
Prüft archivierte Emails gegen DNSBLs (Spamhaus, SpamCop, Barracuda, SORBS) und erlaubt Bulk-Löschen per Absender.

## Features

- **Server-Scan** — durchsucht alle archivierten Emails, zählt Absender, prüft gegen RBL-Blacklists
- **Web UI** — übersichtliche Tabelle mit Absendern, Status (Spam/Clean/Markiert), Such- und Filterfunktion
- **Manuelles Markieren** — Absender als Spammer in SQLite-DB speichern
- **Bulk-Delete** — ausgewählte Absender mit einem Klick löschen
- **Auto-Cleanup** — optionaler Systemd-Timer (alle 6h): löscht automatisch alle markierten Spammer

## Architektur

```
[Browser UI :5000] ← → [Python Backend (Flask)] ← → [Archiver API :4000 (Read)]
                                                         [Archiver API :3000 (Write)]
```

## Installation

### Voraussetzungen

- Python 3 + Flask
- Laufender Open Archiver (Port 4000/3000)

### Setup

```bash
git clone https://github.com/ElectronicResearch/archiver-spam-cleaner.git
cd archiver-spam-cleaner
sudo ./setup.sh http://192.168.2.130:4000
```

Oder manuell:

```bash
python3 server.py --port 5000 --api-url http://192.168.2.130:4000
```

Dann im Browser: `http://192.168.2.130:5000`

### Systemd (dauerhafter Betrieb)

```bash
sudo cp archiver-spam-cleaner.service /etc/systemd/system/
sudo systemctl enable archiver-spam-cleaner
sudo systemctl start archiver-spam-cleaner
```

## Verwendung

1. **Login** mit Admin-Email/Passwort
2. **Scannen** — lädt alle Emails, zählt Absender, prüft RBLs
3. **Prüfen** — rote = Spam-Verdacht, gelbe = manuell markiert
4. **Entmarkieren** bei eigenen/wichtigen Absendern
5. **Löschen** — ausgewählte Absender bulk-löschen

## Auto-Cleanup (optional)

Alle 6 Stunden automatisch markierte Spammer löschen:

```bash
# Service-Datei mit Login-Daten anpassen
sudo nano /etc/systemd/system/archiver-spam-cleaner-cron.service

sudo cp archiver-spam-cleaner-cron.service /etc/systemd/system/
sudo cp archiver-spam-cleaner-cron.timer /etc/systemd/system/
sudo systemctl enable archiver-spam-cleaner-cron.timer
sudo systemctl start archiver-spam-cleaner-cron.timer
```

## Dateien

| Datei | Zweck |
|---|---|
| `server.py` | Flask Backend (Scan, RBL, Delete, Cron) |
| `archiver.html` | Web UI |
| `archiver_spam_cleaner.py` | Originales CLI-Tool |
| `archiver-spam-cleaner.service` | Systemd Service (Webserver) |
| `archiver-spam-cleaner-cron.service` | Systemd Oneshot (Auto-Cleanup) |
| `archiver-spam-cleaner-cron.timer` | Systemd Timer (alle 6h) |
| `setup.sh` | Setup-Skript |

## Lizenz

AGPL-3.0
