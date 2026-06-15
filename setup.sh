#!/bin/bash
set -e

INSTALL_DIR="/opt/archiver-spam-cleaner"
SERVICE_NAME="archiver-spam-cleaner"
API_URL="${1:-http://192.168.2.130:4000}"

echo "=== Archiver Spam Cleaner Setup ==="
echo "Installationsverzeichnis: $INSTALL_DIR"
echo "API URL: $API_URL"
echo ""

# Verzeichnis erstellen
echo "[1/4] Erstelle $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"

# Dateien kopieren
echo "[2/4] Kopiere Dateien..."
sudo cp "$(dirname "$0")/server.py" "$INSTALL_DIR/"
sudo cp "$(dirname "$0")/archiver.html" "$INSTALL_DIR/"

# Service-Datei kopieren
echo "[3/4] Installiere Systemd-Service..."
sudo cp "$(dirname "$0")/archiver-spam-cleaner.service" "/etc/systemd/system/$SERVICE_NAME.service"
sudo sed -i "s|--api-url http://192.168.2.130:4000|--api-url $API_URL|" "/etc/systemd/system/$SERVICE_NAME.service"

# Service aktivieren
echo "[4/4] Starte Service..."
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

echo ""
echo "=== Fertig ==="
echo "Status: sudo systemctl status $SERVICE_NAME"
echo "Logs:   sudo journalctl -u $SERVICE_NAME -f"
echo "UI:     http://$(hostname -I | awk '{print $1}'):5000"
