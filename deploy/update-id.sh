#!/bin/bash
# update-id.sh — stahne JAR z GitHub Releases a restartuje kfs-id service
#
# Pouziti:
#   update-id.sh [VERSION]
#   VERSION = tag (napr. v1.0.0). Bez argumentu = latest release.

set -euo pipefail

REPO="k0fis/kfs-id"
INSTALL_DIR="/opt/id-backend"
JAR_NAME="kfs-id-runner.jar"
SERVICE="kfs-id"

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Zjistuji latest release..."
    DOWNLOAD_URL=$(curl -sfL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -o "https://github.com/$REPO/releases/download/[^\"]*/$JAR_NAME")
else
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$JAR_NAME"
fi

if [ -z "$DOWNLOAD_URL" ]; then
    echo "CHYBA: Nelze zjistit URL pro stahnuti." >&2
    exit 1
fi

echo "Stahuji: $DOWNLOAD_URL"
TMP_JAR=$(mktemp /tmp/kfs-id-XXXXXX.jar)
curl -sfL -o "$TMP_JAR" "$DOWNLOAD_URL"

if [ ! -s "$TMP_JAR" ]; then
    echo "CHYBA: Stahovani selhalo nebo prazdny soubor." >&2
    rm -f "$TMP_JAR"
    exit 1
fi

echo "Zastavuji $SERVICE..."
systemctl stop "$SERVICE"

if [ -f "$INSTALL_DIR/$JAR_NAME" ]; then
    cp "$INSTALL_DIR/$JAR_NAME" "$INSTALL_DIR/$JAR_NAME.bak"
    echo "Backup: $JAR_NAME.bak"
fi

mv "$TMP_JAR" "$INSTALL_DIR/$JAR_NAME"

echo "Spoustim $SERVICE..."
systemctl start "$SERVICE"

sleep 5
if systemctl is-active --quiet "$SERVICE"; then
    echo "OK — $SERVICE bezi."
else
    echo "CHYBA: $SERVICE se nespustil!" >&2
    echo "Rollback z $JAR_NAME.bak..."
    if [ -f "$INSTALL_DIR/$JAR_NAME.bak" ]; then
        mv "$INSTALL_DIR/$JAR_NAME.bak" "$INSTALL_DIR/$JAR_NAME"
        systemctl start "$SERVICE"
        echo "Rollback dokoncen."
    else
        echo "VAROVANI: Neni backup pro rollback!" >&2
    fi
    echo "Zkontroluj logy: journalctl -u $SERVICE -n 50"
    exit 1
fi
