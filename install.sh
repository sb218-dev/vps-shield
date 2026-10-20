#!/usr/bin/env bash
# ==============================================================================
# VPS Shield - Быстрый установщик (One-liner installer)
#
# Использование:
#   curl -sSL https://raw.githubusercontent.com/sb218-dev/vps-shield/main/install.sh | sudo bash
# ==============================================================================
set -e

if [[ $EUID -ne 0 ]]; then
    echo "[ОШИБКА] Запустите установщик с правами root: curl ... | sudo bash" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo ">>> Загрузка VPS Shield Manager..."
curl -sSL "https://raw.githubusercontent.com/sb218-dev/vps-shield/main/vps-shield-manager.sh" -o "$TMP_DIR/vps-shield-manager.sh"
chmod +x "$TMP_DIR/vps-shield-manager.sh"
cp "$TMP_DIR/vps-shield-manager.sh" /usr/local/bin/vps-shield-manager.sh

echo ">>> Запуск процесса установки..."
/usr/local/bin/vps-shield-manager.sh install
