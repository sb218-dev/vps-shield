#!/usr/bin/env bash
# ==============================================================================
# VPS Shield v1.4.1 - Быстрый установщик (One-liner installer)
#
# Использование:
#   curl -sSL https://raw.githubusercontent.com/sb218-dev/vps-shield/main/install.sh | sudo bash
#
# v1.4.0: установщик скачивает менеджер И ядро защиты (vps-shield.sh),
# передавая путь к ядру через VPS_SHIELD_CORE_SRC — менеджер больше не
# содержит дубликат ядра в heredoc (источник рассинхрона копий в v1.3).
# ==============================================================================
set -e

if [[ $EUID -ne 0 ]]; then
    echo "[ОШИБКА] Запустите установщик с правами root: curl ... | sudo bash" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

RAW_BASE="https://raw.githubusercontent.com/sb218-dev/vps-shield/main"

echo ">>> Загрузка VPS Shield Manager..."
curl -sSL "$RAW_BASE/vps-shield-manager.sh" -o "$TMP_DIR/vps-shield-manager.sh"
chmod +x "$TMP_DIR/vps-shield-manager.sh"
cp "$TMP_DIR/vps-shield-manager.sh" /usr/local/bin/vps-shield-manager.sh

echo ">>> Загрузка ядра защиты (vps-shield.sh)..."
curl -sSL "$RAW_BASE/vps-shield.sh" -o "$TMP_DIR/vps-shield.sh"
chmod +x "$TMP_DIR/vps-shield.sh"

echo ">>> Запуск процесса установки..."
VPS_SHIELD_CORE_SRC="$TMP_DIR/vps-shield.sh" /usr/local/bin/vps-shield-manager.sh install
