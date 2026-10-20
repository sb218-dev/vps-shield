#!/usr/bin/env bash
# ==============================================================================
# VPS Shield - Исполняемый модуль применения правил безопасности
# Репозиторий: https://github.com/sb218-dev/vps-shield
# ==============================================================================
set -e

# Защита от параллельного запуска нескольких копий процесса (flock)
LOCKFILE="/var/lock/vps-shield.lock"
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    echo "[VPS-SHIELD] Процесс уже выполняется в другом потоке. Пропускаем параллельный запуск."
    exit 0
fi

echo "[VPS-SHIELD] 1. Настройка ядра (sysctl: отключение ICMP и включение форвардинга)..."
sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[VPS-SHIELD] 2. Создание базовых структур ipset..."
ipset create -exist ip_checkers hash:ip hashsize 4096 maxelem 65536
ipset create -exist ru_zone hash:net family inet hashsize 16384 maxelem 262144

echo "[VPS-SHIELD] 3. Обновление списка IP-чекеров..."
CHECKER_DOMAINS=(
    "whoer.net" "2ip.ru" "2ip.io" "ipinfo.io" "ifconfig.me"
    "ifconfig.co" "icanhazip.com" "api.ipify.org" "ident.me"
    "myip.com" "speedtest.net" "browserleaks.com" "ipaddress.com"
    "whatismyipaddress.com" "ip-api.com"
)
for dom in "${CHECKER_DOMAINS[@]}"; do
    ips=$(dig +short A "$dom" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
    for ip in $ips; do
        ipset add -exist ip_checkers "$ip" 2>/dev/null || true
    done
done

echo "[VPS-SHIELD] 4. Загрузка актуальных CIDR RU-зоны..."
TMP_RU=$(mktemp /tmp/ru_prefixes.XXXXXX)
trap 'rm -f "$TMP_RU"' EXIT

URL_PRIMARY="https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
URL_BACKUP="https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"

LOADED=0
TEMP_SET="ru_tmp_$$"

for url in "$URL_PRIMARY" "$URL_BACKUP"; do
    if curl -sSL --connect-timeout 10 --retry 2 "$url" -o "$TMP_RU" && [ -s "$TMP_RU" ]; then
        {
            echo "create $TEMP_SET hash:net family inet hashsize 16384 maxelem 262144 -exist"
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$TMP_RU" | sed "s/^/add $TEMP_SET /"
        } | ipset restore -!

        ipset swap "$TEMP_SET" ru_zone
        ipset destroy "$TEMP_SET" 2>/dev/null || true
        echo "[VPS-SHIELD] Успешно загружена база RU-зоны из: $url"
        LOADED=1
        break
    fi
done

if [ $LOADED -eq 0 ]; then
    echo "[VPS-SHIELD] Внимание: Не удалось загрузить внешнюю базу RU-зоны, сохранены предыдущие правила."
fi

echo "[VPS-SHIELD] 5. Применение правил фильтрации iptables..."
iptables -N VPS_SHIELD 2>/dev/null || iptables -F VPS_SHIELD

# --- БЕЛЫЙ СПИСОК (Локальный трафик и служебные соединения) ---
iptables -A VPS_SHIELD -i lo -j ACCEPT
iptables -A VPS_SHIELD -o lo -j ACCEPT
iptables -A VPS_SHIELD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Локальные приватные сети (RFC 1918) - предотвращает блокировку SSH и локальных сервисов
iptables -A VPS_SHIELD -d 10.0.0.0/8 -j ACCEPT
iptables -A VPS_SHIELD -d 172.16.0.0/12 -j ACCEPT
iptables -A VPS_SHIELD -d 192.168.0.0/16 -j ACCEPT
iptables -A VPS_SHIELD -d 127.0.0.0/8 -j ACCEPT

# --- БЛОКИРОВКА ICMP (PING) ---
iptables -A VPS_SHIELD -p icmp --icmp-type echo-request -j DROP

# --- БЛОКИРОВКА IP-ЧЕКЕРОВ ---
iptables -A VPS_SHIELD -m set --match-set ip_checkers dst -j DROP

# --- БЛОКИРОВКА RU-ЗОНЫ ---
iptables -A VPS_SHIELD -m set --match-set ru_zone dst -j DROP

# --- БЛОКИРОВКА BITTORRENT / P2P ТРАФИКА ---
BT_SIGS=("BitTorrent" "BitTorrent protocol" "peer_id=" ".torrent" "announce" "info_hash" "get_peers" "find_node")
for sig in "${BT_SIGS[@]}"; do
    iptables -A VPS_SHIELD -m string --algo bm --string "$sig" -j DROP
done

# Стандартные порты трекеров и P2P-клиентов
iptables -A VPS_SHIELD -p tcp -m multiport --dports 6881:6889,51413,6969,1337 -j DROP
iptables -A VPS_SHIELD -p udp -m multiport --dports 6881:6889,51413,6969,1337 -j DROP

# Привязка цепочки VPS_SHIELD к OUTPUT и FORWARD первыми правилами
iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I OUTPUT 1 -j VPS_SHIELD

iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
iptables -I FORWARD 1 -j VPS_SHIELD

echo "[VPS-SHIELD] Все правила защиты успешно активированы!"
