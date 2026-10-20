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

echo "[VPS-SHIELD] 5. Применение правил фильтрации iptables (P2P/BitTorrent & Security)..."
iptables -N VPS_SHIELD 2>/dev/null || iptables -F VPS_SHIELD

# --- БЕЛЫЙ СПИСОК (Локальный трафик и служебные соединения) ---
iptables -A VPS_SHIELD -i lo -j ACCEPT
iptables -A VPS_SHIELD -o lo -j ACCEPT

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

# ------------------------------------------------------------------------------
# --- БЛОКИРОВКА BITTORRENT / P2P ТРАФИКА (СТРОГО ДО ESTABLISHED/RELATED!) ---
# ------------------------------------------------------------------------------

# 1. Стандартные порты трекеров и P2P-клиентов (входящие и исходящие)
iptables -A VPS_SHIELD -p tcp -m multiport --dports 6881:6889,51413,6969,1337,2710 -j DROP
iptables -A VPS_SHIELD -p udp -m multiport --dports 6881:6889,51413,6969,1337,2710 -j DROP
iptables -A VPS_SHIELD -p tcp -m multiport --sports 6881:6889,51413,6969,1337,2710 -j DROP
iptables -A VPS_SHIELD -p udp -m multiport --sports 6881:6889,51413,6969,1337,2710 -j DROP

# 2. BEP 15: Магический заголовок подключения к UDP-трекеру (0x0000041727101980)
iptables -A VPS_SHIELD -p udp -m string --algo bm --hex-string "|0000041727101980|" -j DROP

# 3. BEP 03: Хекс-сигнатура рукопожатия BitTorrent (\x13BitTorrent protocol)
iptables -A VPS_SHIELD -p tcp -m string --algo bm --hex-string "|13426974546f7272656e742070726f746f636f6c|" -j DROP

# 4. DHT (Distributed Hash Table) bencoded сигнатуры over UDP
DHT_PATTERNS=(
    "d1:ad2:id"
    "d1:rd2:id"
    "d1:q4:ping"
    "d1:q9:find_node"
    "d1:q9:get_peers"
    "d1:q13:announce_peer"
)
for pat in "${DHT_PATTERNS[@]}"; do
    iptables -A VPS_SHIELD -p udp -m string --algo bm --string "$pat" -j DROP
done

# 5. Строковые сигнатуры протокола и HTTP-трекеров
BT_STRINGS=(
    "BitTorrent"
    "BitTorrent protocol"
    "peer_id="
    ".torrent"
    "announce?info_hash"
    "announce.php?passkey="
    "info_hash="
    "info_hash"
    "announce_peer"
)
for sig in "${BT_STRINGS[@]}"; do
    iptables -A VPS_SHIELD -m string --algo bm --string "$sig" -j DROP
done

# --- РАЗРЕШЕНИЕ УСТАНОВЛЕННЫХ СОЕДИНЕНИЙ (ДЛЯ ОБЫЧНОГО ТРАФИКА) ---
iptables -A VPS_SHIELD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Привязка цепочки VPS_SHIELD к началу OUTPUT и FORWARD
iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I OUTPUT 1 -j VPS_SHIELD

iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
iptables -I FORWARD 1 -j VPS_SHIELD

# --- 6. ИНТЕГРАЦИЯ С XRAY / 3X-UI (УРОВЕНЬ L7 DPI) ---
sync_xray_bittorrent() {
    for cfg in "/usr/local/x-ui/bin/config.json" "/etc/xray/config.json" "/usr/local/etc/xray/config.json"; do
        if [ -f "$cfg" ]; then
            python3 -c "
import json, sys
try:
    with open('$cfg', 'r') as f:
        c = json.load(f)
    r = c.setdefault('routing', {}).setdefault('rules', [])
    changed = False
    
    # L7 Protocol: bittorrent -> blocked
    if not any('bittorrent' in rule.get('protocol', []) and rule.get('outboundTag') == 'blocked' for rule in r):
        r.insert(0, {'type': 'field', 'outboundTag': 'blocked', 'protocol': ['bittorrent']})
        changed = True
        
    # L7 Domains: trackers and torrents -> blocked
    bt_domains = ['keyword:torrent', 'keyword:tracker', 'keyword:announce', 'domain:opentrackr.org', 'domain:openbittorrent.com']
    if not any(any(d in rule.get('domain', []) for d in bt_domains) and rule.get('outboundTag') == 'blocked' for rule in r):
        r.insert(0, {'type': 'field', 'outboundTag': 'blocked', 'domain': bt_domains})
        changed = True
        
    if changed:
        with open('$cfg', 'w') as f:
            json.dump(c, f, indent=2)
        print('[VPS-SHIELD] Конфигурация Xray ($cfg) обновлена: активирована L7-блокировка BitTorrent.')
except Exception as e:
    print(f'[VPS-SHIELD] Ошибка обновления Xray конфига: {e}', file=sys.stderr)
" 2>/dev/null || true
            if systemctl is-active --quiet x-ui; then
                systemctl restart x-ui >/dev/null 2>&1 || true
            elif systemctl is-active --quiet xray; then
                systemctl restart xray >/dev/null 2>&1 || true
            fi
        fi
    done
}
sync_xray_bittorrent

echo "[VPS-SHIELD] Все правила защиты успешно активированы!"
