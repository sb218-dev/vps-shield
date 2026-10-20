#!/usr/bin/env bash
# ==============================================================================
# VPS Shield - Исполняемый модуль применения правил сетевой безопасности
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

# Определение сетевых параметров сервера
GW_IP=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -n 1 || true)
DNS_SERVERS=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)

for url in "$URL_PRIMARY" "$URL_BACKUP"; do
    if curl -sSL --connect-timeout 10 --retry 2 "$url" -o "$TMP_RU" && [ -s "$TMP_RU" ]; then
        {
            echo "create $TEMP_SET hash:net family inet hashsize 16384 maxelem 262144 -exist"
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' "$TMP_RU" | sed "s/^/add $TEMP_SET /"
        } | ipset restore -!

        # Исключаем из ru_zone IP самого сервера, шлюза и локальных сетей
        for my_ip in $(hostname -I 2>/dev/null || true); do
            ipset del "$TEMP_SET" "$my_ip" 2>/dev/null || true
        done
        if [ -n "$GW_IP" ]; then
            ipset del "$TEMP_SET" "$GW_IP" 2>/dev/null || true
        fi
        for dns in $DNS_SERVERS; do
            ipset del "$TEMP_SET" "$dns" 2>/dev/null || true
        done

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

# --- 1. LOOPBACK (Локальный трафик хоста) ---
iptables -A VPS_SHIELD -i lo -j ACCEPT
iptables -A VPS_SHIELD -o lo -j ACCEPT

# --- 2. ЛОКАЛЬНЫЙ МЕЖМАШИННЫЙ ТРАФИК (RFC 1918) ---
# ВАЖНО: Разрешается ТОЛЬКО если И источник И получатель находятся в локальной сети!
# Это предотвращает ошибочный пропуск исходящего трафика в интернет при сером IP сервера.
iptables -A VPS_SHIELD -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT
iptables -A VPS_SHIELD -s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT
iptables -A VPS_SHIELD -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT
iptables -A VPS_SHIELD -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT

# --- 3. DOCKER ИЗОЛЯЦИЯ И ВНУТРЕННИЙ ТРАФИК МОСТОВ ---
# Внутренний обмен контейнеров с хостом разрешен.
# Исходящий трафик из контейнеров в интернет (FORWARD) ОБЯЗАТЕЛЬНО проверяется правилами ниже!
iptables -A VPS_SHIELD -i docker0 -o docker0 -j ACCEPT 2>/dev/null || true
iptables -A VPS_SHIELD -i br-+ -o br-+ -j ACCEPT 2>/dev/null || true

# --- 4. ШЛЮЗ ПО УМОЛЧАНИЮ И СИСТЕМНЫЙ DNS ---
if [ -n "$GW_IP" ]; then
    iptables -A VPS_SHIELD -d "$GW_IP" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A VPS_SHIELD -d "$GW_IP" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
fi
for dns in $DNS_SERVERS; do
    iptables -A VPS_SHIELD -d "$dns" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A VPS_SHIELD -d "$dns" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
done
iptables -A VPS_SHIELD -p udp --dport 53 -j ACCEPT
iptables -A VPS_SHIELD -p tcp --dport 53 -j ACCEPT

# --- 5. БЛОКИРОВКА ICMP (PING) НА УРОВНЕ IPTABLES ---
iptables -A VPS_SHIELD -p icmp --icmp-type echo-request -j DROP

# --- 6. БЛОКИРОВКА IP-ЧЕКЕРОВ И ГЕОЛОКАЦИОННЫХ СЕРВИСОВ ---
iptables -A VPS_SHIELD -m set --match-set ip_checkers dst -j DROP

# --- 7. БЛОКИРОВКА УТЕЧЕК В RU-ЗОНУ (ТОЛЬКО НОВЫЕ ИСХОДЯЩИЕ СЕССИИ!) ---
# Входящие клиентские подключения из РФ (и ответы сервера на них) НЕ блокируются!
iptables -A VPS_SHIELD -m state --state NEW -m set --match-set ru_zone dst -j DROP

# --- 8. БЛОКИРОВКА BITTORRENT / P2P ТРАФИКА (ДО ESTABLISHED/RELATED!) ---
# А. Порты P2P клиентов, трекеров и LSD
BT_PORTS="6881:6889,51413,6969,1337,2710,6771"
iptables -A VPS_SHIELD -p tcp -m multiport --dports "$BT_PORTS" -j DROP
iptables -A VPS_SHIELD -p udp -m multiport --dports "$BT_PORTS" -j DROP
iptables -A VPS_SHIELD -p tcp -m multiport --sports "$BT_PORTS" -j DROP
iptables -A VPS_SHIELD -p udp -m multiport --sports "$BT_PORTS" -j DROP

# Б. LSD (Local Service Discovery) мультикаст
iptables -A VPS_SHIELD -d 239.255.255.250 -p udp --dport 6771 -j DROP

# В. BEP 15: Магический заголовок подключения к UDP-трекеру (0x0000041727101980)
iptables -A VPS_SHIELD -p udp -m string --algo bm --hex-string "|0000041727101980|" -j DROP

# Г. BEP 03: Хекс-сигнатура рукопожатия BitTorrent (\x13BitTorrent protocol)
iptables -A VPS_SHIELD -p tcp -m string --algo bm --hex-string "|13426974546f7272656e742070726f746f636f6c|" -j DROP

# Д. DHT (Distributed Hash Table) bencoded сигнатуры over UDP
DHT_PATTERNS=(
    "d1:ad2:id"
    "d1:rd2:id"
    "d1:q4:ping"
    "d1:q9:find_node"
    "d1:q9:get_peers"
    "d1:q13:announce_peer"
    "1:ad2:id"
    "1:rd2:id"
    "find_node"
    "get_peers"
    "announce_peer"
    "5:nodes"
    "1:y1:q"
    "1:y1:r"
)
for pat in "${DHT_PATTERNS[@]}"; do
    iptables -A VPS_SHIELD -p udp -m string --algo bm --string "$pat" -j DROP
done

# Е. Строковые сигнатуры протокола и популярных трекеров (включая 80/443)
BT_STRINGS=(
    "BitTorrent"
    "BitTorrent protocol"
    "peer_id="
    ".torrent"
    "announce?info_hash"
    "announce.php?passkey="
    "info_hash="
    "info_hash"
    "torrent"
    "opentrackr"
    "openbittorrent"
    "open.stealth"
    "coppersurfer"
    "torrent.eu.org"
    "bttracker"
)
for sig in "${BT_STRINGS[@]}"; do
    iptables -A VPS_SHIELD -m string --algo bm --string "$sig" -j DROP
done

# Ж. Ограничение всплесков динамических UDP-соединений (борьба с uTP / DHT спамом)
iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m state --state NEW -m limit --limit 20/sec --limit-burst 40 -j ACCEPT 2>/dev/null || true
iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m state --state NEW -j DROP 2>/dev/null || true

# --- 9. РАЗРЕШЕНИЕ УСТАНОВЛЕННЫХ СОЕДИНЕНИЙ ДЛЯ ВХОДЯЩИХ КЛИЕНТОВ ---
# Разрешает ответы сервера на входящие подключения (SSH, VLESS, Mikan, Reality, туннели),
# включая соединения от клиентов, подключающихся из России!
iptables -A VPS_SHIELD -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- 10. ПРИВЯЗКА ЦЕПОЧКИ VPS_SHIELD К НАЧАЛУ INPUT, OUTPUT И FORWARD ---
iptables -D INPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I INPUT 1 -j VPS_SHIELD

iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I OUTPUT 1 -j VPS_SHIELD

iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
iptables -I FORWARD 1 -j VPS_SHIELD

# --- 11. ИНТЕГРАЦИЯ С XRAY / 3X-UI / MIHOMO / MIKAN (УРОВЕНЬ L7 DPI) ---
sync_l7_bittorrent() {
    # 1. Синхронизация Xray / 3x-ui / Marzban
    for cfg in "/usr/local/x-ui/bin/config.json" "/etc/xray/config.json" "/usr/local/etc/xray/config.json" "/var/lib/marzban/xray-config.json"; do
        if [ -f "$cfg" ]; then
            python3 -c "
import json, sys
try:
    with open('$cfg', 'r') as f:
        c = json.load(f)
    r = c.setdefault('routing', {}).setdefault('rules', [])
    changed = False
    
    if not any('bittorrent' in rule.get('protocol', []) and rule.get('outboundTag') == 'blocked' for rule in r):
        r.insert(0, {'type': 'field', 'outboundTag': 'blocked', 'protocol': ['bittorrent']})
        changed = True
        
    bt_domains = ['geosite:torrent', 'keyword:torrent', 'keyword:tracker', 'keyword:announce', 'domain:opentrackr.org', 'domain:openbittorrent.com']
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

    # 2. Синхронизация Mihomo / Mikan / Clash (YAML)
    for yaml_cfg in "/opt/mikan/config.yaml" "/etc/mihomo/config.yaml" "/etc/clash/config.yaml" "/root/.config/mihomo/config.yaml"; do
        if [ -f "$yaml_cfg" ]; then
            python3 -c "
import sys
try:
    with open('$yaml_cfg', 'r') as f:
        lines = f.readlines()
    changed = False
    new_lines = []
    has_torrent = any('GEOSITE,torrent,REJECT' in l or 'bittorrent' in l.lower() for l in lines)
    if not has_torrent:
        for line in lines:
            new_lines.append(line)
            if line.strip().startswith('rules:'):
                new_lines.append('  - GEOSITE,torrent,REJECT\n')
                new_lines.append('  - DST-PORT,6881-6889,REJECT\n')
                new_lines.append('  - DST-PORT,51413,REJECT\n')
                changed = True
        if changed:
            with open('$yaml_cfg', 'w') as f:
                f.writelines(new_lines)
            print('[VPS-SHIELD] Конфигурация Mihomo/Mikan ($yaml_cfg) обновлена: добавлены правила блокировки торрентов.')
except Exception as e:
    print(f'[VPS-SHIELD] Ошибка обновления Mihomo конфига: {e}', file=sys.stderr)
" 2>/dev/null || true
            if systemctl is-active --quiet mikan; then
                systemctl restart mikan >/dev/null 2>&1 || true
            elif systemctl is-active --quiet mihomo; then
                systemctl restart mihomo >/dev/null 2>&1 || true
            fi
        fi
    done
}
sync_l7_bittorrent

echo "[VPS-SHIELD] Все правила защиты успешно активированы!"
