#!/usr/bin/env bash
# ==============================================================================
# VPS Shield v1.4.1 - Исполняемый модуль применения правил сетевой безопасности
# Репозиторий: https://github.com/sb218-dev/vps-shield
#
# Изменения v1.4.0 (по итогам живого аудита на песочнице, см. MEMORY.md):
#  - L7-синхронизация: рестарт панелей ТОЛЬКО при фактическом изменении конфига
#    (устранён ежедневный обрыв клиентских туннелей); для 3x-ui — только проверка
#    protocol:bittorrent (x-ui перезаписывает config.json из своей БД при каждом
#    старте, правки файла не переживают рестарт и создавали рестарт-луп)
#  - ip_checkers: канареечная защита /24 (shared CDN больше не блокируются —
#    ранее ложняк резал example.com и REALITY-таргет www.microsoft.com),
#    урезанный список доменов, атомарная пересборка через temp-set
#  - DNS (53) разрешён только шлюзу/системным резолверам (+ TRUSTED_DNS из
#    /etc/vps-shield.conf) — закрыта утечка через whoami.akamai.net @1.1.1.1
#  - UDP rate-limit: исключены порты туннелей (статические + слушающие UDP-порты
#    сервера), лимиты подняты 20/s -> 50/s
#  - string-правила: только точные сигнатуры; HTTP-слова ограничены портами
#    80/8000/8080/8888; убраны общие подстроки ("torrent", "info_hash", ...)
#  - LOG-цепочка с -m limit для диагностики дропов
#  - ip_forward включается только при обнаружении Docker
#  - Бэкапы конфигов панелей перед L7-правкой
#
# Изменения v1.4.1 (закрытие главной дыры — живой тест qBittorrent, см. MEMORY.md):
#  - uTP (UDP-транспорт BitTorrent на СЛУЧАЙНЫХ портах, основной транспорт
#    qBittorrent) блокируется по сигнатуре заголовка через -m u32: первый байт
#    UDP-payload = type<<4|version(1) -> 0x01 DATA / 0x11 FIN / 0x21 STATE /
#    0x31 RESET / 0x41 SYN. Ранее uTP проходил мимо щита целиком (живой тест:
#    2411 пакетов ACCEPT, 0 дропов — не bencode, порты случайные).
#  - Исключения ПЕРЕД дропом: WireGuard handshake (payload ровно 01 00 00 00),
#    STUN (magic cookie 0x2112A442 на смещении 12); QUIC/Hysteria2/TUIC уже
#    разрешены выше по портам туннелей. Сигнатуры проверены живым u32-тестом на VM.
# ==============================================================================
set -e

CONF_FILE="/etc/vps-shield.conf"

# Защита от параллельного запуска нескольких копий процесса (flock)
LOCKFILE="/var/lock/vps-shield.lock"
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    echo "[VPS-SHIELD] Процесс уже выполняется в другом потоке. Пропускаем параллельный запуск."
    exit 0
fi

# --- Пользовательская конфигурация (опционально) ---
# Пример /etc/vps-shield.conf:
#   TRUSTED_DNS="8.8.8.8 1.1.1.1"
TRUSTED_DNS=""
[ -f "$CONF_FILE" ] && . "$CONF_FILE" || true

echo "[VPS-SHIELD] 1. Настройка ядра (sysctl: отключение ICMP)..."
sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null

# ip_forward включаем ТОЛЬКО при обнаружении Docker (контейнерам нужен NAT).
# На чистых серверах системное значение не трогаем.
if ip link show 2>/dev/null | grep -qE 'docker0|br-[0-9a-f]+' || command -v docker >/dev/null 2>&1; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    echo "[VPS-SHIELD] Docker обнаружен: ip_forward=1."
else
    echo "[VPS-SHIELD] Docker не обнаружен: ip_forward не изменяется."
fi

echo "[VPS-SHIELD] 2. Создание базовых структур ipset..."
ipset create -exist ip_checkers hash:ip hashsize 4096 maxelem 65536
ipset create -exist ru_zone hash:net family inet hashsize 16384 maxelem 262144

# Определение сетевых параметров сервера (используются ниже)
GW_IP=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}' || true)
# systemd-resolved: реальный апстрим лежит в /run/systemd/resolve/resolv.conf,
# а /etc/resolv.conf указывает на стаб 127.0.0.53 — берём оба, фильтруя локальные.
DNS_SERVERS=$(grep -hE '^nameserver' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null \
    | awk '{print $2}' | grep -vE '^(127\.|::1$)' | sort -u || true)

echo "[VPS-SHIELD] 3. Обновление списка IP-чекеров (канареечная защита /24)..."

# 3.1. Канарейки: заведомо легитимные домены. Если IP чекера делит /24 с
# канарейкой — это shared CDN, его блокировать нельзя (находка аудита:
# Edgio 8.6.112.0/8.47.69.0 резался из-за чекеров и ломал example.com,
# example.org, neverssl.com и REALITY-таргет www.microsoft.com).
CANARY_DOMAINS=(
    "example.com" "example.org" "www.google.com" "www.microsoft.com"
    "www.cloudflare.com" "github.com" "raw.githubusercontent.com"
    "archive.ubuntu.com" "security.ubuntu.com"
)
CANARY_NETS=""
for dom in "${CANARY_DOMAINS[@]}"; do
    for ip in $(dig +short A "$dom" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true); do
        CANARY_NETS="$(echo "$ip" | cut -d. -f1-3).0/24\n$CANARY_NETS"
    done
done

# 3.2. Урезанный список чекеров: только сервисы с собственными IP.
# Убраны CDN-heavy: speedtest.net, browserleaks.com, ipaddress.com, myip.com,
# whatismyipaddress.com. Канарейка дополнительно прикрывает остальное.
CHECKER_DOMAINS=(
    "2ip.ru" "2ip.io" "ipinfo.io" "ifconfig.me" "ifconfig.co"
    "icanhazip.com" "api.ipify.org" "ident.me" "ip-api.com" "whoer.net"
)

TEMP_CHK="chk_tmp_$$"
ipset create -exist "$TEMP_CHK" hash:ip hashsize 4096 maxelem 65536
ADDED_CHK=0
SKIPPED_CHK=0
for dom in "${CHECKER_DOMAINS[@]}"; do
    for ip in $(dig +short A "$dom" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true); do
        net="$(echo "$ip" | cut -d. -f1-3).0/24"
        if echo -e "$CANARY_NETS" | grep -qxF "$net"; then
            echo "[VPS-SHIELD] Пропуск $ip ($dom): /24 $net совпадает с канареечным (shared CDN)."
            SKIPPED_CHK=$((SKIPPED_CHK + 1))
            continue
        fi
        ipset add -exist "$TEMP_CHK" "$ip" 2>/dev/null || true
        ADDED_CHK=$((ADDED_CHK + 1))
    done
done

# Атомарная замена только при успешной сборке (>= 5 IP), иначе сохраняем прежний набор
if [ "$ADDED_CHK" -ge 5 ]; then
    ipset swap "$TEMP_CHK" ip_checkers
    echo "[VPS-SHIELD] ip_checkers обновлён: $ADDED_CHK IP (пропущено по канарейке: $SKIPPED_CHK)."
else
    echo "[VPS-SHIELD] Внимание: резолв чекеров дал лишь $ADDED_CHK IP — сохранён предыдущий набор."
fi
ipset destroy "$TEMP_CHK" 2>/dev/null || true

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

        # Исключаем из ru_zone IP самого сервера, шлюза и DNS (чтобы не заблокировать себя)
        for my_ip in $(hostname -I 2>/dev/null || true); do
            ipset del "$TEMP_SET" "$my_ip" 2>/dev/null || true
        done
        if [ -n "$GW_IP" ]; then
            ipset del "$TEMP_SET" "$GW_IP" 2>/dev/null || true
        fi
        for dns in $DNS_SERVERS $TRUSTED_DNS; do
            [ -n "$dns" ] && ipset del "$TEMP_SET" "$dns" 2>/dev/null || true
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

# Rate-limited лог + DROP: диагностика "почему дропается" без риска утопить CPU/log
iptables -N VPS_SHIELD_LOG 2>/dev/null || iptables -F VPS_SHIELD_LOG
iptables -A VPS_SHIELD_LOG -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "VPS_SHIELD_DROP " --log-level 4
iptables -A VPS_SHIELD_LOG -j DROP

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

# --- 4. ДОВЕРЕННЫЕ DNS (порт 53 разрешён ТОЛЬКО им, см. блок 8б) ---
if [ -n "$GW_IP" ]; then
    iptables -A VPS_SHIELD -d "$GW_IP" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A VPS_SHIELD -d "$GW_IP" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
fi
for dns in $DNS_SERVERS $TRUSTED_DNS; do
    [ -z "$dns" ] && continue
    iptables -A VPS_SHIELD -d "$dns" -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -A VPS_SHIELD -d "$dns" -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
done

# --- 5. БЛОКИРОВКА ICMP (PING) НА УРОВНЕ IPTABLES ---
iptables -A VPS_SHIELD -p icmp --icmp-type echo-request -j DROP

# --- 6. БЛОКИРОВКА IP-ЧЕКЕРОВ И ГЕОЛОКАЦИОННЫХ СЕРВИСОВ ---
iptables -A VPS_SHIELD -m set --match-set ip_checkers dst -j VPS_SHIELD_LOG

# --- 7. БЛОКИРОВКА УТЕЧЕК В RU-ЗОНУ (ТОЛЬКО НОВЫЕ ИСХОДЯЩИЕ СЕССИИ!) ---
# Входящие клиентские подключения из РФ (и ответы сервера на них) НЕ блокируются!
iptables -A VPS_SHIELD -m state --state NEW -m set --match-set ru_zone dst -j VPS_SHIELD_LOG

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
iptables -A VPS_SHIELD -p udp -m string --algo bm --hex-string "|0000041727101980|" -j VPS_SHIELD_LOG

# Г. BEP 03: Хекс-сигнатура рукопожатия BitTorrent (\x13BitTorrent protocol)
iptables -A VPS_SHIELD -p tcp -m string --algo bm --hex-string "|13426974546f7272656e742070726f746f636f6c|" -j VPS_SHIELD_LOG

# Д. DHT (Distributed Hash Table) bencoded сигнатуры over UDP.
# Только ТОЧНЫЕ bencode-подписи: общие подстроки (find_node, get_peers, 5:nodes,
# 1:y1:q, 1:y1:r...) уже содержатся внутри точных и лишь давали ложняки + лишний CPU.
DHT_PATTERNS=(
    "d1:ad2:id"
    "d1:rd2:id"
    "d1:q4:ping"
    "d1:q9:find_node"
    "d1:q9:get_peers"
    "d1:q13:announce_peer"
)
for pat in "${DHT_PATTERNS[@]}"; do
    iptables -A VPS_SHIELD -p udp -m string --algo bm --string "$pat" -j VPS_SHIELD_LOG
done

# Е. HTTP-сигнатуры трекеров: ТОЛЬКО на plaintext-HTTP портах (80, 8000, 8080, 8888).
# На 443 трафик зашифрован — string-матч ничего не видит, только тратит CPU на каждый пакет.
# Убраны слишком общие подстроки: "torrent", "info_hash" (без =), "BitTorrent" (без " protocol").
BT_STRINGS=(
    "BitTorrent protocol"
    "peer_id="
    ".torrent"
    "announce?info_hash"
    "announce.php?passkey="
    "info_hash="
    "opentrackr"
    "openbittorrent"
    "open.stealth"
    "coppersurfer"
    "torrent.eu.org"
    "bttracker"
)
for sig in "${BT_STRINGS[@]}"; do
    iptables -A VPS_SHIELD -p tcp -m multiport --dports 80,8000,8080,8888 \
        -m string --algo bm --string "$sig" -j VPS_SHIELD_LOG
done

# Ж. Rate-limit всплесков UDP: исключаем порты туннелей (QUIC/Hysteria2/TUIC/WireGuard).
# Статический список + динамически определённые слушающие UDP-порты сервера
# (ss -uln) — чтобы клиенты при массовом переподключении не ловили дропы.
# Порт 53 сознательно не исключаем: он обрабатывается блоком 4/8б.
TUNNEL_UDP_PORTS="443 2053 2083 2087 2096 8880 8443 51820 51821"
# $(NF-1) = локальная колонка "адрес:порт" (последняя — peer). Устойчиво и к наличию,
# и к отсутствию колонки Netid: ss -uln без других протоколов НЕ печатает Netid,
# и $5 тогда указывает на peer ("0.0.0.0:*") — выявлено по baseline VM (аудит v1.4.0).
for p in $(ss -H -uln 2>/dev/null | awk '{print $(NF-1)}' | sed 's/.*://' | grep -E '^[0-9]+$' || true); do
    [ "$p" = "53" ] && continue
    TUNNEL_UDP_PORTS="$TUNNEL_UDP_PORTS $p"
done
for p in $(echo $TUNNEL_UDP_PORTS | tr ' ' '\n' | sort -un); do
    iptables -A VPS_SHIELD -p udp --dport "$p" -j ACCEPT 2>/dev/null || true
done

# Ж-2. БЛОКИРОВКА uTP (UDP-транспорт BitTorrent) ПО СИГНАТУРЕ ЗАГОЛОВКА (-m u32).
# СУТЬ ПРАВИЛА: -m u32 позволяет iptables читать произвольные байты пакета по
# смещению. Выражение "0>>22&0x3C@8" означает: из байта 0 IP-заголовка сдвигом
# на 22 и маской 0x3C выделить IHL (реальную длину IP-заголовка), пропустить её
# и ещё 8 байтов UDP-заголовка (@8) — курсор встаёт на ПЕРВЫЙ байт UDP-payload.
# Заголовок uTP начинается байтом type<<4|version(1):
#   0x01 ST_DATA, 0x11 ST_FIN, 0x21 ST_STATE, 0x31 ST_RESET, 0x41 ST_SYN
# по этим пяти значениям первого байта и дропаем (маска 0xFF000000 = сравнивается
# только первый байт, младшие три байта не проверяются).
# ПОЧЕМУ ЭТО НУЖНО: порты у uTP случайные (1024-65535) — портовые правила его
# не видят; bencode-сигнатуры DHT не матчатся (uTP — бинарный протокол, не bencode).
# ПОРЯДОК ВАЖЕН (защита от ложняков, все сценарии проверены живым u32-тестом на VM):
#  1) порты туннелей уже разрешены выше (QUIC/Hysteria2/TUIC/WireGuard);
#  2) WireGuard handshake initiation: payload = ровно 01 00 00 00
#     (uTP DATA с connection_id 0x0000 на практике не встречается) -> ACCEPT;
#  3) STUN (WebRTC/NAT-traversal): magic cookie 0x2112A442 в байтах 4-7 payload
#     (смещение 12 от начала IP-пакета) -> ACCEPT;
#  4) дроп пяти типов uTP с логом (VPS_SHIELD_LOG).
# Остаточный риск: QUIC short-header (первый байт 0x40-0x7F) на НЕстандартном
# порту может совпасть с uTP SYN (0x41) — на стене подтверждён только для портов
# вне списка туннелей (443 и слушающие порты исключены выше по цепочке).
iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m u32 --u32 "0>>22&0x3C@8=0x01000000" -j ACCEPT 2>/dev/null || true
iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m u32 --u32 "0>>22&0x3C@12=0x2112A442" -j ACCEPT 2>/dev/null || true
for utp_hdr in 0x01000000 0x11000000 0x21000000 0x31000000 0x41000000; do
    iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m u32 --u32 "0>>22&0x3C@8&0xFF000000=$utp_hdr" -j VPS_SHIELD_LOG 2>/dev/null || true
done

iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m state --state NEW -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
iptables -A VPS_SHIELD -p udp --dport 1024:65535 -m state --state NEW -j VPS_SHIELD_LOG

# --- 8б. DNS ТОЛЬКО НА ДОВЕРЕННЫЕ РЕЗОЛВЕРЫ ---
# Всё, что не разрешено блоком 4 (шлюз/системные/TRUSTED_DNS) — дропаем с логом.
# Закрывает утечку инфы о IP через whoami.akamai.net @1.1.1.1 и DNS-туннели.
iptables -A VPS_SHIELD -p udp --dport 53 -j VPS_SHIELD_LOG
iptables -A VPS_SHIELD -p tcp --dport 53 -j VPS_SHIELD_LOG

# --- 9. РАЗРЕШЕНИЕ УСТАНОВЛЕННЫХ СОЕДИНЕНИЙ ДЛЯ ВХОДЯЩИХ КЛИЕНТОВ ---
# Разрешает ответы сервера на входящие подключения (SSH, VLESS, Mikan, Reality, туннели),
# включая соединения от клиентов, подключающихся из России!
iptables -A VPS_SHIELD -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- 10. ПРИВЯЗКА ЦЕПОЧЕК VPS_SHIELD К НАЧАЛУ INPUT, OUTPUT И FORWARD ---
iptables -D INPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I INPUT 1 -j VPS_SHIELD

iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
iptables -I OUTPUT 1 -j VPS_SHIELD

iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
iptables -I FORWARD 1 -j VPS_SHIELD

# --- 11. ИНТЕГРАЦИЯ С XRAY / 3X-UI / MIHOMO / MIKAN (УРОВЕНЬ L7 DPI) ---
# Рестарт сервиса выполняется ТОЛЬКО при фактическом изменении конфига:
# python печатает маркер CHANGED, bash рестартит панели лишь при его наличии.
# (В v1.3 рестарт был безусловным и ежедневно рвал все клиентские туннели.)
sync_l7_bittorrent() {
    # 1. Синхронизация Xray / 3x-ui / Marzban
    for cfg in "/usr/local/x-ui/bin/config.json" "/etc/xray/config.json" "/usr/local/etc/xray/config.json" "/var/lib/marzban/xray-config.json"; do
        if [ -f "$cfg" ]; then
            # 3x-ui перезаписывает config.json из своей БД при каждом старте: правки
            # файла не переживают рестарт (domains-rule выбрасывался -> рестарт при
            # каждом запуске ядра, находка аудита v1.4.0). Для x-ui — только проверка:
            # правило protocol:bittorrent у 3x-ui идёт из шаблона БД и сохраняется само.
            mode="standalone"
            case "$cfg" in *x-ui*) mode="xui" ;; esac
            out=$(python3 - "$cfg" "$mode" <<'PYEOF' 2>/dev/null || true
import json, sys, shutil
try:
    cfg = sys.argv[1]
    xui_managed = (len(sys.argv) > 2 and sys.argv[2] == 'xui')
    with open(cfg, 'r') as f:
        c = json.load(f)
    r = c.setdefault('routing', {}).setdefault('rules', [])
    changed = False
    has_proto = any('bittorrent' in rule.get('protocol', []) and rule.get('outboundTag') == 'blocked' for rule in r)
    if xui_managed:
        # Конфигом x-ui управляет его БД: не редактируем и не рестартим, только проверяем.
        if not has_proto:
            print('XUI_NO_BT_RULE')
    else:
        if not has_proto:
            r.insert(0, {'type': 'field', 'outboundTag': 'blocked', 'protocol': ['bittorrent']})
            changed = True
        bt_domains = ['geosite:torrent', 'keyword:torrent', 'keyword:tracker', 'keyword:announce', 'domain:opentrackr.org', 'domain:openbittorrent.com']
        if not any(any(d in rule.get('domain', []) for d in bt_domains) and rule.get('outboundTag') == 'blocked' for rule in r):
            r.insert(0, {'type': 'field', 'outboundTag': 'blocked', 'domain': bt_domains})
            changed = True
    if changed:
        shutil.copy2(cfg, cfg + '.vps-shield.bak')
        with open(cfg, 'w') as f:
            json.dump(c, f, indent=2)
        print('CHANGED')
except Exception as e:
    print('ERROR: %s' % e)
PYEOF
)
            if [[ "$out" == *CHANGED* ]]; then
                echo "[VPS-SHIELD] Конфигурация Xray ($cfg) обновлена (L7 BitTorrent) — выполняется рестарт сервиса."
                if systemctl is-active --quiet x-ui; then
                    systemctl restart x-ui >/dev/null 2>&1 || true
                elif systemctl is-active --quiet xray; then
                    systemctl restart xray >/dev/null 2>&1 || true
                fi
            elif [[ "$out" == *XUI_NO_BT_RULE* ]]; then
                echo "[VPS-SHIELD] ВНИМАНИЕ: в конфиге 3x-ui ($cfg) нет правила protocol:bittorrent."
                echo "[VPS-SHIELD] Добавьте его в шаблон Xray в панели 3x-ui: config.json перезаписывается x-ui из БД при каждом старте, авто-правка не переживает рестарт."
            else
                echo "[VPS-SHIELD] Xray ($cfg): L7-правила уже на месте, рестарт не требуется."
            fi
        fi
    done

    # 2. Синхронизация Mihomo / Mikan / Clash (YAML)
    for yaml_cfg in "/opt/mikan/config.yaml" "/etc/mihomo/config.yaml" "/etc/clash/config.yaml" "/root/.config/mihomo/config.yaml"; do
        if [ -f "$yaml_cfg" ]; then
            out=$(python3 - "$yaml_cfg" <<'PYEOF' 2>/dev/null || true
import sys, shutil
try:
    path = sys.argv[1]
    with open(path, 'r') as f:
        lines = f.readlines()
    has_torrent = any('GEOSITE,torrent,REJECT' in l or 'bittorrent' in l.lower() for l in lines)
    changed = False
    new_lines = []
    for line in lines:
        new_lines.append(line)
        if not has_torrent and line.strip().startswith('rules:'):
            new_lines.append('  - GEOSITE,torrent,REJECT\n')
            new_lines.append('  - DST-PORT,6881-6889,REJECT\n')
            new_lines.append('  - DST-PORT,51413,REJECT\n')
            changed = True
    if changed:
        shutil.copy2(path, path + '.vps-shield.bak')
        with open(path, 'w') as f:
            f.writelines(new_lines)
        print('CHANGED')
except Exception as e:
    print('ERROR: %s' % e)
PYEOF
)
            if [[ "$out" == *CHANGED* ]]; then
                echo "[VPS-SHIELD] Конфигурация Mihomo/Mikan ($yaml_cfg) обновлена — выполняется рестарт сервиса."
                if systemctl is-active --quiet mikan; then
                    systemctl restart mikan >/dev/null 2>&1 || true
                elif systemctl is-active --quiet mihomo; then
                    systemctl restart mihomo >/dev/null 2>&1 || true
                fi
            else
                echo "[VPS-SHIELD] Mihomo/Mikan ($yaml_cfg): L7-правила уже на месте, рестарт не требуется."
            fi
        fi
    done
}
sync_l7_bittorrent

# --- 12. СОХРАНЕНИЕ IPSET ДЛЯ РАННЕЙ ЗАГРУЗКИ ПЛАГИНОМ 05-ipset ---
# netfilter-persistent грузит правила ДО старта vps-shield.service; без наборов
# iptables-restore падает ("Set ip_checkers doesn't exist") и сервер грузится без
# правил. Плагин 05-ipset (ставится менеджером) восстанавливает наборы из этого файла.
mkdir -p /etc/iptables
ipset save > /etc/iptables/ipsets.rules 2>/dev/null || true

echo "[VPS-SHIELD] Все правила защиты успешно активированы!"
