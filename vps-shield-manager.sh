#!/usr/bin/env bash
# ==============================================================================
# VPS Shield - Комплексный модуль безопасности для Ubuntu 22.04 и 24.04 LTS
#
# Репозиторий: https://github.com/sb218-dev/vps-shield
# Лицензия: MIT
#
# Функционал:
#  1. Отключение ICMP (Ping) на уровне ядра (sysctl + iptables)
#  2. Блокировка BitTorrent / P2P трафика (L4 iptables + BEP 15/03/DHT + L7 Xray DPI)
#  3. Блокировка IP-чекеров и геолокационных сервисов (динамический ipset)
#  4. Блокировка RU-сегмента (.ru, .рф, .su) по актуальным базам CIDR (ipset hash:net)
#  5. Защита локальных сетей (RFC 1918) от случайной блокировки (SSH, LAN, DNS)
#  6. Автозапуск и персистентность (systemd service + systemd timer + netfilter-persistent)
#
# Использование:
#   sudo ./vps-shield-manager.sh install    - Установка и активация всех модулей
#   sudo ./vps-shield-manager.sh uninstall  - Полное удаление и возврат к штатному состоянию
#   sudo ./vps-shield-manager.sh status     - Проверка статуса компонентов
#   sudo ./vps-shield-manager.sh update     - Принудительное обновление баз IP
# ==============================================================================

set -e

SCRIPT_PATH="/usr/local/bin/vps-shield.sh"
SERVICE_PATH="/etc/systemd/system/vps-shield.service"
UPDATE_SERVICE_PATH="/etc/systemd/system/vps-shield-update.service"
TIMER_PATH="/etc/systemd/system/vps-shield-update.timer"
SYSCTL_CONF="/etc/sysctl.d/99-vps-shield.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ОШИБКА] Данный скрипт необходимо запускать с правами root (sudo)!${NC}" >&2
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        echo -e "${RED}[ОШИБКА] Файл /etc/os-release не найден. Скрипт предназначен для Ubuntu.${NC}" >&2
        exit 1
    fi
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        echo -e "${YELLOW}[ПРЕДУПРЕЖДЕНИЕ] Обнаружена ОС: $NAME ($VERSION_ID). Скрипт оптимизирован для Ubuntu 22.04 и 24.04.${NC}"
    else
        echo -e "${GREEN}[ИНФО] Операционная система: $PRETTY_NAME${NC}"
    fi
}

install_shield() {
    check_root
    check_os

    echo -e "\n${CYAN}>>> [1/7] Подготовка репозиториев и установка системных пакетов...${NC}"
    sed -i '/cdrom:/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    sed -i 's/ru\.archive\.ubuntu\.com/archive.ubuntu.com/g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true

    export DEBIAN_FRONTEND=noninteractive
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true

    apt-get update -y
    apt-get install -y ipset iptables iptables-persistent netfilter-persistent curl dnsutils python3
    modprobe xt_string 2>/dev/null || true

    echo -e "\n${CYAN}>>> [2/7] Создание исполняемого скрипта ядра защиты ($SCRIPT_PATH)...${NC}"
    cat << 'EOF' > "$SCRIPT_PATH"
#!/usr/bin/env bash
set -e

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

# Локальные приватные сети (RFC 1918)
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
EOF
    chmod +x "$SCRIPT_PATH"

    echo -e "\n${CYAN}>>> [3/7] Настройка sysctl для персистентного отключения ICMP...${NC}"
    cat << 'EOF' > "$SYSCTL_CONF"
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.ip_forward = 1
EOF
    sysctl -p "$SYSCTL_CONF" >/dev/null

    echo -e "\n${CYAN}>>> [4/7] Регистрация служб в systemd...${NC}"
    cat << EOF > "$SERVICE_PATH"
[Unit]
Description=VPS Shield Security & Anti-Leak Rules
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > "$UPDATE_SERVICE_PATH"
[Unit]
Description=VPS Shield Daily IPsets Update
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
EOF

    cat << EOF > "$TIMER_PATH"
[Unit]
Description=Daily Update of VPS Shield IPsets

[Timer]
OnCalendar=daily
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable vps-shield.service >/dev/null 2>&1

    echo -e "\n${CYAN}>>> [5/7] Первичный запуск и инициализация правил защиты...${NC}"
    bash "$SCRIPT_PATH"

    echo -e "\n${CYAN}>>> [6/7] Сохранение правил в netfilter-persistent...${NC}"
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

    echo -e "\n${CYAN}>>> [7/7] Запуск таймера ежедневного автообновления...${NC}"
    systemctl enable --now vps-shield-update.timer >/dev/null 2>&1

    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}[УСПЕХ] VPS Shield успешно установлен и активен!${NC}"
    echo -e "${GREEN}====================================================${NC}"
    status_shield
}

uninstall_shield() {
    check_root
    echo -e "\n${YELLOW}====================================================${NC}"
    echo -e "${YELLOW}   УДАЛЕНИЕ VPS SHIELD И ВОССТАНОВЛЕНИЕ СИСТЕМЫ    ${NC}"
    echo -e "${YELLOW}====================================================${NC}"

    echo -e "\n${CYAN}[1/6] Отключение и удаление служб systemd...${NC}"
    systemctl stop vps-shield.service 2>/dev/null || true
    systemctl disable vps-shield.service 2>/dev/null || true
    systemctl stop vps-shield-update.timer 2>/dev/null || true
    systemctl disable vps-shield-update.timer 2>/dev/null || true
    systemctl stop vps-shield-update.service 2>/dev/null || true

    rm -f "$SERVICE_PATH" "$UPDATE_SERVICE_PATH" "$TIMER_PATH"
    systemctl daemon-reload

    echo -e "${CYAN}[2/6] Удаление правил и цепочек iptables...${NC}"
    iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
    iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
    iptables -F VPS_SHIELD 2>/dev/null || true
    iptables -X VPS_SHIELD 2>/dev/null || true

    echo -e "${CYAN}[3/6] Очистка и удаление таблиц ipset...${NC}"
    for s in $(ipset list -n 2>/dev/null | grep -E '^(ru_zone|ru_tmp|ip_checkers)'); do
        ipset flush "$s" 2>/dev/null || true
        ipset destroy "$s" 2>/dev/null || true
    done

    echo -e "${CYAN}[4/6] Восстановление ICMP (Ping) в ядре sysctl...${NC}"
    rm -f "$SYSCTL_CONF"
    sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null

    echo -e "${CYAN}[5/6] Удаление исполняемого файла ($SCRIPT_PATH)...${NC}"
    rm -f "$SCRIPT_PATH" /var/lock/vps-shield.lock

    echo -e "${CYAN}[6/6] Сохранение чистого состояния фаервола...${NC}"
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}[УСПЕХ] VPS Shield полностью удален. Система чистая!${NC}"
    echo -e "${GREEN}====================================================${NC}\n"
}

status_shield() {
    echo -e "\n${CYAN}=============== СТАТУС БЕЗОПАСНОСТИ VPS SHIELD ===============${NC}"

    local icmp_val
    icmp_val=$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null || echo "0")
    if [[ "$icmp_val" == "1" ]]; then
        echo -e " ICMP Echo (Ping):        ${GREEN}[ЗАБЛОКИРОВАН]${NC} (net.ipv4.icmp_echo_ignore_all = 1)"
    else
        echo -e " ICMP Echo (Ping):        ${RED}[РАЗРЕШЕН]${NC}     (net.ipv4.icmp_echo_ignore_all = 0)"
    fi

    if ipset list ru_zone >/dev/null 2>&1; then
        local ru_cnt
        ru_cnt=$(ipset list ru_zone | grep -E -c '^[0-9]' || echo "0")
        echo -e " Блокировка RU-зоны:       ${GREEN}[АКТИВНА]${NC}      (CIDR в базе: $ru_cnt)"
    else
        echo -e " Блокировка RU-зоны:       ${RED}[ОТКЛЮЧЕНА]${NC}"
    fi

    if ipset list ip_checkers >/dev/null 2>&1; then
        local chk_cnt
        chk_cnt=$(ipset list ip_checkers | grep -E -c '^[0-9]' || echo "0")
        echo -e " Блокировка IP-чекеров:    ${GREEN}[АКТИВНА]${NC}      (Заблокировано IP: $chk_cnt)"
    else
        echo -e " Блокировка IP-чекеров:    ${RED}[ОТКЛЮЧЕНА]${NC}"
    fi

    if iptables -n -L VPS_SHIELD >/dev/null 2>&1; then
        local rules_cnt
        rules_cnt=$(iptables -n -L VPS_SHIELD --line-numbers | grep -E -c '^[0-9]')
        echo -e " Фаервол (VPS_SHIELD):     ${GREEN}[АКТИВЕН]${NC}      (Всего правил: $rules_cnt)"
        echo -e " Фильтр BitTorrent L4:    ${GREEN}[АКТИВЕН]${NC}      (BEP15/03/DHT + xt_string + P2P-порты)"
    else
        echo -e " Фаервол (VPS_SHIELD):     ${RED}[НЕ АКТИВЕН]${NC}"
        echo -e " Фильтр BitTorrent L4:    ${RED}[НЕ АКТИВЕН]${NC}"
    fi

    # L7 Xray status
    if [ -f "/usr/local/x-ui/bin/config.json" ] || [ -f "/etc/xray/config.json" ]; then
        echo -e " Фильтр BitTorrent L7 DPI:${GREEN}[АКТИВЕН]${NC}      (Интеграция с Xray/3x-UI)"
    fi

    if systemctl is-enabled vps-shield.service >/dev/null 2>&1; then
        echo -e " Автозагрузка (systemd):   ${GREEN}[ВКЛЮЧЕНА]${NC}     (vps-shield.service)"
    else
        echo -e " Автозагрузка (systemd):   ${RED}[ОТКЛЮЧЕНА]${NC}"
    fi

    if systemctl is-active vps-shield-update.timer >/dev/null 2>&1; then
        echo -e " Ежедневное автообновление:${GREEN}[ВКЛЮЧЕНО]${NC}      (vps-shield-update.timer)"
    else
        echo -e " Ежедневное автообновление:${RED}[ОТКЛЮЧЕНО]${NC}"
    fi

    echo -e "${CYAN}==============================================================${NC}\n"
}

case "$1" in
    install)
        install_shield
        ;;
    uninstall)
        uninstall_shield
        ;;
    status)
        status_shield
        ;;
    update)
        check_root
        bash "$SCRIPT_PATH"
        ;;
    *)
        echo "Использование: sudo $0 {install|uninstall|status|update}"
        echo ""
        echo "Команды:"
        echo "  install    - Полная установка и запуск щита безопасности"
        echo "  uninstall  - Полный демонтаж всех правил и восстановление системы"
        echo "  status     - Отображение текущего статуса всех модулей защиты"
        echo "  update     - Немедленное обновление списков RU-зоны и чекеров IP"
        exit 1
        ;;
esac
