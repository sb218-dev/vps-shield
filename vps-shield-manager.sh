#!/usr/bin/env bash
# ==============================================================================
# VPS Shield v1.4.1 - Комплексный модуль безопасности для Ubuntu 22.04 и 24.04 LTS
#
# Репозиторий: https://github.com/sb218-dev/vps-shield
# Лицензия: MIT
#
# Изменения v1.4.1: блокировка uTP (UDP-транспорт BitTorrent на случайных
# портах, основной транспорт qBittorrent) по сигнатуре заголовка через -m u32
# с исключениями WireGuard/STUN — закрыта главная дыра, найденная живым тестом
# qBittorrent (реализация и суть правила — в vps-shield.sh, блок Ж-2).
#
# Изменения v1.4.0 (по итогам живого аудита на песочнице, см. MEMORY.md):
#  - Ядро защиты больше НЕ дублируется heredoc'ом внутри менеджера:
#    vps-shield.sh берётся из VPS_SHIELD_CORE_SRC (передаёт install.sh),
#    из файла рядом с менеджером (git clone) или скачивается с GitHub raw
#  - Плагин 05-ipset для netfilter-persistent: наборы ipset восстанавливаются
#    ДО загрузки rules.v4 — устранён boot-race "Set ip_checkers doesn't exist",
#    при котором iptables-restore падал и сервер грузился без правил
#  - Легаси-таймер vps-shield.timer удаляется (двойной ежедневный запуск
#    дважды за ночь обрывал клиентские туннели)
#  - sysctl: ip_forward=1 пишется только при обнаруженном Docker
#  - uninstall: откат L7-правил из бэкапов *.vps-shield.bak конфигов панелей,
#    удаление плагина 05-ipset и /etc/iptables/ipsets.rules
#  - Бэкап /etc/apt/sources.list перед sed-правками
#
# Функционал:
#  1. Отключение ICMP (Ping) на уровне ядра (sysctl + iptables)
#  2. Блокировка BitTorrent / P2P трафика (L4 iptables + BEP 15/03/DHT + L7 Xray/Mihomo DPI)
#  3. Блокировка IP-чекеров (динамический ipset + канареечная защита /24 от shared CDN)
#  4. Блокировка утечек в RU-сегмент (.ru, .рф, .su) по CIDR (ipset hash:net)
#  5. Полная совместимость с Docker, Mikan, 3x-UI и подбором SNI (RealiTLScanner)
#  6. Защита локальных сетей (RFC 1918), шлюза и клиентов из РФ от блокировки
#  7. Автозапуск и персистентность (systemd + netfilter-persistent + плагин 05-ipset)
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
LEGACY_TIMER_PATH="/etc/systemd/system/vps-shield.timer"
SYSCTL_CONF="/etc/sysctl.d/99-vps-shield.conf"
IPSET_PLUGIN="/usr/share/netfilter-persistent/plugins.d/05-ipset"
IPSET_RULES="/etc/iptables/ipsets.rules"
RAW_BASE="https://raw.githubusercontent.com/sb218-dev/vps-shield/main"

# Конфиги панелей, куда ядро внедряет L7-правила (для отката при uninstall)
L7_CONFIGS=(
    "/usr/local/x-ui/bin/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/xray/config.json"
    "/var/lib/marzban/xray-config.json"
    "/opt/mikan/config.yaml"
    "/etc/mihomo/config.yaml"
    "/etc/clash/config.yaml"
    "/root/.config/mihomo/config.yaml"
)

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

docker_detected() {
    ip link show 2>/dev/null | grep -qE 'docker0|br-[0-9a-f]+' || command -v docker >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# Установка ядра защиты vps-shield.sh (БЕЗ дублирования кода в менеджере).
# Приоритет источников:
#   1. $VPS_SHIELD_CORE_SRC (передаёт install.sh)
#   2. Файл рядом с менеджером (установка из git clone)
#   3. Уже установленный $SCRIPT_PATH (обновление одного менеджера)
#   4. GitHub raw (main)
# ------------------------------------------------------------------------------
install_core_script() {
    local src=""
    if [ -n "$VPS_SHIELD_CORE_SRC" ] && [ -f "$VPS_SHIELD_CORE_SRC" ]; then
        src="$VPS_SHIELD_CORE_SRC"
    else
        local dir
        dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
        [ -f "$dir/vps-shield.sh" ] && src="$dir/vps-shield.sh"
    fi

    if [ -n "$src" ]; then
        local src_abs
        src_abs="$(readlink -f "$src" 2>/dev/null || echo "$src")"
        if [ "$src_abs" = "$SCRIPT_PATH" ]; then
            echo -e "${GREEN}[ИНФО] Ядро защиты уже установлено: $SCRIPT_PATH${NC}"
        else
            echo -e "${GREEN}[ИНФО] Ядро защиты: копирование из $src_abs${NC}"
            cp "$src_abs" "$SCRIPT_PATH"
        fi
    else
        echo -e "${YELLOW}[ИНФО] Ядро защиты: загрузка из репозитория ($RAW_BASE)...${NC}"
        curl -sSL --connect-timeout 15 --retry 3 "$RAW_BASE/vps-shield.sh" -o "$SCRIPT_PATH"
    fi
    chmod +x "$SCRIPT_PATH"
}

# ------------------------------------------------------------------------------
# Плагин 05-ipset для netfilter-persistent.
# run-parts выполняет плагины в лексическом порядке: 05-ipset -> 15-ip4tables,
# поэтому наборы ipset гарантированно существуют к моменту iptables-restore.
# Это устраняет boot-race, при котором rules.v4 не грузился после перезагрузки.
# ------------------------------------------------------------------------------
install_ipset_plugin() {
    mkdir -p "$(dirname "$IPSET_PLUGIN")"
    cat << 'PLUGIN_EOF' > "$IPSET_PLUGIN"
#!/bin/sh
# 05-ipset: restore/save ipset sets for netfilter-persistent.
# Runs BEFORE 15-ip4tables (run-parts lexical order), so iptables-restore
# never fails with "Set ip_checkers doesn't exist".
IPSET_RULES="/etc/iptables/ipsets.rules"

case "$1" in
    start)
        [ -r "$IPSET_RULES" ] || exit 0
        ipset restore -exist < "$IPSET_RULES" 2>/dev/null || true
        ;;
    save)
        mkdir -p /etc/iptables
        ipset save > "$IPSET_RULES" 2>/dev/null || true
        ;;
esac

exit 0
PLUGIN_EOF
    chmod 755 "$IPSET_PLUGIN"
    echo -e "${GREEN}[ИНФО] Плагин 05-ipset установлен: $IPSET_PLUGIN${NC}"
}

install_shield() {
    check_root
    check_os

    echo -e "\n${CYAN}>>> [1/8] Подготовка репозиториев и установка системных пакетов...${NC}"
    # Бэкап источников apt перед sed-правками
    if [ -f /etc/apt/sources.list ]; then
        cp -p /etc/apt/sources.list "/etc/apt/sources.list.vps-shield.bak" 2>/dev/null || true
    fi
    sed -i '/cdrom:/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    sed -i 's/ru\.archive\.ubuntu\.com/archive.ubuntu.com/g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true

    export DEBIAN_FRONTEND=noninteractive
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true

    apt-get update -y
    apt-get install -y ipset iptables iptables-persistent netfilter-persistent curl dnsutils python3
    modprobe xt_string 2>/dev/null || true

    echo -e "\n${CYAN}>>> [2/8] Установка исполняемого скрипта ядра защиты ($SCRIPT_PATH)...${NC}"
    install_core_script

    echo -e "\n${CYAN}>>> [3/8] Настройка sysctl для персистентного отключения ICMP...${NC}"
    {
        echo "net.ipv4.icmp_echo_ignore_all = 1"
        # ip_forward нужен только серверам с Docker (NAT для контейнеров).
        # На чистых серверах системное значение не трогаем.
        if docker_detected; then
            echo "net.ipv4.ip_forward = 1"
        fi
    } > "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF" >/dev/null

    echo -e "\n${CYAN}>>> [4/8] Регистрация служб в systemd...${NC}"
    cat << EOF > "$SERVICE_PATH"
[Unit]
Description=VPS Shield Security & Anti-Leak Rules
# netfilter-persistent грузит сохранённые правила ДО нас; сервис пересобирает
# поверх них актуальные наборы (идемпотентно).
After=network.target network-online.target netfilter-persistent.service
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

    # Легаси-таймер vps-shield.timer из ранних версий запускал ядро ДОПОЛНИТЕЛЬНО
    # к vps-shield-update.timer — двойной ежедневный обрыв клиентских туннелей.
    if [ -e "$LEGACY_TIMER_PATH" ]; then
        echo -e "${YELLOW}[ИНФО] Обнаружен легаси-таймер vps-shield.timer — удаляю (двойной запуск).${NC}"
    fi
    systemctl stop vps-shield.timer 2>/dev/null || true
    systemctl disable vps-shield.timer 2>/dev/null || true
    rm -f "$LEGACY_TIMER_PATH"

    systemctl daemon-reload
    systemctl enable vps-shield.service >/dev/null 2>&1

    echo -e "\n${CYAN}>>> [5/8] Установка плагина ipset для netfilter-persistent...${NC}"
    install_ipset_plugin

    echo -e "\n${CYAN}>>> [6/8] Первичный запуск и инициализация правил защиты...${NC}"
    bash "$SCRIPT_PATH"

    echo -e "\n${CYAN}>>> [7/8] Сохранение правил в netfilter-persistent (iptables + ipset)...${NC}"
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4

    echo -e "\n${CYAN}>>> [8/8] Запуск таймера ежедневного автообновления...${NC}"
    systemctl enable --now vps-shield-update.timer >/dev/null 2>&1

    echo -e "\n${GREEN}====================================================${NC}"
    echo -e "${GREEN}[УСПЕХ] VPS Shield v1.4.1 успешно установлен и активен!${NC}"
    echo -e "${GREEN}====================================================${NC}"
    status_shield
}

uninstall_shield() {
    check_root
    echo -e "\n${YELLOW}====================================================${NC}"
    echo -e "${YELLOW}   УДАЛЕНИЕ VPS SHIELD И ВОССТАНОВЛЕНИЕ СИСТЕМЫ    ${NC}"
    echo -e "${YELLOW}====================================================${NC}"

    echo -e "\n${CYAN}[1/7] Отключение и удаление служб systemd...${NC}"
    systemctl stop vps-shield.service 2>/dev/null || true
    systemctl disable vps-shield.service 2>/dev/null || true
    systemctl stop vps-shield-update.timer 2>/dev/null || true
    systemctl disable vps-shield-update.timer 2>/dev/null || true
    systemctl stop vps-shield-update.service 2>/dev/null || true
    # Легаси-таймер ранних версий
    systemctl stop vps-shield.timer 2>/dev/null || true
    systemctl disable vps-shield.timer 2>/dev/null || true

    rm -f "$SERVICE_PATH" "$UPDATE_SERVICE_PATH" "$TIMER_PATH" "$LEGACY_TIMER_PATH"
    systemctl daemon-reload

    echo -e "${CYAN}[2/7] Удаление правил и цепочек iptables...${NC}"
    iptables -D INPUT -j VPS_SHIELD 2>/dev/null || true
    iptables -D OUTPUT -j VPS_SHIELD 2>/dev/null || true
    iptables -D FORWARD -j VPS_SHIELD 2>/dev/null || true
    iptables -F VPS_SHIELD 2>/dev/null || true
    iptables -F VPS_SHIELD_LOG 2>/dev/null || true
    iptables -X VPS_SHIELD 2>/dev/null || true
    iptables -X VPS_SHIELD_LOG 2>/dev/null || true

    echo -e "${CYAN}[3/7] Очистка и удаление таблиц ipset...${NC}"
    for s in $(ipset list -n 2>/dev/null | grep -E '^(ru_zone|ru_tmp|chk_tmp|ip_checkers)'); do
        ipset flush "$s" 2>/dev/null || true
        ipset destroy "$s" 2>/dev/null || true
    done

    echo -e "${CYAN}[4/7] Восстановление ICMP (Ping) в ядре sysctl...${NC}"
    rm -f "$SYSCTL_CONF"
    sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null

    echo -e "${CYAN}[5/7] Откат L7-правил в конфигах панелей (из бэкапов *.vps-shield.bak)...${NC}"
    local restored=0
    for cfg in "${L7_CONFIGS[@]}"; do
        if [ -f "$cfg.vps-shield.bak" ]; then
            mv "$cfg.vps-shield.bak" "$cfg"
            restored=$((restored + 1))
            echo -e "  ${GREEN}восстановлен: $cfg${NC}"
            case "$cfg" in
                *x-ui*|*xray*)
                    systemctl is-active --quiet x-ui && systemctl restart x-ui 2>/dev/null || true
                    systemctl is-active --quiet xray && systemctl restart xray 2>/dev/null || true
                    ;;
                *mikan*)
                    systemctl is-active --quiet mikan && systemctl restart mikan 2>/dev/null || true
                    ;;
                *mihomo*)
                    systemctl is-active --quiet mihomo && systemctl restart mihomo 2>/dev/null || true
                    ;;
                *clash*)
                    systemctl is-active --quiet clash && systemctl restart clash 2>/dev/null || true
                    ;;
            esac
        fi
    done
    if [ "$restored" -eq 0 ]; then
        echo -e "  бэкапов не найдено — нечего откатывать."
    fi

    echo -e "${CYAN}[6/7] Удаление плагина 05-ipset и сохранённых баз ipset...${NC}"
    rm -f "$IPSET_PLUGIN" "$IPSET_RULES"

    echo -e "${CYAN}[7/7] Удаление исполняемого файла и сохранение чистого состояния фаервола...${NC}"
    rm -f "$SCRIPT_PATH" /var/lock/vps-shield.lock
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
        echo -e " Блокировка утечек RU:    ${GREEN}[АКТИВНА]${NC}      (CIDR в базе: $ru_cnt, только --state NEW)"
    else
        echo -e " Блокировка утечек RU:    ${RED}[ОТКЛЮЧЕНА]${NC}"
    fi

    if ipset list ip_checkers >/dev/null 2>&1; then
        local chk_cnt
        chk_cnt=$(ipset list ip_checkers | grep -E -c '^[0-9]' || echo "0")
        echo -e " Блокировка IP-чекеров:    ${GREEN}[АКТИВНА]${NC}      (IP: $chk_cnt, канареечная защита /24 от shared CDN)"
    else
        echo -e " Блокировка IP-чекеров:    ${RED}[ОТКЛЮЧЕНА]${NC}"
    fi

    if iptables -n -L VPS_SHIELD >/dev/null 2>&1; then
        local rules_cnt
        rules_cnt=$(iptables -n -L VPS_SHIELD --line-numbers | grep -E -c '^[0-9]')
        echo -e " Фаервол (VPS_SHIELD):     ${GREEN}[АКТИВЕН]${NC}      (Всего правил: $rules_cnt)"
        echo -e " Фильтр BitTorrent L4:    ${GREEN}[АКТИВЕН]${NC}      (BEP15/03/DHT + точные сигнатуры + P2P-порты)"
        if iptables -n -L VPS_SHIELD_LOG >/dev/null 2>&1; then
            echo -e " Логирование дропов:      ${GREEN}[ВКЛЮЧЕНО]${NC}     (VPS_SHIELD_LOG; смотреть: journalctl -k | grep VPS_SHIELD)"
        else
            echo -e " Логирование дропов:      ${RED}[ОТКЛЮЧЕНО]${NC}"
        fi
    else
        echo -e " Фаервол (VPS_SHIELD):     ${RED}[НЕ АКТИВЕН]${NC}"
        echo -e " Фильтр BitTorrent L4:    ${RED}[НЕ АКТИВЕН]${NC}"
    fi

    echo -e " L7 DPI (Xray/Mihomo):     ${GREEN}[РЕСТАРТ ТОЛЬКО ПРИ ИЗМЕНЕНИИ КОНФИГА]${NC}"
    echo -e " DNS (порт 53):            ${GREEN}[ТОЛЬКО ДОВЕРЕННЫЕ РЕЗОЛВЕРЫ]${NC} (шлюз/системные/TRUSTED_DNS в /etc/vps-shield.conf)"
    echo -e " Подбор SNI (порт 443/80): ${GREEN}[РАЗРЕШЕН]${NC}      (Совместимость с Mikan / RealiTLScanner)"
    echo -e " Сети Docker & Мосты:      ${GREEN}[РАЗРЕШЕНЫ]${NC}     (docker0, br-*, veth*)"

    if [ -x "$IPSET_PLUGIN" ]; then
        echo -e " Плагин 05-ipset:          ${GREEN}[УСТАНОВЛЕН]${NC}     (ipset грузится до rules.v4 при загрузке)"
    else
        echo -e " Плагин 05-ipset:          ${RED}[ОТСУТСТВУЕТ]${NC}   (риск boot-race при перезагрузке!)"
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

    if [ -e "$LEGACY_TIMER_PATH" ]; then
        echo -e " Легаси-таймер:            ${RED}[ОБНАРУЖЕН]${NC}     (vps-shield.timer — переустановите: vps-shield-manager.sh install)"
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
