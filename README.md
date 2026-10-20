# 🛡️ VPS Shield

Комплексный модуль автоматической сетевой защиты, глубокой блокировки BitTorrent/P2P и предотвращения утечек трафика для серверов под управлением **Ubuntu 22.04 LTS и Ubuntu 24.04 LTS**.

Полная совместимость с популярными VPN/прокси-панелями: **[mikan](https://github.com/Miroshka000/mikan)** (на ядре mihomo / Docker), **3x-UI** (на ядре Xray), Marzban, а также протоколами VLESS-Reality, WireGuard, Shadowsocks, Hysteria 2 и TUIC.

---

## ⚡ Быстрая установка (One-Liner)

Для быстрой установки выполните на сервере под пользователем `root` (или через `sudo`):

```bash
curl -sSL https://raw.githubusercontent.com/sb218-dev/vps-shield/main/install.sh | sudo bash
```

Или вручную:

```bash
git clone https://github.com/sb218-dev/vps-shield.git
cd vps-shield
sudo chmod +x vps-shield-manager.sh
sudo ./vps-shield-manager.sh install
```

---

## 🚀 Основные возможности

| Функция | Реализация | Назначение |
| :--- | :--- | :--- |
| **Скрытие от сканеров (No ICMP)** | `net.ipv4.icmp_echo_ignore_all = 1` через `sysctl` + фильтр `iptables` | Сервер перестает отвечать на эхо-запросы (ping), снижая видимость в ботнетах и сканерах портов. |
| **Блокировка BitTorrent L4 (Kernel)** | BEP 15 (UDP tracker magic), BEP 03 (`\x13BitTorrent protocol`), DHT (`d1:q4:ping`, `d1:q9:get_peers`...), P2P-порты | Блокировка на уровне ядра Linux до правила `ESTABLISHED` — перехватывает запросы трекеров, пиров и DHT. |
| **Блокировка BitTorrent L7 (DPI)** | Автоматическая интеграция с Xray-core / 3x-UI (`protocol: bittorrent`, доменные списки трекеров) | Глубокий анализ пакетов на прикладном уровне внутри туннелей перед отправкой наружу. |
| **Поддержка подбора SNI (RealiTLScanner / Mikan)** | Белый список для исходящих портов 443 и 80 | Беспрепятственная работа сканеров маскировки REALITY (`mikan`, XTLS RealiTLScanner, подбор соседних доменов). |
| **Поддержка Docker & Mikan** | Белый список интерфейсов (`docker0`, `br-*`, `veth*`) и пулов `172.16.0.0/12` | Контейнеры панели Mikan и mihomo работают стабильно без разрывов сети. |
| **Блокировка IP-чекеров** | Динамический список `ipset` (Whoer, 2ip, IPinfo, icanhazip и др.) | Запрещает прямые исходящие запросы к чекерам геолокации и IP. |
| **Блокировка утечек в RU-сегмент** | Автоматическая выгрузка CIDR в `ipset` (hash:net, ~8 500+ подсетей) с фильтром `--state NEW` | Исключает исходящие фоновые утечки из ОС в сторону RU-зоны. При этом **входящие клиентские подключения из РФ НЕ блокируются**! |
| **Защита доступа (LAN / RFC 1918 / Шлюз)** | Белый список для `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, шлюза и DNS провайдера | Исключает случайную блокировку SSH, локальной консоли и панелей управления. |
| **Персистентность и автообновление** | Службы `systemd` + `vps-shield-update.timer` + `netfilter-persistent` | Настройки фаервола сохраняются после перезагрузки, а базы IP обновляются ежедневно. |

---

## 📋 Управление через `vps-shield-manager.sh`

Скрипт менеджмента устанавливается в системный путь `/usr/local/bin/vps-shield-manager.sh`.

### Проверка статуса

```bash
sudo vps-shield-manager.sh status
```

### Принудительное обновление списков IP

```bash
sudo vps-shield-manager.sh update
```

### Полное удаление (Uninstall)

```bash
sudo vps-shield-manager.sh uninstall
```

---

## 🛠️ Совместимость

- **Ubuntu 24.04 LTS (Noble Numbat)**
- **Ubuntu 22.04 LTS (Jammy Jellyfish)**
- Панели: **Mikan**, **3x-UI**, **Marzban**

---

## 📄 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
