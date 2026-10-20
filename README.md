# 🛡️ VPS Shield

Комплексный модуль автоматической сетевой безопасности, глубокой блокировки BitTorrent/P2P и предотвращения утечек трафика для серверов под управлением **Ubuntu 22.04 LTS и Ubuntu 24.04 LTS**.

Полная совместимость с популярными VPN/прокси-панелями: **[mikan](https://github.com/Miroshka000/mikan)** (на ядре mihomo / Docker), **3x-UI** (на ядре Xray), Marzban, Hiddify, а также протоколами VLESS-Reality, WireGuard, Shadowsocks, Hysteria 2 и TUIC.

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
| **Блокировка BitTorrent L4 (Kernel)** | BEP 15 (UDP tracker magic), BEP 03 (`\x13BitTorrent protocol`), DHT Kademlia (`d1:ad2:id`, `q9:get_peers`, `1:rd2:id`...), LSD (`239.255.255.250:6771`), P2P-порты (6881:6889, 51413, 6969, 1337, 2710) | Полная блокировка пиров, трекеров и децентрализованной сети DHT на уровне ядра Linux (qBittorrent, uTorrent, Transmission, aria2). |
| **Блокировка BitTorrent L7 (DPI)** | Авто-интеграция с Xray-core / 3x-UI (`protocol: bittorrent`, `geosite:torrent`) и Mihomo / Mikan (`GEOSITE,torrent,REJECT`) | Глубокий анализ пакетов на прикладном уровне внутри туннелей перед отправкой наружу. |
| **Корректная изоляция Docker & NAT** | Фильтрация исходящего трафика контейнеров в интернет с сохранением локального межконтейнерного взаимодействия | Исходящий трафик из контейнеров Docker (панель Mikan, mihomo) проходит полную инспекцию фаервола. |
| **Поддержка подбора SNI (RealiTLScanner / Mikan)** | Разрешение TLS 1.3 / h2 проверок соседей на порту 443 | Беспрепятственная работа сканеров маскировки REALITY (`mikan`, XTLS RealiTLScanner, подбор соседних доменов). |
| **Блокировка IP-чекеров** | Динамический список `ipset` (Whoer, 2ip, IPinfo, icanhazip и др.) | Запрещает прямые исходящие запросы к чекерам геолокации и IP. |
| **Блокировка утечек в RU-сегмент** | Автоматическая выгрузка CIDR в `ipset` (hash:net, ~8 500+ подсетей) с фильтром `--state NEW` | Исключает исходящие фоновые утечки из ОС в сторону RU-зоны. При этом **входящие клиентские подключения из РФ НЕ блокируются**! |
| **Защита доступа (LAN / RFC 1918 / Шлюз)** | Правила `src+dst` для `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, шлюза и DNS провайдера | Исключает случайную блокировку SSH, локальной консоли и панелей управления даже на облачных серверах с серыми IP (1:1 NAT). |
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
- Панели: **Mikan**, **3x-UI**, **Marzban**, **Hiddify**
- Протоколы: **VLESS-Reality**, **WireGuard**, **Shadowsocks**, **Hysteria 2**, **TUIC**, **Trojan**

---

## 📄 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
