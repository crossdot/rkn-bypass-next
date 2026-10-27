# Нативная установка (systemd) — ADR-026

Установка `rkn-server` / `rkn-client` на Linux без Docker. Целевые
дистрибутивы: **Debian 12**, **Ubuntu 22.04/24.04** (systemd ≥ 249).
RHEL/Fedora — Phase 2.

Артефакты: `deploy/systemd/*.service`, `deploy/systemd/*.env.example`,
`deploy/nftables/rkn-server.nft`, `scripts/install.sh`.

> Полный прогон на целевой ВМ (systemctl start + curl) — **вручную**.
> CI проверяет `systemd-analyze security --offline=true` (score < 5.0) и
> e2e через бинарники; установку unit'а CI не выполняет.

## 0. Сборка

```bash
cargo build --release --workspace
# бинарники: target/release/{server,client,admin-cli}
```

## 1. Сервер

### 1.1. Сертификаты (mTLS, ADR-021)

Нужны **CA + leaf**, не self-signed. Для dev можно взять `certs/dev-*`;
для production — ваш CA.

```bash
install -d -m 0750 -o root -g rkn /etc/netcore
install -m 0640 -o root -g rkn ca.crt     /etc/netcore/ca.crt
install -m 0640 -o root -g rkn server.crt /etc/netcore/server.crt
install -m 0640 -o root -g rkn server.key /etc/netcore/server.key
```

### 1.2. Реестр клиентов (admin-cli)

```bash
export CLIENTS_PATH=/etc/netcore/clients.toml
export CLIENTS_DIR=/etc/netcore/clients
./target/release/admin-cli client add alice
# приватный ключ клиента печатается в stdout — передать на устройство;
# cert: /etc/netcore/clients/alice.crt
```

`max_sessions` — это поле клиента в `clients.toml` (`[[clients]] max_sessions`),
**не env**. По умолчанию `null` (без лимита).

### 1.3. Адресные правила

`/etc/netcore/rules.toml`:

```toml
[server.address_rules]
allow_cidrs = ["203.0.113.0/24"]
deny_cidrs = []
allow_ports_low = [80, 443]
```

### 1.4. env

```bash
install -m 0640 -o root -g rkn \
  deploy/systemd/rkn-server.env.example /etc/netcore/server.env
# отредактировать: LISTEN_ADDR=0.0.0.0:443, TRANSPORT=auto,
# CERT_PATH/KEY_PATH/CA_PATH/RULES_PATH/CLIENTS_PATH
```

### 1.5. Установка

```bash
sudo scripts/install.sh --server
```

Скрипт: создаёт пользователя `rkn`, ставит бинарник в `/usr/local/bin/rkn-server`,
unit в `/etc/systemd/system/rkn-server.service`, env (если ещё нет),
копирует nftables в `/etc/nftables.d/` (не применяет), делает
`daemon-reload && enable --now`, печатает exposure score.

### 1.6. nftables (после проверки SSH!)

> **ВНИМАНИЕ:** `policy drop` может отрезать SSH. Сначала убедитесь, что
> доступ по SSH на разрешённом порту (по умолчанию 22/tcp) работает, затем:

```bash
nft -f /etc/nftables.d/rkn-server.nft
```

Авто-применение: `sudo scripts/install.sh --server --apply-nft --yes`
(по умолчанию выключено). Для сохранения между перезагрузками включите файл
в `/etc/nftables.conf` (дистрибутив-специфично).

### 1.7. Проверка

```bash
systemctl status rkn-server
journalctl -u rkn-server -n 50 --no-pager
systemd-analyze security rkn-server.service          # exposure < 5.0
systemd-analyze security --offline=true deploy/systemd/rkn-server.service
```

## 2. Клиент

### 2.1. Сертификаты

С клиентского устройства из `admin-cli client add` взять `alice.crt` +
приватный ключ; положить:

```bash
install -d -m 0750 -o root -g rkn /etc/netcore
install -m 0640 -o root -g rkn ca.crt     /etc/netcore/ca.crt
install -m 0640 -o root -g rkn alice.crt  /etc/netcore/client.crt
install -m 0600 -o root -g rkn alice.key  /etc/netcore/client.key
```

### 2.2. env

```bash
install -m 0640 -o root -g rkn \
  deploy/systemd/rkn-client.env.example /etc/netcore/client.env
# SERVER_ADDR=<IP сервера>:443; TRANSPORT=auto; пути к cert/key/ca
```

### 2.3. Установка и проверка

```bash
sudo scripts/install.sh --client
systemctl status rkn-client
# цель должна быть в allow_cidrs сервера:
curl -sS -o /dev/null -w '%{http_code}\n' --socks5 127.0.0.1:1080 http://<target>/
# ожидается 200
systemd-analyze security rkn-client.service          # exposure < 5.0
```

## 3. Hardening и диагностика

- Score: `rkn-server` 1.9, `rkn-client` 1.8 (`--offline=true`), цель < 5.0.
- **SIGSYS в journalctl** (фильтр сисколлов сломал бинарник):
  в unit заменить `SystemCallFilter=@system-service` на
  `SystemCallFilter=@system-service @network-io`; если не помогло —
  зафиксировать причину в ADR-026, не убирать молча.
- **Не резолвятся домены-цели** (SOCKS5 с hostname): добавить `AF_NETLINK`
  в `RestrictAddressFamilies` (AI_ADDRCONFIG) и отметить в ADR-026.
- **443 занят**: изменить `LISTEN_ADDR` (например, `0.0.0.0:8443`) и правило
  nftables; либо освободить порт.
- Логи — journald (`journalctl -u rkn-server`), формат key=value.
