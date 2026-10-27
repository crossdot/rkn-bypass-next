# Staging (P10)

Развёртывание релизного тега на staging-VM и smoke. Автоматизация в CI **не
делается** (нет VM в GitHub Actions) — процедура ручная.

## 1. Подготовка staging-VM

- Debian 12 / Ubuntu 22.04/24.04, systemd ≥ 249, root/sudo.
- Отдельные сертификаты/клиенты от production.

## 2. Развернуть тег

```bash
git fetch --tags
git checkout vX.Y-name
cargo build --release --locked --workspace
sudo scripts/install.sh --server          # сервер (см. native-install.md)
# на staging-клиенте:
sudo scripts/install.sh --client
```

Конфигурация — по [`native-install.md`](native-install.md): сертификаты
(CA+leaf), `clients.toml`, `rules.toml`, `server.env`/`client.env`.

## 3. Smoke

```bash
# сервер
systemctl status rkn-server
journalctl -u rkn-server -n 100 --no-pager     # нет ошибок/SIGSYS
systemd-analyze security --offline=true deploy/systemd/rkn-server.service

# клиент → цель (цель должна быть в allow_cidrs сервера)
curl -sS -o /dev/null -w '%{http_code}\n' --socks5 127.0.0.1:1080 http://<target>/
# ожидается 200
```

Проверки:
- `systemctl is-active rkn-server` = active;
- `journalctl` без `SIGSYS` (иначе — fallback `SystemCallFilter`, ADR-026 §6);
- e2e → `200`;
- `systemd-analyze security` exposure < 5.0.

## 4. После smoke

- Зафиксировать результат в release-notes/тикете.
- При успехе — тег уже стоит (релиз); при проблеме — откат
  ([`rollback.md`](rollback.md)).
