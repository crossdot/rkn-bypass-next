# Rollback (P10)

Откат на предыдущий релиз. Миграций нет: `clients.toml` и env — аддитивны
(лишние/новые ключи старые бинарники игнорируют; `deny_unknown_fields` нет).

## 1. Откатить ОБА бинарника (server + client)

```bash
git fetch --tags
git checkout vPREV        # предыдущий тег
cargo build --release --locked --workspace

# на сервере:
sudo scripts/install.sh --server --force-env
# на клиенте:
sudo scripts/install.sh --client --force-env
```

**Почему оба:** wire-формат `Ping/Pong` (0x04/0x05) добавлен после `v0.3-sync`
(проба транспорта). Если откатить только сервер, новый клиент шлёт `Ping`, а
старый сервер отвечает `UnknownMessageKind` → проба падает. Откат только
клиента — аналогично. Всегда откатывайте server+client из одного тега.

## 2. `--force-env`

`install.sh` по умолчанию env **не перезаписывает** (защита production-настроек).
Для отката нужен `--force-env`: он копирует env-пример из тега.

**Внимание:** `--force-env` перезаписывает `/etc/netcore/server.env` /
`client.env` — кастомные правки (порты, пути, `TRANSPORT_*`) будут потеряны.
Перед откатом сохраните текущий env (см. [`backup-restore.md`](backup-restore.md)).

## 3. Проверка после отката

```bash
systemctl status rkn-server rkn-client
journalctl -u rkn-server -n 50 --no-pager     # без ошибок/SIGSYS
curl -sS -o /dev/null -w '%{http_code}\n' --socks5 127.0.0.1:1080 http://<target>/
# 200
```

## 4. Совместимость

- **env:** новые ключи (`TRANSPORT*` и т.п.) старые версии игнорируют; при
  необходимости задайте `TRANSPORT=tls|quic` явно (старая версия без `auto`).
- **clients.toml:** `max_sessions` — аддитивное поле; старые версии его
  игнорируют (без enforcement), ошибки парсинга нет.
- **Wire:** см. §1 — откатывать обе стороны.
- **Сертификаты:** не меняются между релизами (если CA тот же).
