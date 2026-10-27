# Backup и restore (P10)

## Что бэкапить

`/etc/netcore/` целиком:

| Файл | Почему критично |
|---|---|
| **CA private key** (в dev — `certs/dev-ca.key`; в production — ваш CA key) | **потеря = перевыпуск всех клиентских сертификатов** |
| `ca.crt`, `server.crt`, `server.key` | mTLS-сервер (ADR-021) |
| `clients/<id>.crt` + выданные приватные ключи | идентичность клиентов |
| `clients.toml` | реестр клиентов, `max_sessions`, `revoked` |
| `server.env`, `client.env` | конфигурация (порты, пути, `TRANSPORT*`) |
| `rules.toml` | адресные правила (allow/deny) |

Остальное (бинарники, unit, nft) восстанавливается из тега.

## Как (шифрование)

Локально есть **gpg** (age — опционально, если установлен):

```bash
tar czf - /etc/netcore | gpg -c > "backup-$(date +%F).tar.gz.gpg"
```

- Пароль/ключ gpg — **вне сервера** (менеджер секретов/офлайн).
- Хранить бэкап **вне сервера** (другой хост/хранилище), не рядом с CA key.
- Периодичность: после каждого изменения `clients.toml`/cert/env/rules и перед
  апгрейдом/откатом.

## Restore

```bash
gpg -d backup-YYYY-MM-DD.tar.gz.gpg | tar xzf - -C /
# права:
chown -R root:rkn /etc/netcore
chmod 0750 /etc/netcore
chmod 0640 /etc/netcore/*.crt /etc/netcore/*.env /etc/netcore/rules.toml /etc/netcore/clients.toml
chmod 0600 /etc/netcore/*.key
# проверка и перезапуск:
sudo /usr/local/bin/rkn-server --check-config /etc/netcore/server.env
sudo systemctl restart rkn-server
```

## Dev vs production CA key

- `certs/dev-ca.key` — **dev-only**: тестовые/демо-сертификаты
  (`docs/development/dev-certificates.md`). **Не использовать в production.**
- Production CA key генерируется **отдельно** (openssl/CA), **никогда не
  коммитится** в git и хранится **только** на сервере + в шифрованном бэкапе.

## Предупреждение

**Потеря CA private key = перевыпуск всех клиентских сертификатов** (старые
клиенты перестают проходить mTLS). Восстановление возможно только из бэкапа
CA key; иначе — новый CA, новые leaf-сертификаты, `admin-cli client add` для
всех клиентов и перевыпуск их ключей. Держите CA key в бэкапе **и** офлайн.
