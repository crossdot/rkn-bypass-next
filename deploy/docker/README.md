# Docker-артефакты

- `Dockerfile.client` — клиент (SOCKS5, non-root, slim).
- `Dockerfile.server-direct` — сервер Profile A (Direct), non-root, slim.
- `Dockerfile.server-camouflaged` — Profile B (Reality + nginx) — Phase 2/опционально.
- `smoke-test.sh` — сборка образов + сквозной smoke-тест (см. ADR-011).
- `docker-compose.dev.yml`, `docker-compose.test.yml` — будущие артефакты.

См. ADR-011 и ADR-012.

## Конфигурация (env)

Сервер: `LISTEN_ADDR`, `CERT_PATH`, `KEY_PATH`, `CA_PATH`, `RULES_PATH`.
Клиент: `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`.

Сертификаты и ключи передаются через volume/secrets, не в образе и не в `ENV`
(ADR-011). Для smoke-теста используются dev-сертификаты из `certs/`.

## Smoke-тест

```bash
bash deploy/docker/smoke-test.sh
```

1. Собирает `rkn-server:test` и `rkn-client:test`.
2. Поднимает сервер (read-only, non-root, cap_drop=ALL), клиент и HTTP-цель.
3. Проверяет: blocked-адрес (127.0.0.1) → REP `0x02`; relay к цели → HTTP 200.

Клиент с `entry = wireguard` требует проброса порта (UDP/TCP 51820 или 443)
и не входит в минимальный smoke-тест (ADR-016).
