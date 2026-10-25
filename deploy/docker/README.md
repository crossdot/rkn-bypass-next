# Docker-артефакты

- `Dockerfile.client` — клиент (SOCKS5, non-root, slim).
- `Dockerfile.server-direct` — сервер Profile A (Direct), non-root, slim.
- `Dockerfile.server-camouflaged` — Profile B (Reality + nginx) — Phase 2/опционально.
- `smoke-test.sh` — сборка образов + сквозной smoke-тест (см. ADR-011).
- `docker-compose.dev.yml`, `docker-compose.test.yml` — будущие артефакты.

См. ADR-011 и ADR-012.

## Конфигурация (env)

Сервер: `LISTEN_ADDR`, `CERT_PATH`, `KEY_PATH`, `CA_PATH`, `RULES_PATH`,
`CLIENTS_PATH` (реестр клиентов mTLS, ADR-021).
Клиент: `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`, `CLIENT_CERT`, `CLIENT_KEY`.

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

## Подпись и SBOM (ADR-011 п.10)

Реализация (job `docker-smoke`): SBOM — **syft** в формате **CycloneDX JSON**;
подпись — **cosign** в режиме **keyless** (OIDC GitHub Actions).

- **syft** (не trivy) — purpose-built генератор SBOM, лёгкий и быстрый.
- **CycloneDX** (не SPDX) — de-facto стандарт для security-контекста
  (читается grype/trivy/dependency-track).
- **keyless** (не ключ из CI-secrets) — без долгоживущих секретов; проверка
  через OIDC-идентичность GitHub Actions (`id-token: write`).

SBOM-файлы — `rkn-server-sha256-<hash>.cdx.json`,
`rkn-client-sha256-<hash>.cdx.json` (имя содержит digest образа, `:` заменён
на `-`). Доступны как GitHub Actions artifacts (job `docker-smoke`). Smoke
падает, если подпись невалидна или SBOM пуст.

`upload-artifact@v4` не допускает `:` в именах файлов, поэтому digest в имени
файла санитизирован (`:` → `-`); digest в `cosign sign`/`verify` остаётся в
формате `sha256:<hash>`.

### Локальная проверка подписи

Образы подписываются **только из `master`**: подпись и публикация выполняются
на push в `master` и на ручной запуск `workflow_dispatch` с ветки `master`;
запуск с других веток ничего не пушит и не подписывает. Verify в CI и
локально привязан к `refs/heads/master`.

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/crossdot/rkn-bypass-next/.github/workflows/ci.yml@refs/heads/master$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/crossdot/rkn-bypass-next/rkn-server@sha256:<digest>
```

### Где скачать SBOM

SBOM (CycloneDX JSON) публикуется как артефакт **только для master-сборок**
(push и `workflow_dispatch` с `master`). На `pull_request` SBOM в артефакты
не выгружается, так как PR-образы не публикуются.

Actions → последний run → job `docker-smoke` → Artifacts → `sbom`
(`rkn-server-sha256-<hash>.cdx.json`, `rkn-client-sha256-<hash>.cdx.json`).

Локальная генерация (по digest из registry):

```bash
syft ghcr.io/crossdot/rkn-bypass-next/rkn-server@sha256:<hash> -o cyclonedx-json > rkn-server-sha256-<hash>.cdx.json
```

### Ручной перезапуск

Пересобрать и переподписать вручную (с ветки master):

```bash
gh workflow run ci.yml --ref master
# или Actions → CI → Run workflow → ветка master
```

Связь с ADR-011 п.10: подпись + SBOM — обязательные артефакты релиза (не
опция); производственные образы не публикуются без подписи и SBOM.
