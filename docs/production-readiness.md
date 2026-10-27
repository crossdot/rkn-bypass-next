# Production-readiness: что считается готовым релизом

Чек-лист production-готовности. Собран по фактическому состоянию репозитория
(внешний план в `docs/` не переносился). Статусы: ✅ закрыто, 🟡 частично,
⬜ открыто (Phase 2/вне scope).

## Установка и развёртывание

| Пункт | Статус | Артефакт/примечание |
|---|---|---|
| Docker-образы сервера/клиента | ✅ | `deploy/docker/` (ADR-011): non-root, read-only, `cap_drop=ALL`, smoke |
| Нативные systemd-unit'ы + hardening | ✅ | `deploy/systemd/` (ADR-026), score 1.9/1.8 |
| nftables-правила | ✅ | `deploy/nftables/rkn-server.nft` (ручное применение) |
| Инструкция нативной установки | ✅ | `docs/operations/native-install.md` |
| `--check-config` (валидация env/cert/key/rules/clients) | ✅ | `rkn-server`/`rkn-client`; `install.sh` использует |
| Автоматизированная установка (пакеты) | 🟡 | `scripts/install.sh` + `--check-config`; deb/rpm — Phase 2 |
| RHEL/Fedora | ⬜ | Phase 2 (systemd/пакеты) |
| Установка/удаление на поддерживаемых дистрибутивах | 🟡 | Debian 12 + Ubuntu 22.04/24.04; удаление вручную (`systemctl disable --now`) |

## Релиз и эксплуатация (P10)

| Пункт | Статус | Артефакт/примечание |
|---|---|---|
| Артефакты релиза + checksums + SBOM | ✅ | `scripts/release.sh` (dist/, tarballs, SHA256SUMS) |
| Подпись бинарников (cosign keyless) | ✅ | `.github/workflows/release.yml` (sign-blob + verify) |
| Release process | ✅ | `docs/operations/release-process.md` |
| Staging + smoke | ✅ | `docs/operations/staging.md` (ручной) |
| Rollback | ✅ | `docs/operations/rollback.md` (`--force-env`, оба бинарника) |
| Backup/restore | ✅ | `docs/operations/backup-restore.md` (предупреждение о CA key) |
| Beta-процесс | ✅ | `docs/operations/beta.md` (без `--beta` флага) |
| Теги релизов | ✅ | новые — annotated (`vX.Y-name`); исторические lightweight |

## Безопасность и аутентификация

| Пункт | Статус | Примечание |
|---|---|---|
| mTLS per-client (ADR-021) | ✅ | клиентский сертификат обязателен |
| Отзыв/ротация ключей | ✅ | перезагрузка конфига (ADR-021); живой reload — Phase 2 |
| `max_sessions` (глобальный) | ✅ | ADR-023 §8 |
| Секреты без `Debug`/`Display` | ✅ | `crypto::Secret` |
| Hardening unit'а (systemd) | ✅ | `NoNewPrivileges`, `ProtectSystem=strict`, `SystemCallFilter`, caps |
| SBOM + подпись образов | ✅ | syft CycloneDX + cosign keyless (CI `docker-smoke`) |

## Транспорт и протокол

| Пункт | Статус | Примечание |
|---|---|---|
| TLS + QUIC, выбор транспорта | ✅ | ADR-023 (`TRANSPORT=auto`, TTL/backoff) |
| Холодный выбор: singleflight (1 проба на N) | ✅ | ADR-027 |
| Двунаправленный relay без дедлока | ✅ | ADR-025 |
| SOCKS5-режим (MVP) | ✅ | TCP CONNECT; UDP ASSOCIATE отклоняется |
| 0-RTT/session resumption | ✅ | отключено (ADR-021/ADR-022) |
| TUN | ⬜ | Phase 2 |
| Reality / Profile B артефакты (nginx, site-content) | ⬜ | README-only; Phase 2/опционально |

## Наблюдаемость и качество

| Пункт | Статус | Примечание |
|---|---|---|
| Аудит handshake/выбора транспорта | ✅ | key=value в journald (ADR-021/ADR-023) |
| Нагрузочные испытания (baseline) | ✅ | `docs/operations/load-testing.md` (P11) |
| Полный прогон 1000 / 1–4 ч | 🟡 | не выполнен; процедура — `load-testing-results/README.md` |
| CI: fmt/clippy/test/build | ✅ | job `check` |
| CI: e2e (tls/quic/auto/fallback) | ✅ | job `e2e` |
| CI: load-smoke | ✅ | job `load-smoke` |
| CI: systemd-hardening (score < 5.0) | ✅ | job `systemd-hardening` |
| CI: release на тег v* | ✅ | `release.yml` |
| Реальные замеры throughput на целевых сетях | 🟡 | localhost-only (P11); `scripts/field-test.sh` (P5.2) — ручной прогон на реальных сетях РФ |

## Известные ограничения / кандидаты

- **Cold-select `TransportManager::select()`** — **исправлено в ADR-027**
  (singleflight: 1 проба на N, `invalidate` при пробе побеждает, метрика
  `transport_acquire_wait_ms`). Гистерезис переключения не реализован —
  TTL+backoff достаточно для MVP; при необходимости ADR-028.
- **`deploy/profiles/*/README.md`** ссылаются на артефакты, которых нет
  (nginx/, site-content/ для Profile B). Для Profile A systemd/nft закрыты.
- **SELinux** (RHEL) не покрыт — Phase 2.

## Критерий «готово к production»

- ✅ Docker-путь (ADR-011) и ✅ нативный systemd-путь (ADR-026) работают.
- ✅ mTLS, отзыв, лимиты сессий, аудит.
- ✅ Релиз: артефакты+checksums+SBOM, подпись (cosign), staging/rollback/backup/beta.
- ✅ CI-гейты (check/e2e/load-smoke/systemd-hardening/docker/release).
- 🟡 «Автоматизированная установка» — частично (install.sh + ручной nft);
  пакеты — Phase 2.
