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
| Автоматизированная установка (пакеты) | 🟡 | `scripts/install.sh` есть; deb/rpm — Phase 2 |
| RHEL/Fedora | ⬜ | Phase 2 (systemd/пакеты) |
| Установка/удаление на поддерживаемых дистрибутивах | 🟡 | Debian 12 + Ubuntu 22.04/24.04; удаление — вручную (`systemctl disable --now`, удалить unit/бинарник) |

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
| Реальные замеры throughput на целевых сетях | ⬜ | localhost-only (P11); нужны полевые замеры |

## Известные ограничения / кандидаты

- **Cold-select `TransportManager::select()`** (P11): Mutex удерживается через
  `probe().await`, худший cold ≈ 4 с; на localhost не проявляется. Кандидат на
  **ADR-027** (singleflight / release-lock-before-probe), не блокер.
- **`deploy/profiles/*/README.md`** ссылаются на артефакты, которых нет
  (nginx/, site-content/ для Profile B). Для Profile A systemd/nft закрыты.
- **SELinux** (RHEL) не покрыт — Phase 2.

## Критерий «готово к production»

- ✅ Docker-путь (ADR-011) и ✅ нативный systemd-путь (ADR-026) работают.
- ✅ mTLS, отзыв, лимиты сессий, аудит.
- ✅ CI-гейты (check/e2e/load-smoke/systemd-hardening/docker).
- 🟡 «Автоматизированная установка» — частично (install.sh + ручной nft);
  пакеты — Phase 2.
