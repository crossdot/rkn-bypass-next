# netcore-docs

Документация и опциональные артефакты для Rust/Linux-системы
устойчивого обхода сетевых блокировок (целевая среда: РФ).

## Что входит в MVP
- Режим клиента `mode = "socks5"` (обязательный).
- Опциональный режим `entry = "wireguard"` (AmneziaWG, точка входа для других устройств).
- Профили развёртывания A (Direct) и B (Camouflaged entry).
- TUN-режим — **Phase 2**, в MVP его нет.

## Структура
- `docs/requirements.md` — требования, целевая среда, режимы клиента, профили
- `docs/security/threat-model.md` — РФ-специфичные угрозы
- `docs/architecture/deployment-layers.md` — границы слоёв
- `docs/development/optional-profiles.md` — таблица осей и опциональных профилей
- `docs/adr/` — ADR-011 … ADR-016
- `deploy/profiles/` — артефакты по профилям
- `configs/` — примеры конфигураций
- `AGENTS.md` — правила для coding-агентов

## Быстрый старт для агентов
1. Прочитать `AGENTS.md`.
2. Прочитать `docs/requirements.md`.
3. Прочитать `docs/adr/ADR-013-deployment-profiles.md` и `ADR-016-wireguard-entry.md`.
4. Для задачи выбрать комбинацию `mode` × `entry` × `profile`.
5. Не добавлять Profile B-специфику в `transport-api` или `protocol`.
6. Не реализовывать TUN в MVP.
