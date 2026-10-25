# AGENTS.md

## Проект
Rust/Linux-система устойчивого обхода блокировок. Целевая среда: РФ.

## Обязательно прочитать перед любой задачей
@docs/requirements.md
@docs/adr/ADR-013-deployment-profiles.md
@docs/adr/ADR-016-wireguard-entry.md
@docs/development/optional-profiles.md

## Жёсткие правила
- Не добавлять Profile B-специфику (Reality, Fallbacks, nginx) в `transport-api` или `protocol`.
- Profile A должен собираться и работать без домена, сертификата и nginx.
- Политика выбора транспорта не переключает профиль автоматически.
- Не реализовывать собственную криптографию.
- Не логировать payload, credentials, ключи.

## Режимы клиента (три независимые оси)
- `mode`: `socks5` — MVP и обязательный; `tun` — Phase 2, в MVP его нет.
- `entry`: `none` — MVP по умолчанию; `wireguard` — MVP, опционально (AmneziaWG, не голый WireGuard).
- `profile`: `direct` — MVP; `camouflaged` — MVP, опциональный.

## SOCKS5
- SOCKS5 — полноценный режим MVP, не «только для контейнера».
- Не требует root, `NET_ADMIN`, не меняет маршруты и DNS хоста.
- Не смешивать код SOCKS5 и TUN в одном модуле без явной границы.
- UDP ASSOCIATE в MVP отклоняется с понятной ошибкой (без тихого fallback).

## TUN
- TUN — Phase 2. Не реализовывать в MVP.
- При упоминании TUN в коде или документации помечать как Phase 2.

## wireguard-entry
- `entry = wireguard` — это AmneziaWG, не голый WireGuard.
- Голый WireGuard в целевой среде не работает; не предлагать его как вариант.
- Рекомендуемая комбинация в MVP: `entry = wireguard` + `mode = socks5`.
- `entry = wireguard` + `mode = tun` откладывается вместе с TUN (Phase 2).
- Параметры обфускации AmneziaWG должны быть одинаковыми на обеих сторонах;
  при их отсутствии соединение падает молча.
- TCP/443-режим AmneziaWG обязателен для мобильных операторов РФ.
- Минимальная версия — AmneziaWG 3.1 (2.x несовместим с 3.1).

## Профили развёртывания
- A (Direct) — MVP, обязательный.
- B (Camouflaged entry) — MVP, опциональный.
- C (CDN-fronted) — только после ADR.
- D (Serverless) — исследовательский, не в MVP.
