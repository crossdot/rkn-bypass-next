# Field testing (P5.2): реальные сети РФ

Проверка, какие транспорты (TLS / QUIC) живут или блокируются в целевой
среде РФ (ТСПУ, DPI-сигнатуры, NSDI, «белые списки» на мобильных сетях).
Прогон — **вручную владельцем проекта на реальных сим-картах/сетях**,
**не в CI**. CI проверяет только `field-test.sh --dry-run` (валидация
аргументов и печать плана; см. `.github/workflows/ci.yml`, шаг
`field-test dry-run (P5.2)`).

Инструменты в `scripts/`:
- `field-test.sh` — полевой стенд: `diag-cli check --json` (этапы
  connect/handshake/data/socks5) + `load.sh --remote` (auto/tls/quic) +
  curl на реальные сайты. Пишет CSV (26 колонок) на сценарий.
- `load.sh --remote` — полевой режим: клиент стартует локально, идёт на
  удалённый сервер с реальным mTLS и гонит трафик на `--target`.
- `diag-cli check --json` — однострочный JSON со стадиями и классами
  отказа (для машинного парсинга CSV).

## Матрица сетей (M1–M6, R, H1–H3, C)

Матрица — набор сетей/доступов, на каждой из которых прогоняется
`field-test.sh` (6 сценариев на сеть, см. ниже). Конкретные операторы и
регионы владелец заполняет фактические; метки — проектная группировка.

| Метка | Тип | Доступ | Пример (заполняется владельцем) |
|---|---|---|---|
| M1 | Мобильная | 4G | МТС |
| M2 | Мобильная | 5G | МТС |
| M3 | Мобильная | 4G | Мегафон |
| M4 | Мобильная | 4G | Билайн |
| M5 | Мобильная | 4G | Tele2 |
| M6 | Мобильная | 5G | Мегафон |
| R | Роуминг | 4G/5G | Зарубежная сеть (контроль: вне зоны ТСПУ РФ) |
| H1 | Домашняя | Wi-Fi/оптика | Ростелеком |
| H2 | Домашняя | Wi-Fi/оптика | МГТС |
| H3 | Домашняя | Wi-Fi | Дом. роутер / др. провайдер |
| C | Корпоративная | Ethernet/Wi-Fi | Офис |

Для каждой сети также фиксируются метаданные: `operator`, `region`,
`access` (4g/5g/wifi/ethernet), `device` (android/ios/laptop/desktop),
`timestamp` — они попадают в первые 5 колонок CSV.

## Сценарии (6 на сеть)

`field-test.sh` прогоняет на сети 6 сценариев:

1. `diag TLS` — `diag-cli check --transport tls --json`.
2. `diag QUIC` — `diag-cli check --transport quic --json`.
3. `load auto` — `load.sh --remote --transport auto` (политика выбора,
   ADR-023).
4. `load TLS` — `load.sh --remote --transport tls`.
5. `load QUIC` — `load.sh --remote --transport quic`.
6. `curl` на реальный сайт (relay end-to-end, `--transport tls`).

CSV-строка пишется на каждый сценарий (см. схему ниже); «все сценарии
одной сети складываются в один CSV-файл сети».

## Классификация отказа

`diag-cli --json` сопоставляет класс отказа с reason-enum политики выбора
(ADR-023), чтобы CSV не требовал маппинга:

| Класс | Симптом | Что делать |
|---|---|---|
| `tls_refused` | Сервер недоступен/отказал на TCP+TLS-хендшейке | Проверить сервер, что он поднят и слушает TLS |
| `udp_filtered` | UDP-пакеты (QUIC) не доходят до сервера | `TRANSPORT_PREFERRED=tls` для этой сети |
| `server_unreachable` | Сервер не отвечает (TCP/UDP) | Проверить сервер/сеть; для `auto` → `all_failed_default` |
| `handshake` | TLS/QUIC-хендшейк падает после connect | Проверить сертификаты/`max_sessions`/mTLS |
| `data_path` | Ping/Pong (1 байт) не доходит | Проверить relay/backpressure (ADR-025) |

Ключевое различие для РФ: **`udp_filtered` ≠ `server_unreachable`**.
`udp_filtered` — UDP блокируется (QUIC мёртв, но TCP возможен) → идти на
`TRANSPORT_PREFERRED=tls`. `server_unreachable` — сервер недоступен вообще
(проблема сервера/сети, а не DPI) → проверять сервер, не менять политику.

## Процедура при отказе

1. `diag-cli check <host>:<port> --json` → посмотреть, какой этап упал и
   какой класс.
2. `server_unreachable` → проверить, что удалённый сервер поднят
   (`systemctl status rkn-server`), порт открыт, сеть дотягивается.
3. `udp_filtered` → QUIC блокируется на этой сети → зафиксировать
   `TRANSPORT_PREFERRED=tls` (это ожидаемое поведение в РФ, не баг).
4. `all_failed_default` + `server_unreachable` → политика вернула `preferred`
   после тотального отказа (ADR-023). Зафиксировать, **не чинить** — это
   осознанное поведение.
5. Отклонения/обходы не «подкручивать» в конфиге против DPI в обход
   правил; писать в `TEMPLATE.md`.
6. Любой «работает там, где ждали блокировку» — **finding**, не ошибка,
   вносить в findings.

## CSV-схема (26 колонок)

Первые 5 колонок — метаданные сети; остальные — результаты сценария.
Значения по сценарию: `diag_*` заполняются только для diag-сценариев,
`requests/errors/...` — только для load-сценариев; незаполненные поля
пустые (`,,`).

```text
operator,region,access,device,timestamp,
scenario,transport,requests,errors,req_s,
probe_ok,cached_ok,udp_filtered,tls_refused,server_unreachable,
all_failed_default,fallback_prev_failed,transport_selected,
p50,p95,p99,
diag_connect,diag_handshake,diag_data,diag_socks5,note
```

- `scenario` — `diag_tls|diag_quic|load_auto|load_tls|load_quic|curl`.
- `transport` — запрошенный транспорт (`tls|quic|auto`).
- `transport_selected` — фактически выбранный (из SUMMARY `transports=`).
- `p50/p95/p99` — латентность load-сценария, сек.
- `diag_*` — класс/статус этапа (`ok|skipped|<класс>`).

Файл: `docs/operations/field-testing-results/<operator>-<region>-<date>/<operator>-<region>-<date>.csv`.

## Предупреждения

- **Сим-карты/реальные сети** — только владелец, вручную; не CI.
- Доступ на мобильных операторах может быть «белым списком»: часть сайтов
  (особенно не-RU) недоступна вообще — это ограничение оператора, не поля.
- `allow_cidrs` в адресных правилах должен включать реальный IP/сеть
  сервера; loopback в `HARDCODED_DENY` — не использовать как цель.
- QUIC 0-RTT в проекте **отключён** (ADR-022); на реальной сети могут
  наблюдаться более высокие задержки первого соединения (полный handshake
  + mTLS), это не регрессия.
- UDP может быть заблокирован на некоторых операторах; это ожидаемо и
  значит только «на этой сети предпочесть TLS».

## Выходные артефакты

- `docs/operations/field-testing-results/CHECKLIST.md` — пошаговый чек-лист.
- `docs/operations/field-testing-results/TEMPLATE.md` — шаблон сводки
  (матрица «какой транспорт живёт» + `TRANSPORT_PREFERRED` + findings).
- CSV на каждую сеть в `field-testing-results/<operator>-<region>-<date>/`.
