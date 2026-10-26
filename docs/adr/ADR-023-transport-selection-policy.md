# ADR-023: Политика выбора транспорта (P5.3)

## Статус: Принято

## Контекст
После P4b есть два транспорта — TLS (TCP/443) и QUIC (UDP/443) — но выбор
ручной: `transport = "tls" | "quic"`. В целевой среде РФ UDP на мобильных
сетях часто блокируется (ADR-022), поэтому ручной выбор означает либо
неработающий QUIC, либо отказ от QUIC там, где он проходит.

Нужна детерминированная политика: проверка доступности, fallback, backoff,
кэш результатов и диагностика причины выбора. Без ML и без выбора по
задержке.

## Решение

### 1. Компонент
Крейт `transport-manager`: `TransportManager` (политика + состояние),
`Probe` (проверка доступности, в тестах подменяется), `TransportProbe`
(реальная проба). `crates/transport-manager` не знает о конкретных
приложениях; `apps/client` создаёт один `Arc<TransportManager>` и берёт
транспорт на каждое соединение.

### 2. Стратегия по умолчанию — `auto`, TLS-first, serial
Порядок фиксирован: `[preferred, other]`, `preferred = tls` по умолчанию.
`TRANSPORT_PREFERRED=quic` меняет порядок на обратный.

Обоснование (RTT РФ↔EU ≈ 25–50 мс):

| Стратегия | Успех основного | Провал основного |
|---|---|---|
| TLS-first | 2 RTT ≈ 50–100 мс (TCP + TLS1.3) + проба | TCP RST — быстро (<1 RTT) |
| QUIC-first | 1 RTT ≈ 25–50 мс + проба | UDP blackhole — ждать `probe_timeout` |

Провал QUIC на мобильных стоит полного таймаута (UDP-«чёрная дыра» не даёт
RST), провал TLS — дёшев. Поэтому TLS-first; QUIC-first — явный выбор
(`preferred=quic`) для сетей, где UDP проходит.

Race (оба параллельно) отклонён: требует, чтобы сервер слушал оба
транспорта одновременно, и даёт 2× handshake, 2× mTLS-аудит и 2× сессии.

### 3. Критерий «транспорт работает» — передача данных
`connect → mTLS → session → Ping → Pong → close`. Handshake недостаточно:
у QUIC `connect` не открывает bi-stream, а отозванный клиент должен
отсекаться до пробы. Проба идёт через полный серверный путь (mTLS →
session-limit → прикладной слой), поэтому обход `verify_client_cert` /
аудита невозможен (ADR-021).

Протокол: `MessageKind::Ping = 0x04`, `Pong = 0x05`, payload 1 байт,
сервер эхом возвращает payload и закрывает соединение. См. ADR-020
(дополнение «Ping/Pong»).

После записи `Pong` сервер не рвёт соединение сразу, а ждёт закрытия
клиентом (не дольше 1 с): у QUIC закрытие конкурирует с доставкой только что
записанного STREAM-фрейма, и клиент иначе получает «connection lost» вместо
`Pong`. Для TLS это просто чтение до EOF.

Известное ограничение: проба занимает слот `max_sessions` на время
round-trip. Для MVP приемлемо; отдельного «дешёвого» канала нет.

### 3a. Задержка пробы и закрытие QUIC
`probe_*_ms` — полное время пробы, включая закрытие соединения.
До исправления `QuicClientTransport::close` вызывал `Endpoint::wait_idle()`
синхронно: дренирование после `CONNECTION_CLOSE` (≈3×PTO) добавляло
**~90 мс** к каждой пробе (`close_ms=87–91` при `connect_ms=2`, `data_ms=0`).
Теперь `close()` только инициирует закрытие и передаёт клон endpoint
фоновой задаче, которая дождётся idle и отпустит сокет; вызывающий не
блокируется. Замер на loopback: `probe_quic_ms=4` в 10/10 прогонов.
Компонентные тайминги пишутся на `debug` (`probe timings`: `factory_ms`,
`connect_ms`, `data_ms`, `close_ms`).

### 3b. Back-compat и rolling upgrade
- Новый клиент (`auto`) → старый сервер (без `Ping/Pong`): проба TLS получает
  закрытие соединения вместо `Pong` (`DataPath`), проба QUIC не проходит →
  `all_failed_default = preferred (tls)`; обычный `CONNECT` продолжает
  работать. Проверено `crates/transport-manager/tests/rolling_upgrade.rs`
  (фейковый «старый» сервер отвечает только на `Connect`).
- Старый клиент → новый сервер: `Connect`/`ConnectAck` не менялись, `Ping`
  старый клиент не отправляет — поведение прежнее.
- Рекомендуемый порядок обновления — **сервер первым**. Обратный порядок
  работоспособен, но первое соединение (и каждое после истечения backoff)
  платит неудачную пробу TLS + `probe_timeout` на QUIC до
  `all_failed_default`.
- Старые и новые peer'ы сосуществуют; несовместимость протокола не
  возникает (неизвестный kind по-прежнему отвергается, ADR-020).

### 4. TTL и backoff (явные пороги)
- Успех: `ttl = 300 с` — в пределах TTL проба не повторяется.
- Неудача: backoff `min(1s · 2^(n-1), fail_ttl)` при `n` подряд идущих
  неудачах; `fail_ttl = 30 с` — потолок и negative-TTL.
- `max_probe_attempts = 1` — одна попытка на кандидата за цикл выбора.
- Задержка пробы **только логируется** и не участвует в выборе: переключение
  из-за «скачка задержки» невозможно by design.
- Все кандидаты недоступны → возвращается `preferred` с причиной
  `all_failed_default`. **Не** «последний успешный»: иначе при флапе обоих
  транспортов выбор осциллирует.

### 5. При блокировке UDP
QUIC timeout классифицируется проверкой TCP до того же `host:port`:
- TCP доступен, QUIC не прошёл → `udp_filtered` (UDP фильтруется);
- TCP отвергнут → `server_unreachable`;
- TLS: TCP отвергнут → `tls_refused`; TCP доступен, handshake упал →
  `fallback_prev_failed` (уточнение только в `transport_state`).

При `udp_filtered` fallback на TLS немедленный, без повторных попыток QUIC
в этом цикле.

### 6. Диагностика
Одно событие на решение + одно на смену состояния (structured `key=value`,
как `event=mtls_handshake`):

```
event=transport_selected transport=tls reason=udp_filtered strategy=auto
  preferred=quic fallback_from=quic probe_tls_ms=62 probe_quic_ms=1000
  cached_age_s=0 fail_count=1
event=transport_state transport=quic state=unavailable reason=udp_filtered
  fail_count=1 until_s=1
```

`reason` — закрытый enum: `cached_ok | probe_ok | fallback_prev_failed |
udp_filtered | tls_refused | server_unreachable | all_failed_default | manual`.
Уровни: `cached_ok`/`probe_ok`/`manual` → INFO; fallback и отказ → WARN.
Чтение: `journalctl -u rkn-client | grep 'event=transport_selected'`.

### 7. Конфигурация (минимальная)
Env (у клиента нет TOML-конфига):

| Переменная | Дефолт | Смысл |
|---|---|---|
| `TRANSPORT` | `auto` | `auto` \| `tls` \| `quic` |
| `TRANSPORT_PREFERRED` | `tls` | первый транспорт в `auto` |
| `TRANSPORT_PROBE_TIMEOUT_MS` | `2000` | таймаут connect и Ping/Pong |
| `TRANSPORT_TTL_S` | `300` | TTL успешного результата |
| `TRANSPORT_FAIL_TTL_S` | `30` | потолок backoff |
| `TRANSPORT_PROBE_ATTEMPTS` | `1` | попыток на кандидата за цикл |

`strategy = tls|quic` — ручной режим: транспорт фиксирован, пробы и кэш не
используются (`reason=manual`). `auto` работает без настройки.

### 8. Сервер: dual-listen
`TRANSPORT=auto` (дефолт сервера) — TLS на TCP и QUIC на UDP по одному
адресу. `inner`-верификатор цепочки, реестр клиентов, `SessionManager` и
адресные правила общие для обоих циклов: `max_sessions` считается глобально,
аудит идёт в один subscriber. QUIC-верификатор по-прежнему один на Endpoint
(ADR-022) и строится из того же `inner` — состояния не расходятся.
`TRANSPORT=tls|quic` оставляет прежнее поведение (один транспорт).

### 9. diag-cli
Использует тот же `transport-manager` (без subprocess и без дублирования).
Исправлены два бага: mTLS-конфиг (был `with_no_client_auth`, из-за чего
проверка не проходила против текущего сервера) и фиктивный этап `relay`
(ставился OK без единого байта). Этапы теперь: `connect → handshake →
data (Ping/Pong) → socks5`.

## Ограничения
- Холодный путь платит два handshake: пробу и реальное соединение. TTL
  300 с амортизирует; тёплый путь пробы не делает.
- Выбор сериализован одним мьютексом: худшая задержка цикла —
  `кандидаты × попытки × probe_timeout`. Это осознанно (нет «стада» проб).
- При UDP-«чёрной дыре» без ICMP проба QUIC стоит полного `probe_timeout`;
  уменьшение до 2 с — компромисс между скоростью fallback и ложными
  negative на медленных каналах.
- Проба занимает слот `max_sessions` (см. §3).
- Клиент оценивает только свой текущий сервер; координация между
  несколькими серверами — вне MVP.

## Что не делаем
- ML, эвристики, выбор по задержке/пропускной способности.
- Automatic profile switching (ADR-013): выбор транспорта не меняет
  профиль развёртывания.
- 0-RTT / resumption в пробе (ADR-021, ADR-022).
- «Последний успешный» как дефолт при тотальном отказе.

## Последствия
- Новый крейт `transport-manager`; `transport-any` остаётся диспетчером.
- `config`: `TransportStrategy`, `TransportPolicy`.
- `protocol`: `Ping`/`Pong` (обратная совместимость: старые peer'ы не
  присылают эти типы; неизвестный kind по-прежнему отвергается).
- Сервер по умолчанию слушает оба транспорта.
- Логи клиента переведены на `tracing` (как сервер).
- Общий per-connection путь вынесен в `server::Services`; TLS- и QUIC-циклы
  получают один `Arc<Services>`, поэтому глобальность `max_sessions` —
  структурная, а не «по договорённости». Тест:
  `apps/server/tests/dual_transport_sessions.rs` (1 TLS + 1 QUIC при лимите 2
  → третья сессия отклоняется; мутация «счётчик на транспорт» ломает тест).
- e2e (`scripts/e2e.sh`) выполняется в CI отдельным job `e2e` — регрессия
  политики ловится на каждом push.
