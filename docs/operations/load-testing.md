# Load testing: throughput and backpressure (relay fix, ADR-025)

Проверка производительности и устойчивости relay после ADR-025
(двунаправленный relay вместо таймерного поллинга).

Тесты сняты в контейнере на хосте `192.168.206.1` (адрес изменяемый; в тестах
берётся фактический адрес интерфейса). Все значения — для `cargo build --release`.

## Пропускная способность

### Методика
1. Готовится файл 100 MB (`dd if=/dev/zero of=file bs=1M count=100`).
2. Запускается HTTP-сервер, отдающий этот файл по `GET /file`.
3. Клиент-прокси запускается с профилем (A: TLS / B: QUIC) и правилом
   `allow_cidrs=["<host>/32"]`.
4. 5 прогонов:
   `curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' -x socks5h://127.0.0.1:11080 http://<host>:6080/file`
5. Скорость: `100 MB / time_total`. Ниже — медиана по 5 прогонам.

### Результат

| Relay | TLS (MB/s) | QUIC (MB/s) |
|---|---|---|
| Baseline (поллинг, ADR-025 до) | 4.76 | 4.88 |
| Fixed (`copy_bidirectional` / 2 задачи) | 978.90 | 619.21 |
| **Скорость** | **~206×** | **~127×** |

Клиент-прокси ограничен сверху скоростью HTTP-сервера на локалхосте; значения
~1 GB/s для TLS близки к пределу `copy_bidirectional` на этом стенде, а не к
скорости сети.

**Оговорка (localhost):** числа получены на localhost (loopback, без сети).
В реальной среде throughput ограничен каналом (RTT, потери, полоса), а не
relay. Это reference для проверки, что relay не узкое место; для production
нужны реальные замеры на целевых сетях (см. P11).

## Backpressure (дедлок)

### Сценарий 1 — односторонний (target читает медленно)
Клиент шлёт 100 MB, target читает по 64 KB и спит 10 ms (≈6.4 MB/s). Ожидание:
поток не «зависает навсегда», а просто упирается в скорость target.

| Transport | sent | target получил | elapsed | RSS max |
|---|---|---|---|---|
| TLS (fixed) | 104857600 | 104857600 | 19.31 s | server 6.8 MB, client 6.6 MB |
| QUIC (fixed) | 104857600 | 104857600 | 19.27 s | server 11.2 MB, client 10.8 MB |

Данные доходят до конца (104857600 == 104857600), дедлока нет. RSS ограничен и
не растёт бесконечно (QUIC буферизует чуть больше из-за окна перегрузки).

### Сценарий 2 — двунаправленный конкурентный (эхо)
Target читает по 64 KB и **сразу отправляет обратно** (эхо), затем спит 100 ms.
Данные текут в обе стороны одновременно; обе стороны насыщены.

| Relay | Исход |
|---|---|
| Baseline (поллинг) | **Дедлок**: sender упёрся на 16 MB и не двигался (20 s, одна строка progress, target завис). |
| Fixed | **Нет дедлока**: непрерывный прогресс 16 → 32 MB за 60 s (эхо растёт параллельно: 26.4 MB), target получает данные до остановки по таймауту. |

Это и есть дедлок, описанный в ADR-025: поллинговая версия, упираясь
в `transport.send`/`tcp.write_all` с заполненным окном, перестаёт обрабатывать
противоположную сторону, и весь путь замирает. `BidirectionalRelay`
(`copy_bidirectional` для TLS, две конкурентные задачи для QUIC) обрабатывает
обе стороны независимо и дедлока не даёт.

## CPU
Отдельный CPU-бенчмарк не снимался (опционально). Косвенно: relay больше не
делает таймерный поллинг (нет churn таймеров на каждом соединении), что
снижает накладные расходы; throughput-выигрыш подтверждён выше.

## Итог
После ADR-025 relay:
- не дедлочится под backpressure (сценарии 1 и 2);
- пропускная способность выросла в ~206× (TLS) и ~127× (QUIC);
- mTLS/аудит/`max_sessions` не затронуты (relay работает после handshake и
  аутентификации, ADR-021).

---

# P11: нагрузочные испытания (сценарии, contention)

Стенд: localhost, `bash scripts/load.sh`, `cargo build --release`.
Loadgen — bash+coreutils (`xargs -P`, `sort -n | awk`, спин-барьер по timestamp).
python3 используется только как helper-таргет (high-concurrency 200 и slow
reader) — как уже делает `scripts/e2e.sh`; сам loadgen от python не зависит.

Метрики: curl `--write-out '%{http_code} %{time_connect} %{time_total}'`,
`/proc/<pid>/fd`, `ps -o rss=`, `/proc/<pid>/task`, tokio `alive_tasks`
(`TASK_METRICS_INTERVAL_S=1` → `Handle::metrics().num_alive_tasks()`;
отдельная фича `rt-metrics` не нужна — метод доступен под `rt`).

## basic — N через auto (проверка TTL и конкуренции)

| N | requests | errors | req/s | p50 | p95 | p99 | connect p99 | probe_ok | cached_ok | alive_tasks max | fd max | rss max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 213 | 0 | 21.3 | 42 ms | 43 ms | 43 ms | 0.1 ms | 1 | 212 | 3 | 12 | 7.4 MB |
| 10 | 6433 | 0 | 214.4 | 42 ms | 43 ms | 43 ms | 0.08 ms | 1 | 6432 | 12 | 30 | 10.1 MB |
| 100 | 19845 | 0 | 1984.5 | 44 ms | 48 ms | 51 ms | 0.11 ms | 1 | 19844 | 102 | 210 | 21.8 MB |
| 500 | 30751 | 0 | 3075.1 | 156 ms | 161 ms | 164 ms | 0.14 ms | 1 | 30750 | 483 | 974 | 48.9 MB |

- **TTL-кэш работает**: на 500 соединений — 1 проба (`probe_ok=1`) и ~N
  `cached_ok`. Probe storm отсутствует.
- fd/tasks после drain возвращаются к baseline (10→10, 33→33) вплоть до N=500.
  RSS под 500 concurrency доходит до ~49 MB (буферы + арена аллокатора) и
  ограничен, не растёт линейно после закрытия.
- Латентность на N=500 (p50 156 ms) — это closed-loop насыщение при 500
  параллельных клиентах (3075 req/s); p50≈p99, то есть **без хвостов
  конкуренции** (см. finding ниже: на localhost проба дешёвая).

## run_both — 500 TLS + 500 QUIC, max_sessions=750

| Группа | requests | errors | req/s | p50 | p95 | p99 |
|---|---|---|---|---|---|---|
| TLS (500) | 15886 | 11543 | 1985.8 | 15 ms | 824 ms | 856 ms |
| QUIC (500) | 10954 | 6965 | 1369.2 | 28 ms | 986 ms | 1790 ms |

- Глобальный `max_sessions=750`: ~750 admitted, ~250 отклонены («session limit
  reached»); отклонённые воркеры ретраят → высокий error-rate ожидаем.
- `alive_tasks max=1414`, `fd max=1205`, `rss max=222 MB` — память ограничена
  `max_sessions`, после drain fd 10→13 (в пределах slack), tasks без роста.
- Глобальный счётчик общий для TLS и QUIC (ADR-023 §8) — подтверждено.

## slow — медленный target (20 MB upload)

- target получил 20971699 B, elapsed ~20 s (reader 64 KB + sleep 20 ms).
- server `rss max=6.8 MB`, fd 9→9, tasks стабильны: relay держит буферы
  ограниченными под backpressure (согласуется с ADR-025).

## abort — kill клиента mid-transfer

- До/после kill: server fd 11→9, tasks 33→33, RSS без роста.
- `max_sessions=1`: после kill повторный CONNECT дал **200** (сессия
  освобождена, `session_limit_events=0`) — нет утечки сессий.

## churn — быстрые connect/disconnect (N=100, 10 s)

- 19865 requests, 0 errors, 1985 req/s, `probe_ok=1`/`cached_ok=19864`
  (probe storm нет), client fd 9→9, tasks 33→33.

## failover — kill сервера, backoff, recovery

- initial `200`; сервер убит → первый запрос упал (0 s).
- down-hold 5 s: клиент ушёл в fallback/backoff — в логе
  `reason=all_failed_default=3`, `reason=fallback_prev_failed=4`.
- рестарт сервера → **recovery ≤1 s** (в пределах 30 s).

## Finding: `TransportManager::select()` сериализуется через `Mutex`

`TransportManager.state: tokio::sync::Mutex<State>` (`lib.rs:253`) берётся в
`select()` (`lib.rs:298`) и **удерживается через `probe_with_attempts().await`**
(`lib.rs:342`). Холодный выбор (старт/истечение TTL) держит лок до
`order().len() × max_probe_attempts × probe_timeout` (комментарий
`lib.rs:246-248`) — для `auto` это ≈ `2 × 1 × 2 s = 4 s` худший случай.
При 500 одновременных соединениях на холодном старте 499 ждут первую пробу.

Наблюдения P11 (localhost): проба — connect+Ping/Pong на loopback, sub-ms,
поэтому конкуренция фактически не видна: `probe_ok=1`, `cached_ok≈N`,
p50≈p99. В реальной сети (RTT, потери) холодная проба — десятки-сотни ms, и
залповый старт N соединений (или залп после истечения TTL) будет
сериализоваться на пробе.

**Метрики acquire-wait нет.** Есть только `event=transport_selected`
(`probe_ms`, `cached_age_s`, `fail_count`) — тайминга ожидания лока нет.

`alive_tasks` в `run_both` — ~1.9/сессия (relay: 2 task'а на QUIC + 1 на TLS).
Rejected соединения (250 при `max_sessions=750`) тоже создают task, который
затем умирает — это **не утечка** (после drain fd/tasks возвращаются к
baseline), но даёт CPU-нагрузку на spawn/destroy под reject-нагрузкой.
Зафиксировать для ADR-026, не фиксить.

**Исправлено в ADR-027** (в P11 не фиксили): singleflight — на холодном выборе
ровно 1 проба на N, остальные ждут `Notify` и берут результат из кэша
(`invalidate` при идущей пробе побеждает и будит ждущих). Добавлена метрика
`transport_acquire_wait_ms` (ожидание лока/уже-идущей пробы). Гистерезис
переключения (защита от флапа) — out-of-scope; при необходимости — ADR-028.

## Критерии (baseline-гипотезы)

- 0 потерь в контроле (basic/churn: errors=0 на healthy target).
- RSS ±10 % за час (долгий прогон).
- recovery ≤30 с (failover: факт ≤1 с).
- 1–4 ч без утечек fd/RSS/tasks.
- Отсутствие probe storm (probe_ok ≈ порядок транспортов, не N).

## Полный прогон (1000 клиентов, 1–4 ч)

В рамках P11 **не выполнялся** (ограничение времени/ресурсов runner'а).
Как запускать и куда писать результат — `docs/operations/load-testing-results/`.
