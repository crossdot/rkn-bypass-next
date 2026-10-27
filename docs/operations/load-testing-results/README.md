# Результаты нагрузочных испытаний (P11)

Сюда кладутся результаты **полного** прогона (1000 клиентов, 1–4 ч) по датам:
`docs/operations/load-testing-results/<YYYY-MM-DD>/`.

Дымовой прогон (`--clients 10 --duration 30 --scenario basic`) идёт в CI
(job `load-smoke`) и здесь не дублируется.

## Статус

Полный прогон (1000 клиентов, 1–4 ч) в рамках P11 **не выполнялся**:
ограничение времени/ресурсов runner'а. Ниже — как его запустить и что
считать успехом.

## Как запустить

Сборка:

```bash
cargo build --release --workspace
```

Долгий прогон (1 ч), базовый сценарий через auto:

```bash
DAY="$(date +%F)"
OUT="docs/operations/load-testing-results/$DAY"
mkdir -p "$OUT"
bash scripts/load.sh --clients 1000 --transport auto --duration 3600 \
  --scenario basic --out "$OUT/basic-1000-1h.txt"
```

4-часовой прогон — тем же скриптом (`--duration 14400`) либо 4×1 ч подряд
(удобнее сравнивать дельты fd/RSS/tasks между часами).

`run_both` (500 TLS + 500 QUIC, `max_sessions=750`):

```bash
bash scripts/load.sh --clients 1000 --scenario run_both --max-sessions 750 \
  --duration 3600 --out "$OUT/run_both-750-1h.txt"
```

Остальные сценарии (`slow`, `abort`, `churn`, `failover`) — короткие, для
долгого прогона не нужны, но можно периодически повторять:

```bash
bash scripts/load.sh --scenario abort    --out "$OUT/abort.txt"
bash scripts/load.sh --scenario failover --out "$OUT/failover.txt"
```

## Что снимает скрипт

- Латентность: `curl --write-out '%{http_code} %{time_connect} %{time_total}'`
  → p50/p95/p99/mean, req/s, errors.
- fd: `/proc/<pid>/fd`; RSS: `ps -o rss=`; потоки: `/proc/<pid>/task`.
- tokio `alive_tasks`: `TASK_METRICS_INTERVAL_S=1` →
  `event=task_metrics alive_tasks=N` (env-gated, `Handle::metrics()`).
- До/во время/после — дельты в конце (`leak_check`). Скрипт завершается
  `RESULT: FAIL`, если fd вырос >8 или tasks >4.

## Критерии успеха

- 0 потерь в контроле (healthy target) — `errors=0`.
- RSS ±10 % за час (сравнить `rss` после дренажа на старте и в конце).
- recovery ≤30 с (failover).
- 1–4 ч без утечек fd/RSS/tasks (нет монотонного роста между часами).
- Нет probe storm: `probe_ok` ≈ порядок транспортов, не N.
