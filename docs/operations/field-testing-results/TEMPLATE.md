# Шаблон результатов полевых тестов (P5.2)

Заполняется на каждую сеть после прогона `field-test.sh`. Заполнить и
положить в `docs/operations/field-testing-results/<operator>-<region>-<date>/`
вместе с CSV. Не «подкручивать» конфиг против DPI в обход правил.

## Метаданные сети

```yaml
operator:     # MTS | Megafon | Beeline | Tele2 | Rostelecom | ...
region:       # MSK, SPB, ...
access:       # 4g | 5g | wifi | ethernet
device:       # android | ios | laptop | desktop
server:       # <host:port>
timestamp:
client_id:
```

## Сводка по транспортам

| Сценарий | transport | requests | errors | req/s | transport_selected | p50 | p95 | p99 | diag_connect | diag_handshake | diag_data | diag_socks5 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| diag TLS | tls |  |  |  |  |  |  |  |  |  |  |  |
| diag QUIC | quic |  |  |  |  |  |  |  |  |  |  |  |
| load auto | auto |  |  |  |  |  |  |  |  |  |  |  |
| load TLS | tls |  |  |  |  |  |  |  |  |  |  |  |
| load QUIC | quic |  |  |  |  |  |  |  |  |  |  |  |
| curl | tls |  |  |  |  |  |  |  |  |  |  |  |

## Вывод

- `TRANSPORT_PREFERRED=` `tls` | `quic` | `auto` (для этого типа сети).
- Работоспособность: TLS жив / QUIC жив / оба живы / оба заблокированы.
- Отклонения (аномалии, не-ожидаемое): записать.

## Findings

- «QUIC работает на МТС, хотя ожидали блокировку» — finding, **не ошибка**.
- `udp_filtered` на сети → транспорт мёртв (DPI), политика → `tls`.
- `all_failed_default` + `server_unreachable` → зафиксировать, **не чинить**
  (осознанное поведение ADR-023).
