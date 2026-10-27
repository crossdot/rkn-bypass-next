# Чек-лист полевых тестов (P5.2)

Прогон — владелец проекта, вручную, на реальных сим-картах. Не CI.

## Подготовка (один раз)
- [ ] Сервер: VPS вне РФ, `install.sh`, `TRANSPORT=auto`, `systemd-analyze security` < 5.0.
- [ ] Клиентские сертификаты: `admin-cli client add --max-sessions 100 field-test` (для каждой тестовой сети — свой client_id, чтобы отличить в логах).
- [ ] Бинарники: `cargo build --release --locked`, `load.sh`, `field-test.sh`, `diag-cli` на устройстве.
- [ ] `--dry-run` на каждой сети перед прогоном.

## На каждую сеть (M1–M6, R, H1–H3, C)
- [ ] Метаданные: оператор, регион, доступ (4g/5g/wifi/ethernet), устройство, timestamp.
- [ ] `field-test.sh --operator ... --region ... --access ... --device ... --host <server> --client-cert ... --client-key ... --ca ... --out results/`
- [ ] CSV: 26 полей, нет `NaN`/пустых в критичных (`requests`, `probe_ok`, `cached_ok`, `transport_selected`, `p50/p95/p99`).
- [ ] Отклонения записать в `TEMPLATE.md` (не «подкручивать» конфиг).

## После всех сетей
- [ ] Сводная таблица в `TEMPLATE.md`: какой транспорт живёт/заблокирован по операторам.
- [ ] Вывод `TRANSPORT_PREFERRED=tls|quic|auto` для каждого типа сети.
- [ ] Findings: «QUIC работает на МТС, хотя ожидали блокировку» — это finding, не ошибка.
- [ ] Если сеть не работает: `diag check --json` → этап; `server_unreachable` → проверить сервер; `udp_filtered` → `TRANSPORT_PREFERRED=tls`; `all_failed_default`+`server_unreachable` → зафиксировать, не чинить.

## Куда класть
- [ ] `docs/operations/field-testing-results/<operator>-<region>-<date>/` (CSV + `TEMPLATE.md`).
- [ ] Коммит в `master` или ветку `field-results-<date>`.
- [ ] После прогона — `v1.0.0` (если результаты подтверждают работоспособность).
