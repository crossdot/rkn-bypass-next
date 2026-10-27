# ADR-026: P8 — нативная установка и hardening (scope)

## Статус: Принято (P8, 2026-10-27)

## Контекст

- `deploy/docker/` готов: сервер/клиент non-root, read-only, `cap_drop=ALL`,
  SBOM (syft) + подпись (cosign keyless) — см. ADR-011 и CI-job `docker-smoke`.
  Docker — **единственный** автоматизированный путь установки.
- `deploy/systemd/`, `deploy/nftables/`, `deploy/deb/`, `deploy/rpm/` —
  отсутствуют. `deploy/profiles/{direct,camouflaged}/README.md` перечисляют
  `systemd/` как артефакт, но каталогов нет — операционный долг по ADR-013
  («профили с отдельными наборами артефактов»).
- Документа «Что считается готовым production-релизом» в `docs/` нет (он был
  во внешнем плане и не перенесён). Терминов
  `systemd`/`hardening`/`NoNewPrivileges`/`MemoryMax` нет ни в
  `docs/requirements.md`, ни в ADR-011.
- Бинарники читают конфигурацию из **env**: сервер — `LISTEN_ADDR`,
  `TRANSPORT`, `CERT_PATH`, `KEY_PATH`, `CA_PATH`, `RULES_PATH`,
  `CLIENTS_PATH`; клиент — `LISTEN_ADDR`, `SERVER_ADDR`, `CA_PATH`,
  `CLIENT_CERT`, `CLIENT_KEY`, `TRANSPORT*`. TOML загружается только как
  `AddressRules` и `ClientRegistry`. `configs/*.example.toml`
  (`[listen]`, `[tls]`, `profile`) бинарниками **не загружаются** — это
  документация/задел, а не единый config-loader.
- P11 выявил кандидата на фикс (`TransportManager::select()` cold-select).
  Это **вне scope** данного ADR (см. §8).

## Решение

### 1. Область P8 (in scope)

Только артефакты развёртывания + документация, без изменения runtime-кода:

| Артефакт | Назначение |
|---|---|
| `deploy/systemd/rkn-server.service` | unit сервера (mTLS, 443/tcp+udp) |
| `deploy/systemd/rkn-client.service` | unit клиента (SOCKS5, без root) |
| `deploy/systemd/rkn-server.env.example` | пример `EnvironmentFile=` сервера |
| `deploy/systemd/rkn-client.env.example` | пример `EnvironmentFile=` клиента |
| `deploy/nftables/rkn-server.nft` | минимальный firewall сервера |
| `scripts/install.sh` | установка: бинарник+unit+env+nft, `daemon-reload`, `enable --now`, проверка score |
| `docs/operations/native-install.md` | инструкция нативной установки |
| `docs/production-readiness.md` | чек-лист production-готовности (закрыто/открыто) |

`docs/production-readiness.md` переносится из внешнего плана и адаптируется
под фактическое состояние репозитория (Docker/SBOM/sign/mTLS/relay/P11 —
закрыто; нативная установка/пакеты — открыто). Внешний план в `docs/` не
входил, поэтому чек-лист собирается по фактам репозитория.

### 2. Пакетирование (deb/rpm) — Phase 2 (подтверждено)

**P8 = systemd + nftables + env + docs; deb/rpm — Phase 2, отдельный спринт.**
Причина: `debian/rules`, `*.spec`, GPG-подпись, репозиторий и тестовая
матрица — большой объём, раздувает P8. Нативная установка без пакетов
воспроизводима (`scripts/install.sh` или ручное копирование), просто не
автоматизирована на уровне менеджера пакетов. В `docs/production-readiness.md`
пункт «автоматизированная установка» помечается как **частично** закрытый.

### 3. Целевые дистрибутивы

- Минимум P8: **Debian 12** (systemd 252), **Ubuntu 22.04** (systemd 249),
  **Ubuntu 24.04** (systemd 255).
- Требование: **systemd ≥ 249** (`ProtectSystem=strict`, `MemoryHigh`,
  `MemoryMax`, `RestrictNamespaces`, `SystemCallFilter` доступны).
- **Тестовая матрица** `systemd-analyze security` на Debian 12, Ubuntu 22.04,
  Ubuntu 24.04.
- RHEL/Fedora — Phase 2.

### 4. `rkn-server.service` (эскиз)

- `Type=simple`, `ExecStart=/usr/local/bin/rkn-server`
- `User=rkn`, `Group=rkn` (не root)
- `EnvironmentFile=/etc/netcore/server.env` (пример —
  `deploy/systemd/rkn-server.env.example`)
- `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (bind 443)
- `Restart=on-failure`, `RestartSec=5`
- Hardening — §6.

### 5. `rkn-client.service` (эскиз)

- `Type=simple`, `ExecStart=/usr/local/bin/rkn-client`
- `User=rkn`, SOCKS5 на `127.0.0.1:1080` (порт > 1024 → **без capabilities**)
- `CapabilityBoundingSet=` (пусто), `AmbientCapabilities=` (пусто)
- `EnvironmentFile=/etc/netcore/client.env` (пример —
  `deploy/systemd/rkn-client.env.example`)
- Тот же hardening-набор, что у сервера.

### 6. Hardening

```
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RemoveIPC=true
UMask=0077
SystemCallFilter=@system-service
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryHigh=384M
MemoryMax=512M
CPUQuota=200%
LimitNOFILE=65536
TasksMax=1024
```

- `MemoryHigh=384M` (75 % от `MemoryMax`) — soft-лимит: **throttle before OOM**
  (доступен с systemd 231, есть во всех целевых версиях). `MemoryMax=512M` —
  жёсткий предел.
- **Масштабирование**: 512M рассчитан на `max_sessions=750` (P11: пик RSS
  222 MB). При `max_sessions > 750` увеличивать `MemoryMax` по формуле
  `2× P11-пик + 100M`: 1500 сессий ≈ 550M, 3000 ≈ 1G. Не поднимать без
  замера, иначе OOM.
- **Почему 512M, а не 256/768**: 256M — вплотную к пику (222 MB) → OOM;
  768M — избыточно (3.5×) и может снизить `systemd-analyze security`;
  512M — 2.3×, оптимум.
- `CPUQuota=200%` (2 ядра), `LimitNOFILE=65536` (P11: fd max 974 при 500
  клиентах → ~32K клиентов запас).
- `ReadWritePaths=` не требуется: логи идут в journald (stderr), состояние —
  в памяти (`SessionManager`), файлов на запись нет. Сертификаты/конфиги —
  только чтение: `ProtectSystem=strict` делает `/` read-only,
  `ReadOnlyPaths=/etc/netcore` — явно. При появлении состояния —
  `StateDirectory=rkn` (`/var/lib/rkn`).
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`: `AF_UNIX` нужен для
  nss-resolve/локальных сокетов. Если на целевой резолв доменов-целей упадёт
  (AI_ADDRCONFIG через netlink) — fallback `… AF_NETLINK`, зафиксировать.
- `SystemCallFilter=@system-service` обязателен (без него score > 5.0).
  Fallback при SIGSYS на целевых: `@system-service @network-io`; если и это
  ломает — зафиксировать причину в ADR, не убирать молча.

### 7. `deploy/nftables/rkn-server.nft`

Минимальный `input`-фильтр: `policy drop`; разрешить `443/tcp` + `443/udp`
(`TRANSPORT=auto`), `22/tcp` (SSH админа, настраивается), `established/related`,
`loopback`, icmp/icmpv6. `forward` — drop; NAT не нужен (сервер — конечная
точка).

**Применение**: `install.sh` только копирует файл в `/etc/nftables.d/` и
печатает инструкцию `nft -f` (после проверки SSH) — **не применяет
автоматически** (защита от lockout). Опциональный `--apply-nft --yes` —
явное применение, по умолчанию выключено.

### 8. Вне scope

- Runtime-код (`Transport`, `proxy-core`, `SessionManager`), новые транспорты,
  TUN, Reality, mTLS/аудит (ADR-021).
- Пакеты deb/rpm — Phase 2 (§2).
- Cold-select finding (P11) — остаётся в `docs/operations/load-testing.md`
  **без номера ADR**; если решим фиксить, это **ADR-027**, не раньше.

## Критерий приёмки

- `systemd-analyze security --offline=true` для `rkn-server.service` и
  `rkn-client.service` — **exposure < 5.0** (проверяется в CI-job
  `systemd-hardening`). Если не достигается без поломки функциональности —
  зафиксировать в этом ADR «почему» (не молча).
- Unit стартует; e2e-запрос через нативную установку (без Docker) → HTTP 200.
- `nftables` не ломает relay и не режет SSH.

## Последствия

- Нативная установка (без Docker) становится документированной и
  воспроизводимой (unit + env + nft + install.sh).
- `deploy/profiles/*/README.md` перестают ссылаться на несуществующий
  `systemd/` (обновляются на `deploy/systemd/` и `deploy/nftables/`).
- «Автоматизированная установка» в чек-листе — **частично** (systemd), пакеты
  Phase 2; отражено в `docs/production-readiness.md`.
- runtime-код и mTLS/аудит/`max_sessions` не затрагиваются (ADR-021).

## Подтверждённые решения (2026-10-27)

1. **Пакеты**: deb/rpm — Phase 2 (отдельный спринт); P8 = systemd + nftables +
   env + docs. Нативная установка без пакетов воспроизводима (`install.sh` /
   ручное копирование), просто не автоматизирована на уровне пакетов.
2. **Дистрибутивы**: Debian 12 + Ubuntu 22.04/24.04; RHEL/Fedora — Phase 2;
   матрица `systemd-analyze security` на трёх целевых.
3. **Числа**: `MemoryHigh=384M`, `MemoryMax=512M`, `CPUQuota=200%`,
   `LimitNOFILE=65536`; правило масштабирования по `max_sessions`
   (2× P11-пик + 100M).
4. **Порт/привилегии**: `LISTEN_ADDR=0.0.0.0:443`; `CAP_NET_BIND_SERVICE`
   через `AmbientCapabilities` + `CapabilityBoundingSet`. NAT не вводить.
5. **SystemCallFilter**: включать `@system-service` сразу; fallback при SIGSYS
   — `@system-service @network-io`.
6. **Файлы**: `ReadWritePaths=` не нужен; `ReadOnlyPaths=/etc/netcore`.
7. **nftables**: `install.sh` копирует в `/etc/nftables.d/`, не применяет;
   опциональный `--apply-nft --yes` (по умолчанию off), в инструкции —
   предупреждение о SSH-lockout.
