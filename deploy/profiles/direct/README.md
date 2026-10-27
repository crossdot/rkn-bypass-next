# Profile A — Direct (MVP)

Минимальная конфигурация: VPS с TLS-сертификатом на домене.
Не требует nginx, фейкового сайта или Reality.

Артефакты:
- конфиг: `configs/server.direct.example.toml`
- systemd: `deploy/systemd/` (`rkn-server.service` + env-пример)
- nftables: `deploy/nftables/rkn-server.nft`

Установка: `docs/operations/native-install.md`.
