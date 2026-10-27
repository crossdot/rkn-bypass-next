# Profile B — Camouflaged entry (self-steal, MVP)

Требует: домен, nginx, фейковый сайт, Reality, DNS-01 для сертификата.

Артефакты:
- конфиг: `configs/server.camouflaged.example.toml`
- systemd: `deploy/systemd/` (`rkn-server.service` + env-пример)
- nftables: `deploy/nftables/rkn-server.nft`
- nginx/, site-content/, certbot/ — Phase 2 (ещё не созданы)

Перед развёртыванием: см. ADR-014. Установка: `docs/operations/native-install.md`.
