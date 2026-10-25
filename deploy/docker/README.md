# Docker-артефакты

- Dockerfile.client
- Dockerfile.server-direct
- Dockerfile.server-camouflaged
- docker-compose.dev.yml
- docker-compose.test.yml

См. ADR-011 и ADR-012.

Клиент с `entry = wireguard` требует проброса порта (UDP/TCP 51820 или 443)
и не входит в минимальный smoke-тест.
