# Статус CI и операционной инфраструктуры

## Текущее состояние
- Remote отсутствует: `git remote -v` пуст. CI не запускается
  автоматически.
- `.github/workflows/ci.yml` существует, но не выполняется без remote.
- Docker-образы (ADR-011) не собираются: `deploy/docker/` пуст.
- Перед каждым коммитом — ручной прогон:
  `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
  && cargo test && cargo build`.

## Долг
1. Настроить remote (GitHub / GitLab / Gitea / self-hosted) и включить CI.
2. Реализовать `deploy/docker/`: `Dockerfile.client`,
   `Dockerfile.server-direct`, `Dockerfile.server-camouflaged`,
   smoke-тест в CI.
3. Настроить бэкап репозитория (`git bundle` минимум) до появления remote.

## Правило
Коммит без remote — временно допустим. Коммит без ручного прогона
fmt/clippy/test/build — недопустим.
