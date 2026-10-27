# Статус CI и операционной инфраструктуры

## Основной CI — `.github/workflows/ci.yml`

Триггеры: `push` (все ветки), `pull_request`, `workflow_dispatch`.

Job'ы:
1. **check** — `cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo build`.
2. **e2e** — TLS/QUIC/auto/dual-listen/UDP-fallback (`scripts/e2e.sh`).
3. **load-smoke** — P11: `scripts/load.sh --clients 10 --duration 30 --scenario basic`.
4. **systemd-hardening** — `systemd-analyze security --offline=true` для
   `rkn-server`/`rkn-client`, порог exposure < 5.0.
5. **docker-smoke** — сборка образов (ADR-011), push в `ghcr.io` (master),
   SBOM (syft, CycloneDX), `cosign sign` keyless + verify.

## Release — `.github/workflows/release.yml`

Триггер: `push` тега `v*` (и `workflow_dispatch` — dry-run без GitHub Release).

Шаги: `scripts/release.sh --require-sbom` (build `--locked`, SBOM, tarballs,
checksums) → `cosign sign-blob` keyless → verify → GitHub Release
(`*.tar.gz`, `SHA256SUMS`, `sbom.cdx.json`, `.sig`, `.pem`).

## Правило

- Коммит без зелёного `check` (fmt/clippy/test/build) недопустим.
- Релиз — только через `release.yml` на annotated-тег; процесс см.
  [`release-process.md`](release-process.md).
- Перед мержем — зелёный CI на ветке; после мержа — зелёный CI на `master`.
