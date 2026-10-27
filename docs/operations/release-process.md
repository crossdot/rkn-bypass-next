# Release process (P10)

Воспроизводимый релиз: build → test → SBOM → sign → staging → smoke → tag →
push → rollback.

## 1. Локальная сборка артефактов

```bash
cargo build --release --locked --workspace   # внутри release.sh
bash scripts/release.sh --no-sign
```

`scripts/release.sh`:
1. `cargo build --release --locked` + `cargo test --workspace --locked`;
2. stage в `dist/<version>/` (bin: `rkn-server`/`rkn-client`/`rkn-admin-cli`,
   `deploy/systemd/*`, `deploy/nftables/*`, docs);
3. SBOM (`syft`, CycloneDX) — если syft есть; иначе warn+skip
   (`--require-sbom` — падать без syft);
4. `SHA256SUMS` (внутренний, по файлам) + tarballs
   (`rkn-<v>.tar.gz`, `rkn-server-<v>.tar.gz`, `rkn-client-<v>.tar.gz`);
5. внешний `dist/SHA256SUMS` (tarballs + SBOM);
6. `--sign` — опционально, key-based (`COSIGN_KEY=<path>`), локально.

Reproducibility: `--locked` + `SOURCE_DATE_EPOCH`/mtime коммита, `tar --sort=name`,
owner/group 0. Best-effort.

## 2. CI (release.yml)

Триггер: `push` тега `v*` (и `workflow_dispatch` — dry-run). Job:
1. `cargo build --release --locked` (через `release.sh --require-sbom`);
2. syft SBOM;
3. `cosign sign-blob` **keyless** (OIDC) → `dist/SHA256SUMS.sig` + `.pem`;
4. `cosign verify-blob` (identity `…/release.yml@refs/(tags|heads)/`);
5. GitHub Release: `*.tar.gz`, `SHA256SUMS`, `sbom.cdx.json`, `.sig`, `.pem`.

Проверка подписи вручную:

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

## 3. Теги

- Исторические `v0.3-sync…v0.8-native` — lightweight (оставляем как есть).
- Новые релизы — **annotated**: `git tag -a vX.Y-name -m "…"` (release notes в
  сообщении), затем `git push origin vX.Y-name`.
- `release.yml` подхватывает любой тег `v*`.

## 4. Staging и smoke

См. [`staging.md`](staging.md): развернуть тег на staging VM, `curl --socks5`
→ 200, `journalctl -u rkn-server` без ошибок/SIGSYS, `systemd-analyze security`.

## 5. Rollback

См. [`rollback.md`](rollback.md): `git checkout <prev-tag>` + `install.sh
--force-env` (оба бинарника), без миграций.

## 6. Backup

См. [`backup-restore.md`](backup-restore.md): `/etc/netcore/` (CA key,
clients.toml, env, rules) → `tar | gpg -c` вне сервера.

## 7. Beta

См. [`beta.md`](beta.md): отдельные `clients.toml` записи, отдельный сервер,
сбор логов/метрик. `--beta` флаг в код не вводится (нужен ADR).
