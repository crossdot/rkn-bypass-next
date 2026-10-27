#!/usr/bin/env bash
# P10: сборка релизных артефактов (бинарники + deploy + docs) — reproducible.
#
# Usage:
#   scripts/release.sh [--no-sign | --sign] [--require-sbom] \
#                      [--out DIR] [--version V]
#
#   --no-sign      (default) не подписывать
#   --sign         подписать SHA256SUMS через cosign (нужен COSIGN_KEY)
#   --require-sbom падать, если syft недоступен (иначе SBOM пропускается с warn)
#   --out DIR      каталог артефактов (default: dist/)
#   --version V    версия/префикс (default: git describe --tags)
#
# Артефакты: dist/<version>/ (bin/, deploy/, docs/, SHA256SUMS),
#             dist/rkn-<version>.tar.gz, dist/rkn-{server,client}-<version>.tar.gz,
#             dist/SHA256SUMS (tarballs+sbom), опц. dist/SHA256SUMS.sig.
# Подпись в CI (keyless) делает release.yml; --sign — локально (key-based).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist"
VERSION=""
SIGN=0
REQUIRE_SBOM=0

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "error: $*" >&2; exit 1; }
say() { echo "[release] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --sign) SIGN=1; shift ;;
    --no-sign) SIGN=0; shift ;;
    --require-sbom) REQUIRE_SBOM=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

[ -f "$ROOT/Cargo.lock" ] || die "Cargo.lock not found"
if [ -z "$VERSION" ]; then
  VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
fi
[ -n "$VERSION" ] || die "empty version"
case "$VERSION" in
  */*) die "version must not contain '/': $VERSION" ;;
esac
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}"

DEST="$OUT/$VERSION"
rm -rf "$DEST"
mkdir -p "$DEST/bin" "$DEST/deploy/systemd" "$DEST/deploy/nftables" "$DEST/docs"
say "version=$VERSION out=$OUT"

# --- build + test (reproducible: --locked) ---
cargo build --release --locked --workspace
cargo test --workspace --locked

# --- stage ---
cp "$ROOT/target/release/server" "$DEST/bin/rkn-server"
cp "$ROOT/target/release/client" "$DEST/bin/rkn-client"
cp "$ROOT/target/release/admin-cli" "$DEST/bin/rkn-admin-cli"
cp "$ROOT/deploy/systemd/"*.service "$ROOT/deploy/systemd/"*.env.example "$DEST/deploy/systemd/"
cp "$ROOT/deploy/nftables/rkn-server.nft" "$DEST/deploy/nftables/"
cp "$ROOT/docs/operations/native-install.md" "$DEST/docs/"
cp "$ROOT/docs/production-readiness.md" "$DEST/docs/"
cp "$ROOT/docs/adr/ADR-026-p8-native-deployment.md" "$DEST/docs/"
say "staged: $DEST"

# --- SBOM ---
SBOM=""
if command -v syft >/dev/null 2>&1; then
  syft dir:"$DEST/bin" -o "cyclonedx-json=$DEST/sbom.cdx.json" >/dev/null
  cp "$DEST/sbom.cdx.json" "$OUT/sbom.cdx.json"
  SBOM="sbom.cdx.json"
  say "SBOM: $OUT/$SBOM"
elif [ "$REQUIRE_SBOM" -eq 1 ]; then
  die "syft not found but --require-sbom was given"
else
  say "WARN: syft not found — SBOM skipped (use --require-sbom to fail)"
fi

# --- inner checksums (files in dist/<version>/) ---
(
  cd "$DEST"
  find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
say "inner checksums: $DEST/SHA256SUMS"

# --- tarballs (reproducible-ish: sorted, fixed owner/mtime) ---
TAROPTS=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH")
tar "${TAROPTS[@]}" -czf "$OUT/rkn-$VERSION.tar.gz" -C "$OUT" "$VERSION"
tar "${TAROPTS[@]}" -czf "$OUT/rkn-server-$VERSION.tar.gz" -C "$DEST" \
  bin/rkn-server deploy/systemd/rkn-server.service deploy/systemd/rkn-server.env.example \
  deploy/nftables/rkn-server.nft docs/native-install.md
tar "${TAROPTS[@]}" -czf "$OUT/rkn-client-$VERSION.tar.gz" -C "$DEST" \
  bin/rkn-client deploy/systemd/rkn-client.service deploy/systemd/rkn-client.env.example \
  docs/native-install.md
say "tarballs: $OUT/rkn-*.tar.gz"

# --- outer checksums (tarballs + sbom) ---
(
  cd "$OUT"
  sha256sum "rkn-$VERSION.tar.gz" "rkn-server-$VERSION.tar.gz" "rkn-client-$VERSION.tar.gz" \
    ${SBOM:+$SBOM} > SHA256SUMS
)
say "outer checksums: $OUT/SHA256SUMS"

# --- optional local signing (key-based; CI uses keyless cosign) ---
if [ "$SIGN" -eq 1 ]; then
  command -v cosign >/dev/null 2>&1 || die "--sign requires cosign"
  [ -n "${COSIGN_KEY:-}" ] || die "--sign requires COSIGN_KEY (path to cosign private key)"
  cosign sign-blob --yes --key "$COSIGN_KEY" \
    --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  say "signed (key): $OUT/SHA256SUMS.sig"
fi

say "done:"
ls -1 "$OUT"
