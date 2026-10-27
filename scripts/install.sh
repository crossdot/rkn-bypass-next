#!/usr/bin/env bash
# P8: нативная установка rkn-server / rkn-client (systemd) — ADR-026.
#
# Usage:
#   sudo scripts/install.sh --server [--bin PATH] [--prefix DIR] [--etc DIR]
#                            [--apply-nft --yes]
#   sudo scripts/install.sh --client [--bin PATH] [--prefix DIR] [--etc DIR]
#
# Что делает:
#   1. проверяет root и systemd >= 249;
#   2. создаёт системного пользователя rkn;
#   3. копирует бинарник, unit и env-пример (env — только если ещё нет);
#   4. pre-check сертификатов (fail-fast) по путям из env;
#   5. для сервера копирует nftables-правила в /etc/nftables.d/ и НЕ применяет
#      (печатает `nft -f`; авто-применение — только --apply-nft --yes);
#   6. systemctl daemon-reload && enable --now;
#   7. печатает exposure score (systemd-analyze security --offline=true),
#      предупреждает при >= 5.0.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPONENT="server"
PREFIX="/usr/local/bin"
UNIT_DIR="/etc/systemd/system"
ETC_DIR="/etc/netcore"
NFT_DIR="/etc/nftables.d"
BIN=""
APPLY_NFT=0
ASSUME_YES=0

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "error: $*" >&2; exit 1; }
say() { echo "[install] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) COMPONENT="server"; shift ;;
    --client) COMPONENT="client"; shift ;;
    --bin) BIN="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --unit-dir) UNIT_DIR="$2"; shift 2 ;;
    --etc) ETC_DIR="$2"; shift 2 ;;
    --apply-nft) APPLY_NFT=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

if command -v systemctl >/dev/null 2>&1; then
  sysd="$(systemctl --version | awk 'NR==1{print $2}')"
  [ "${sysd:-0}" -ge 249 ] 2>/dev/null || die "systemd >= 249 required (found ${sysd:-?})"
else
  die "systemctl not found (systemd required)"
fi

case "$COMPONENT" in
  server)
    BIN_KIND="server"; BIN_NAME="rkn-server"; UNIT_NAME="rkn-server.service"
    ENV_SRC="$ROOT/deploy/systemd/rkn-server.env.example"; ENV_DST="$ETC_DIR/server.env"
    ;;
  client)
    BIN_KIND="client"; BIN_NAME="rkn-client"; UNIT_NAME="rkn-client.service"
    ENV_SRC="$ROOT/deploy/systemd/rkn-client.env.example"; ENV_DST="$ETC_DIR/client.env"
    ;;
  *) die "component must be server|client" ;;
esac

SRC_BIN="${BIN:-$ROOT/target/release/$BIN_KIND}"
[ -x "$SRC_BIN" ] || die "binary not found/executable: $SRC_BIN (run: cargo build --release --workspace)"
[ -f "$ROOT/deploy/systemd/$UNIT_NAME" ] || die "unit not found: deploy/systemd/$UNIT_NAME"

# --- user ---
if ! id -u rkn >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin rkn
  say "created system user rkn"
else
  say "user rkn exists"
fi

install -d -m 0750 -o root -g rkn "$ETC_DIR"

# --- binary + unit ---
install -D -m 0755 "$SRC_BIN" "$PREFIX/$BIN_NAME"
say "installed binary: $PREFIX/$BIN_NAME"
install -D -m 0644 "$ROOT/deploy/systemd/$UNIT_NAME" "$UNIT_DIR/$UNIT_NAME"
say "installed unit: $UNIT_DIR/$UNIT_NAME"

# --- env (only if absent) ---
if [ ! -e "$ENV_DST" ]; then
  install -D -m 0640 -o root -g rkn "$ENV_SRC" "$ENV_DST"
  say "installed env example: $ENV_DST (edit before production)"
else
  say "kept existing env: $ENV_DST"
fi

# --- pre-check certs (fail-fast) ---
get_env() { [ -f "$ENV_DST" ] && sed -n "s/^$1=//p" "$ENV_DST" | tail -1 || true; }
chk() { [ -f "$1" ] || die "missing required file: $1"; }

if [ "$COMPONENT" = "server" ]; then
  cert="$(get_env CERT_PATH)"; cert="${cert:-$ETC_DIR/server.crt}"
  key="$(get_env KEY_PATH)"; key="${key:-$ETC_DIR/server.key}"
  ca="$(get_env CA_PATH)"; ca="${ca:-$ETC_DIR/ca.crt}"
  chk "$cert"; chk "$key"; chk "$ca"
  rules="$(get_env RULES_PATH)"; [ -n "$rules" ] && [ ! -f "$rules" ] && say "WARN: RULES_PATH not found: $rules"
  clients="$(get_env CLIENTS_PATH)"; [ -n "$clients" ] && [ ! -f "$clients" ] && say "WARN: CLIENTS_PATH not found: $clients (server fails closed)"
  say "certificates OK: $cert $key $ca"
else
  ca="$(get_env CA_PATH)"; ca="${ca:-$ETC_DIR/ca.crt}"
  ccert="$(get_env CLIENT_CERT)"; ccert="${ccert:-$ETC_DIR/client.crt}"
  ckey="$(get_env CLIENT_KEY)"; ckey="${ckey:-$ETC_DIR/client.key}"
  chk "$ca"; chk "$ccert"; chk "$ckey"
  say "certificates OK: $ccert $ckey $ca"
fi

# --- nftables (server only): copy, do not apply ---
if [ "$COMPONENT" = "server" ]; then
  install -D -m 0644 "$ROOT/deploy/nftables/rkn-server.nft" "$NFT_DIR/rkn-server.nft"
  say "installed nftables ruleset: $NFT_DIR/rkn-server.nft (NOT applied)"
  if [ "$APPLY_NFT" -eq 1 ]; then
    [ "$ASSUME_YES" -eq 1 ] || die "--apply-nft requires --yes"
    command -v nft >/dev/null 2>&1 || die "nft not found"
    say "applying nftables ruleset (explicit --apply-nft --yes)"
    nft -f "$NFT_DIR/rkn-server.nft"
  else
    say "apply manually after verifying SSH: nft -f $NFT_DIR/rkn-server.nft"
  fi
fi

# --- systemd ---
systemctl daemon-reload
systemctl enable --now "$UNIT_NAME" || {
  echo "error: failed to start $UNIT_NAME; inspect: journalctl -u $UNIT_NAME -n 50" >&2
  exit 1
}
say "started: $UNIT_NAME"

# --- hardening score ---
if command -v systemd-analyze >/dev/null 2>&1; then
  score="$(systemd-analyze security --offline=true "$ROOT/deploy/systemd/$UNIT_NAME" 2>/dev/null \
    | sed -n 's/.*exposure level for [^:]*: \([0-9][0-9.]*\) .*/\1/p' | tail -1)"
  if [ -n "$score" ]; then
    say "systemd-analyze security: $UNIT_NAME exposure=$score (target < 5.0)"
    if awk -v s="$score" 'BEGIN{exit !(s >= 5.0)}'; then
      say "WARN: exposure >= 5.0 — проверьте hardening (ADR-026 §6)"
    fi
  else
    say "WARN: could not parse exposure score (systemd-analyze unavailable/offline?)"
  fi
fi

say "done. Next: edit $ENV_DST, place certificates, verify with: systemctl status $UNIT_NAME"
