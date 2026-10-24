#!/usr/bin/env bash
# Scan passivo (baseline) do OWASP ZAP contra uma URL.
#
# Uso:
#   ./scans/zap-baseline.sh https://minha-app.local [nome-relatorio]
#
# Gera HTML + JSON + Markdown em ./reports/zap.
# Use somente em alvos que você tem autorização para testar.
set -euo pipefail

TARGET="${1:?uso: $0 <url-alvo> [nome-relatorio]}"
NAME="${2:-baseline}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports/zap"
mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$OUT_DIR:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET" \
  -r "$NAME.html" \
  -J "$NAME.json" \
  -w "$NAME.md" \
  -I

echo "Relatório: $OUT_DIR/$NAME.html"
