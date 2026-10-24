#!/usr/bin/env bash
# Scan ativo completo do OWASP ZAP contra uma URL.
#
# Uso:
#   ./scans/zap-full-scan.sh https://minha-app.local [nome-relatorio]
#
# ATENÇÃO: scan ativo envia payloads de ataque. Use apenas em ambiente
# de teste/homologação e com autorização formal.
set -euo pipefail

TARGET="${1:?uso: $0 <url-alvo> [nome-relatorio]}"
NAME="${2:-full-scan}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports/zap"
mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$OUT_DIR:/zap/wrk:rw" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t "$TARGET" \
  -r "$NAME.html" \
  -J "$NAME.json" \
  -w "$NAME.md" \
  -I

echo "Relatório: $OUT_DIR/$NAME.html"
