#!/usr/bin/env bash
# Scan de API REST a partir de uma especificação OpenAPI/Swagger.
#
# Uso:
#   ./scans/zap-api-scan.sh https://minha-api.local /caminho/openapi.json [nome]
#
# A especificação é copiada para dentro do container pelo mount do diretório
# que a contém.
set -euo pipefail

TARGET="${1:?uso: $0 <url-base-da-api> <openapi.json|yaml> [nome-relatorio]}"
SPEC="${2:?informe o caminho da especificação OpenAPI}"
NAME="${3:-api-scan}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports/zap"
mkdir -p "$OUT_DIR"

if [[ ! -f "$SPEC" ]]; then
  echo "ERRO: especificação não encontrada: $SPEC" >&2
  exit 1
fi

SPEC_DIR="$(cd "$(dirname "$SPEC")" && pwd)"
SPEC_FILE="$(basename "$SPEC")"

docker run --rm \
  -v "$OUT_DIR:/zap/wrk:rw" \
  -v "$SPEC_DIR:/spec:ro" \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t "$TARGET" \
  -f "/spec/$SPEC_FILE" \
  -r "$NAME.html" \
  -J "$NAME.json" \
  -w "$NAME.md" \
  -I

echo "Relatório: $OUT_DIR/$NAME.html"
