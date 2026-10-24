#!/usr/bin/env bash
# Envia um SBOM (CycloneDX ou SPDX) para o Dependency-Track.
#
# Uso:
#   DTRACK_API_KEY=xxxx ./scans/dtrack-upload.sh bom.json "minha-api" "1.0.0"
#
# Variáveis:
#   DTRACK_API_KEY  (obrigatória) API key criada em Administration > Access Management > Teams
#   DTRACK_URL      padrão http://localhost:8081
#
# O projeto/versão é criado automaticamente se não existir (autoCreate=true).
set -euo pipefail

BOM_FILE="${1:?uso: $0 <arquivo-bom.json> [nome-projeto] [versao]}"
PROJECT_NAME="${2:-$(basename "$(cd "$(dirname "$BOM_FILE")" && pwd)")}"
PROJECT_VERSION="${3:-1.0.0}"
DTRACK_URL="${DTRACK_URL:-http://localhost:8081}"

if [[ -z "${DTRACK_API_KEY:-}" ]]; then
  echo "ERRO: defina DTRACK_API_KEY." >&2
  exit 1
fi

if [[ ! -f "$BOM_FILE" ]]; then
  echo "ERRO: arquivo não encontrado: $BOM_FILE" >&2
  exit 1
fi

echo ">> SBOM    : $BOM_FILE"
echo ">> Projeto : $PROJECT_NAME / $PROJECT_VERSION"
echo ">> Servidor: $DTRACK_URL"

curl -sS -X POST "$DTRACK_URL/api/v1/bom" \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -H "Accept: application/json" \
  -F "projectName=$PROJECT_NAME" \
  -F "projectVersion=$PROJECT_VERSION" \
  -F "autoCreate=true" \
  -F "bom=@$BOM_FILE"

echo
echo "SBOM enviado. O processamento é assíncrono: acompanhe em Projects no Dependency-Track."
