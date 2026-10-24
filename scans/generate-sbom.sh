#!/usr/bin/env bash
# Gera um SBOM CycloneDX usando a imagem oficial do Syft.
#
# Uso:
#   ./scans/generate-sbom.sh /caminho/do/projeto        # diretório (código-fonte)
#   ./scans/generate-sbom.sh nginx:latest               # imagem de container
#
# Saída: ./reports/sbom/<nome>.cdx.json
set -euo pipefail

TARGET="${1:?uso: $0 <diretorio|imagem:tag> [nome-de-saida]}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/reports/sbom"
mkdir -p "$OUT_DIR"

if [[ -d "$TARGET" ]]; then
  NAME="${2:-$(basename "$(cd "$TARGET" && pwd)")}"
  docker run --rm \
    -v "$(cd "$TARGET" && pwd):/src:ro" \
    -v "$OUT_DIR:/out" \
    ghcr.io/anchore/syft:latest \
    dir:/src -o cyclonedx-json=/out/"$NAME".cdx.json
else
  NAME="${2:-$(echo "$TARGET" | tr '/:' '__')}"
  docker run --rm \
    -v "$OUT_DIR:/out" \
    ghcr.io/anchore/syft:latest \
    "$TARGET" -o cyclonedx-json=/out/"$NAME".cdx.json
fi

echo "SBOM gerado: $OUT_DIR/$NAME.cdx.json"
