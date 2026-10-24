#!/usr/bin/env bash
# Dispara uma análise do SonarQube em um projeto local usando o scanner oficial.
#
# Uso:
#   SONAR_TOKEN=xxxx ./scans/sonar-scan.sh /caminho/do/projeto [projectKey] [args extras]
#
# Variáveis:
#   SONAR_TOKEN     (obrigatória) token gerado em My Account > Security
#   SONAR_HOST_URL  padrão http://host.docker.internal:9000
set -euo pipefail

PROJECT_DIR="${1:?uso: $0 <diretorio-do-projeto> [projectKey] [args extras]}"
PROJECT_KEY="${2:-$(basename "$(cd "$PROJECT_DIR" && pwd)")}"
SONAR_HOST_URL="${SONAR_HOST_URL:-http://host.docker.internal:9000}"

if [[ -z "${SONAR_TOKEN:-}" ]]; then
  echo "ERRO: defina SONAR_TOKEN (SonarQube > My Account > Security > Generate Tokens)." >&2
  exit 1
fi

echo ">> Projeto : $(cd "$PROJECT_DIR" && pwd)"
echo ">> Chave   : $PROJECT_KEY"
echo ">> Servidor: $SONAR_HOST_URL"

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e SONAR_HOST_URL="$SONAR_HOST_URL" \
  -e SONAR_TOKEN="$SONAR_TOKEN" \
  -v "$(cd "$PROJECT_DIR" && pwd):/usr/src" \
  -w /usr/src \
  sonarsource/sonar-scanner-cli:latest \
  -Dsonar.projectKey="$PROJECT_KEY" \
  -Dsonar.projectName="$PROJECT_KEY" \
  -Dsonar.sourceEncoding=UTF-8 \
  "${@:3}"
