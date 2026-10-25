#!/usr/bin/env bash
# common.sh — utilidades compartilhadas pelo CLI devsec.
# Este arquivo é carregado por bin/devsec; não é executável por conta própria.

# shellcheck shell=bash

DEVSEC_ROOT="${DEVSEC_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export DEVSEC_ROOT

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
fi

log()  { printf '%s▸%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; }

have() { command -v "$1" >/dev/null 2>&1; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
epoch_s() { date +%s; }

slugify() {
  printf '%s' "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -e 's/[^a-z0-9._-]\+/-/g' -e 's/^-//' -e 's/-$//'
}

# Resolve caminho relativo à raiz do devsec (não ao diretório atual), para
# que o perfil funcione de qualquer lugar.
resolve_path() {
  local p="${1:-}"
  [[ -z "$p" ]] && return 0
  if [[ "$p" = /* ]]; then
    printf '%s' "$p"
  else
    printf '%s' "$DEVSEC_ROOT/$p"
  fi
}

# Mesmo que resolve_path, mas normaliza e exige existência.
require_dir() {
  local label="$1" path="$2"
  [[ -n "$path" ]] || return 0
  [[ -d "$path" ]] || die "$label não existe: $path"
  (cd "$path" && pwd)
}

load_dotenv() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  set -a
  # shellcheck disable=SC1090
  source "$file"
  set +a
}

load_profile() {
  local file="${1:?informe --profile <arquivo.env>}"
  local abs
  if [[ "$file" = /* ]]; then
    abs="$file"
  elif [[ -f "$file" ]]; then
    abs="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
  else
    abs="$DEVSEC_ROOT/$file"
  fi
  [[ -f "$abs" ]] || die "perfil não encontrado: $file"
  PROFILE_FILE="$abs"
  PROFILE_DIR="$(dirname "$abs")"

  # Base: .env do devsec (senhas/chaves da stack).
  load_dotenv "$DEVSEC_ROOT/.env"

  # Perfil do projeto (sobrepõe o .env).
  load_dotenv "$PROFILE_FILE"

  # Segredos locais do perfil: <perfil>.secrets.env (gitignored).
  local secrets="${PROFILE_FILE%.*}.secrets.env"
  [[ "$secrets" != "$PROFILE_FILE" && -f "$secrets" ]] && load_dotenv "$secrets"

  RUN_NAME="${RUN_NAME:-$(basename "${PROFILE_FILE%.*}")}"

  BACKEND_PATH="$(resolve_path "${BACKEND_PATH:-}")"
  FRONTEND_PATH="$(resolve_path "${FRONTEND_PATH:-}")"
  OPENAPI_SPEC="$(resolve_path "${OPENAPI_SPEC:-}")"
  AUTH_PLAYWRIGHT_SCRIPT="$(resolve_path "${AUTH_PLAYWRIGHT_SCRIPT:-}")"
  APP_COMPOSE_FILE="$(resolve_path "${APP_COMPOSE_FILE:-}")"
  APP_COMPOSE_ENV_FILE="$(resolve_path "${APP_COMPOSE_ENV_FILE:-}")"
  : "${APP_STACK_UP:=1}"
  : "${APP_START_TIMEOUT:=180}"

  # Portas/URLs da stack (perfil pode sobrescrever).
  : "${SONAR_PORT:=9000}"
  : "${DTRACK_API_PORT:=9081}"
  : "${ZAP_PORT:=9082}"
  : "${SONAR_URL:=http://localhost:${SONAR_PORT}}"
  : "${DTRACK_URL:=http://localhost:${DTRACK_API_PORT}}"
  : "${ZAP_URL:=http://localhost:${ZAP_PORT}}"

  # Flags (0/1).
  : "${ENABLE_SAST:=1}"
  : "${ENABLE_SCA:=1}"
  : "${ENABLE_SECRETS:=1}"
  : "${ENABLE_DAST:=1}"
  : "${ENABLE_SONAR:=1}"
  : "${ENABLE_DTRACK:=1}"
  : "${ENABLE_GRYPE:=1}"
  : "${STACK_UP:=1}"
  : "${ZAP_ACTIVE:=0}"
  : "${AUTH_MODE:=none}"
  : "${GATE_FAIL_ON:=critical,high}"
  : "${ZAP_TIMEOUT:=0}"

  : "${SEMGREP_CONFIG:=p/owasp-top-ten}"
  : "${SONAR_PROJECT_KEY:=${RUN_NAME}}"
  : "${SONAR_ADMIN_USER:=admin}"
  : "${SONAR_ADMIN_PASSWORD:=admin}"
  : "${DTRACK_ADMIN_USER:=admin}"
  : "${DTRACK_ADMIN_PASSWORD:=admin}"

  : "${STACK_TIMEOUT:=240}"

  export RUN_NAME BACKEND_PATH FRONTEND_PATH OPENAPI_SPEC
  export SONAR_URL DTRACK_URL ZAP_URL SONAR_PORT DTRACK_API_PORT ZAP_PORT
  export ENABLE_SAST ENABLE_SCA ENABLE_SECRETS ENABLE_DAST ENABLE_SONAR ENABLE_DTRACK ENABLE_GRYPE
  export STACK_UP ZAP_ACTIVE AUTH_MODE GATE_FAIL_ON SEMGREP_CONFIG STACK_TIMEOUT
}

init_run() {
  RUN_ID="${RUN_ID:-$(slugify "$RUN_NAME")-$(date +%Y%m%d-%H%M%S)}"
  RUN_DIR="$DEVSEC_ROOT/reports/runs/$RUN_ID"
  mkdir -p "$RUN_DIR"/raw/{sast,sca,secrets,dast,stack} "$RUN_DIR"/logs "$RUN_DIR"/artifacts
  export RUN_ID RUN_DIR

  jq -n \
    --arg run_id "$RUN_ID" \
    --arg project "$RUN_NAME" \
    --arg group "${GROUP_NAME:-$RUN_NAME}" \
    --arg started_at "$(now_iso)" \
    --arg profile "$PROFILE_FILE" \
    --arg backend "$BACKEND_PATH" \
    --arg frontend "$FRONTEND_PATH" \
    --arg app_url "${APP_URL:-}" \
    --arg api_url "${API_URL:-}" \
    --arg auth_mode "$AUTH_MODE" \
    --arg zap_active "$ZAP_ACTIVE" \
    --arg devsec_root "$DEVSEC_ROOT" \
    '{
      run_id: $run_id,
      project: $project,
      group: $group,
      started_at: $started_at,
      finished_at: null,
      profile: $profile,
      devsec_root: $devsec_root,
      scope: {
        backend: (if $backend == "" then null else $backend end),
        frontend: (if $frontend == "" then null else $frontend end),
        app_url: (if $app_url == "" then null else $app_url end),
        api_url: (if $api_url == "" then null else $api_url end)
      },
      dast: {
        mode: (if $zap_active == "1" then "active" else "baseline" end),
        auth_mode: $auth_mode
      },
      tools: [],
      versions: {}
    }' > "$RUN_DIR/run.json"
}

run_meta_set() {
  local key="$1" value="$2"
  local tmp="$RUN_DIR/run.json.tmp"
  jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$RUN_DIR/run.json" > "$tmp" && mv "$tmp" "$RUN_DIR/run.json"
}

run_meta_add_tool() {
  local stage="$1" status="$2" detail="$3"
  local tmp="$RUN_DIR/run.json.tmp"
  jq --arg stage "$stage" --arg status "$status" --arg detail "$detail" \
    '.tools = ((.tools // []) | map(select(.stage != $stage)) + [{stage: $stage, status: $status, detail: $detail}])' \
    "$RUN_DIR/run.json" > "$tmp" && mv "$tmp" "$RUN_DIR/run.json"
}

record_status() {
  local stage="$1" status="$2" detail="${3:-}" duration="${4:-0}"
  local dir="$RUN_DIR/raw/$stage"
  mkdir -p "$dir"
  jq -n \
    --arg stage "$stage" \
    --arg status "$status" \
    --arg detail "$detail" \
    --argjson duration "$duration" \
    '{stage: $stage, status: $status, detail: $detail, duration_s: $duration}' \
    > "$dir/status.json"
  run_meta_add_tool "$stage" "$status" "$detail"
}

# Executa um comando, mede duração e registra o status do estágio.
# Uso: run_stage <stage> <função> [args...]
run_stage() {
  local stage="$1"; shift
  local started ended rc=0
  started="$(epoch_s)"
  set +e
  "$@"
  rc=$?
  set -e
  ended="$(epoch_s)"
  if [[ "$rc" -eq 0 ]]; then
    return 0
  elif [[ "$rc" -eq 3 ]]; then
    record_status "$stage" "partial" "estágio concluído com avisos" "$((ended - started))"
    return 0
  else
    record_status "$stage" "failed" "estágio falhou (rc=$rc); veja logs/" "$((ended - started))"
    return 0
  fi
}

wait_http() {
  local url="$1" name="$2" timeout="${3:-60}"
  local i=0
  while (( i < timeout )); do
    if curl -fsS --max-time 5 -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 2
    i=$((i + 2))
  done
  return 1
}

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

open_report() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  if [[ "$(uname -s)" == "Darwin" ]]; then
    open "$file"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$file" >/dev/null 2>&1 &
  else
    printf 'Relatório: %s\n' "$file"
  fi
}
