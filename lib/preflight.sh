#!/usr/bin/env bash
# preflight.sh — validações antes de iniciar o pipeline.

# shellcheck shell=bash

cmd_doctor() {
  local failures=0

  step "Pré-requisitos"
  for bin in docker jq python3 curl; do
    if have "$bin"; then
      ok "$bin: $(command -v "$bin")"
    else
      err "$bin: não encontrado"
      failures=$((failures + 1))
    fi
  done

  if have docker; then
    if docker info >/dev/null 2>&1; then
      ok "Docker daemon: ativo ($(docker info --format '{{.ServerVersion}}' 2>/dev/null))"
    else
      err "Docker daemon: não está rodando"
      failures=$((failures + 1))
    fi
    if docker compose version >/dev/null 2>&1; then
      ok "Docker Compose: $(docker compose version --short 2>/dev/null)"
    else
      err "Docker Compose v2: não encontrado"
      failures=$((failures + 1))
    fi
  fi

  if have semgrep; then
    ok "semgrep: $(semgrep --version 2>/dev/null | head -1)"
  else
    warn "semgrep local não encontrado (será usado via container)"
  fi

  step "Stack local"
  load_dotenv "$DEVSEC_ROOT/.env"
  local sonar="http://localhost:${SONAR_PORT:-9000}"
  local dtrack="http://localhost:${DTRACK_API_PORT:-9081}"
  local zap="http://localhost:${ZAP_PORT:-9082}"

  if curl -fsS --max-time 5 "$sonar/api/system/status" 2>/dev/null | jq -e '.status == "UP"' >/dev/null 2>&1; then
    ok "SonarQube: UP ($sonar)"
  else
    warn "SonarQube: indisponível ($sonar) — rode 'make up'"
  fi

  if curl -fsS --max-time 5 "$dtrack/api/version" >/dev/null 2>&1; then
    ok "Dependency-Track: UP ($dtrack)"
  else
    warn "Dependency-Track: indisponível ($dtrack) — rode 'make up'"
  fi

  if curl -fsS --max-time 5 "$zap/JSON/core/view/version/?apikey=${ZAP_API_KEY:-}" >/dev/null 2>&1; then
    ok "OWASP ZAP: UP ($zap)"
  else
    warn "OWASP ZAP: indisponível ($zap) — rode 'make up'"
  fi

  step "Imagens auxiliares (serão baixadas na primeira execução)"
  for image in ghcr.io/anchore/syft:latest ghcr.io/anchore/grype:latest zricethezav/gitleaks:latest ghcr.io/zaproxy/zaproxy:stable; do
    if docker image inspect "$image" >/dev/null 2>&1; then
      ok "$image (local)"
    else
      warn "$image (será baixada)"
    fi
  done

  if [[ "$failures" -gt 0 ]]; then
    err "$failures pré-requisito(s) crítico(s) não atendido(s)"
    return 1
  fi
  ok "Pré-requisitos essenciais OK"
}

run_preflight() {
  local failures=0

  step "Preflight"
  have docker || { err "docker não encontrado"; failures=$((failures + 1)); }
  have jq || { err "jq não encontrado"; failures=$((failures + 1)); }
  have python3 || { err "python3 não encontrado"; failures=$((failures + 1)); }
  have curl || { err "curl não encontrado"; failures=$((failures + 1)); }
  [[ "$failures" -eq 0 ]] || die "pré-requisitos ausentes"

  local needs_code=0
  is_true "$ENABLE_SAST" && needs_code=1
  is_true "$ENABLE_SCA" && needs_code=1
  is_true "$ENABLE_SECRETS" && needs_code=1

  if [[ "$needs_code" -eq 1 && -z "${BACKEND_PATH:-}" && -z "${FRONTEND_PATH:-}" ]]; then
    die "informe BACKEND_PATH e/ou FRONTEND_PATH no perfil"
  fi
  [[ -z "${BACKEND_PATH:-}" ]] || [[ -d "$BACKEND_PATH" ]] || die "BACKEND_PATH não existe: $BACKEND_PATH"
  [[ -z "${FRONTEND_PATH:-}" ]] || [[ -d "$FRONTEND_PATH" ]] || die "FRONTEND_PATH não existe: $FRONTEND_PATH"
  [[ -z "${OPENAPI_SPEC:-}" ]] || [[ -f "$OPENAPI_SPEC" ]] || die "OPENAPI_SPEC não existe: $OPENAPI_SPEC"

  ok "caminhos válidos"

  if is_true "$ENABLE_DAST"; then
    [[ -n "${APP_URL:-}" || -n "${API_URL:-}" ]] || die "DAST habilitado sem APP_URL/API_URL"
    local target="${APP_URL:-$API_URL}"
    if curl -fsS --max-time 8 -o /dev/null "$target" 2>/dev/null; then
      ok "alvo acessível: $target"
    elif curl -sS --max-time 8 -o /dev/null "$target" 2>/dev/null; then
      ok "alvo acessível (resposta não-2xx): $target"
    else
      if is_true "${ALLOW_UNREACHABLE_TARGET:-0}"; then
        warn "alvo inacessível: $target (ALLOW_UNREACHABLE_TARGET=1)"
      else
        die "alvo inacessível: $target — suba a aplicação ou use ALLOW_UNREACHABLE_TARGET=1"
      fi
    fi
  fi

  if [[ "${AUTH_MODE:-none}" != "none" ]]; then
    [[ -n "${AUTH_USERNAME:-}" && -n "${AUTH_PASSWORD:-}" ]] \
      || die "AUTH_MODE=$AUTH_MODE exige AUTH_USERNAME e AUTH_PASSWORD"
    ok "credenciais de teste presentes (AUTH_MODE=$AUTH_MODE)"
  fi

  if is_true "$ZAP_ACTIVE"; then
    if ! is_true "${I_HAVE_AUTHORIZATION:-0}"; then
      die "DAST ativo exige autorização explícita: use --i-have-authorization"
    fi
    warn "DAST ATIVO habilitado: payloads de ataque serão enviados a $APP_URL"
  fi

  ok "preflight concluído"
}
