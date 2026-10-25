#!/usr/bin/env bash
# stack.sh — sobe a stack de ferramentas e espera os serviços ficarem saudáveis.

# shellcheck shell=bash

stack_up() {
  if ! is_true "$STACK_UP"; then
    warn "stack: pulada (STACK_UP=$STACK_UP)"
    record_status "stack" "skipped" "STACK_UP desabilitado" 0
    return 0
  fi

  step "Stack de ferramentas"
  if ! docker compose version >/dev/null 2>&1; then
    record_status "stack" "failed" "docker compose v2 ausente" 0
    return 3
  fi

  ( cd "$DEVSEC_ROOT" && docker compose up -d ) || {
    record_status "stack" "failed" "docker compose up falhou" 0
    return 3
  }

  local started
  started="$(epoch_s)"

  if is_true "$ENABLE_SONAR"; then
    log "aguardando SonarQube..."
    wait_sonar || { warn "SonarQube não ficou UP em ${STACK_TIMEOUT}s"; record_status "stack" "partial" "SonarQube indisponível" "$(( $(epoch_s) - started ))"; return 3; }
    ok "SonarQube UP"
  fi

  if is_true "$ENABLE_DTRACK"; then
    log "aguardando Dependency-Track..."
    wait_dtrack || { warn "Dependency-Track não ficou UP em ${STACK_TIMEOUT}s"; record_status "stack" "partial" "Dependency-Track indisponível" "$(( $(epoch_s) - started ))"; return 3; }
    ok "Dependency-Track UP"
  fi

  if is_true "$ENABLE_DAST"; then
    log "aguardando OWASP ZAP..."
    wait_zap || { warn "ZAP não ficou UP em ${STACK_TIMEOUT}s"; record_status "stack" "partial" "ZAP indisponível" "$(( $(epoch_s) - started ))"; return 3; }
    ok "ZAP UP"
  fi

  record_status "stack" "ok" "stack saudável" "$(( $(epoch_s) - started ))"
  return 0
}

wait_sonar() {
  local i=0
  while (( i < STACK_TIMEOUT )); do
    if curl -fsS --max-time 5 "$SONAR_URL/api/system/status" 2>/dev/null | jq -e '.status == "UP"' >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
    i=$((i + 5))
  done
  return 1
}

wait_dtrack() {
  local i=0
  while (( i < STACK_TIMEOUT )); do
    if curl -fsS --max-time 5 "$DTRACK_URL/api/version" >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
    i=$((i + 5))
  done
  return 1
}

wait_zap() {
  local i=0
  while (( i < STACK_TIMEOUT )); do
    if curl -fsS --max-time 5 "$ZAP_URL/JSON/core/view/version/?apikey=${ZAP_API_KEY:-}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
    i=$((i + 3))
  done
  return 1
}

# Compose é configuração explícita do perfil; nenhum comando shell é avaliado.
application_up() {
  APP_STARTED=0
  if ! is_true "${APP_STACK_UP:-1}" || [[ -z "${APP_COMPOSE_FILE:-}" ]]; then
    record_status "application" "skipped" "Compose da aplicação não solicitado/configurado" 0
    return 0
  fi
  local started compose_dir rc=0
  started="$(epoch_s)"
  compose_dir="$(dirname "$APP_COMPOSE_FILE")"
  local args=(compose --project-directory "$compose_dir" -f "$APP_COMPOSE_FILE")
  [[ -n "${APP_COMPOSE_ENV_FILE:-}" ]] && args+=(--env-file "$APP_COMPOSE_ENV_FILE")
  step "Aplicação de teste (Docker Compose)"
  local start_args=(up -d --no-build --pull never)
  if is_true "${APP_ALLOW_BUILD_WITH_INTERNAL_REGISTRIES:-0}"; then
    start_args=(up -d --build)
  fi
  (cd "$compose_dir" && docker "${args[@]}" "${start_args[@]}") >"$RUN_DIR/logs/application-compose.log" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    warn "Compose da aplicação falhou; veja logs/application-compose.log"
    record_status "application" "failed" "Compose da aplicação falhou; consulte o log local" "$(( $(epoch_s) - started ))"
    return 3
  fi
  APP_STARTED=1
  record_status "application" "ok" "Compose iniciado; volumes e serviços preservados" "$(( $(epoch_s) - started ))"
}

check_dast_targets() {
  DAST_TARGET_READY=1
  is_true "$ENABLE_DAST" || return 0
  local target started timeout=0
  [[ "${APP_STARTED:-0}" == "1" ]] && timeout="${APP_START_TIMEOUT:-180}"
  for target in "${APP_URL:-}" "${APP_HEALTH_URL:-${API_URL:-}}"; do
    [[ -n "$target" ]] || continue
    started="$(epoch_s)"
    until target_ready "$target"; do
      if (( $(epoch_s) - started >= timeout )); then
        DAST_TARGET_READY=0
        warn "Alvo inacessível; DAST não será executado: $target"
        break
      fi
      sleep 2
    done
  done
}

target_ready() {
  local target="$1"
  local args=(-sS --connect-timeout 3 --max-time 5 -o /dev/null)
  # Uma URL de saúde explícita deve retornar sucesso, não apenas abrir conexão.
  [[ -n "${APP_HEALTH_URL:-}" && "$target" == "$APP_HEALTH_URL" ]] && args+=(-f)
  curl "${args[@]}" "$target" 2>/dev/null
}
