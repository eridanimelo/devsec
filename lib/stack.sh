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
