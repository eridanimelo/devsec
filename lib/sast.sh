#!/usr/bin/env bash
# sast.sh — análise estática: Semgrep (rápido) + SonarQube (profundo).

# shellcheck shell=bash

run_sast() {
  if ! is_true "$ENABLE_SAST"; then
    record_status "sast" "skipped" "ENABLE_SAST=0" 0
    return 0
  fi

  step "SAST"
  local started
  started="$(epoch_s)"
  local rc=0

  run_semgrep || rc=3

  if is_true "$ENABLE_SONAR"; then
    run_sonar || rc=3
  else
    warn "SonarQube desabilitado (ENABLE_SONAR=0)"
  fi

  if [[ "$rc" -eq 0 ]]; then
    record_status "sast" "ok" "Semgrep e SonarQube concluídos" "$(( $(epoch_s) - started ))"
  else
    record_status "sast" "partial" "um ou mais analisadores SAST falharam" "$(( $(epoch_s) - started ))"
  fi
  return 0
}

component_names() {
  COMPONENT_NAMES=()
  COMPONENT_PATHS=()
  if [[ -n "${BACKEND_PATH:-}" ]]; then
    COMPONENT_NAMES+=("backend")
    COMPONENT_PATHS+=("$BACKEND_PATH")
  fi
  if [[ -n "${FRONTEND_PATH:-}" ]]; then
    COMPONENT_NAMES+=("frontend")
    COMPONENT_PATHS+=("$FRONTEND_PATH")
  fi
}

run_semgrep() {
  component_names
  local out_dir="$RUN_DIR/raw/sast"
  local rc=0

  local i
  for i in "${!COMPONENT_NAMES[@]}"; do
    local name="${COMPONENT_NAMES[$i]}"
    local path="${COMPONENT_PATHS[$i]}"
    local out="$out_dir/semgrep-$name.json"

    log "Semgrep: $name ($path)"

    # `auto` exige métricas ligadas; configs explícitas funcionam com métricas off.
    local metrics_flag="--metrics=off"
    case "$SEMGREP_CONFIG" in *auto*) metrics_flag="--metrics=on" ;; esac

    local config_args=()
    local cfg
    for cfg in $SEMGREP_CONFIG; do
      config_args+=(--config "$cfg")
    done
    [[ ${#config_args[@]} -gt 0 ]] || config_args=(--config "p/owasp-top-ten")

    local code=0
    if have semgrep; then
      semgrep scan \
        "${config_args[@]}" \
        --json \
        "$metrics_flag" \
        --quiet \
        --output "$out" \
        "$path" >>"$RUN_DIR/logs/semgrep-$name.log" 2>&1 || code=$?
    else
      docker run --rm \
        -v "$path:/src:ro" \
        -v "$out_dir:/out" \
        semgrep/semgrep:latest \
        semgrep scan "${config_args[@]}" --json "$metrics_flag" --quiet \
        --output "/out/semgrep-$name.json" /src \
        >>"$RUN_DIR/logs/semgrep-$name.log" 2>&1 || code=$?
    fi

    # Semgrep: 0 = sem achados, 1 = achados encontrados, >1 = erro.
    if [[ "$code" -gt 1 ]] || [[ ! -s "$out" ]]; then
      warn "Semgrep falhou em $name (rc=$code). Veja logs/semgrep-$name.log"
      rc=1
      continue
    fi

    local count
    count="$(jq -r '.results | length' "$out" 2>/dev/null || echo 0)"
    ok "Semgrep: $name → $count achado(s)"
  done

  return "$rc"
}

sonar_host_for_container() {
  case "$SONAR_URL" in
    *localhost*) printf '%s' "${SONAR_URL/localhost/host.docker.internal}" ;;
    *) printf '%s' "$SONAR_URL" ;;
  esac
}

ensure_sonar_token() {
  if [[ -n "${SONAR_TOKEN:-}" ]]; then
    SONAR_TOKEN_EFFECTIVE="$SONAR_TOKEN"
    return 0
  fi

  log "SonarQube: gerando token via API (usuário $SONAR_ADMIN_USER)"
  local resp
  resp="$(curl -sS -u "$SONAR_ADMIN_USER:$SONAR_ADMIN_PASSWORD" \
    -X POST "$SONAR_URL/api/user_tokens/generate" \
    --data-urlencode "name=devsec-$RUN_ID" 2>/dev/null || true)"

  SONAR_TOKEN_EFFECTIVE="$(jq -r '.token // empty' <<<"$resp" 2>/dev/null || true)"
  if [[ -z "$SONAR_TOKEN_EFFECTIVE" ]]; then
    warn "não foi possível gerar token no SonarQube (login/senha padrão alterados?)."
    warn "defina SONAR_TOKEN no perfil ou em <perfil>.secrets.env"
    return 1
  fi
  ok "token do SonarQube gerado"
}

wait_sonar_ce() {
  local key="$1" timeout="${2:-300}"
  local i=0 body pending status
  while (( i < timeout )); do
    body="$(curl -sS -u "$SONAR_TOKEN_EFFECTIVE:" \
      "$SONAR_URL/api/ce/component?component=$key" 2>/dev/null || true)"
    # `current` permanece preenchido com a última tarefa concluída; só conta
    # como pendente enquanto o status não for terminal.
    pending="$(jq -r '
      ((.queue // []) | length)
      + (if (.current // null) == null then 0
         elif ((.current.status // "") | test("^(SUCCESS|FAILED|CANCELED)$")) then 0
         else 1 end)
    ' <<<"$body" 2>/dev/null || echo 1)"
    status="$(jq -r '.current.status // empty' <<<"$body" 2>/dev/null || true)"
    [[ "$pending" == "0" ]] && {
      [[ "$status" == "FAILED" || "$status" == "CANCELED" ]] && warn "CE do SonarQube terminou com $status ($key)"
      return 0
    }
    sleep 5
    i=$((i + 5))
  done
  return 1
}

fetch_sonar_issues() {
  local key="$1" out="$2"
  local page=1 total=1 tmp="$RUN_DIR/raw/sast/.issues-page.json"
  local acc="$RUN_DIR/raw/sast/.issues-acc.json"
  printf '[]' > "$acc"

  while :; do
    curl -sS -u "$SONAR_TOKEN_EFFECTIVE:" \
      "$SONAR_URL/api/issues/search?componentKeys=$key&resolved=false&ps=500&p=$page" \
      -o "$tmp" 2>/dev/null || break

    total="$(jq -r '.total // 0' "$tmp" 2>/dev/null || echo 0)"
    jq -s '.[0] + (.[1].issues // [])' "$acc" "$tmp" > "$acc.tmp" && mv "$acc.tmp" "$acc"

    local fetched
    fetched="$(jq -r '.issues | length' "$tmp" 2>/dev/null || echo 0)"
    [[ "$fetched" -eq 0 ]] && break
    page=$((page + 1))
    [[ $(( (page - 1) * 500 )) -ge "$total" ]] && break
  done

  mv "$acc" "$out" 2>/dev/null || printf '[]' > "$out"
  rm -f "$tmp"
}

fetch_sonar_hotspots() {
  local key="$1" out="$2"
  local page=1 total=1 tmp="$RUN_DIR/raw/sast/.hot-page.json"
  local acc="$RUN_DIR/raw/sast/.hot-acc.json"
  printf '[]' > "$acc"

  while :; do
    curl -sS -u "$SONAR_TOKEN_EFFECTIVE:" \
      "$SONAR_URL/api/hotspots/search?projectKey=$key&ps=500&p=$page" \
      -o "$tmp" 2>/dev/null || break

    total="$(jq -r '.paging.total // 0' "$tmp" 2>/dev/null || echo 0)"
    jq -s '.[0] + (.[1].hotspots // [])' "$acc" "$tmp" > "$acc.tmp" && mv "$acc.tmp" "$acc"

    local fetched
    fetched="$(jq -r '.hotspots | length' "$tmp" 2>/dev/null || echo 0)"
    [[ "$fetched" -eq 0 ]] && break
    page=$((page + 1))
    [[ $(( (page - 1) * 500 )) -ge "$total" ]] && break
  done

  mv "$acc" "$out" 2>/dev/null || printf '[]' > "$out"
  rm -f "$tmp"
}

run_sonar() {
  component_names
  if ! ensure_sonar_token; then
    return 1
  fi

  local host_in_container
  host_in_container="$(sonar_host_for_container)"
  local rc=0

  local i
  for i in "${!COMPONENT_NAMES[@]}"; do
    local name="${COMPONENT_NAMES[$i]}"
    local path="${COMPONENT_PATHS[$i]}"
    local key="${SONAR_PROJECT_KEY}-${name}"

    log "SonarQube: $name → projeto $key"
    local java_args=()
    if [[ -d "$path/target/classes" ]]; then
      java_args=(-Dsonar.java.binaries=target/classes)
    elif [[ -f "$path/pom.xml" ]]; then
      warn "SonarQube: $name é Maven sem target/classes; análise Java ficará menos precisa"
      warn "compile antes (mvn -q -DskipTests package) para melhorar o resultado"
    fi

    local code=0
    docker run --rm \
      --add-host=host.docker.internal:host-gateway \
      -e SONAR_HOST_URL="$host_in_container" \
      -e SONAR_TOKEN="$SONAR_TOKEN_EFFECTIVE" \
      -v "$path:/usr/src" \
      -w /usr/src \
      sonarsource/sonar-scanner-cli:latest \
      -Dsonar.projectKey="$key" \
      -Dsonar.projectName="$key" \
      -Dsonar.sourceEncoding=UTF-8 \
      -Dsonar.exclusions="**/node_modules/**,**/dist/**,**/build/**,**/target/**,**/.angular/**,**/coverage/**" \
      "${java_args[@]}" \
      >>"$RUN_DIR/logs/sonar-$name.log" 2>&1 || code=$?

    if [[ "$code" -ne 0 ]]; then
      warn "scanner do SonarQube falhou em $name (rc=$code). Veja logs/sonar-$name.log"
      rc=1
      continue
    fi

    if ! wait_sonar_ce "$key" 300; then
      warn "análise do SonarQube não terminou em 300s ($key)"
      rc=1
      continue
    fi

    fetch_sonar_issues "$key" "$RUN_DIR/raw/sast/sonar-issues-$name.json"
    fetch_sonar_hotspots "$key" "$RUN_DIR/raw/sast/sonar-hotspots-$name.json"

    curl -sS -u "$SONAR_TOKEN_EFFECTIVE:" \
      "$SONAR_URL/api/qualitygates/project_status?projectKey=$key" \
      -o "$RUN_DIR/raw/sast/sonar-qualitygate-$name.json" 2>/dev/null || true

    local issues hotspots
    issues="$(jq -r 'length' "$RUN_DIR/raw/sast/sonar-issues-$name.json" 2>/dev/null || echo 0)"
    hotspots="$(jq -r 'length' "$RUN_DIR/raw/sast/sonar-hotspots-$name.json" 2>/dev/null || echo 0)"
    ok "SonarQube: $name → $issues issue(s), $hotspots hotspot(s)"
  done

  return "$rc"
}
